"""Persistence collector: anything set to run automatically.

Attackers want to survive a reboot, so they add themselves to an autostart
location (MITRE ATT&CK tactic TA0003, Persistence). Vigil takes an inventory of
the most common ones and reports anything added, changed or removed:

  - Registry Run / RunOnce keys (HKCU and HKLM, 64- and 32-bit)   T1547.001
  - Startup folders (current user and all users)                    T1547.001
  - Scheduled tasks                                                 T1053.005
  - Windows services                                                T1543.003

Tools like Sysinternals Autoruns check hundreds of locations; these four
cover the majority of commodity malware.
"""
import csv
import io
import os

from . import Collector
from ..config import CONFIG, IS_WINDOWS
from ..util import run

RUN_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
]
STARTUP_DIRS = [
    os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
]


def _run_keys():
    import winreg
    hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    items = {}
    for hive, path in RUN_KEYS:
        try:
            key = winreg.OpenKey(hives[hive], path)
        except OSError:
            continue
        with key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                items[f"registry|{hive}\\{path}|{name}"] = {
                    "persistence.type": "registry_run", "persistence.name": name,
                    "persistence.location": f"{hive}\\{path}", "persistence.value": str(value),
                    "registry.path": f"{hive}\\{path}\\{name}",
                }
                i += 1
    return items


def _startup_folders():
    items = {}
    for d in STARTUP_DIRS:
        if not os.path.isdir(d):
            continue
        for fn in os.listdir(d):
            if fn.lower() == "desktop.ini":
                continue
            p = os.path.join(d, fn)
            items[f"startup|{p}"] = {
                "persistence.type": "startup_folder", "persistence.name": fn,
                "persistence.location": d, "persistence.value": p, "file.path": p,
            }
    return items


def _scheduled_tasks():
    ok, out = run(["schtasks", "/query", "/fo", "CSV", "/v"], timeout=60)
    items = {}
    if not ok:
        return items
    reader = csv.DictReader(io.StringIO(out))
    for row in reader:
        name = row.get("TaskName") or ""
        if not name or name == "TaskName" or name.startswith("\\Microsoft\\"):
            continue  # skip header repeats and the hundreds of built-in Microsoft tasks
        action = row.get("Task To Run", "")
        items[f"task|{name}"] = {
            "persistence.type": "scheduled_task", "persistence.name": name,
            "persistence.location": "Task Scheduler", "persistence.value": action,
            "persistence.author": row.get("Author", ""),
        }
    return items


def _services():
    import psutil
    items = {}
    for s in psutil.win_service_iter():
        try:
            info = s.as_dict()
        except Exception:
            continue
        items[f"service|{info['name']}"] = {
            "persistence.type": "service", "persistence.name": info["name"],
            "persistence.location": "Service Control Manager",
            "persistence.value": info.get("binpath") or "",
            "service.start_type": info.get("start_type"), "service.display_name": info.get("display_name"),
        }
    return items


def snapshot():
    if not IS_WINDOWS:
        return {}
    items = {}
    for fn in (_run_keys, _startup_folders, _scheduled_tasks, _services):
        try:
            items.update(fn())
        except Exception as exc:
            print(f"[persistence] {fn.__name__} failed: {exc}")
    return items


class PersistenceCollector(Collector):
    name = "persistence"

    def __init__(self, pipeline):
        super().__init__(pipeline)
        self.interval = CONFIG["persistence_poll_seconds"]
        self.inventory = {}

    def setup(self):
        if not IS_WINDOWS:
            self.detail = "Windows only"
            return False
        self.inventory = snapshot()
        self.detail = f"Baseline: {len(self.inventory)} autostart entries"
        return True

    def poll(self):
        current = snapshot()
        for key, item in current.items():
            old = self.inventory.get(key)
            if old is None:
                self.emit({"category": "persistence", "action": "create", **item})
            elif old.get("persistence.value") != item.get("persistence.value"):
                self.emit({"category": "persistence", "action": "modify",
                           "persistence.previous_value": old.get("persistence.value"), **item})
        for key in set(self.inventory) - set(current):
            self.emit({"category": "persistence", "action": "delete", **self.inventory[key]})
        self.inventory = current

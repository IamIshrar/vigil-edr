"""Process collector: who started what, with which command line, from which parent.

Process creation is the single most valuable EDR signal. Most attacks are
visible here: Word starting PowerShell, an encoded command, a tool run from
the Downloads folder.

How it works: every second, compare the list of running process IDs with the
last list. New IDs are new processes. For each one, read its name, path,
command line, parent and user, and hash its executable.

Limitation (worth knowing for interviews): a process that starts and exits
within one polling interval is missed. Commercial EDRs avoid this with a
kernel callback (PsSetCreateProcessNotifyRoutineEx) or ETW. Vigil fills the
gap by reading Sysmon event ID 1 when Sysmon is installed (see eventlog.py).
"""
import psutil

from . import Collector
from ..config import CONFIG
from ..util import sha256_file


def describe(proc, parent_cache=None):
    """Turn a psutil.Process into a normalised process event. Returns None if it has exited."""
    try:
        with proc.oneshot():
            info = {
                "process.pid": proc.pid,
                "process.name": proc.name(),
                "process.ppid": proc.ppid(),
                "process.create_time": proc.create_time(),
            }
            for field, getter in (("process.executable", proc.exe), ("process.user", proc.username)):
                try:
                    info[field] = getter()
                except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    info[field] = ""
            try:
                info["process.command_line"] = " ".join(proc.cmdline())
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                info["process.command_line"] = ""
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return None
    except psutil.AccessDenied:
        return None
    parent_name, parent_exe = "", ""
    try:
        parent = psutil.Process(info["process.ppid"])
        parent_name = parent.name()
        try:
            parent_exe = parent.exe()
        except (psutil.AccessDenied, OSError):
            pass
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
        pass
    info["process.parent.name"] = parent_name
    info["process.parent.executable"] = parent_exe
    info["user.name"] = info.get("process.user", "")
    if info.get("process.executable"):
        info["process.hash.sha256"] = sha256_file(info["process.executable"]) or ""
    return info


class ProcessCollector(Collector):
    name = "process"

    def __init__(self, pipeline, sysmon_handles_processes=lambda: False):
        super().__init__(pipeline)
        self.interval = CONFIG["process_poll_seconds"]
        self.known = set()
        self.sysmon_handles_processes = sysmon_handles_processes

    def setup(self):
        # Baseline: processes already running are not "new".
        self.known = set(psutil.pids())
        return True

    def poll(self):
        current = set(psutil.pids())
        new = current - self.known
        self.known = current
        if self.sysmon_handles_processes():
            self.detail = "Sysmon is supplying process events; polling only tracks the live tree"
            return
        for pid in sorted(new):
            try:
                info = describe(psutil.Process(pid))
            except psutil.NoSuchProcess:
                continue
            if not info:
                continue
            info.update({"category": "process", "action": "start"})
            self.emit(info)


def process_tree():
    """Snapshot of every running process, for the dashboard's process tree."""
    procs = []
    for p in psutil.process_iter(["pid", "ppid", "name", "username", "exe", "create_time", "cmdline"]):
        try:
            i = p.info
            cpu = p.cpu_percent(interval=None)
            mem = p.memory_info().rss
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            cpu, mem = 0.0, 0
        procs.append({
            "pid": i["pid"], "ppid": i["ppid"], "name": i["name"] or "", "user": i["username"] or "",
            "exe": i["exe"] or "", "cmdline": " ".join(i["cmdline"] or [])[:400],
            "started": i["create_time"], "cpu": cpu, "mem_mb": round(mem / 1048576, 1),
        })
    return procs

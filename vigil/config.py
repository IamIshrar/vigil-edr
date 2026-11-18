"""Settings for Vigil EDR.

Defaults live here. To change anything, copy the key into config.json in the
project folder; values there override the defaults below.
"""
import json
import os
import platform
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
QUARANTINE_DIR = DATA_DIR / "quarantine"
RULES_FILE = Path(__file__).resolve().parent / "detection" / "rules.json"
IOC_DIR = BASE_DIR / "iocs"
CONFIG_FILE = BASE_DIR / "config.json"

IS_WINDOWS = platform.system() == "Windows"


def _home(*parts):
    return str(Path.home().joinpath(*parts))


DEFAULTS = {
    # Dashboard. Keep the host on 127.0.0.1 so only this machine can reach it.
    "host": "127.0.0.1",
    "port": 8787,

    # How often each collector looks for changes, in seconds.
    "process_poll_seconds": 1.0,
    "network_poll_seconds": 3.0,
    "file_poll_seconds": 5.0,
    "persistence_poll_seconds": 30.0,
    "eventlog_poll_seconds": 3.0,

    # Folders the file watcher scans for new executables and scripts.
    "watched_folders": [
        _home("Downloads"),
        _home("Desktop"),
        os.environ.get("TEMP", _home("AppData", "Local", "Temp")),
        _home("AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        r"C:\Users\Public",
    ],
    "watched_extensions": [
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
        ".hta", ".lnk", ".msi", ".jar", ".iso", ".img", ".wsf", ".cpl",
    ],

    # Hash executables up to this size (MB). Bigger files are skipped to keep CPU low.
    "max_hash_mb": 100,

    # Optional VirusTotal lookups for file hashes. Leave empty to stay fully offline.
    "virustotal_api_key": "",

    # Use Sysmon for process, network, file and registry events when it is installed.
    # Sysmon catches short-lived processes that polling can miss.
    "use_sysmon_if_available": True,

    # Read Windows event logs (Security needs Vigil to run as Administrator).
    "enable_eventlog": True,

    # Allow response actions (kill, quarantine, block IP, isolate) from the dashboard.
    "response_enabled": True,

    # Do not raise the same alert for the same thing more than once in this window.
    "alert_dedup_minutes": 10,

    # Delete stored events older than this.
    "retention_days": 7,
}


def load():
    cfg = dict(DEFAULTS)
    if CONFIG_FILE.exists():
        try:
            cfg.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            print(f"[config] Could not read {CONFIG_FILE}: {exc}. Using defaults.")
    DATA_DIR.mkdir(exist_ok=True)
    QUARANTINE_DIR.mkdir(exist_ok=True)
    return cfg


CONFIG = load()

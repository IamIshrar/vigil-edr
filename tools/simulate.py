"""Safe attack simulator for testing Vigil.

Every test here is HARMLESS. It runs commands that *look like* attacker
behaviour so you can watch Vigil detect them, then cleans up after itself.
Nothing is downloaded, nothing malicious is executed, nothing is left behind.

    python tools/simulate.py            run the live tests on this machine (Windows)
    python tools/simulate.py --inject   send synthetic events straight into the pipeline
                                        (works on any OS, no admin needed; great for
                                        testing rules you write)
    python tools/simulate.py --list     show what each test does

Run it in a second terminal while run.py is running, then watch the dashboard.
"""
import argparse
import base64
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
IS_WINDOWS = os.name == "nt"
DOWNLOADS = Path.home() / "Downloads"


def sh(args):
    print("   $", " ".join(args))
    try:
        subprocess.run(args, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print("     (skipped:", exc, ")")


# ---------------- live tests (Windows) ----------------
def t_encoded_powershell():
    """VIG-002: PowerShell with a Base64 -EncodedCommand (the command just prints a message)."""
    cmd = "Write-Output 'Vigil test: encoded command'"
    b64 = base64.b64encode(cmd.encode("utf-16le")).decode()
    sh(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", b64])


def t_hidden_bypass():
    """VIG-004: PowerShell started hidden with execution policy bypass (prints the date)."""
    sh(["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", "Get-Date"])


def t_discovery():
    """VIG-B02: four or more reconnaissance tools within two minutes (read-only commands). Reliable with Sysmon installed."""
    for args in (["whoami.exe", "/all"], ["hostname.exe"], ["ipconfig.exe", "/all"], ["systeminfo.exe"], ["net.exe", "user"], ["tasklist.exe"]):
        sh(args)
        time.sleep(1.5)  # spread out so the 1-second process poller sees each one


def t_certutil_decode():
    """VIG-010: certutil -decode on a local Base64 file containing plain text. Reliable with Sysmon installed."""
    tmp = Path(os.environ.get("TEMP", "."))
    src, dst = tmp / "vigil_test.b64", tmp / "vigil_test.txt"
    src.write_text(base64.b64encode(b"Vigil test file - harmless text").decode())
    sh(["certutil.exe", "-decode", str(src), str(dst)])
    time.sleep(2)
    for p in (src, dst):
        p.unlink(missing_ok=True)


def _reload_iocs():
    """Ask the running agent to reload rules and IOC lists now, instead of waiting up to a minute."""
    try:
        token = (BASE / "data" / ".token").read_text().strip()
        port = 8787
        if (BASE / "config.json").exists():
            port = json.loads((BASE / "config.json").read_text()).get("port", 8787)
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/rules/reload", data=b"{}", method="POST",
                                     headers={"Content-Type": "application/json", "X-Vigil-Token": token})
        urllib.request.urlopen(req, timeout=10).read()
        return True
    except Exception as exc:
        print(f"   could not reach Vigil to reload IOCs ({exc}); waiting 65s for the automatic reload instead")
        time.sleep(65)
        return False


def t_double_extension():
    """VIG-050 + VIG-070: add a test hash to the IOC list, then create invoice.pdf.exe with that content (plain text, never run)."""
    import hashlib
    content = b"Vigil test file. This is plain text with an .exe name. It cannot run."
    digest = hashlib.sha256(content).hexdigest()
    # Order matters: the indicator must be loaded BEFORE the file appears, because
    # enrichment happens once, when the event passes through the pipeline.
    ioc = BASE / "iocs" / "bad_hashes.txt"
    lines = ioc.read_text().splitlines() if ioc.exists() else []
    if not any(l.startswith(digest) for l in lines):
        with ioc.open("a") as f:
            f.write(f"\n{digest}  # vigil-test-invoice.pdf.exe (simulator)\n")
    _reload_iocs()
    DOWNLOADS.mkdir(exist_ok=True)
    fake = DOWNLOADS / "vigil-test-invoice.pdf.exe"
    fake.write_bytes(content)
    print(f"   created {fake} (sha256 {digest[:16]}...); waiting 15s for the file watcher")
    time.sleep(15)
    fake.unlink(missing_ok=True)
    print("   removed the test file")


def t_run_key():
    """VIG-042: add a Registry Run value that points to Notepad, then remove it."""
    import winreg
    path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "VigilTest", 0, winreg.REG_SZ, r"C:\Windows\System32\notepad.exe")
    print("   added HKCU\\...\\Run\\VigilTest -> notepad.exe; waiting 40s for the persistence check")
    time.sleep(40)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as k:
        winreg.DeleteValue(k, "VigilTest")
    print("   removed VigilTest")


def t_schtask():
    """VIG-040 + VIG-044: create a scheduled task that would open Notepad at 23:59, then delete it 40s later."""
    sh(["schtasks.exe", "/create", "/tn", "VigilTest", "/tr", r"C:\Windows\System32\notepad.exe", "/sc", "once", "/st", "23:59", "/f"])
    print("   waiting 40s for the persistence check")
    time.sleep(40)
    sh(["schtasks.exe", "/delete", "/tn", "VigilTest", "/f"])


LIVE = [t_encoded_powershell, t_hidden_bypass, t_discovery, t_certutil_decode, t_schtask, t_run_key, t_double_extension]


# ---------------- injected events (any OS) ----------------
INJECT = [
    ("Office spawning PowerShell (VIG-001, VIG-002)", {"category": "process", "action": "start", "process.pid": 4242, "process.name": "powershell.exe",
     "process.executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "process.parent.name": "WINWORD.EXE",
     "process.command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", "user.name": "LAB\\alice"}),
    ("Shadow copy deletion (VIG-020)", {"category": "process", "action": "start", "process.pid": 4250, "process.name": "vssadmin.exe",
     "process.executable": r"C:\Windows\System32\vssadmin.exe", "process.parent.name": "cmd.exe", "process.command_line": "vssadmin.exe delete shadows /all /quiet"}),
    ("LSASS dump via comsvcs (VIG-030)", {"category": "process", "action": "start", "process.pid": 4260, "process.name": "rundll32.exe",
     "process.executable": r"C:\Windows\System32\rundll32.exe", "process.parent.name": "cmd.exe",
     "process.command_line": r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 724 C:\Users\Public\l.dmp full"}),
    ("Fake svchost in AppData (VIG-016)", {"category": "process", "action": "start", "process.pid": 4270, "process.name": "svchost.exe",
     "process.executable": r"C:\Users\alice\AppData\Roaming\svchost.exe", "process.parent.name": "explorer.exe", "process.command_line": "svchost.exe"}),
    ("rundll32 talking to the internet on port 4444 (VIG-060, VIG-061)", {"category": "network", "action": "connect", "process.pid": 4280,
     "process.name": "rundll32.exe", "destination.ip": "203.0.113.50", "destination.port": 4444, "destination.public": True}),
    ("Run key persistence (VIG-042)", {"category": "persistence", "action": "create", "persistence.type": "registry_run", "persistence.name": "Updater",
     "persistence.location": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "persistence.value": r"C:\Users\alice\AppData\Local\Temp\upd.exe"}),
    ("Double-extension file (VIG-050)", {"category": "file", "action": "create", "file.path": r"C:\Users\alice\Downloads\invoice.pdf.exe",
     "file.name": "invoice.pdf.exe", "file.extension": ".exe"}),
    ("Event log cleared (VIG-080)", {"category": "system", "action": "log_cleared", "message": "Security log cleared by alice", "user.name": "alice"}),
]


def inject(brute_force=True):
    token_file = BASE / "data" / ".token"
    if not token_file.exists():
        sys.exit("Start Vigil first (python run.py), then run this again.")
    token = token_file.read_text().strip()
    cfg = {"port": 8787}
    if (BASE / "config.json").exists():
        cfg.update(json.loads((BASE / "config.json").read_text()))
    url = f"http://127.0.0.1:{cfg['port']}/api/test-event"

    def send(e):
        req = urllib.request.Request(url, data=json.dumps(e).encode(), headers={"Content-Type": "application/json", "X-Vigil-Token": token})
        urllib.request.urlopen(req, timeout=10).read()

    for title, e in INJECT:
        print(f" -> {title}")
        send(e)
        time.sleep(0.4)
    if brute_force:
        print(" -> 12 failed logons from one IP (VIG-B01)")
        for i in range(12):
            send({"category": "auth", "action": "logon_failed", "user.name": f"user{i % 4}", "source.ip": "198.51.100.23", "logon.type": "3"})
    print("\nDone. Open the dashboard's Alerts page.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inject", action="store_true", help="send synthetic events instead of running commands")
    ap.add_argument("--list", action="store_true", help="list the tests")
    args = ap.parse_args()

    if args.list:
        print("Live tests (Windows):")
        for t in LIVE:
            print(f"  - {t.__doc__}")
        print("\nInjected events (--inject):")
        for title, _ in INJECT:
            print(f"  - {title}")
        return
    if args.inject or not IS_WINDOWS:
        if not IS_WINDOWS and not args.inject:
            print("Not on Windows: using --inject mode.\n")
        inject()
        return

    print("Vigil safe attack simulator. Each step is harmless and cleans up after itself.")
    print("Note: whoami, ipconfig and certutil finish in milliseconds. Without Sysmon, the 1-second")
    print("process poller usually misses them, so the recon-burst and certutil alerts may not fire.\n")
    for i, t in enumerate(LIVE, 1):
        print(f"[{i}/{len(LIVE)}] {t.__doc__}")
        try:
            t()
        except Exception as exc:
            print(f"   failed: {exc}")
        print()
    print("All tests finished. Check the Alerts page in the dashboard.")


if __name__ == "__main__":
    main()

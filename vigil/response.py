"""Response actions: the "R" in EDR.

Every action is:
  - explicit   (the dashboard asks you to confirm first),
  - guarded    (core Windows processes and Vigil itself cannot be killed),
  - reversible where possible (quarantine can be restored, IP blocks and
                isolation can be undone),
  - audited    (every attempt is written to the actions table, success or not).

Actions that change the firewall need Vigil to run as Administrator.
"""
import ipaddress
import os
import shutil
import uuid

import psutil

from .config import CONFIG, IS_WINDOWS, QUARANTINE_DIR
from .db import now_iso
from .util import run, sha256_file, is_admin

PROTECTED = {
    "system", "system idle process", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe",
    "memcompression", "secure system", "msmpeng.exe", "explorer.exe",
}
RULE_PREFIX = "Vigil-Block-"


class ActionError(Exception):
    pass


class Responder:
    def __init__(self, db):
        self.db = db
        self.own_pid = os.getpid()

    # ---------- helpers ----------
    def _guard(self):
        if not CONFIG["response_enabled"]:
            raise ActionError("Response actions are turned off in config.json (response_enabled).")

    def _record(self, action, target, ok, detail, alert_id):
        self.db.add_action(action, target, ok, detail, alert_id)
        return {"ok": ok, "detail": detail}

    def run_action(self, action, target, alert_id=None):
        handlers = {
            "kill": self.kill_process, "suspend": self.suspend_process, "resume": self.resume_process,
            "quarantine": self.quarantine_file, "restore": self.restore_file,
            "block_ip": self.block_ip, "unblock_ip": self.unblock_ip,
            "isolate": self.isolate_host, "unisolate": self.unisolate_host,
        }
        if action not in handlers:
            return {"ok": False, "detail": f"Unknown action '{action}'"}
        try:
            self._guard()
            detail = handlers[action](target)
            return self._record(action, target, True, detail, alert_id)
        except ActionError as exc:
            return self._record(action, target, False, str(exc), alert_id)
        except Exception as exc:
            return self._record(action, target, False, f"Unexpected error: {exc}", alert_id)

    # ---------- processes ----------
    def _own_lineage(self):
        """Vigil's own PID and every ancestor (the terminal, the shell...). Killing any of them would kill Vigil."""
        pids = {self.own_pid}
        try:
            for p in psutil.Process(self.own_pid).parents():
                pids.add(p.pid)
        except psutil.Error:
            pass
        return pids

    def _process(self, pid):
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            raise ActionError("Not a valid process ID.")
        if pid in (0, 1, 4) or pid in self._own_lineage():
            raise ActionError("That process is protected (system process, or Vigil itself and the terminal running it).")
        try:
            p = psutil.Process(pid)
            name = p.name()
        except psutil.NoSuchProcess:
            raise ActionError(f"Process {pid} is no longer running.")
        if name.lower() in PROTECTED:
            raise ActionError(f"{name} is a core system process; stopping it could crash Windows.")
        return p, name

    def kill_process(self, pid):
        p, name = self._process(pid)
        protected = self._own_lineage()
        children = [c for c in p.children(recursive=True) if c.pid not in protected]
        for proc in [p] + children:
            try:
                proc.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        gone, alive = psutil.wait_procs([p] + children, timeout=3)
        for proc in alive:
            try:
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
                raise ActionError(f"Could not stop {proc.pid}: {exc}. Try running Vigil as Administrator.")
        return f"Stopped {name} (pid {pid}) and {len(children)} child process(es)."

    def suspend_process(self, pid):
        p, name = self._process(pid)
        try:
            p.suspend()
        except psutil.AccessDenied:
            raise ActionError("Access denied. Run Vigil as Administrator.")
        return f"Suspended {name} (pid {pid}). It is frozen but still in memory, so you can investigate it."

    def resume_process(self, pid):
        p, name = self._process(pid)
        p.resume()
        return f"Resumed {name} (pid {pid})."

    # ---------- files ----------
    def quarantine_file(self, path):
        path = os.path.abspath(str(path))
        if not os.path.isfile(path):
            raise ActionError("File not found (it may already be deleted or quarantined).")
        low = path.lower()
        if IS_WINDOWS and (low.startswith(r"c:\windows\system32") or low.startswith(r"c:\windows\syswow64")):
            raise ActionError("Refusing to quarantine a file inside System32/SysWOW64.")
        digest = sha256_file(path) or ""
        # Stop anything running from this file first, otherwise Windows will not let us move it.
        for p in psutil.process_iter(["pid", "exe"]):
            try:
                if p.info["exe"] and os.path.normcase(p.info["exe"]) == os.path.normcase(path):
                    p.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        stored = QUARANTINE_DIR / f"{uuid.uuid4().hex}.quarantined"
        try:
            shutil.move(path, stored)
        except OSError as exc:
            raise ActionError(f"Could not move the file: {exc}")
        self.db.execute("INSERT INTO quarantine (ts, original_path, stored_path, sha256) VALUES (?,?,?,?)",
                        (now_iso(), path, str(stored), digest))
        return f"Moved {os.path.basename(path)} into quarantine (sha256 {digest[:16]}...). It can be restored from the Response page."

    def restore_file(self, quarantine_id):
        rows = self.db.query("SELECT * FROM quarantine WHERE id = ? AND restored = 0", (int(quarantine_id),))
        if not rows:
            raise ActionError("Nothing to restore with that ID.")
        q = rows[0]
        if os.path.exists(q["original_path"]):
            raise ActionError("A file already exists at the original path.")
        os.makedirs(os.path.dirname(q["original_path"]), exist_ok=True)
        shutil.move(q["stored_path"], q["original_path"])
        self.db.execute("UPDATE quarantine SET restored = 1 WHERE id = ?", (q["id"],))
        return f"Restored {q['original_path']}."

    # ---------- network ----------
    def _need_firewall(self):
        if not IS_WINDOWS:
            raise ActionError("Firewall actions are only available on Windows.")
        if not is_admin():
            raise ActionError("Changing the firewall needs Administrator rights. Restart Vigil as Administrator.")

    def block_ip(self, ip):
        try:
            ip = str(ipaddress.ip_address(str(ip).strip()))
        except ValueError:
            raise ActionError("Not a valid IP address.")
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_unspecified:
            raise ActionError("Refusing to block a loopback or unspecified address.")
        self._need_firewall()
        name = RULE_PREFIX + ip
        for direction in ("out", "in"):
            ok, out = run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
                           f"dir={direction}", "action=block", f"remoteip={ip}", "enable=yes"])
            if not ok:
                raise ActionError(f"netsh failed: {out.strip()[:200]}")
        note = " (private address: this may cut off a device on your own network)" if addr.is_private else ""
        return f"Blocked all traffic to and from {ip} with Windows Firewall rule '{name}'{note}."

    def unblock_ip(self, ip):
        self._need_firewall()
        ok, out = run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_PREFIX}{ip}"])
        if not ok:
            raise ActionError(f"No Vigil rule found for {ip}.")
        return f"Removed the block on {ip}."

    def blocked_ips(self):
        if not IS_WINDOWS:
            return []
        ok, out = run(["netsh", "advfirewall", "firewall", "show", "rule", f"name=all"], timeout=60)
        ips = set()
        for line in out.splitlines():
            line = line.strip()
            if line.lower().startswith("rule name:") and RULE_PREFIX in line:
                ips.add(line.split(RULE_PREFIX, 1)[1].strip())
        return sorted(ips)

    def isolate_host(self, _target=None):
        """Basic network containment: switch every firewall profile to block outbound by default.

        Commercial EDRs isolate a host while keeping their own cloud channel open.
        Here the dashboard is local, so it keeps working. Applications that have an
        explicit outbound 'allow' rule can still connect, so this is containment,
        not a perfect air gap.
        """
        self._need_firewall()
        ok, out = run(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"])
        if not ok:
            raise ActionError(f"netsh failed: {out.strip()[:200]}")
        return "Host isolated: inbound and outbound traffic now blocked by default on all firewall profiles. Use 'Release isolation' to undo."

    def unisolate_host(self, _target=None):
        self._need_firewall()
        ok, out = run(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"])
        if not ok:
            raise ActionError(f"netsh failed: {out.strip()[:200]}")
        return "Isolation released: firewall back to the Windows default (block inbound, allow outbound)."

    def quarantined(self):
        return self.db.query("SELECT * FROM quarantine ORDER BY id DESC")

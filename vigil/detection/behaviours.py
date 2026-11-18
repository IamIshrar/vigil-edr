"""Stateful detections: patterns that only show up across several events.

A single failed logon is normal. Twenty in two minutes is an attack. Rules in
rules.json look at one event at a time; the detections here keep a short
memory (a sliding time window) so they can count and correlate.
"""
import time
from collections import defaultdict, deque

DISCOVERY = {"whoami.exe", "net.exe", "net1.exe", "nltest.exe", "ipconfig.exe", "systeminfo.exe",
             "tasklist.exe", "quser.exe", "query.exe", "netstat.exe", "arp.exe", "route.exe",
             "hostname.exe", "dsquery.exe", "nslookup.exe", "wmic.exe"}


def M(tactic, technique, name):
    return {"tactic": tactic, "technique": technique, "name": name}


RULES = {
    "brute_force": {
        "id": "VIG-B01", "title": "Brute-force or password-spray attempt", "severity": "high",
        "mitre": M("Credential Access", "T1110", "Brute Force"),
        "description": "Many failed logons in a short time (Windows event 4625).",
        "advice": "Check the source IP and targeted accounts; block the source and confirm no logon succeeded afterwards."},
    "discovery": {
        "id": "VIG-B02", "title": "Burst of reconnaissance commands", "severity": "medium",
        "mitre": M("Discovery", "T1087", "Account Discovery"),
        "description": "Several system and account discovery tools ran within two minutes. Hands-on-keyboard attackers do this right after gaining access.",
        "advice": "Look at the parent process and the user. An admin troubleshooting is fine; a document or a web server is not."},
    "process_burst": {
        "id": "VIG-B03", "title": "One process spawned many shells", "severity": "medium",
        "mitre": M("Execution", "T1059", "Command and Scripting Interpreter"),
        "description": "The same parent launched cmd or PowerShell many times in a minute, typical of scripted attacks and worms.",
        "advice": "Inspect the parent process and its command line."},
    "beacon": {
        "id": "VIG-B04", "title": "Regular repeated connections (possible beaconing)", "severity": "medium",
        "mitre": M("Command and Control", "T1071", "Application Layer Protocol"),
        "description": "A process kept reconnecting to the same public IP at a steady interval. Command-and-control implants check in on a timer.",
        "advice": "Look up the IP's reputation and the process's signature."},
}


class Window:
    """Timestamps within the last `seconds`, per key."""

    def __init__(self, seconds):
        self.seconds = seconds
        self.items = defaultdict(deque)

    def add(self, key, value=None, now=None):
        now = now or time.time()
        q = self.items[key]
        q.append((now, value))
        while q and q[0][0] < now - self.seconds:
            q.popleft()
        return q


class Behaviours:
    def __init__(self):
        self.failed_logons = Window(300)
        self.discovery = Window(120)
        self.shells = Window(60)
        self.connections = Window(900)
        self.hits = {}
        self.cooldown = {}  # (behaviour, key) -> time it last fired

    def _hit(self, name, extra, key, cooldown=600):
        """Fire once per key, then stay quiet for `cooldown` seconds so one attack gives one alert."""
        now = time.time()
        if now - self.cooldown.get((name, key), 0) < cooldown:
            return []
        self.cooldown[(name, key)] = now
        rule = RULES[name]
        self.hits[rule["id"]] = self.hits.get(rule["id"], 0) + 1
        return [(rule, extra)]

    def evaluate(self, e):
        c, a = e.get("category"), e.get("action")

        if c == "auth" and a == "logon_failed":
            src = e.get("source.ip") or "local"
            q = self.failed_logons.add(src, e.get("user.name"))
            if len(q) >= 10:
                users = {u for _, u in q if u}
                return self._hit("brute_force", f"{len(q)} failures from {src} against {len(users)} account(s) in 5 minutes.", src)

        if c == "process" and a == "start":
            name = (e.get("process.name") or "").lower()
            if name in DISCOVERY:
                key = e.get("user.name") or "?"
                q = self.discovery.add(key, name)
                tools = {n for _, n in q}
                if len(tools) >= 4:
                    return self._hit("discovery", f"Tools: {', '.join(sorted(tools))}.", key)
            if name in ("cmd.exe", "powershell.exe", "pwsh.exe"):
                parent = e.get("process.parent.name") or "?"
                if parent.lower() not in ("explorer.exe", "windowsterminal.exe", "code.exe"):
                    q = self.shells.add(f"{e.get('process.ppid')}|{parent}")
                    if len(q) >= 10:
                        return self._hit("process_burst", f"{parent} started {len(q)} shells in a minute.", parent)

        if c == "network" and a == "connect" and e.get("destination.public"):
            key = f"{e.get('process.name')}|{e.get('destination.ip')}"
            q = self.connections.add(key)
            if len(q) >= 6:
                times = [t for t, _ in q]
                gaps = [b - a for a, b in zip(times, times[1:])]
                mean = sum(gaps) / len(gaps)
                if mean > 5:
                    spread = max(gaps) - min(gaps)
                    if spread <= max(10, mean * 0.2):
                        return self._hit("beacon", f"{e.get('process.name')} -> {e.get('destination.ip')} every ~{mean:.0f}s ({len(q)} times).", key, 3600)
        return []

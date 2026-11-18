"""The event pipeline: the heart of the agent.

    collectors  ->  submit()  ->  queue  ->  enrich  ->  store  ->  detect  ->  alerts

Every collector turns what it sees into a *normalised event*: a flat dict with
dotted field names such as "process.name" or "destination.ip" (the same idea
as Elastic ECS or Microsoft ASIM). Because every source uses the same field
names, one detection rule can work on events from any collector.
"""
import queue
import threading
import time
from collections import Counter

from .config import CONFIG
from .db import now_iso


def summarize(e):
    """One readable line for the timeline."""
    c, a = e["category"], e["action"]
    p = e.get("process.name", "?")
    if c == "process":
        cmd = (e.get("process.command_line") or "")[:160]
        return f"{e.get('process.parent.name', '?')} -> {p} (pid {e.get('process.pid')}) {cmd}".strip()
    if c == "network":
        return f"{p} (pid {e.get('process.pid')}) -> {e.get('destination.ip')}:{e.get('destination.port')}"
    if c == "file":
        return f"{a} {e.get('file.path')}"
    if c == "persistence":
        return f"{a} {e.get('persistence.type')}: {e.get('persistence.name')} -> {e.get('persistence.value', '')}"[:220]
    if c == "auth":
        return f"{a} user={e.get('user.name', '?')} from {e.get('source.ip', '-')}"
    if c in ("system", "av"):
        return e.get("message", a)
    return a


def entities_of(e):
    keys = {
        "pid": "process.pid", "process": "process.name", "executable": "process.executable",
        "command_line": "process.command_line", "parent": "process.parent.name",
        "file": "file.path", "sha256": "file.hash.sha256", "ip": "destination.ip",
        "port": "destination.port", "user": "user.name", "source_ip": "source.ip",
        "autostart": "persistence.name", "autostart_runs": "persistence.value", "autostart_type": "persistence.type",
        "group": "group.name", "threat": "threat.name",
    }
    return {k: e[v] for k, v in keys.items() if e.get(v) not in (None, "")}


class Pipeline:
    def __init__(self, db, engine, behaviours, intel):
        self.db, self.engine, self.behaviours, self.intel = db, engine, behaviours, intel
        self.queue = queue.Queue(maxsize=20000)
        self.stats = Counter()
        self.last_event_ts = None
        self.started = time.time()
        self._thread = threading.Thread(target=self._run, name="pipeline", daemon=True)

    def start(self):
        self._thread.start()

    def submit(self, event):
        """Called by collectors. Never blocks: if the queue is full the event is counted and dropped."""
        event.setdefault("ts", now_iso())
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            self.stats["dropped"] += 1

    def _run(self):
        while True:
            event = self.queue.get()
            try:
                self.process(event)
            except Exception as exc:  # keep the pipeline alive whatever one event does
                self.stats["errors"] += 1
                print(f"[pipeline] error processing event: {exc}")

    def process(self, event):
        event.setdefault("ts", now_iso())
        # 1. Enrich: add context the raw event does not carry (hash reputation, IP reputation).
        self.intel.enrich(event)
        # 2. Store.
        event["summary"] = summarize(event)
        event_id = self.db.add_event(event)
        self.stats["events"] += 1
        self.stats[f"events.{event['category']}"] += 1
        self.last_event_ts = event["ts"]
        # 3. Detect: stateless rules first, then stateful behaviours.
        hits = self.engine.evaluate(event) + self.behaviours.evaluate(event)
        for rule, extra in hits:
            self._raise(rule, event, event_id, extra)
        return event_id

    def _raise(self, rule, event, event_id, extra=None):
        ents = entities_of(event)
        key_part = ents.get("executable") or ents.get("file") or ents.get("ip") or ents.get("autostart") \
            or ents.get("source_ip") or ents.get("user") or ents.get("command_line") or ""
        dedup_key = f"{rule['id']}|{key_part}"[:400]
        if self.db.recent_alert_exists(dedup_key, CONFIG["alert_dedup_minutes"]):
            self.stats["alerts_suppressed"] += 1
            return
        mitre = rule.get("mitre", {})
        description = rule.get("description", "")
        if extra:
            description = f"{description} {extra}".strip()
        self.db.add_alert({
            "ts": now_iso(), "rule_id": rule["id"], "title": rule["title"], "severity": rule["severity"],
            "tactic": mitre.get("tactic"), "technique": mitre.get("technique"),
            "technique_name": mitre.get("name"), "description": description,
            "advice": rule.get("advice", ""), "event_id": event_id,
            "dedup_key": dedup_key, "entities": ents,
        })
        self.stats["alerts"] += 1
        print(f"[ALERT] {rule['severity'].upper():8} {rule['title']} :: {event.get('summary', '')[:120]}")

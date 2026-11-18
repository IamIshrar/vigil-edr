"""Local storage for events, alerts and response actions (SQLite).

A real EDR streams telemetry to a cloud backend. Vigil keeps everything on
this machine in one SQLite file: data/vigil.db. You can open it with any
SQLite browser to see exactly what was recorded.
"""
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from .config import DATA_DIR

DB_PATH = DATA_DIR / "vigil.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    category  TEXT NOT NULL,   -- process, network, file, persistence, auth, system, av
    action    TEXT NOT NULL,   -- start, connect, create, logon_failed, ...
    source    TEXT,            -- which collector produced it
    summary   TEXT,            -- one human-readable line
    pid       INTEGER,
    data      TEXT NOT NULL    -- the full normalised event as JSON
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_cat ON events(category);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,   -- low, medium, high, critical
    tactic      TEXT,
    technique   TEXT,
    technique_name TEXT,
    description TEXT,
    advice      TEXT,
    event_id    INTEGER,
    status      TEXT NOT NULL DEFAULT 'open',  -- open, investigating, resolved, false_positive
    dedup_key   TEXT,
    entities    TEXT             -- JSON: pid, process, file, ip, user
);
CREATE INDEX IF NOT EXISTS ix_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS actions (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    action   TEXT NOT NULL,
    target   TEXT NOT NULL,
    ok       INTEGER NOT NULL,
    detail   TEXT,
    alert_id INTEGER
);

CREATE TABLE IF NOT EXISTS quarantine (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    original_path TEXT NOT NULL,
    stored_path   TEXT NOT NULL,
    sha256        TEXT,
    restored      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS intel_cache (
    sha256   TEXT PRIMARY KEY,
    ts       TEXT NOT NULL,
    result   TEXT NOT NULL
);
"""


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path=DB_PATH):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.commit()

    # ---------- low level ----------
    def execute(self, sql, params=()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur.lastrowid

    def query(self, sql, params=()):
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    # ---------- events ----------
    def add_event(self, event):
        return self.execute(
            "INSERT INTO events (ts, category, action, source, summary, pid, data) VALUES (?,?,?,?,?,?,?)",
            (event["ts"], event["category"], event["action"], event.get("source"),
             event.get("summary"), event.get("process.pid"), json.dumps(event, default=str)),
        )

    def events(self, category=None, search=None, limit=200, since=None, pid=None):
        sql, params = "SELECT * FROM events WHERE 1=1", []
        if category:
            sql += " AND category = ?"; params.append(category)
        if search:
            sql += " AND (summary LIKE ? OR data LIKE ?)"; params += [f"%{search}%", f"%{search}%"]
        if since:
            sql += " AND ts >= ?"; params.append(since)
        if pid is not None:
            sql += " AND pid = ?"; params.append(pid)
        sql += " ORDER BY id DESC LIMIT ?"; params.append(limit)
        rows = self.query(sql, params)
        for r in rows:
            r["data"] = json.loads(r["data"])
        return rows

    def event(self, event_id):
        rows = self.query("SELECT * FROM events WHERE id = ?", (event_id,))
        if not rows:
            return None
        rows[0]["data"] = json.loads(rows[0]["data"])
        return rows[0]

    # ---------- alerts ----------
    def add_alert(self, alert):
        return self.execute(
            """INSERT INTO alerts (ts, rule_id, title, severity, tactic, technique, technique_name,
               description, advice, event_id, dedup_key, entities) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (alert["ts"], alert["rule_id"], alert["title"], alert["severity"], alert.get("tactic"),
             alert.get("technique"), alert.get("technique_name"), alert.get("description"),
             alert.get("advice"), alert.get("event_id"), alert.get("dedup_key"),
             json.dumps(alert.get("entities", {}))),
        )

    def recent_alert_exists(self, dedup_key, minutes):
        since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(timespec="seconds")
        return bool(self.query("SELECT 1 FROM alerts WHERE dedup_key = ? AND ts >= ? LIMIT 1", (dedup_key, since)))

    def alerts(self, status=None, severity=None, limit=200):
        sql, params = "SELECT * FROM alerts WHERE 1=1", []
        if status:
            sql += " AND status = ?"; params.append(status)
        if severity:
            sql += " AND severity = ?"; params.append(severity)
        sql += " ORDER BY id DESC LIMIT ?"; params.append(limit)
        rows = self.query(sql, params)
        for r in rows:
            r["entities"] = json.loads(r["entities"] or "{}")
        return rows

    def alert(self, alert_id):
        rows = self.query("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        if not rows:
            return None
        rows[0]["entities"] = json.loads(rows[0]["entities"] or "{}")
        return rows[0]

    def set_alert_status(self, alert_id, status):
        self.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))

    # ---------- actions & quarantine ----------
    def add_action(self, action, target, ok, detail, alert_id=None):
        return self.execute(
            "INSERT INTO actions (ts, action, target, ok, detail, alert_id) VALUES (?,?,?,?,?,?)",
            (now_iso(), action, str(target), 1 if ok else 0, detail, alert_id),
        )

    def actions(self, limit=200):
        return self.query("SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,))

    # ---------- housekeeping ----------
    def purge_older_than(self, days):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        self.execute("DELETE FROM events WHERE ts < ?", (cutoff,))

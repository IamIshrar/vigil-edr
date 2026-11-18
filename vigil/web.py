"""The local dashboard: a small Flask API plus one HTML page.

Security notes (good habits for any local admin tool):
  - It listens on 127.0.0.1 only, so other machines cannot reach it.
  - Every request must use Host 127.0.0.1 or localhost, which blocks DNS-rebinding
    attacks from malicious websites.
  - Every action that changes something (POST) needs a random token that is
    generated at start-up and embedded in the page, which blocks cross-site
    request forgery.
"""
import secrets
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

from flask import Flask, abort, jsonify, request, send_from_directory

from .collectors.network import live_connections
from .collectors.persistence import snapshot as persistence_snapshot
from .collectors.process import process_tree
from .config import CONFIG, DATA_DIR, IS_WINDOWS
from .db import now_iso

STATIC = __import__("pathlib").Path(__file__).resolve().parent / "static"
TOKEN = secrets.token_urlsafe(24)
SEVERITIES = ["critical", "high", "medium", "low"]


def create_app(agent):
    app = Flask(__name__, static_folder=None)
    (DATA_DIR / ".token").write_text(TOKEN, encoding="utf-8")
    persistence_cache = {"ts": 0, "items": []}

    @app.before_request
    def _security():
        host = (request.host or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost"):
            abort(403)
        if request.method == "POST" and request.headers.get("X-Vigil-Token") != TOKEN:
            abort(403)

    @app.after_request
    def _headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---------- page ----------
    @app.get("/")
    def index():
        html = (STATIC / "index.html").read_text(encoding="utf-8").replace("__VIGIL_TOKEN__", TOKEN)
        return html, 200, {"Content-Type": "text/html; charset=utf-8"}

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(STATIC, name)

    # ---------- overview ----------
    @app.get("/api/summary")
    def summary():
        db = agent.db
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
        open_alerts = db.query("SELECT severity, COUNT(*) n FROM alerts WHERE status IN ('open','investigating') GROUP BY severity")
        by_cat = db.query("SELECT category, COUNT(*) n FROM events WHERE ts >= ? GROUP BY category", (since,))
        hourly = db.query("SELECT substr(ts,1,13) h, COUNT(*) n FROM alerts WHERE ts >= ? GROUP BY h", (since,))
        tactics = db.query("SELECT tactic, COUNT(*) n FROM alerts WHERE ts >= ? GROUP BY tactic ORDER BY n DESC", (since,))
        top_rules = db.query("SELECT rule_id, title, severity, COUNT(*) n FROM alerts WHERE ts >= ? GROUP BY rule_id ORDER BY n DESC LIMIT 5", (since,))
        now = datetime.now(timezone.utc)
        hours = [(now - timedelta(hours=23 - i)).strftime("%Y-%m-%dT%H") for i in range(24)]
        hmap = {r["h"]: r["n"] for r in hourly}
        stats = agent.pipeline.stats
        return jsonify({
            "host": agent.host(),
            "open_alerts": {s: next((r["n"] for r in open_alerts if r["severity"] == s), 0) for s in SEVERITIES},
            "events_24h": {r["category"]: r["n"] for r in by_cat},
            "alerts_by_hour": [{"hour": h, "n": hmap.get(h, 0)} for h in hours],
            "tactics": tactics, "top_rules": top_rules,
            "pipeline": {"events": stats["events"], "alerts": stats["alerts"], "suppressed": stats["alerts_suppressed"],
                         "dropped": stats["dropped"], "errors": stats["errors"], "queue": agent.pipeline.queue.qsize(),
                         "last_event": agent.pipeline.last_event_ts},
            "collectors": [c.info() for c in agent.collectors],
            "rules": {"total": len(agent.engine.rules), "enabled": sum(r["enabled"] for r in agent.engine.rules)},
            "intel": {"bad_hashes": len(agent.intel.bad_hashes), "bad_ips": len(agent.intel.bad_ips),
                      "virustotal": bool(agent.intel.vt_key), **agent.intel.vt_stats},
            "response_enabled": CONFIG["response_enabled"], "windows": IS_WINDOWS,
        })

    # ---------- alerts ----------
    @app.get("/api/alerts")
    def alerts():
        return jsonify(agent.db.alerts(status=request.args.get("status") or None,
                                       severity=request.args.get("severity") or None,
                                       limit=int(request.args.get("limit", 300))))

    @app.get("/api/alerts/<int:alert_id>")
    def alert(alert_id):
        a = agent.db.alert(alert_id)
        if not a:
            abort(404)
        ev = agent.db.event(a["event_id"]) if a["event_id"] else None
        related = []
        pid = a["entities"].get("pid")
        if pid:
            related = agent.db.events(pid=pid, limit=50)
        rule = next((r for r in agent.engine.rules if r["id"] == a["rule_id"]), None)
        actions = agent.db.query("SELECT * FROM actions WHERE alert_id = ? ORDER BY id DESC", (alert_id,))
        vt = agent.intel.vt_report(a["entities"]["sha256"]) if a["entities"].get("sha256") else None
        return jsonify({"alert": a, "event": ev, "related": related, "rule": rule, "actions": actions, "virustotal": vt})

    @app.post("/api/alerts/<int:alert_id>/status")
    def alert_status(alert_id):
        status = (request.get_json(silent=True) or {}).get("status")
        if status not in ("open", "investigating", "resolved", "false_positive"):
            abort(400)
        agent.db.set_alert_status(alert_id, status)
        return jsonify({"ok": True})

    # ---------- telemetry ----------
    @app.get("/api/events")
    def events():
        return jsonify(agent.db.events(category=request.args.get("category") or None,
                                       search=request.args.get("q") or None,
                                       limit=min(int(request.args.get("limit", 300)), 2000)))

    @app.get("/api/processes")
    def processes():
        flagged = Counter()
        for a in agent.db.alerts(status="open", limit=500):
            if a["entities"].get("pid"):
                flagged[a["entities"]["pid"]] += 1
        procs = process_tree()
        for p in procs:
            p["alerts"] = flagged.get(p["pid"], 0)
        return jsonify(procs)

    @app.get("/api/network")
    def network():
        return jsonify(live_connections())

    @app.get("/api/persistence")
    def persistence():
        if time.time() - persistence_cache["ts"] > 30:
            items = [{"key": k, **v} for k, v in persistence_snapshot().items()]
            persistence_cache.update(ts=time.time(), items=items)
        return jsonify(persistence_cache["items"])

    # ---------- rules ----------
    @app.get("/api/rules")
    def rules():
        hits = {**agent.engine.hits, **agent.behaviours.hits}
        out = [{**r, "hits": hits.get(r["id"], 0), "kind": "rule"} for r in agent.engine.rules]
        from .detection.behaviours import RULES as BEH
        out += [{**r, "enabled": True, "hits": hits.get(r["id"], 0), "kind": "behaviour", "category": "multi-event"} for r in BEH.values()]
        return jsonify(out)

    @app.post("/api/rules/<rule_id>/toggle")
    def toggle_rule(rule_id):
        state = agent.engine.toggle(rule_id)
        if state is None:
            abort(404)
        return jsonify({"enabled": state})

    @app.post("/api/rules/reload")
    def reload_rules():
        try:
            agent.engine.load()
            agent.intel.reload()
            return jsonify({"ok": True, "detail": f"Loaded {len(agent.engine.rules)} rules and IOC lists."})
        except Exception as exc:
            return jsonify({"ok": False, "detail": str(exc)})

    # ---------- response ----------
    @app.post("/api/respond")
    def respond():
        body = request.get_json(silent=True) or {}
        return jsonify(agent.responder.run_action(body.get("action"), body.get("target"), body.get("alert_id")))

    @app.get("/api/response")
    def response_state():
        return jsonify({"actions": agent.db.actions(), "quarantine": agent.responder.quarantined(),
                        "blocked_ips": agent.responder.blocked_ips(), "admin": agent.admin,
                        "enabled": CONFIG["response_enabled"]})

    # ---------- learning / testing ----------
    @app.post("/api/test-event")
    def test_event():
        """Push a synthetic event through the real pipeline. Used by tools/simulate.py --inject."""
        e = request.get_json(silent=True) or {}
        if "category" not in e or "action" not in e:
            abort(400)
        e["source"] = "simulation"
        e["ts"] = now_iso()
        event_id = agent.pipeline.process(e)
        return jsonify({"ok": True, "event_id": event_id})

    return app

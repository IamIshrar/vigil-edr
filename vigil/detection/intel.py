"""Threat intelligence enrichment.

Before an event is stored, Vigil checks it against:

  1. Local IOC lists you control: iocs/bad_hashes.txt and iocs/bad_ips.txt
     (one SHA-256 or IP per line, # for comments). Edit them any time;
     they are reloaded every minute.
  2. VirusTotal (optional). Put an API key in config.json and Vigil looks up
     each new file hash once, in the background, and caches the answer.
     The free API allows 4 lookups a minute, so lookups are rate-limited.

Matches are written onto the event as intel.* fields, and rules in rules.json
(VIG-070, VIG-071, VIG-072) turn them into alerts.
"""
import json
import queue
import threading
import time
import urllib.error
import urllib.request

from ..config import CONFIG, IOC_DIR
from ..db import now_iso


def _read_list(path):
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            out.add(line)
    return out


class Intel:
    def __init__(self, db):
        self.db = db
        self.bad_hashes, self.bad_ips = set(), set()
        self._loaded = 0
        self.vt_key = CONFIG.get("virustotal_api_key", "").strip()
        self._vt_queue = queue.Queue()
        self._vt_pending = set()
        self.vt_stats = {"lookups": 0, "errors": 0}
        self.reload()
        if self.vt_key:
            threading.Thread(target=self._vt_worker, name="virustotal", daemon=True).start()

    def reload(self):
        IOC_DIR.mkdir(exist_ok=True)
        self.bad_hashes = _read_list(IOC_DIR / "bad_hashes.txt")
        self.bad_ips = _read_list(IOC_DIR / "bad_ips.txt")
        self._loaded = time.time()

    def enrich(self, e):
        if time.time() - self._loaded > 60:
            self.reload()
        hashes = [h.lower() for h in (e.get("file.hash.sha256"), e.get("process.hash.sha256")) if h]
        for h in hashes:
            if h in self.bad_hashes:
                e["intel.hash_match"] = True
                e["intel.matched"] = h
            cached = self._vt_cached(h)
            if cached is not None:
                e["intel.vt_malicious"] = cached.get("malicious", 0)
                e["intel.vt_total"] = cached.get("total", 0)
            elif self.vt_key and h not in self._vt_pending:
                self._vt_pending.add(h)
                self._vt_queue.put(h)
        ip = (e.get("destination.ip") or "").lower()
        if ip and ip in self.bad_ips:
            e["intel.ip_match"] = True
            e["intel.matched"] = ip
        return e

    # ---------- VirusTotal ----------
    def _vt_cached(self, sha256):
        rows = self.db.query("SELECT result FROM intel_cache WHERE sha256 = ?", (sha256,))
        return json.loads(rows[0]["result"]) if rows else None

    def _vt_worker(self):
        while True:
            h = self._vt_queue.get()
            result = self._vt_lookup(h)
            if result is not None:
                self.db.execute("INSERT OR REPLACE INTO intel_cache (sha256, ts, result) VALUES (?,?,?)",
                                (h, now_iso(), json.dumps(result)))
                if result.get("malicious", 0) >= 3:
                    print(f"[intel] VirusTotal: {h} flagged by {result['malicious']} engines")
            self._vt_pending.discard(h)
            time.sleep(16)  # free tier: 4 requests per minute

    def _vt_lookup(self, sha256):
        req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha256}",
                                     headers={"x-apikey": self.vt_key})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode())
            stats = data["data"]["attributes"]["last_analysis_stats"]
            self.vt_stats["lookups"] += 1
            return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                    "total": sum(stats.values()), "found": True}
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                self.vt_stats["lookups"] += 1
                return {"malicious": 0, "total": 0, "found": False}
            self.vt_stats["errors"] += 1
            return None
        except (urllib.error.URLError, OSError, ValueError, KeyError):
            self.vt_stats["errors"] += 1
            return None

    def vt_report(self, sha256):
        return self._vt_cached(sha256.lower())

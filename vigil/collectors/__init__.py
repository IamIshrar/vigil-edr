"""Collectors: the sensors of the EDR.

Each collector runs in its own thread, looks at one part of the system on a
timer, and submits normalised events to the pipeline. Commercial EDRs use
kernel drivers and ETW (Event Tracing for Windows) to see events the instant
they happen; Vigil uses polling and Windows event logs, which is simpler to
read and needs no driver, at the cost of missing some very short-lived activity.
"""
import threading
import time
import traceback


class Collector:
    name = "collector"
    interval = 5.0

    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.status = "starting"
        self.detail = ""
        self.last_run = None
        self.events_sent = 0
        self._thread = threading.Thread(target=self._loop, name=self.name, daemon=True)

    # Override these two.
    def setup(self):
        """Take a baseline. Return False (and set self.detail) to disable the collector."""
        return True

    def poll(self):
        """Look for changes and call self.emit() for each one."""

    def emit(self, event):
        event.setdefault("source", self.name)
        self.events_sent += 1
        self.pipeline.submit(event)

    def start(self):
        self._thread.start()

    def _loop(self):
        try:
            if self.setup() is False:
                self.status = "disabled"
                return
        except Exception as exc:
            self.status, self.detail = "error", f"setup failed: {exc}"
            traceback.print_exc()
            return
        self.status = "running"
        while True:
            try:
                self.poll()
                self.last_run = time.time()
                if self.status == "error":
                    self.status, self.detail = "running", ""
            except Exception as exc:
                self.status, self.detail = "error", str(exc)
            time.sleep(self.interval)

    def info(self):
        return {"name": self.name, "status": self.status, "detail": self.detail,
                "events": self.events_sent, "interval": self.interval, "last_run": self.last_run}

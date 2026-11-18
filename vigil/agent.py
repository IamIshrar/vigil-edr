"""Wires every part together: storage, detection, pipeline, collectors, response."""
import platform
import socket
import threading
import time

import psutil

from . import __version__
from .collectors.eventlog import EventLogCollector
from .collectors.files import FileCollector
from .collectors.network import NetworkCollector
from .collectors.persistence import PersistenceCollector
from .collectors.process import ProcessCollector
from .config import CONFIG, RULES_FILE
from .db import Database
from .detection.behaviours import Behaviours
from .detection.engine import RuleEngine
from .detection.intel import Intel
from .pipeline import Pipeline
from .response import Responder
from .util import is_admin


class Agent:
    def __init__(self):
        self.db = Database()
        self.engine = RuleEngine(RULES_FILE)
        self.behaviours = Behaviours()
        self.intel = Intel(self.db)
        self.pipeline = Pipeline(self.db, self.engine, self.behaviours, self.intel)
        self.responder = Responder(self.db)
        self.eventlog = EventLogCollector(self.pipeline)
        sysmon = lambda: self.eventlog.sysmon_active  # noqa: E731
        self.collectors = [
            ProcessCollector(self.pipeline, sysmon_handles_processes=sysmon),
            NetworkCollector(self.pipeline),
            FileCollector(self.pipeline),
            PersistenceCollector(self.pipeline),
            self.eventlog,
        ]
        self.started = time.time()
        self.admin = is_admin()

    def start(self):
        self.pipeline.start()
        for c in self.collectors:
            c.start()
        threading.Thread(target=self._housekeeping, name="housekeeping", daemon=True).start()
        psutil.cpu_percent(interval=None)  # prime the CPU counter

    def _housekeeping(self):
        while True:
            time.sleep(3600)
            self.db.purge_older_than(CONFIG["retention_days"])

    def host(self):
        vm = psutil.virtual_memory()
        return {
            "hostname": socket.gethostname(), "os": f"{platform.system()} {platform.release()} ({platform.version()})",
            "python": platform.python_version(), "admin": self.admin, "version": __version__,
            "boot_time": psutil.boot_time(), "uptime_agent": time.time() - self.started,
            "cpu_percent": psutil.cpu_percent(interval=None), "mem_percent": vm.percent,
            "agent_mem_mb": round(psutil.Process().memory_info().rss / 1048576, 1),
            "processes": len(psutil.pids()),
        }

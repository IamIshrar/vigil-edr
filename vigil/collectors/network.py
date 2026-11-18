"""Network collector: which process is talking to which address.

Linking a connection to the process that made it is what separates EDR
network telemetry from a firewall log. "Something talked to 203.0.113.9" is
noise; "rundll32.exe talked to 203.0.113.9" is a lead.

How it works: every few seconds, list TCP/UDP connections with their owning
PID (psutil.net_connections). A remote endpoint not seen before for that
process is emitted as a "connect" event. Loopback traffic is ignored.
"""
import psutil

from . import Collector
from ..config import CONFIG
from ..util import is_public_ip


class NetworkCollector(Collector):
    name = "network"

    def __init__(self, pipeline):
        super().__init__(pipeline)
        self.interval = CONFIG["network_poll_seconds"]
        self.seen = set()
        self._names = {}

    def _conns(self):
        try:
            return psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            self.detail = "Run as Administrator to see every process's connections"
            return []

    def setup(self):
        for c in self._conns():
            if c.raddr:
                self.seen.add((c.pid, c.raddr.ip, c.raddr.port))
        return True

    def _name(self, pid):
        if pid in self._names:
            return self._names[pid]
        try:
            p = psutil.Process(pid)
            val = (p.name(), p.exe() if p.exe() else "")
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, OSError):
            val = ("?", "")
        if len(self._names) > 2000:
            self._names.clear()
        self._names[pid] = val
        return val

    def poll(self):
        current = set()
        for c in self._conns():
            if not c.raddr or c.raddr.ip in ("127.0.0.1", "::1"):
                continue
            key = (c.pid, c.raddr.ip, c.raddr.port)
            current.add(key)
            if key in self.seen:
                continue
            name, exe = self._name(c.pid) if c.pid else ("?", "")
            self.emit({
                "category": "network", "action": "connect",
                "process.pid": c.pid, "process.name": name, "process.executable": exe,
                "source.ip": c.laddr.ip if c.laddr else "", "source.port": c.laddr.port if c.laddr else 0,
                "destination.ip": c.raddr.ip, "destination.port": c.raddr.port,
                "network.transport": "tcp" if c.type == 1 else "udp",
                "network.state": c.status,
                "destination.public": is_public_ip(c.raddr.ip),
            })
        # Forget closed connections so a later reconnect is seen again.
        self.seen = current


def live_connections():
    """Current connections for the dashboard."""
    out = []
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return out
    names = {}
    for c in conns:
        if not c.raddr:
            continue
        if c.pid not in names:
            try:
                names[c.pid] = psutil.Process(c.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
                names[c.pid] = "?"
        out.append({
            "pid": c.pid, "process": names[c.pid], "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
            "remote_ip": c.raddr.ip, "remote_port": c.raddr.port, "state": c.status,
            "public": is_public_ip(c.raddr.ip),
        })
    return out

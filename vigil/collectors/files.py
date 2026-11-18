"""File collector: new executables and scripts in the places attackers drop them.

Malware has to land on disk somewhere before it runs: Downloads, Desktop,
the Temp folder, the Startup folder, C:\\Users\\Public. Vigil watches those
folders (one level deep) for new or changed files with risky extensions, and
hashes each one so threat intelligence can be checked against it.

A production EDR uses a file-system minifilter driver to see every write as it
happens. Polling a handful of high-risk folders gives most of the value for
far less complexity.
"""
import os

from . import Collector
from ..config import CONFIG
from ..util import sha256_file


class FileCollector(Collector):
    name = "files"

    def __init__(self, pipeline):
        super().__init__(pipeline)
        self.interval = CONFIG["file_poll_seconds"]
        self.exts = tuple(e.lower() for e in CONFIG["watched_extensions"])
        self.folders = [f for f in CONFIG["watched_folders"] if f and os.path.isdir(f)]
        self.state = {}

    def _scan(self):
        found = {}
        for folder in self.folders:
            for root, dirs, files in os.walk(folder):
                depth = root[len(folder):].count(os.sep)
                if depth >= 1:
                    dirs[:] = []  # only the folder itself and its direct subfolders
                for fn in files:
                    if not fn.lower().endswith(self.exts):
                        continue
                    path = os.path.join(root, fn)
                    try:
                        st = os.stat(path)
                    except OSError:
                        continue
                    found[path] = (st.st_mtime, st.st_size)
        return found

    def setup(self):
        if not self.folders:
            self.detail = "None of the watched folders exist on this machine"
            return False
        self.state = self._scan()
        self.detail = f"Watching {len(self.folders)} folders"
        return True

    def poll(self):
        current = self._scan()
        for path, meta in current.items():
            old = self.state.get(path)
            if old == meta:
                continue
            action = "create" if old is None else "modify"
            self.emit({
                "category": "file", "action": action,
                "file.path": path, "file.name": os.path.basename(path),
                "file.extension": os.path.splitext(path)[1].lower(),
                "file.size": meta[1], "file.hash.sha256": sha256_file(path) or "",
                "file.directory": os.path.dirname(path),
            })
        for path in set(self.state) - set(current):
            self.emit({"category": "file", "action": "delete", "file.path": path,
                       "file.name": os.path.basename(path)})
        self.state = current

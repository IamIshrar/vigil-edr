"""Small helpers shared by several modules."""
import hashlib
import ipaddress
import os
import subprocess

from .config import CONFIG, IS_WINDOWS

_hash_cache = {}  # (path, mtime, size) -> sha256


def sha256_file(path):
    """SHA-256 of a file, cached by path + modification time. Returns None if unreadable or too big."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    if st.st_size > CONFIG["max_hash_mb"] * 1024 * 1024:
        return None
    key = (path, st.st_mtime, st.st_size)
    if key in _hash_cache:
        return _hash_cache[key]
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return None
    digest = h.hexdigest()
    if len(_hash_cache) > 5000:
        _hash_cache.clear()
    _hash_cache[key] = digest
    return digest


def is_public_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)


def run(args, timeout=30):
    """Run a command without a shell (no injection risk). Returns (ok, output)."""
    kwargs = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW: no console flashes
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace", **kwargs)
        return p.returncode == 0, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)


def is_admin():
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0

"""Windows Event Log collector (and Sysmon, when installed).

Windows already records a lot of security-relevant activity. Vigil reads the
events that matter, using the built-in wevtutil.exe so no extra Python
packages are needed:

  Security (needs Administrator)
    4625  failed logon                  -> brute force detection (T1110)
    4720  user account created          (T1136.001)
    4728 / 4732 / 4756  user added to a security group   (T1098)
    1102  Security log cleared          (T1070.001)
  System
    7045  new service installed         (T1543.003)
    104   event log cleared             (T1070.001)
  Microsoft Defender
    1116 / 1117  malware detected / action taken
    5001  real-time protection disabled (T1562.001)
  Sysmon (free from Sysinternals; strongly recommended)
    1  process create   3  network connect   11  file create   13  registry value set

How it works: at start, remember the newest record number in each log. Every
few seconds, ask wevtutil for records newer than that with an XPath filter,
parse the XML, and turn each record into a normalised event.
"""
import os
import re
import xml.etree.ElementTree as ET

from . import Collector
from ..config import CONFIG, IS_WINDOWS
from ..util import run, is_public_ip

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
SYSMON = "Microsoft-Windows-Sysmon/Operational"

CHANNELS = {
    "Security": [4625, 4720, 4728, 4732, 4756, 1102],
    "System": [7045, 104],
    "Microsoft-Windows-Windows Defender/Operational": [1116, 1117, 5001],
    SYSMON: [1, 3, 11, 13],
}


def _parse(xml_text):
    """wevtutil prints <Event> elements back to back; wrap them so they parse as one document."""
    xml_text = re.sub(r"<\?xml[^>]*\?>", "", xml_text)
    try:
        root = ET.fromstring(f"<Events>{xml_text}</Events>")
    except ET.ParseError:
        return []
    out = []
    for ev in root.findall(f"{NS}Event"):
        sys_ = ev.find(f"{NS}System")
        rec = {
            "event_id": int(sys_.findtext(f"{NS}EventID", "0")),
            "record_id": int(sys_.findtext(f"{NS}EventRecordID", "0")),
            "time": (sys_.find(f"{NS}TimeCreated").get("SystemTime") if sys_.find(f"{NS}TimeCreated") is not None else ""),
            "computer": sys_.findtext(f"{NS}Computer", ""),
            "data": {},
        }
        for d in ev.iter(f"{NS}Data"):
            rec["data"][d.get("Name") or f"param{len(rec['data'])}"] = (d.text or "").strip()
        out.append(rec)
    return out


def _basename(path):
    return os.path.basename(path.replace("\\", "/")) if path else ""


def _sha256_from_sysmon(hashes):
    m = re.search(r"SHA256=([A-Fa-f0-9]{64})", hashes or "")
    return m.group(1).lower() if m else ""


def normalise(channel, rec):
    """Map one Windows event to Vigil's field names. Returns None for events we ignore."""
    eid, d = rec["event_id"], rec["data"]
    base = {"windows.channel": channel, "windows.event_id": eid, "windows.record_id": rec["record_id"],
            "host.name": rec["computer"]}

    if channel == "Security":
        if eid == 4625:
            return {**base, "category": "auth", "action": "logon_failed",
                    "user.name": d.get("TargetUserName", ""), "user.domain": d.get("TargetDomainName", ""),
                    "source.ip": d.get("IpAddress", ""), "logon.type": d.get("LogonType", ""),
                    "logon.failure_status": d.get("Status", ""), "process.name": _basename(d.get("ProcessName", ""))}
        if eid == 4720:
            return {**base, "category": "auth", "action": "user_created",
                    "user.name": d.get("TargetUserName", ""), "actor.name": d.get("SubjectUserName", "")}
        if eid in (4728, 4732, 4756):
            return {**base, "category": "auth", "action": "group_member_added",
                    "group.name": d.get("TargetUserName", ""), "user.name": d.get("MemberName", "") or d.get("MemberSid", ""),
                    "actor.name": d.get("SubjectUserName", "")}
        if eid == 1102:
            return {**base, "category": "system", "action": "log_cleared",
                    "message": f"Security log cleared by {d.get('SubjectUserName', 'unknown')}",
                    "user.name": d.get("SubjectUserName", "")}
    if channel == "System":
        if eid == 7045:
            return {**base, "category": "persistence", "action": "service_installed",
                    "persistence.type": "service", "persistence.name": d.get("ServiceName", ""),
                    "persistence.value": d.get("ImagePath", ""), "persistence.location": "Service Control Manager",
                    "user.name": d.get("AccountName", "")}
        if eid == 104:
            return {**base, "category": "system", "action": "log_cleared",
                    "message": f"Event log '{d.get('Channel', d.get('param2', ''))}' cleared"}
    if channel.endswith("Defender/Operational"):
        if eid in (1116, 1117):
            return {**base, "category": "av", "action": "malware_detected" if eid == 1116 else "malware_action",
                    "threat.name": d.get("Threat Name", ""), "file.path": d.get("Path", ""),
                    "message": f"Defender: {d.get('Threat Name', 'threat')} at {d.get('Path', '')}",
                    "threat.action": d.get("Action Name", "")}
        if eid == 5001:
            return {**base, "category": "av", "action": "realtime_disabled",
                    "message": "Microsoft Defender real-time protection was turned off"}
    if channel == SYSMON:
        img = d.get("Image", "")
        common = {**base, "source": "sysmon", "process.pid": int(d.get("ProcessId") or 0),
                  "process.executable": img, "process.name": _basename(img), "user.name": d.get("User", "")}
        if eid == 1:
            pimg = d.get("ParentImage", "")
            return {**common, "category": "process", "action": "start",
                    "process.command_line": d.get("CommandLine", ""), "process.ppid": int(d.get("ParentProcessId") or 0),
                    "process.parent.executable": pimg, "process.parent.name": _basename(pimg),
                    "process.parent.command_line": d.get("ParentCommandLine", ""),
                    "process.hash.sha256": _sha256_from_sysmon(d.get("Hashes")),
                    "process.integrity_level": d.get("IntegrityLevel", ""),
                    "process.current_directory": d.get("CurrentDirectory", "")}
        if eid == 3:
            ip = d.get("DestinationIp", "")
            return {**common, "category": "network", "action": "connect",
                    "destination.ip": ip, "destination.port": int(d.get("DestinationPort") or 0),
                    "destination.hostname": d.get("DestinationHostname", ""),
                    "source.ip": d.get("SourceIp", ""), "source.port": int(d.get("SourcePort") or 0),
                    "network.transport": d.get("Protocol", ""), "destination.public": is_public_ip(ip)}
        if eid == 11:
            path = d.get("TargetFilename", "")
            return {**common, "category": "file", "action": "create", "file.path": path,
                    "file.name": _basename(path), "file.extension": os.path.splitext(path)[1].lower()}
        if eid == 13:
            target = d.get("TargetObject", "")
            if "\\currentversion\\run" not in target.lower():
                return None  # only autostart keys; everything else is too noisy for a laptop
            return {**common, "category": "persistence", "action": "create", "persistence.type": "registry_run",
                    "persistence.name": target.rsplit("\\", 1)[-1], "persistence.location": target.rsplit("\\", 1)[0],
                    "persistence.value": d.get("Details", ""), "registry.path": target}
    return None


class EventLogCollector(Collector):
    name = "eventlog"

    def __init__(self, pipeline):
        super().__init__(pipeline)
        self.interval = CONFIG["eventlog_poll_seconds"]
        self.bookmarks = {}
        self.sysmon_active = False

    def _latest_record(self, channel):
        ok, out = run(["wevtutil", "qe", channel, "/c:1", "/rd:true", "/f:xml"])
        if not ok:
            return None
        recs = _parse(out)
        return recs[0]["record_id"] if recs else 0

    def setup(self):
        if not IS_WINDOWS:
            self.detail = "Windows only"
            return False
        if not CONFIG["enable_eventlog"]:
            self.detail = "Turned off in config"
            return False
        skipped = []
        for channel in CHANNELS:
            if channel == SYSMON and not CONFIG["use_sysmon_if_available"]:
                continue
            latest = self._latest_record(channel)
            if latest is None:
                skipped.append(channel.split("/")[0].replace("Microsoft-Windows-", ""))
                continue
            self.bookmarks[channel] = latest
        self.sysmon_active = SYSMON in self.bookmarks
        parts = [f"Reading {len(self.bookmarks)} logs"]
        if self.sysmon_active:
            parts.append("Sysmon detected")
        if skipped:
            parts.append("not readable: " + ", ".join(skipped) + (" (run as Administrator)" if "Security" in skipped else ""))
        self.detail = "; ".join(parts)
        return bool(self.bookmarks)

    def poll(self):
        for channel, last in list(self.bookmarks.items()):
            ids = " or ".join(f"EventID={i}" for i in CHANNELS[channel])
            query = f"*[System[({ids}) and EventRecordID>{last}]]"
            ok, out = run(["wevtutil", "qe", channel, f"/q:{query}", "/f:xml", "/c:500"])
            if not ok:
                continue
            for rec in sorted(_parse(out), key=lambda r: r["record_id"]):
                self.bookmarks[channel] = max(self.bookmarks[channel], rec["record_id"])
                event = normalise(channel, rec)
                if event:
                    self.emit(event)

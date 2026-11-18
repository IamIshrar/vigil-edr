"""Generates vigil/detection/rules.json.

Rules are authored here as Python so regexes are easier to read (raw strings),
then saved as JSON for the engine. Edit this file, run it, restart Vigil.

    python tools/build_rules.py
"""
import json
from pathlib import Path

OFFICE = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe"]
SHELLS = ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"]
PS = ["powershell.exe", "pwsh.exe", "powershell_ise.exe"]
LOLBINS_NET = ["rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe", "wscript.exe", "cscript.exe", "cmstp.exe"]
USER_WRITABLE = ["\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\", "\\appdata\\roaming\\", "\\desktop\\", "\\programdata\\"]


def M(tactic, technique, name):
    return {"tactic": tactic, "technique": technique, "name": name}


def f(field, op, value=None):
    leaf = {"field": field, "op": op}
    if value is not None:
        leaf["value"] = value
    return leaf


RULES = [
    # ---------------- Execution ----------------
    {"id": "VIG-001", "title": "Office application started a shell or script host", "severity": "high",
     "mitre": M("Execution", "T1204.002", "User Execution: Malicious File"),
     "category": "process", "action": "start",
     "match": {"all": [f("process.parent.name", "in", OFFICE), f("process.name", "in", SHELLS)]},
     "description": "A Microsoft Office program launched a command shell or scripting engine. Documents rarely need to do this; malicious macros almost always do.",
     "advice": "Find the document the user opened, kill the child process, and check what it downloaded or ran."},

    {"id": "VIG-002", "title": "PowerShell with an encoded command", "severity": "high",
     "mitre": M("Execution", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
     "category": "process", "action": "start",
     "match": {"all": [f("process.name", "in", PS),
                       f("process.command_line", "regex", r"\s[-/](e|ec|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{16,}")]},
     "description": "PowerShell was given a Base64-encoded command. Attackers encode commands to hide them from people and simple filters.",
     "advice": "Decode the Base64 text (it is UTF-16LE) to read the real command, then judge whether it is legitimate."},

    {"id": "VIG-003", "title": "PowerShell download cradle", "severity": "high",
     "mitre": M("Command and Control", "T1105", "Ingress Tool Transfer"),
     "category": "process", "action": "start",
     "match": {"all": [f("process.name", "in", PS),
                       f("process.command_line", "regex", r"(downloadstring|downloadfile|downloaddata|invoke-webrequest|iwr\s|invoke-restmethod|irm\s|net\.webclient|start-bitstransfer)"),
                       {"any": [f("process.command_line", "regex", r"(iex|invoke-expression)"),
                                f("process.command_line", "regex", r"https?://")]}]},
     "description": "PowerShell fetched content from the internet, often followed by running it in memory (IEX). This is the classic way to load a second-stage payload.",
     "advice": "Check the URL, block it, and look for the next process or file this one created."},

    {"id": "VIG-004", "title": "PowerShell started hidden or bypassing policy", "severity": "medium",
     "mitre": M("Defense Evasion", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
     "category": "process", "action": "start",
     "match": {"all": [f("process.name", "in", PS),
                       {"any": [f("process.command_line", "regex", r"[-/]w(indowstyle)?\s+h(idden)?\b"),
                                f("process.command_line", "regex", r"[-/](ep|exec|executionpolicy)\s+(bypass|unrestricted)"),
                                f("process.command_line", "regex", r"[-/]nop(rofile)?\s.*[-/]noni")]}]},
     "description": "PowerShell was launched with a hidden window or with execution policy bypassed. Admin scripts use these too, so check the context.",
     "advice": "Review the full command line and the parent process."},

    {"id": "VIG-005", "title": "Script host running a script from a user folder", "severity": "medium",
     "mitre": M("Execution", "T1059.005", "Command and Scripting Interpreter: Visual Basic"),
     "category": "process", "action": "start",
     "match": {"all": [f("process.name", "in", ["wscript.exe", "cscript.exe"]),
                       f("process.command_line", "contains_any", USER_WRITABLE + [".js", ".vbs", ".jse", ".vbe", ".wsf"])]},
     "description": "Windows Script Host ran a JavaScript or VBScript file. Phishing attachments often arrive as .js or .vbs files inside a ZIP.",
     "advice": "Quarantine the script file and check where it came from."},

    # ---------------- Defense evasion / LOLBins ----------------
    {"id": "VIG-010", "title": "certutil used to download or decode a file", "severity": "high",
     "mitre": M("Defense Evasion", "T1140", "Deobfuscate/Decode Files or Information"),
     "category": "process", "action": "start",
     "match": {"all": [f("process.name", "equals", "certutil.exe"),
                       f("process.command_line", "regex", r"[-/](urlcache|decode|decodehex|verifyctl)\b")]},
     "description": "certutil is a certificate tool that attackers abuse to download files and to decode Base64 payloads. It is a classic living-off-the-land binary (LOLBin).",
     "advice": "Find the file it wrote and quarantine it."},

    {"id": "VIG-011", "title": "mshta running a script or remote content", "severity": "high",
     "mitre": M("Defense Evasion", "T1218.005", "System Binary Proxy Execution: Mshta"),
     "category": "process", "action": "start",
     "match": {"all": [f("process.name", "equals", "mshta.exe"),
                       f("process.command_line", "regex", r"(https?://|javascript:|vbscript:|\.hta)")]},
     "description": "mshta.exe runs HTML Applications. Attackers use it to execute scripts while appearing as a signed Microsoft binary.",
     "advice": "Block the URL or quarantine the .hta file, and kill the process."},

    {"id": "VIG-012", "title": "rundll32 running script or an unusual DLL path", "severity": "high",
     "mitre": M("Defense Evasion", "T1218.011", "System Binary Proxy Execution: Rundll32"),
     "category": "process", "action": "start",
     "match": {"all": [f("process.name", "equals", "rundll32.exe"),
                       {"any": [f("process.command_line", "regex", r"(javascript:|vbscript:|mshtml,runhtmlapplication)"),
                                f("process.command_line", "contains_any", USER_WRITABLE)]}]},
     "description": "rundll32 loaded a DLL from a user-writable folder or ran inline script. Legitimate DLLs normally live in Windows or Program Files.",
     "advice": "Hash and quarantine the DLL, then check how it arrived."},

    {"id": "VIG-013", "title": "regsvr32 loading a remote scriptlet (Squiblydoo)", "severity": "high",
     "mitre": M("Defense Evasion", "T1218.010", "System Binary Proxy Execution: Regsvr32"),
     "category": "process", "action": "start",
     "match": {"all": [f("process.name", "equals", "regsvr32.exe"),
                       f("process.command_line", "regex", r"(/i:\s*https?://|scrobj\.dll)")]},
     "description": "regsvr32 was told to fetch and run a scriptlet. This technique bypasses application allow-listing.",
     "advice": "Block the URL and kill the process."},

    {"id": "VIG-014", "title": "BITS job used to transfer a file", "severity": "medium",
     "mitre": M("Defense Evasion", "T1197", "BITS Jobs"),
     "category": "process", "action": "start",
     "match": {"all": [f("process.name", "equals", "bitsadmin.exe"),
                       f("process.command_line", "regex", r"/(transfer|addfile|setnotifycmdline)")]},
     "description": "bitsadmin created a background transfer. BITS jobs can download payloads and even re-run them after reboot.",
     "advice": "List jobs with 'bitsadmin /list /allusers /verbose' and cancel unknown ones."},

    {"id": "VIG-015", "title": "Program run from a user-writable folder", "severity": "low",
     "mitre": M("Execution", "T1204.002", "User Execution: Malicious File"),
     "category": "process", "action": "start",
     "match": {"all": [f("process.executable", "contains_any", ["\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\"]),
                       f("process.executable", "endswith_any", [".exe", ".scr", ".com"])]},
     "description": "An executable ran from Temp, Downloads or Public. Installers do this legitimately; so does most malware on first run.",
     "advice": "Check the file's hash reputation and digital signature."},

    {"id": "VIG-016", "title": "System process name running from the wrong folder", "severity": "high",
     "mitre": M("Defense Evasion", "T1036.005", "Masquerading: Match Legitimate Name or Location"),
     "category": "process", "action": "start",
     "match": {"all": [f("process.name", "in", ["svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "explorer.exe", "taskhostw.exe", "spoolsv.exe"]),
                       f("process.executable", "exists"),
                       {"none": [f("process.executable", "startswith", r"C:\Windows\System32"),
                                 f("process.executable", "startswith", r"C:\Windows\SysWOW64"),
                                 f("process.executable", "equals", r"C:\Windows\explorer.exe")]}]},
     "description": "A process uses the name of a core Windows process but runs from somewhere else. Malware does this to blend in.",
     "advice": "This is almost always malicious. Kill it and quarantine the file."},

    {"id": "VIG-017", "title": "Microsoft Defender protection turned off from the command line", "severity": "high",
     "mitre": M("Defense Evasion", "T1562.001", "Impair Defenses: Disable or Modify Tools"),
     "category": "process", "action": "start",
     "match": {"any": [f("process.command_line", "regex", r"set-mppreference.*-(disablerealtimemonitoring|disablebehaviormonitoring|disableioavprotection)\s+(\$true|1)"),
                       f("process.command_line", "regex", r"add-mppreference.*-exclusion(path|process|extension)"),
                       f("process.command_line", "regex", r"sc(\.exe)?\s+(stop|delete|config)\s+windefend")]},
     "description": "Someone tried to switch off or carve exclusions into Microsoft Defender. Ransomware operators do this right before encrypting.",
     "advice": "Re-enable protection, remove exclusions, and investigate who ran the command."},

    {"id": "VIG-018", "title": "Event logs cleared from the command line", "severity": "high",
     "mitre": M("Defense Evasion", "T1070.001", "Indicator Removal: Clear Windows Event Logs"),
     "category": "process", "action": "start",
     "match": {"any": [f("process.command_line", "regex", r"wevtutil(\.exe)?\s+(cl|clear-log)\s"),
                       f("process.command_line", "regex", r"clear-eventlog|remove-eventlog")]},
     "description": "Event logs were wiped. Attackers clear logs to destroy evidence.",
     "advice": "Treat the host as compromised and check other sources (Sysmon, SIEM) for what happened before."},

    # ---------------- Impact ----------------
    {"id": "VIG-020", "title": "Backups or shadow copies deleted (ransomware behaviour)", "severity": "critical",
     "mitre": M("Impact", "T1490", "Inhibit System Recovery"),
     "category": "process", "action": "start",
     "match": {"any": [f("process.command_line", "regex", r"vssadmin(\.exe)?\s+(delete\s+shadows|resize\s+shadowstorage)"),
                       f("process.command_line", "regex", r"wmic(\.exe)?\s+shadowcopy\s+delete"),
                       f("process.command_line", "regex", r"bcdedit(\.exe)?.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)"),
                       f("process.command_line", "regex", r"wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)"),
                       f("process.command_line", "regex", r"get-wmiobject\s+win32_shadowcopy.*delete")]},
     "description": "Volume shadow copies or backups were deleted. Almost every ransomware family does this just before encryption so the victim cannot recover.",
     "advice": "Act immediately: isolate the host from the network and kill the process tree."},

    # ---------------- Credential access ----------------
    {"id": "VIG-030", "title": "LSASS memory dump attempt", "severity": "critical",
     "mitre": M("Credential Access", "T1003.001", "OS Credential Dumping: LSASS Memory"),
     "category": "process", "action": "start",
     "match": {"any": [f("process.command_line", "regex", r"comsvcs(\.dll)?[, ]+#?(24|minidump)"),
                       f("process.command_line", "regex", r"procdump(64)?(\.exe)?\s.*(-ma\s.*)?lsass"),
                       f("process.command_line", "regex", r"sekurlsa::|lsadump::|mimikatz"),
                       f("process.command_line", "regex", r"rdrleakdiag.*/fullmemdmp")]},
     "description": "A tool tried to dump the memory of LSASS, the process that holds logged-on users' credentials. This is how attackers steal passwords and hashes.",
     "advice": "Isolate the host, kill the process, and reset passwords for accounts that were logged on."},

    {"id": "VIG-031", "title": "Registry hive saved (SAM / SECURITY / SYSTEM)", "severity": "high",
     "mitre": M("Credential Access", "T1003.002", "OS Credential Dumping: Security Account Manager"),
     "category": "process", "action": "start",
     "match": {"all": [f("process.name", "equals", "reg.exe"),
                       f("process.command_line", "regex", r"\s(save|export)\s+hklm\\(sam|security|system)\b")]},
     "description": "The SAM, SECURITY or SYSTEM registry hive was copied. Together they let an attacker extract local password hashes offline.",
     "advice": "Find and delete the saved hive files, and rotate local administrator passwords."},

    # ---------------- Persistence & privilege ----------------
    {"id": "VIG-040", "title": "Scheduled task created from the command line", "severity": "medium",
     "mitre": M("Persistence", "T1053.005", "Scheduled Task/Job: Scheduled Task"),
     "category": "process", "action": "start",
     "match": {"all": [f("process.name", "equals", "schtasks.exe"), f("process.command_line", "regex", r"/create")]},
     "description": "A scheduled task was created. Malware uses tasks to start again at logon or on a timer.",
     "advice": "Open Task Scheduler, inspect the task's action, and delete it if unknown."},

    {"id": "VIG-041", "title": "Local account created or added to Administrators", "severity": "high",
     "mitre": M("Persistence", "T1136.001", "Create Account: Local Account"),
     "category": "process", "action": "start",
     "match": {"any": [f("process.command_line", "regex", r"net1?(\.exe)?\s+user\s+\S+\s+\S+.*/add"),
                       f("process.command_line", "regex", r"net1?(\.exe)?\s+localgroup\s+administrators\s+\S+\s+/add"),
                       f("process.command_line", "regex", r"new-localuser|add-localgroupmember\s.*administrators")]},
     "description": "A new local user was created or a user was made an administrator from the command line.",
     "advice": "Confirm with the owner of the machine; remove the account if it was not expected."},

    {"id": "VIG-042", "title": "New autostart entry in a Registry Run key", "severity": "high",
     "mitre": M("Persistence", "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys"),
     "category": "persistence", "action": ["create", "modify"],
     "match": {"all": [f("persistence.type", "equals", "registry_run")]},
     "description": "A program was added to a Registry Run key, so it starts every time a user logs on.",
     "advice": "Check the program path. If unknown, delete the value and quarantine the file."},

    {"id": "VIG-043", "title": "New file in a Startup folder", "severity": "high",
     "mitre": M("Persistence", "T1547.001", "Boot or Logon Autostart Execution: Startup Folder"),
     "category": None, "action": ["create", "modify"],
     "match": {"any": [{"all": [f("persistence.type", "equals", "startup_folder")]},
                       {"all": [f("file.path", "contains", "\\start menu\\programs\\startup\\")]}]},
     "description": "A file was placed in a Startup folder, so it runs at every logon.",
     "advice": "Quarantine the file unless you put it there."},

    {"id": "VIG-044", "title": "New scheduled task registered", "severity": "medium",
     "mitre": M("Persistence", "T1053.005", "Scheduled Task/Job: Scheduled Task"),
     "category": "persistence", "action": ["create", "modify"],
     "match": {"all": [f("persistence.type", "equals", "scheduled_task")]},
     "description": "A new non-Microsoft scheduled task appeared.",
     "advice": "Inspect what the task runs and who created it."},

    {"id": "VIG-045", "title": "New Windows service installed", "severity": "high",
     "mitre": M("Persistence", "T1543.003", "Create or Modify System Process: Windows Service"),
     "category": "persistence", "action": ["create", "service_installed"],
     "match": {"all": [f("persistence.type", "equals", "service")]},
     "description": "A new service was installed. Services run as SYSTEM, so attackers use them for persistence and privilege escalation (and tools like PsExec create them for lateral movement).",
     "advice": "Check the service binary path and signature."},

    # ---------------- Files ----------------
    {"id": "VIG-050", "title": "File with a fake double extension", "severity": "medium",
     "mitre": M("Defense Evasion", "T1036.007", "Masquerading: Double File Extension"),
     "category": "file", "action": ["create", "modify"],
     "match": {"all": [f("file.name", "regex", r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|zip|rtf)\.(exe|scr|com|bat|cmd|js|vbs|hta|lnk|ps1)$")]},
     "description": "A file is named to look like a document (invoice.pdf.exe) but is actually executable. Windows hides known extensions by default, so users see only 'invoice.pdf'.",
     "advice": "Quarantine it. Do not open it."},

    {"id": "VIG-051", "title": "Script or shortcut dropped in Downloads or Temp", "severity": "low",
     "mitre": M("Initial Access", "T1566.001", "Phishing: Spearphishing Attachment"),
     "category": "file", "action": "create",
     "match": {"all": [f("file.extension", "in", [".js", ".jse", ".vbs", ".vbe", ".hta", ".wsf", ".lnk", ".iso", ".img"]),
                       f("file.path", "contains_any", ["\\downloads\\", "\\appdata\\local\\temp\\"])]},
     "description": "A script, shortcut or disk image arrived in Downloads or Temp. These formats are favourites for phishing payloads.",
     "advice": "Check where it came from before anyone opens it."},

    # ---------------- Network ----------------
    {"id": "VIG-060", "title": "LOLBin connected to the internet", "severity": "medium",
     "mitre": M("Command and Control", "T1105", "Ingress Tool Transfer"),
     "category": "network", "action": "connect",
     "match": {"all": [f("process.name", "in", LOLBINS_NET), f("destination.public", "is_true")]},
     "description": "A built-in Windows binary that rarely needs the internet opened a connection to a public IP. Often a download of a second-stage payload.",
     "advice": "Look up the IP, block it, and check what the process wrote to disk."},

    {"id": "VIG-061", "title": "Connection to a port used by remote-access tools", "severity": "high",
     "mitre": M("Command and Control", "T1571", "Non-Standard Port"),
     "category": "network", "action": "connect",
     "match": {"all": [f("destination.port", "in", [4444, 1337, 31337, 6666, 6667, 5555, 8888, 9001, 1234]),
                       f("destination.public", "is_true")]},
     "description": "A process connected out on a port commonly used by Metasploit, IRC bots and other remote-access tools.",
     "advice": "Identify the process; if it is not expected, block the IP and kill it."},

    {"id": "VIG-062", "title": "PowerShell connected to the internet", "severity": "low",
     "mitre": M("Command and Control", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
     "category": "network", "action": "connect",
     "match": {"all": [f("process.name", "in", PS), f("destination.public", "is_true")]},
     "description": "PowerShell opened an outbound connection. Fine for admin scripts and updates; worth a look otherwise.",
     "advice": "Correlate with the PowerShell process's command line."},

    # ---------------- Threat intelligence ----------------
    {"id": "VIG-070", "title": "Known-bad file hash", "severity": "critical",
     "mitre": M("Execution", "T1204", "User Execution"),
     "category": None, "action": None,
     "match": {"all": [f("intel.hash_match", "is_true")]},
     "description": "A file or process matches a hash on your local IOC list (iocs/bad_hashes.txt).",
     "advice": "Quarantine the file and kill any process running from it."},

    {"id": "VIG-071", "title": "Connection to a known-bad IP", "severity": "critical",
     "mitre": M("Command and Control", "T1071", "Application Layer Protocol"),
     "category": "network", "action": "connect",
     "match": {"all": [f("intel.ip_match", "is_true")]},
     "description": "A process connected to an IP on your local IOC list (iocs/bad_ips.txt).",
     "advice": "Block the IP and investigate the process."},

    {"id": "VIG-072", "title": "VirusTotal: file flagged by multiple engines", "severity": "high",
     "mitre": M("Execution", "T1204", "User Execution"),
     "category": None, "action": None,
     "match": {"all": [f("intel.vt_malicious", "gte", 3)]},
     "description": "Three or more antivirus engines on VirusTotal flag this file as malicious.",
     "advice": "Quarantine it and check the VirusTotal report for the family name."},

    # ---------------- Windows event log ----------------
    {"id": "VIG-080", "title": "Security or system event log cleared", "severity": "high",
     "mitre": M("Defense Evasion", "T1070.001", "Indicator Removal: Clear Windows Event Logs"),
     "category": "system", "action": "log_cleared",
     "match": {"all": [f("action", "equals", "log_cleared")]},
     "description": "Windows recorded that an event log was cleared (event 1102 or 104).",
     "advice": "Find out who did it and why; treat as suspicious unless it was planned maintenance."},

    {"id": "VIG-081", "title": "New local user account", "severity": "medium",
     "mitre": M("Persistence", "T1136.001", "Create Account: Local Account"),
     "category": "auth", "action": "user_created",
     "match": {"all": [f("user.name", "exists")]},
     "description": "A user account was created (event 4720).",
     "advice": "Confirm it was expected."},

    {"id": "VIG-082", "title": "User added to a security group", "severity": "high",
     "mitre": M("Persistence", "T1098", "Account Manipulation"),
     "category": "auth", "action": "group_member_added",
     "match": {"all": [f("group.name", "exists")]},
     "description": "A user was added to a security-enabled group (events 4728, 4732, 4756). Being added to Administrators gives full control of the machine.",
     "advice": "Confirm with the owner; remove the membership if not expected."},

    {"id": "VIG-083", "title": "Microsoft Defender detected malware", "severity": "high",
     "mitre": M("Execution", "T1204", "User Execution"),
     "category": "av", "action": ["malware_detected", "malware_action"],
     "match": {"all": [f("threat.name", "exists")]},
     "description": "Microsoft Defender reported a threat. Vigil surfaces it next to the process and network activity around it.",
     "advice": "Check the timeline for what ran just before and after the detection."},

    {"id": "VIG-084", "title": "Defender real-time protection turned off", "severity": "high",
     "mitre": M("Defense Evasion", "T1562.001", "Impair Defenses: Disable or Modify Tools"),
     "category": "av", "action": "realtime_disabled",
     "match": {"all": [f("action", "equals", "realtime_disabled")]},
     "description": "Real-time protection was switched off (Defender event 5001).",
     "advice": "Turn it back on and find out who turned it off."},
]

if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "vigil" / "detection" / "rules.json"
    out.write_text(json.dumps(RULES, indent=2), encoding="utf-8")
    print(f"Wrote {len(RULES)} rules to {out}")

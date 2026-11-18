# Learning guide: how Vigil EDR works

This guide walks you through the code in the order an event travels, explains the
security ideas behind each part, compares Vigil with commercial EDRs, and finishes
with exercises and interview preparation. Keep the dashboard open while you read,
and run `python tools/simulate.py --inject` whenever you want fresh alerts.

---

## 1. What an EDR is

Antivirus (an **EPP**, endpoint protection platform) asks *"is this file bad?"* and blocks it.
An **EDR** asks *"is this behaviour bad?"*. It records what happens on the machine (telemetry),
looks for attacker patterns in that record (detection), gives an analyst the evidence (investigation),
and lets them act (response).

Every EDR, from Microsoft Defender for Endpoint to CrowdStrike Falcon, follows the same loop:

```
  SENSORS          PIPELINE                                   ANALYST
 ┌─────────┐     ┌──────────┐   ┌────────┐   ┌───────┐   ┌──────────┐   ┌───────────┐
 │process  │     │normalise │   │ enrich │   │ store │   │ detect   │   │ triage    │
 │network  ├────►│ to common├──►│ intel, ├──►│ SQLite├──►│ rules +  ├──►│ evidence  │
 │files    │     │ fields   │   │ VT     │   │       │   │behaviours│   │ respond   │
 │autostart│     └──────────┘   └────────┘   └───────┘   └────┬─────┘   └─────┬─────┘
 │eventlog │                                                  │ alerts        │ kill / quarantine /
 └─────────┘                                                  ▼               ▼ block / isolate
```

## 2. Read the code in this order

| Step | File | What to look for |
| --- | --- | --- |
| 1 | `vigil/collectors/__init__.py` | The `Collector` base class: a thread that takes a baseline in `setup()` and reports changes in `poll()`. Every sensor follows this pattern. |
| 2 | `vigil/collectors/process.py` | How a new process is spotted by diffing PID lists, and how `describe()` builds a normalised event. Read the comment about short-lived processes. |
| 3 | `vigil/collectors/eventlog.py` | How Windows event IDs (4625, 7045, Sysmon 1) are pulled with `wevtutil` and mapped to the same field names. This is normalisation in action. |
| 4 | `vigil/pipeline.py` | The heart: `process()` enriches, stores, runs detections, and `_raise()` de-duplicates alerts. |
| 5 | `vigil/detection/engine.py` | A rule engine in 120 lines: a tree of `all` / `any` / `none` groups with leaf operators. |
| 6 | `tools/build_rules.py` | The 36 rules, each with MITRE mapping, description and advice. Read five of them closely. |
| 7 | `vigil/detection/behaviours.py` | Why some attacks need memory: sliding windows for brute force, recon bursts and beaconing. |
| 8 | `vigil/detection/intel.py` | IOC matching and rate-limited VirusTotal lookups with a cache. |
| 9 | `vigil/response.py` | Response actions and, more importantly, the guards that stop them causing damage. |
| 10 | `vigil/web.py` + `static/app.js` | A local API that is secure by default (host check, CSRF token, HTML escaping). |

## 3. The ideas that matter

### Telemetry beats signatures
A hash identifies one file; change one byte and the hash changes. A behaviour such as
"Word started PowerShell with an encoded command" survives repacking, renaming and recompiling.
That is why EDRs record process trees and command lines, not just files.

### Normalisation
Every collector writes the same field names: `process.name`, `process.command_line`,
`destination.ip`, `file.path`. Rule VIG-061 works whether the connection came from psutil or
from Sysmon event 3. This is exactly what Microsoft Sentinel's **ASIM** and Elastic's **ECS** do at SIEM scale.

### Rules versus behaviours
- **Rules** (`rules.json`) judge one event: *this* command line is suspicious.
- **Behaviours** (`behaviours.py`) judge a pattern over time: 10 failed logons from one IP in
  5 minutes; 4 different recon tools in 2 minutes; the same process calling the same IP every 60 seconds.

### MITRE ATT&CK
Each detection carries a tactic (the attacker's goal, such as *Persistence*) and a technique
(how, such as *T1547.001 Registry Run Keys*). This gives analysts a shared vocabulary and lets
you measure coverage: which techniques can you see, and which are blind spots?

### False positives and tuning
Admins run `whoami`, installers run from Downloads, and IT scripts use `-ExecutionPolicy Bypass`.
That is why some rules are **low** or **medium** severity, why the alert says *what to check* and
not just *what happened*, and why every rule can be switched off. Real detection engineering is
mostly tuning: tightening a rule until it is quiet on normal activity and loud on attacks.

### Alert fatigue and de-duplication
One attack should give one alert, not two hundred. `pipeline._raise()` suppresses the same rule
on the same entity for 10 minutes, and behaviours have a cooldown. Watch the
"duplicates suppressed" counter on the Overview page.

### Safe response
A response action that kills `lsass.exe` crashes Windows; one that kills its own terminal
kills the EDR. `response.py` refuses core processes, System32 files, loopback addresses and
Vigil's own process tree, asks for confirmation in the UI, and logs every attempt. During
development, a test that tried to kill PID 1 is what led to the `_own_lineage()` guard.
Safety checks are written because things go wrong.

### Securing the tool itself
Security tools are targets. The dashboard escapes every value because an attacker controls
command lines: `powershell -c "<script>..."` would otherwise run in your browser.
POST requests need a random token, and the Host header must be localhost.

## 4. Vigil compared with a commercial EDR

| Capability | Vigil | Commercial EDR (e.g. Defender for Endpoint) |
| --- | --- | --- |
| Process creation | Polls PIDs every second, or reads Sysmon event 1 | Kernel callback `PsSetCreateProcessNotifyRoutineEx`: sees every process before it runs and can block it |
| File activity | Polls high-risk folders | File-system minifilter driver sees every read and write |
| Script content | Command line only | **AMSI** inspects PowerShell, VBScript and JScript content after de-obfuscation |
| Memory attacks | Not covered | ETW Threat-Intelligence provider, memory scanning, injection detection |
| Self-protection | None; an admin can stop it | Runs as a Protected Process Light, with tamper protection and an ELAM driver |
| Analytics | Local rules | Cloud correlation across millions of machines, machine learning, threat-intel teams |
| Isolation | Firewall default-deny policy | Isolation that keeps the EDR's own cloud channel open |
| Scale | One machine | Thousands of machines, central console, SIEM integration |

Knowing these gaps, and why they exist, is exactly what interviewers probe.

## 5. Exercises

Start each one by writing a test in `tests/test_detection.py` that fails, then make it pass.

1. **Write a rule.** Detect `whoami /priv` and `whoami /groups` (attackers checking their privileges, T1033).
   Add it to `tools/build_rules.py`, run `python tools/build_rules.py`, then click *Reload rules* in the dashboard.
2. **Reduce a false positive.** VIG-015 fires for every installer in Downloads. Add a `none` group
   that skips files whose name contains `setup` or `install`. Decide whether that makes it too easy to evade, and why.
3. **Add a behaviour.** Detect mass file changes: more than 50 file `modify` events in one minute
   (a ransomware signal, T1486). Model it on `brute_force` in `behaviours.py`.
4. **Add a sensor.** Read Sysmon event 22 (DNS query) in `eventlog.py`, map it to
   `category: "dns"`, and write a rule for domains on a new `iocs/bad_domains.txt` list.
5. **Signature check.** Use PowerShell `Get-AuthenticodeSignature` (via `util.run`) to add
   `process.signed` and `process.signer` to process events, then raise the severity of VIG-015 for unsigned files.
6. **Ship alerts to Microsoft Sentinel.** Send each alert to a Log Analytics workspace with the
   Logs Ingestion API (a data collection endpoint plus a DCR) into a custom table `VigilAlerts_CL`, then write a KQL analytics rule on it.
   This connects your EDR to the SIEM work you already do.
7. **Run as a service.** Use NSSM or `sc.exe create` to run Vigil at boot, and think about what
   changes when it runs as SYSTEM instead of as your user.

## 6. Interview preparation

**Walk me through your EDR.**
Five collectors produce normalised events into a queue. The pipeline enriches them with IOC and
VirusTotal data, stores them in SQLite, and runs 36 JSON rules plus 4 stateful behaviours, all mapped
to MITRE ATT&CK. Alerts are de-duplicated and shown with evidence and guidance in a local dashboard,
where the analyst can kill, suspend, quarantine, block or isolate, with guard rails and an audit log.

**Why does process polling miss things, and how did you handle it?**
A process that starts and exits between two polls is never seen. Vigil switches to Sysmon event 1
when Sysmon is present; commercial EDRs use a kernel process-creation callback.

**How do you keep false positives down?**
Severity levels that reflect confidence, rules that combine conditions (parent *and* child *and*
command line), de-duplication and cooldowns, per-rule toggles, and a test for every rule with one
event that should match and one that should not.

**An attacker has admin rights. Can they blind Vigil?**
Yes: they can kill it, edit its rules or clear its database. Commercial products defend against
this with protected processes, tamper protection and sending telemetry off the box immediately.
Exercise 6 is the first step towards the last one.

**What would you build next?**
Signature checks, AMSI-style script logging via PowerShell Script Block Logging (event 4104),
DNS telemetry from Sysmon event 22, and forwarding to a SIEM.

## 7. Putting it on your CV

> **Vigil EDR** (Python, Flask, SQLite, Sysmon) · github.com/&lt;you&gt;/vigil-edr
> - Built a Windows endpoint detection and response agent with five telemetry collectors (process, network, file, persistence, Windows event log / Sysmon) feeding a normalised event pipeline.
> - Wrote 36 JSON detection rules and 4 stateful behaviours (brute force, recon burst, beaconing) mapped to MITRE ATT&CK, with unit tests for true and false positives.
> - Implemented guarded response actions (process kill and suspend, file quarantine and restore, Windows Firewall IP block, host isolation) with an audit trail, behind a localhost dashboard hardened against XSS, CSRF and DNS rebinding.

Keep the README honest about limitations. Interviewers trust a candidate who knows exactly where their own tool stops.

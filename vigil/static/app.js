/* Vigil EDR dashboard.
 *
 * Plain JavaScript, no frameworks, so every line is readable.
 * SECURITY: everything shown here (process names, command lines, file paths)
 * can be chosen by an attacker. It is always passed through esc() before it
 * goes into HTML, so a malicious command line cannot inject script into the
 * dashboard (stored XSS). Keep that rule if you add views.
 */
"use strict";

const TOKEN = document.querySelector('meta[name="vigil-token"]').content;
const $ = (s, el = document) => el.querySelector(s);
const view = $("#view");
const state = { view: "overview", timer: null, summary: null, alertFilter: { status: "open", severity: "" },
  timelineFilter: { category: "", q: "" }, tree: { expanded: new Set(), selected: null, q: "" }, rulesOpen: new Set() };

/* ---------- helpers ---------- */
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtTime = (iso) => { if (!iso) return "-"; const d = new Date(iso); return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }); };
const ago = (iso) => { if (!iso) return "never"; const s = (Date.now() - new Date(iso)) / 1000; if (s < 60) return `${Math.max(0, Math.round(s))}s ago`; if (s < 3600) return `${Math.round(s / 60)}m ago`; if (s < 86400) return `${Math.round(s / 3600)}h ago`; return `${Math.round(s / 86400)}d ago`; };
const dur = (sec) => { const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60); return h ? `${h}h ${m}m` : `${m}m`; };
const sev = (s) => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
const mitreUrl = (t) => t ? `https://attack.mitre.org/techniques/${t.replace(".", "/")}/` : "#";

async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { "Content-Type": "application/json", "X-Vigil-Token": TOKEN, ...(opts.headers || {}) } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}
const post = (path, body) => api(path, { method: "POST", body: JSON.stringify(body || {}) });

function toast(msg, err = false) {
  const t = document.createElement("div");
  t.className = "toast" + (err ? " err" : "");
  t.textContent = msg;
  $("#toasts").appendChild(t);
  setTimeout(() => t.remove(), err ? 7000 : 4500);
}

function confirmBox(title, text, okLabel = "Confirm") {
  return new Promise((resolve) => {
    const m = $("#modal");
    $("#modal-title").textContent = title;
    $("#modal-text").textContent = text;
    $("#modal-ok").textContent = okLabel;
    m.hidden = false;
    $("#modal-ok").focus();
    const done = (v) => { m.hidden = true; $("#modal-ok").onclick = $("#modal-cancel").onclick = null; resolve(v); };
    $("#modal-ok").onclick = () => done(true);
    $("#modal-cancel").onclick = () => done(false);
  });
}

const ACTIONS = {
  kill: { label: "Kill process", confirm: (t) => `Stop process ${t} and all of its child processes?` },
  suspend: { label: "Suspend", confirm: (t) => `Freeze process ${t}? It stays in memory so you can investigate it.` },
  resume: { label: "Resume", confirm: (t) => `Resume process ${t}?` },
  quarantine: { label: "Quarantine file", confirm: (t) => `Move this file into quarantine? Any process running from it will be stopped.\n\n${t}` },
  restore: { label: "Restore", confirm: () => "Put this file back where it was?" },
  block_ip: { label: "Block IP", confirm: (t) => `Block all traffic to and from ${t} in Windows Firewall?` },
  unblock_ip: { label: "Unblock", confirm: (t) => `Remove the firewall block on ${t}?` },
  isolate: { label: "Isolate host", confirm: () => "Block all inbound and outbound network traffic on this computer by default? Your internet connection will stop working until you release isolation." },
  unisolate: { label: "Release isolation", confirm: () => "Restore normal network access?" },
};

async function respond(action, target, alertId) {
  const a = ACTIONS[action];
  if (!(await confirmBox(a.label, a.confirm(target), a.label))) return;
  try {
    const r = await post("/api/respond", { action, target, alert_id: alertId || null });
    toast(r.detail, !r.ok);
  } catch (e) { toast(`Action failed: ${e.message}`, true); }
  refresh();
}

function actionButton(action, target, alertId, cls = "btn") {
  return `<button class="${cls}" data-act="${action}" data-target="${esc(target)}" data-alert="${alertId || ""}">${ACTIONS[action].label}</button>`;
}
document.addEventListener("click", (ev) => {
  const b = ev.target.closest("[data-act]");
  if (b) { ev.stopPropagation(); respond(b.dataset.act, b.dataset.target, b.dataset.alert); }
});

/* ---------- router ---------- */
const VIEWS = { overview: ["Overview", renderOverview], alerts: ["Alerts", renderAlerts], processes: ["Process tree", renderProcesses],
  timeline: ["Timeline", renderTimeline], network: ["Network", renderNetwork], persistence: ["Persistence", renderPersistence],
  rules: ["Detection rules", renderRules], response: ["Response", renderResponse], how: ["How it works", renderHow] };

function go() {
  const name = (location.hash || "#overview").slice(1);
  state.view = VIEWS[name] ? name : "overview";
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.view === state.view));
  $("#view-title").textContent = VIEWS[state.view][0];
  view.innerHTML = `<div class="empty">Loading...</div>`;
  refresh(true);
}
window.addEventListener("hashchange", go);

async function refresh(first = false) {
  clearTimeout(state.timer);
  try {
    await loadSummary();
    await VIEWS[state.view][1](first);
  } catch (e) {
    view.innerHTML = `<div class="card"><div class="empty"><b>Cannot reach the Vigil agent</b>Is run.py still running? (${esc(e.message)})</div></div>`;
  }
  const slow = ["persistence", "rules", "how"].includes(state.view);
  state.timer = setTimeout(() => { if ($("#drawer").hidden && $("#modal").hidden) refresh(); else state.timer = setTimeout(refresh, 2000); }, slow ? 15000 : 4000);
}

async function loadSummary() {
  const s = await api("/api/summary");
  state.summary = s;
  const open = Object.values(s.open_alerts).reduce((a, b) => a + b, 0);
  $("#nav-alerts").textContent = open || "";
  const ab = $("#admin-badge");
  ab.textContent = s.host.admin ? "Administrator" : "Limited rights";
  ab.className = "badge " + (s.host.admin ? "ok" : "warn");
  ab.title = s.host.admin ? "Full visibility" : "Run as Administrator to read the Security log and use firewall actions";
  $("#host-foot").innerHTML = `<b>${esc(s.host.hostname)}</b>${esc(s.host.os.split(" (")[0])}<br>Agent up ${dur(s.host.uptime_agent)} · v${esc(s.host.version)}`;
}

/* ---------- overview ---------- */
async function renderOverview() {
  const s = state.summary;
  const recent = await api("/api/alerts?limit=6");
  const maxH = Math.max(1, ...s.alerts_by_hour.map((h) => h.n));
  const events24 = Object.values(s.events_24h).reduce((a, b) => a + b, 0);
  const cats = ["process", "network", "file", "persistence", "auth", "system", "av"];
  const maxCat = Math.max(1, ...cats.map((c) => s.events_24h[c] || 0));
  const maxTac = Math.max(1, ...s.tactics.map((t) => t.n));
  view.innerHTML = `
    <div class="grid g4">
      ${["critical", "high", "medium", "low"].map((k) => `
        <button class="card kpi clickable ${k}" data-sev="${k}">
          <span class="k-label">${k} · open</span><span class="k-val">${s.open_alerts[k]}</span>
          <span class="k-sub">${k === "critical" ? "Act now" : k === "high" ? "Investigate today" : k === "medium" ? "Review" : "For awareness"}</span>
        </button>`).join("")}
    </div>
    <div class="grid g21">
      <div class="card"><div class="card-h"><h2>Alerts, last 24 hours</h2><span class="sub">${s.pipeline.alerts} raised since start · ${s.pipeline.suppressed} duplicates suppressed</span></div>
        <div class="card-b"><div class="bars">${s.alerts_by_hour.map((h) => `<div class="b ${h.n ? "" : "zero"}" style="height:${Math.max(2, (h.n / maxH) * 100)}%" title="${esc(h.hour)}:00 UTC · ${h.n} alerts"></div>`).join("")}</div>
        <div class="bars-axis"><span>24h ago</span><span>12h ago</span><span>now</span></div></div></div>
      <div class="card"><div class="card-h"><h2>Telemetry, last 24 hours</h2><span class="sub">${events24.toLocaleString()} events</span></div>
        <div class="card-b">${cats.map((c) => `<div class="hbar"><span>${c}</span><div class="track"><div class="fill" style="width:${((s.events_24h[c] || 0) / maxCat) * 100}%"></div></div><span class="num">${s.events_24h[c] || 0}</span></div>`).join("")}</div></div>
    </div>
    <div class="grid g21">
      <div class="card"><div class="card-h"><h2>Latest alerts</h2><a class="ext" href="#alerts">View all</a></div>
        <div class="list">${recent.length ? recent.map(alertRow).join("") : `<div class="empty"><b>No alerts yet</b>Run <code>python tools/simulate.py</code> to trigger safe test detections.</div>`}</div></div>
      <div class="card"><div class="card-h"><h2>MITRE ATT&amp;CK tactics seen</h2><span class="sub">24h</span></div>
        <div class="card-b">${s.tactics.length ? s.tactics.map((t) => `<div class="hbar"><span>${esc(t.tactic || "Unmapped")}</span><div class="track"><div class="fill" style="width:${(t.n / maxTac) * 100}%"></div></div><span class="num">${t.n}</span></div>`).join("") : `<div class="muted">Nothing yet.</div>`}</div></div>
    </div>
    <div class="grid g2">
      <div class="card"><div class="card-h"><h2>Sensors</h2><span class="sub">pipeline queue ${s.pipeline.queue} · dropped ${s.pipeline.dropped}</span></div>
        <div class="card-b flush">${s.collectors.map(collectorRow).join("")}</div></div>
      <div class="card"><div class="card-h"><h2>Host health</h2></div>
        <div class="card-b"><dl class="kv">
          <dt>Hostname</dt><dd>${esc(s.host.hostname)}</dd><dt>Operating system</dt><dd>${esc(s.host.os)}</dd>
          <dt>CPU / memory</dt><dd>${s.host.cpu_percent}% / ${s.host.mem_percent}%</dd><dt>Processes</dt><dd>${s.host.processes}</dd>
          <dt>Agent memory</dt><dd>${s.host.agent_mem_mb} MB</dd><dt>Detection rules</dt><dd>${s.rules.enabled} of ${s.rules.total} enabled + 4 behaviours</dd>
          <dt>Threat intel</dt><dd>${s.intel.bad_hashes} hashes, ${s.intel.bad_ips} IPs · VirusTotal ${s.intel.virustotal ? "on" : "off"}</dd>
          <dt>Last event</dt><dd>${ago(s.pipeline.last_event)}</dd></dl></div></div>
    </div>`;
  view.querySelectorAll("[data-sev]").forEach((b) => b.onclick = () => { state.alertFilter = { status: "open", severity: b.dataset.sev }; location.hash = "#alerts"; });
  bindAlertRows();
}

function collectorRow(c) {
  const cls = c.status === "running" ? "ok" : c.status === "error" ? "bad" : "warn";
  return `<div class="collector"><b>${esc(c.name)}</b><span class="pill ${cls}">${esc(c.status)}</span><span class="muted trunc" title="${esc(c.detail)}">${esc(c.detail || `every ${c.interval}s`)}</span><span class="num">${c.events}</span></div>`;
}

function alertEntity(a) {
  const e = a.entities || {};
  return e.process ? `${e.process}${e.pid ? ` (pid ${e.pid})` : ""}` : e.file || e.ip || (e.autostart ? `${e.autostart} → ${e.autostart_runs || ""}` : "") || e.threat || e.source_ip || e.user || "";
}
function alertRow(a) {
  return `<div class="list-row" data-alert="${a.id}">${sev(a.severity)}<div class="grow"><div class="t">${esc(a.title)}</div><div class="s">${esc(alertEntity(a))}</div></div><span class="muted nowrap">${ago(a.ts)}</span></div>`;
}
function bindAlertRows() {
  view.querySelectorAll("[data-alert]").forEach((r) => r.onclick = () => openAlert(r.dataset.alert));
}

/* ---------- alerts ---------- */
async function renderAlerts() {
  const f = state.alertFilter;
  const rows = await api(`/api/alerts?status=${f.status}&severity=${f.severity}`);
  const chip = (group, val, label) => `<button class="chip" data-g="${group}" data-v="${val}" aria-pressed="${f[group] === val}">${label}</button>`;
  view.innerHTML = `
    <div class="toolbar">
      ${chip("status", "open", "Open")}${chip("status", "investigating", "Investigating")}${chip("status", "resolved", "Resolved")}${chip("status", "false_positive", "False positive")}${chip("status", "", "All")}
      <span class="muted" style="margin:0 6px">|</span>
      ${chip("severity", "", "Any severity")}${chip("severity", "critical", "Critical")}${chip("severity", "high", "High")}${chip("severity", "medium", "Medium")}${chip("severity", "low", "Low")}
    </div>
    <div class="card"><div class="table-wrap">${rows.length ? `
      <table><thead><tr><th>Time</th><th>Severity</th><th>Alert</th><th>Entity</th><th>MITRE</th><th>Status</th></tr></thead><tbody>
      ${rows.map((a) => `<tr class="row-click" data-alert="${a.id}"><td class="nowrap muted">${fmtTime(a.ts)}</td><td>${sev(a.severity)}</td>
        <td><b>${esc(a.title)}</b><div class="muted mono">${esc(a.rule_id)}</div></td><td class="trunc mono">${esc(alertEntity(a))}</td>
        <td class="nowrap"><span class="pill accent">${esc(a.technique || "-")}</span><div class="muted">${esc(a.tactic || "")}</div></td><td><span class="pill">${esc(a.status.replace("_", " "))}</span></td></tr>`).join("")}
      </tbody></table>` : `<div class="empty"><b>No alerts match these filters</b>That is good news.</div>`}</div></div>`;
  view.querySelectorAll("[data-g]").forEach((b) => b.onclick = () => { state.alertFilter[b.dataset.g] = b.dataset.v; refresh(); });
  bindAlertRows();
}

async function openAlert(id) {
  const d = await api(`/api/alerts/${id}`);
  const a = d.alert, e = a.entities || {};
  const ev = d.event ? d.event.data : null;
  const acts = [];
  if (e.pid) acts.push(actionButton("kill", e.pid, a.id, "btn danger"), actionButton("suspend", e.pid, a.id));
  const file = e.file || e.executable;
  if (file) acts.push(actionButton("quarantine", file, a.id));
  if (e.ip) acts.push(actionButton("block_ip", e.ip, a.id));
  else if (e.source_ip && e.source_ip !== "-" && e.source_ip !== "127.0.0.1") acts.push(actionButton("block_ip", e.source_ip, a.id));
  if (a.severity === "critical") acts.push(actionButton("isolate", "host", a.id, "btn ghost-danger"));
  const labels = { pid: "Process ID", process: "Process", executable: "Executable", command_line: "Command line", parent: "Parent process",
    file: "File", sha256: "SHA-256", ip: "Remote IP", port: "Remote port", user: "User", source_ip: "Source IP",
    autostart: "Autostart entry", autostart_runs: "It runs", autostart_type: "Autostart type", group: "Group", threat: "Threat name" };
  $("#drawer-body").innerHTML = `
    <div class="meta">${sev(a.severity)}<span class="mono">${esc(a.rule_id)}</span><span>· ${fmtTime(a.ts)}</span></div>
    <h2 id="drawer-title">${esc(a.title)}</h2>
    <div class="meta">MITRE ATT&amp;CK: <span class="pill">${esc(a.tactic || "-")}</span>
      <a class="ext" href="${mitreUrl(a.technique)}" target="_blank" rel="noopener">${esc(a.technique || "")} ${esc(a.technique_name || "")}</a></div>
    <div class="section"><h3>What happened</h3><div class="callout">${esc(a.description)}</div></div>
    <div class="section"><h3>What to do</h3><div class="callout advice">${esc(a.advice || "Review the details below.")}</div></div>
    <div class="section"><h3>Respond</h3><div class="actions-row">${acts.join("") || '<span class="muted">No direct action for this alert type.</span>'}</div></div>
    <div class="section"><h3>Status</h3>
      <select class="status-select" id="alert-status">${["open", "investigating", "resolved", "false_positive"].map((s) => `<option value="${s}" ${a.status === s ? "selected" : ""}>${s.replace("_", " ")}</option>`).join("")}</select></div>
    <div class="section"><h3>Entities</h3><dl class="kv">${Object.entries(e).map(([k, v]) => `<dt>${esc(labels[k] || k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl></div>
    ${d.virustotal ? `<div class="section"><h3>VirusTotal</h3><div class="callout">${d.virustotal.found ? `${d.virustotal.malicious} of ${d.virustotal.total} engines flag this file.` : "Hash not known to VirusTotal."} <a class="ext" target="_blank" rel="noopener" href="https://www.virustotal.com/gui/file/${esc(e.sha256)}">Open report</a></div></div>` : ""}
    ${d.related.length > 1 ? `<div class="section"><h3>Other activity by this process</h3><div class="card"><table><tbody>${d.related.map((r) => `<tr><td class="nowrap muted">${fmtTime(r.ts)}</td><td><span class="pill">${esc(r.category)}</span></td><td class="mono">${esc(r.summary)}</td></tr>`).join("")}</tbody></table></div></div>` : ""}
    ${d.actions.length ? `<div class="section"><h3>Actions taken</h3>${d.actions.map((x) => `<div class="muted">${fmtTime(x.ts)} · ${esc(x.action)} · ${x.ok ? "done" : "failed"}: ${esc(x.detail)}</div>`).join("")}</div>` : ""}
    <div class="section"><details><summary>Show the raw event (what the sensor recorded)</summary><pre class="json">${esc(JSON.stringify(ev, null, 2))}</pre></details></div>
    ${d.rule ? `<div class="section"><details><summary>Show the detection logic</summary><pre class="json">${esc(JSON.stringify(d.rule.match, null, 2))}</pre></details></div>` : ""}`;
  $("#alert-status").onchange = async (x) => { await post(`/api/alerts/${a.id}/status`, { status: x.target.value }); toast("Status updated"); refresh(); };
  openDrawer();
}

function openDrawer() { $("#drawer").hidden = false; $(".drawer-close").focus(); }
function closeDrawer() { $("#drawer").hidden = true; }
$("#drawer").addEventListener("click", (e) => { if (e.target.closest("[data-close]")) closeDrawer(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") { if (!$("#modal").hidden) $("#modal-cancel").click(); else closeDrawer(); } });

/* ---------- process tree ---------- */
async function renderProcesses(first) {
  const procs = await api("/api/processes");
  const byPid = new Map(procs.map((p) => [p.pid, p]));
  const kids = new Map();
  procs.forEach((p) => { const parent = byPid.has(p.ppid) && p.ppid !== p.pid ? p.ppid : 0; if (!kids.has(parent)) kids.set(parent, []); kids.get(parent).push(p); });
  kids.forEach((list) => list.sort((a, b) => a.name.localeCompare(b.name)));
  const q = state.tree.q.toLowerCase();
  // PID 0 and recycled PIDs can make a parent look like its own descendant; guard every walk.
  const childrenOf = (pid) => (kids.get(pid) || []).filter((c) => c.pid !== pid);
  if (first && !q && state.tree.expanded.size === 0) childrenOf(0).forEach((p) => state.tree.expanded.add(p.pid));
  const matchesQ = (p) => !q || p.name.toLowerCase().includes(q) || String(p.pid) === q || p.cmdline.toLowerCase().includes(q);
  const visible = (p, seen = new Set()) => { if (seen.has(p.pid)) return false; seen.add(p.pid); return matchesQ(p) || childrenOf(p.pid).some((c) => visible(c, seen)); };
  const rows = [];
  const drawn = new Set();
  const walk = (pid, depth) => childrenOf(pid).forEach((p) => {
    if (drawn.has(p.pid) || !visible(p)) return;
    drawn.add(p.pid);
    const has = childrenOf(p.pid).length;
    const open = q ? true : state.tree.expanded.has(p.pid);
    rows.push(`<div class="tree-row ${p.alerts ? "flag" : ""} ${state.tree.selected === p.pid ? "sel" : ""}" data-pid="${p.pid}">
      <span class="pname" style="padding-left:${depth * 18}px"><button class="twisty ${has ? "" : "none"}" data-tw="${p.pid}" aria-label="${open ? "Collapse" : "Expand"}">${open ? "▾" : "▸"}</button>
      <span class="n">${esc(p.name)}</span>${p.alerts ? `<span class="sev high">${p.alerts} alert${p.alerts > 1 ? "s" : ""}</span>` : ""}</span>
      <span class="num muted">${p.pid}</span><span class="num muted">${p.mem_mb} MB</span><span class="num muted">${p.cpu.toFixed(1)}%</span><span class="muted trunc">${esc(p.user)}</span></div>`);
    if (has && open && depth < 40) walk(p.pid, depth + 1);
  });
  walk(0, 0);
  const sel = byPid.get(state.tree.selected);
  view.innerHTML = `
    <div class="toolbar"><input class="search" id="tree-q" placeholder="Search by name, PID or command line" value="${esc(state.tree.q)}">
      <button class="btn" id="tree-expand">Expand all</button><button class="btn" id="tree-collapse">Collapse all</button>
      <span class="muted">${procs.length} processes · red = has open alerts</span></div>
    <div class="grid g21">
      <div class="card"><div class="tree-row" style="cursor:default;background:var(--surface-2);font-weight:650;font-size:11.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)"><span>Process</span><span class="num">PID</span><span class="num">Memory</span><span class="num">CPU</span><span>User</span></div>
        <div class="tree table-wrap">${rows.join("") || '<div class="empty">No matching process.</div>'}</div></div>
      <div class="card"><div class="card-h"><h2>${sel ? esc(sel.name) : "Select a process"}</h2></div>
        <div class="card-b">${sel ? `<dl class="kv"><dt>PID</dt><dd>${sel.pid}</dd><dt>Parent</dt><dd>${esc((byPid.get(sel.ppid) || {}).name || "?")} (${sel.ppid})</dd>
          <dt>User</dt><dd>${esc(sel.user || "-")}</dd><dt>Started</dt><dd>${sel.started ? new Date(sel.started * 1000).toLocaleString() : "-"}</dd>
          <dt>Executable</dt><dd>${esc(sel.exe || "access denied")}</dd><dt>Command line</dt><dd>${esc(sel.cmdline || "-")}</dd></dl>
          <div class="actions-row" style="margin-top:16px">${actionButton("kill", sel.pid, "", "btn danger")}${actionButton("suspend", sel.pid)}${actionButton("resume", sel.pid)}${sel.exe ? actionButton("quarantine", sel.exe) : ""}</div>`
          : `<p class="muted">Click any process to see its path, command line and parent, and to stop or freeze it.</p><p class="muted">Reading a process tree is a core analyst skill: malware usually shows up as an odd parent-child pair, such as <code>winword.exe → powershell.exe</code>.</p>`}</div></div>
    </div>`;
  const qi = $("#tree-q");
  qi.oninput = () => { state.tree.q = qi.value; clearTimeout(state.qt); state.qt = setTimeout(() => refresh(), 250); };
  if (document.activeElement !== qi && state.tree.focusSearch) { qi.focus(); qi.setSelectionRange(qi.value.length, qi.value.length); }
  qi.onfocus = () => state.tree.focusSearch = true; qi.onblur = () => state.tree.focusSearch = false;
  $("#tree-expand").onclick = () => { procs.forEach((p) => state.tree.expanded.add(p.pid)); refresh(); };
  $("#tree-collapse").onclick = () => { state.tree.expanded.clear(); refresh(); };
  view.querySelectorAll("[data-tw]").forEach((b) => b.onclick = (e) => { e.stopPropagation(); const pid = +b.dataset.tw; state.tree.expanded.has(pid) ? state.tree.expanded.delete(pid) : state.tree.expanded.add(pid); refresh(); });
  view.querySelectorAll("[data-pid]").forEach((r) => r.onclick = () => { state.tree.selected = +r.dataset.pid; refresh(); });
}

/* ---------- timeline ---------- */
async function renderTimeline() {
  const f = state.timelineFilter;
  const rows = await api(`/api/events?category=${encodeURIComponent(f.category)}&q=${encodeURIComponent(f.q)}&limit=400`);
  const cats = ["", "process", "network", "file", "persistence", "auth", "system", "av"];
  view.innerHTML = `
    <div class="toolbar">${cats.map((c) => `<button class="chip" data-cat="${c}" aria-pressed="${f.category === c}">${c || "All"}</button>`).join("")}
      <input class="search" id="tl-q" placeholder="Search events (e.g. powershell, 4625, Downloads)" value="${esc(f.q)}"></div>
    <div class="card"><div class="table-wrap">${rows.length ? `<table><thead><tr><th>Time</th><th>Type</th><th>Source</th><th>What happened</th></tr></thead><tbody>
      ${rows.map((r) => `<tr class="row-click" data-ev="${r.id}"><td class="nowrap muted">${fmtTime(r.ts)}</td><td class="nowrap"><span class="pill">${esc(r.category)}</span> <span class="muted">${esc(r.action)}</span></td>
        <td class="muted">${esc(r.source || "")}</td><td class="mono trunc" style="max-width:720px">${esc(r.summary)}</td></tr>`).join("")}</tbody></table>`
      : `<div class="empty"><b>No events yet</b>Open an app, download a file or run a command and it will appear here within seconds.</div>`}</div></div>`;
  view.querySelectorAll("[data-cat]").forEach((b) => b.onclick = () => { f.category = b.dataset.cat; refresh(); });
  const qi = $("#tl-q");
  qi.onkeydown = (e) => { if (e.key === "Enter") { f.q = qi.value; refresh(); } };
  const byId = new Map(rows.map((r) => [String(r.id), r]));
  view.querySelectorAll("[data-ev]").forEach((r) => r.onclick = () => {
    const x = byId.get(r.dataset.ev);
    $("#drawer-body").innerHTML = `<div class="meta"><span class="pill">${esc(x.category)}</span><span>${esc(x.action)}</span><span>· ${fmtTime(x.ts)} · from ${esc(x.source)}</span></div>
      <h2 id="drawer-title">Event #${x.id}</h2><div class="callout mono">${esc(x.summary)}</div>
      <div class="section"><h3>All fields (normalised)</h3><pre class="json">${esc(JSON.stringify(x.data, null, 2))}</pre></div>
      <div class="section prose muted"><p>Every sensor writes the same field names (process.name, destination.ip, file.path...). That is <b>normalisation</b>: it lets one rule work on events from any source, the same idea as Microsoft Sentinel's ASIM or Elastic's ECS.</p></div>`;
    openDrawer();
  });
}

/* ---------- network ---------- */
async function renderNetwork() {
  const rows = await api("/api/network");
  rows.sort((a, b) => (b.public - a.public) || a.process.localeCompare(b.process));
  view.innerHTML = `<div class="toolbar"><span class="muted">${rows.length} connections · ${rows.filter((r) => r.public).length} to public addresses</span></div>
    <div class="card"><div class="table-wrap">${rows.length ? `<table><thead><tr><th>Process</th><th>PID</th><th>Local</th><th>Remote</th><th>State</th><th></th></tr></thead><tbody>
    ${rows.map((r) => `<tr><td><b>${esc(r.process)}</b></td><td class="num muted">${r.pid ?? "-"}</td><td class="mono muted">${esc(r.local)}</td>
      <td class="mono">${esc(r.remote_ip)}:${r.remote_port} ${r.public ? '<span class="pill accent">public</span>' : '<span class="pill">private</span>'}</td>
      <td class="muted">${esc(r.state)}</td><td class="nowrap">${r.public ? actionButton("block_ip", r.remote_ip) : ""} ${r.public ? `<a class="ext" target="_blank" rel="noopener" href="https://www.abuseipdb.com/check/${esc(r.remote_ip)}">Reputation</a>` : ""}</td></tr>`).join("")}
    </tbody></table>` : `<div class="empty"><b>No connections visible</b>Run Vigil as Administrator to see every process's connections.</div>`}</div></div>`;
}

/* ---------- persistence ---------- */
async function renderPersistence() {
  if (!state.summary.windows) { view.innerHTML = `<div class="card"><div class="empty"><b>Windows only</b>Autostart locations are a Windows concept.</div></div>`; return; }
  const items = await api("/api/persistence");
  const groups = { registry_run: "Registry Run keys (T1547.001)", startup_folder: "Startup folders (T1547.001)", scheduled_task: "Scheduled tasks, non-Microsoft (T1053.005)", service: "Services (T1543.003)" };
  view.innerHTML = `<div class="prose muted">Everything set to start automatically on this computer. Malware almost always adds itself to one of these so it survives a reboot. Vigil checks them every 30 seconds and raises an alert when something new appears.</div>` +
    Object.entries(groups).map(([type, title]) => {
      const rows = items.filter((i) => i["persistence.type"] === type);
      return `<div class="card"><div class="card-h"><h2>${title}</h2><span class="sub">${rows.length}</span></div><div class="table-wrap" style="max-height:360px">
        <table><thead><tr><th>Name</th><th>Runs</th><th>Location</th></tr></thead><tbody>${rows.map((r) => `<tr><td><b>${esc(r["persistence.name"])}</b></td><td class="mono trunc" title="${esc(r["persistence.value"])}">${esc(r["persistence.value"])}</td><td class="muted trunc">${esc(r["persistence.location"])}</td></tr>`).join("") || `<tr><td colspan="3" class="muted">None</td></tr>`}</tbody></table></div></div>`;
    }).join("");
}

/* ---------- rules ---------- */
async function renderRules() {
  const rules = await api("/api/rules");
  view.innerHTML = `<div class="toolbar"><span class="muted">${rules.length} detections. Single-event rules live in <code>vigil/detection/rules.json</code>; multi-event behaviours in <code>behaviours.py</code>.</span>
    <button class="btn" id="reload-rules">Reload rules and IOC lists</button></div>
    <div class="card"><div class="table-wrap"><table><thead><tr><th>ID</th><th>Detection</th><th>Severity</th><th>MITRE</th><th>Watches</th><th class="num">Hits</th><th>On</th></tr></thead><tbody>
    ${rules.map((r) => `<tr class="row-click" data-rule="${esc(r.id)}"><td class="mono nowrap">${esc(r.id)}</td><td><b>${esc(r.title)}</b>
      ${state.rulesOpen.has(r.id) ? `<div class="muted" style="margin-top:6px">${esc(r.description)}</div>${r.match ? `<pre class="json" style="margin-top:8px">${esc(JSON.stringify(r.match, null, 2))}</pre>` : ""}` : ""}</td>
      <td>${sev(r.severity)}</td><td class="nowrap"><a class="ext" href="${mitreUrl(r.mitre.technique)}" target="_blank" rel="noopener">${esc(r.mitre.technique)}</a><div class="muted">${esc(r.mitre.tactic)}</div></td>
      <td class="muted">${esc(r.category || "any")}</td><td class="num">${r.hits}</td>
      <td>${r.kind === "rule" ? `<input type="checkbox" aria-label="Enable ${esc(r.id)}" data-toggle="${esc(r.id)}" ${r.enabled ? "checked" : ""}>` : '<span class="muted">always</span>'}</td></tr>`).join("")}
    </tbody></table></div></div>`;
  $("#reload-rules").onclick = async () => { const r = await post("/api/rules/reload"); toast(r.detail, !r.ok); refresh(); };
  view.querySelectorAll("[data-toggle]").forEach((c) => { c.onclick = (e) => e.stopPropagation(); c.onchange = async () => { const r = await post(`/api/rules/${c.dataset.toggle}/toggle`); toast(`${c.dataset.toggle} ${r.enabled ? "enabled" : "disabled"} until restart`); }; });
  view.querySelectorAll("[data-rule]").forEach((row) => row.onclick = () => { const id = row.dataset.rule; state.rulesOpen.has(id) ? state.rulesOpen.delete(id) : state.rulesOpen.add(id); refresh(); });
}

/* ---------- response ---------- */
async function renderResponse() {
  const r = await api("/api/response");
  view.innerHTML = `
    ${!r.admin ? `<div class="callout">Vigil is running without Administrator rights. Killing your own processes and quarantining files work; firewall blocks and host isolation need Vigil restarted as Administrator.</div>` : ""}
    ${!r.enabled ? `<div class="callout">Response actions are turned off in config.json.</div>` : ""}
    <div class="grid g2">
      <div class="card"><div class="card-h"><h2>Network containment</h2></div><div class="card-b">
        <p class="muted" style="margin-top:0">Isolation switches every Windows Firewall profile to block traffic by default, cutting this machine off while you investigate. This dashboard keeps working because it is local.</p>
        <div class="actions-row">${actionButton("isolate", "host", "", "btn danger")}${actionButton("unisolate", "host")}</div></div></div>
      <div class="card"><div class="card-h"><h2>Blocked IP addresses</h2><span class="sub">${r.blocked_ips.length}</span></div><div class="card-b flush">
        ${r.blocked_ips.length ? `<table><tbody>${r.blocked_ips.map((ip) => `<tr><td class="mono">${esc(ip)}</td><td style="text-align:right">${actionButton("unblock_ip", ip)}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">No IPs blocked by Vigil.</div>`}</div></div>
    </div>
    <div class="card"><div class="card-h"><h2>Quarantine</h2><span class="sub">files are moved to data/quarantine and renamed so they cannot run</span></div><div class="card-b flush">
      ${r.quarantine.length ? `<table><thead><tr><th>When</th><th>Original location</th><th>SHA-256</th><th></th></tr></thead><tbody>${r.quarantine.map((q) => `<tr><td class="nowrap muted">${fmtTime(q.ts)}</td><td class="mono">${esc(q.original_path)}</td><td class="mono muted">${esc((q.sha256 || "").slice(0, 16))}...</td><td style="text-align:right">${q.restored ? '<span class="pill">restored</span>' : actionButton("restore", q.id)}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">Quarantine is empty.</div>`}</div></div>
    <div class="card"><div class="card-h"><h2>Action log</h2><span class="sub">every response attempt, for audit</span></div><div class="table-wrap" style="max-height:420px">
      ${r.actions.length ? `<table><thead><tr><th>When</th><th>Action</th><th>Target</th><th>Result</th></tr></thead><tbody>${r.actions.map((x) => `<tr><td class="nowrap muted">${fmtTime(x.ts)}</td><td><b>${esc(x.action)}</b></td><td class="mono">${esc(x.target)}</td><td>${x.ok ? '<span class="pill ok">done</span>' : '<span class="pill bad">failed</span>'} <span class="muted">${esc(x.detail)}</span></td></tr>`).join("")}</tbody></table>` : `<div class="empty">No actions yet.</div>`}</div></div>`;
}

/* ---------- how it works ---------- */
async function renderHow() {
  const s = state.summary;
  const col = (n) => (s.collectors.find((c) => c.name === n) || {});
  view.innerHTML = `
    <div class="prose"><p>Every EDR, from Microsoft Defender for Endpoint to CrowdStrike, follows the same five steps. Here they are in Vigil, with live numbers from this machine.</p></div>
    <div class="pipe">
      <div class="stage"><span class="n">01 · COLLECT</span><h4>Sensors</h4><p>Five collectors watch processes, network, files, autostarts and Windows event logs.</p><div class="stat">${s.collectors.reduce((a, c) => a + c.events, 0).toLocaleString()}</div><span class="muted">events seen</span></div>
      <div class="stage"><span class="n">02 · NORMALISE</span><h4>Common fields</h4><p>Each event is reshaped into the same field names, so rules work on any source.</p><div class="stat">${s.pipeline.queue}</div><span class="muted">waiting in queue</span></div>
      <div class="stage"><span class="n">03 · ENRICH</span><h4>Threat intel</h4><p>Hashes and IPs are checked against your IOC lists${s.intel.virustotal ? " and VirusTotal" : ""}.</p><div class="stat">${s.intel.bad_hashes + s.intel.bad_ips}</div><span class="muted">indicators loaded</span></div>
      <div class="stage"><span class="n">04 · DETECT</span><h4>Rules + behaviours</h4><p>${s.rules.enabled} single-event rules and 4 multi-event behaviours, mapped to MITRE ATT&amp;CK.</p><div class="stat">${s.pipeline.alerts}</div><span class="muted">alerts raised</span></div>
      <div class="stage"><span class="n">05 · RESPOND</span><h4>Contain</h4><p>Kill or suspend a process, quarantine a file, block an IP, isolate the host.</p><div class="stat">${s.response_enabled ? "On" : "Off"}</div><span class="muted">response actions</span></div>
    </div>
    <div class="grid g2">
      <div class="card"><div class="card-h"><h2>Where each signal comes from</h2></div><div class="card-b flush"><table><tbody>
        <tr><td><b>Processes</b></td><td class="muted">${col("eventlog").detail?.includes("Sysmon") ? "Sysmon event 1 (catches even short-lived processes)" : "psutil polling every second (install Sysmon to catch very short-lived processes)"}</td></tr>
        <tr><td><b>Network</b></td><td class="muted">psutil connection table, linked to the owning process</td></tr>
        <tr><td><b>Files</b></td><td class="muted">Downloads, Desktop, Temp, Startup and Public folders</td></tr>
        <tr><td><b>Persistence</b></td><td class="muted">Run keys, Startup folders, scheduled tasks, services</td></tr>
        <tr><td><b>Event logs</b></td><td class="muted">Security 4625/4720/4732/1102, System 7045/104, Defender 1116/5001${s.host.admin ? "" : " (Security needs Administrator)"}</td></tr>
      </tbody></table></div></div>
      <div class="card"><div class="card-h"><h2>Try it safely</h2></div><div class="card-b prose">
        <p>Open a second terminal in the Vigil folder and run:</p><p><code>python tools/simulate.py</code></p>
        <p class="muted">It runs harmless commands that look like attacker behaviour (an encoded PowerShell command, reconnaissance commands, a fake <code>invoice.pdf.exe</code>, a test Run key) and cleans up after itself. Watch the alerts arrive, then open one and follow the evidence.</p>
        <p class="muted">The full walkthrough is in <code>LEARN.md</code>.</p></div></div>
    </div>`;
}

go();

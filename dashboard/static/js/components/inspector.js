/**
 * Details panel on the right (alert / session / attacker / campaign / family).
 * Every tab starts with a plain-language summary; raw data is one tab away.
 * Credentials are always shown apart from raw_data.
 */

import { api } from "../core/api.js";
import {
  agoCell,
  asList,
  badgeProtocol,
  badgeSeverity,
  badgeTag,
  classifyCommand,
  copyText,
  escapeHtml,
  fmtLocal,
  fmtNum,
  renderStagePips,
  shortId,
  stageLabel,
  timeAgo,
} from "../core/escape.js";
import { store } from "../core/store.js";

let maskPasswords = false;
let attackerRequest = 0;

function maskVal(val) {
  if (!val) return "(empty)";
  return maskPasswords ? "•".repeat(Math.min(10, String(val).length)) : String(val);
}

function plural(n, one, many) {
  return `${fmtNum(n)} ${n === 1 ? one : many}`;
}

export async function inspectAttacker(ip) {
  if (!ip) return;
  const req = ++attackerRequest;
  store.openInspector("attacker", { ip }, "summary", true);
  try {
    const detail = await api.getAttackerDetail(ip, false);
    if (req !== attackerRequest) return; // user already clicked another IP
    store.openInspector("attacker", detail, "summary", false);
  } catch (err) {
    if (req !== attackerRequest || (err && err.name === "AbortError")) return;
    store.openInspector("attacker", { ip, error: err.message || "Could not load this IP" }, "summary", false);
  }
}

export function initInspectorResizer() {
  const resizer = document.getElementById("inspector-resizer");
  const pane = document.getElementById("inspector-pane");
  if (!resizer || !pane) return;

  let dragging = false;
  resizer.addEventListener("mousedown", (ev) => {
    dragging = true;
    resizer.classList.add("dragging");
    document.body.style.userSelect = "none";
    ev.preventDefault();
  });

  window.addEventListener("mousemove", (ev) => {
    if (!dragging) return;
    const nextW = Math.max(340, Math.min(window.innerWidth * 0.65, window.innerWidth - ev.clientX));
    pane.style.width = `${Math.round(nextW)}px`;
    pane.style.flexBasis = `${Math.round(nextW)}px`;
  });

  window.addEventListener("mouseup", () => {
    if (!dragging) return;
    dragging = false;
    resizer.classList.remove("dragging");
    document.body.style.userSelect = "";
  });
}

function kv(rows) {
  return `<div class="kv-grid">${rows
    .filter(Boolean)
    .map(([k, v]) => `<div class="kv-k">${escapeHtml(k)}</div><div class="kv-v">${v}</div>`)
    .join("")}</div>`;
}

function rawTab(obj) {
  const json = JSON.stringify(obj, null, 2);
  return `
    <div class="btn-group"><button class="btn sm" data-copy="${escapeHtml(json)}">Copy JSON</button></div>
    <pre class="code-block tall">${escapeHtml(json)}</pre>
  `;
}

function credentialsBlock(creds, protocol) {
  if (!creds) return "";
  const ok = Boolean(creds.success);
  return `
    <div class="creds-box ${ok ? "success" : ""}">
      <div class="creds-head">
        <span>Login attempt over ${escapeHtml(protocol || "the network")}</span>
        <div class="btn-group">
          <button class="btn sm ghost" data-action="toggle-mask">${maskPasswords ? "Show password" : "Hide password"}</button>
          <button class="btn sm" data-copy="${escapeHtml(`${creds.username}:${creds.password}`)}">Copy</button>
        </div>
      </div>
      <div class="creds-pair">
        <span class="cell-muted">Username</span><span class="mono">${escapeHtml(creds.username || "(empty)")}</span>
        <span class="cell-muted">Password</span><span class="mono">${escapeHtml(maskVal(creds.password))}</span>
        <span class="cell-muted">Result</span><span>${ok ? '<span class="badge sev-CRITICAL">Accepted</span>' : '<span class="badge sev-NONE">Rejected</span>'}</span>
      </div>
    </div>`;
}

function ipLink(ip) {
  return `<span class="ip-link" data-inspect-ip="${escapeHtml(ip)}">${escapeHtml(ip)}</span>`;
}

/* ---------- Alert ---------- */

function alertBody(al, tab) {
  const pd = al.payload_details || {};
  if (tab === "raw") return rawTab(al);

  if (tab === "payload") {
    return `
      ${credentialsBlock(al.credentials, al.protocol)}
      ${kv([
        ["Command", pd.command ? `<span class="mono">${escapeHtml(pd.command)}</span>` : "—"],
        ["HTTP request", pd.http_path ? `<span class="mono">${escapeHtml(`${pd.http_method || ""} ${pd.http_path}`)}</span>` : "—"],
        ["User agent", escapeHtml(pd.http_user_agent || "—")],
        ["Download URL", pd.extracted_url ? `<span class="mono">${escapeHtml(pd.extracted_url)}</span>` : "—"],
      ])}
      <div class="section-title">Raw data</div>
      <pre class="code-block">${escapeHtml(pd.raw_data || "(nothing captured)")}</pre>
    `;
  }

  const geo = al.geo ? [al.geo.country, al.geo.city].filter(Boolean).join(", ") : "";
  return `
    <div class="summary-box ${al.severity === "CRITICAL" ? "crit" : ""}">
      <span class="headline">${escapeHtml(al.alert_reason || "Alert")}</span>
      From ${ipLink(al.source_ip)} over ${escapeHtml(al.protocol)}, ${escapeHtml(timeAgo(al.timestamp))}.
    </div>

    <div class="badge-row">
      ${badgeSeverity(al.severity)}
      ${badgeProtocol(al.protocol)}
      <span class="badge">Score ${fmtNum(al.score)}</span>
      ${al.technique ? `<span class="badge" title="${escapeHtml(al.technique_name)}">${escapeHtml(al.technique)}</span>` : ""}
      ${asList(al.tags).map(badgeTag).join("")}
    </div>

    ${credentialsBlock(al.credentials, al.protocol)}

    ${
      pd.command
        ? `<div class="term-box">
            <div class="term-head"><span>Command typed</span><button class="btn sm" data-copy="${escapeHtml(pd.command)}">Copy</button></div>
            <div class="term-body">
              <div class="term-line flag-${classifyCommand(pd.command)}">
                <span class="term-idx">$</span><span class="term-cmd">${escapeHtml(pd.command)}</span>
              </div>
            </div>
          </div>`
        : ""
    }

    ${al.recommendation ? `<div class="section-title">What to do</div><div>${escapeHtml(al.recommendation)}</div>` : ""}

    <div class="section-title">Details</div>
    ${kv([
      ["When", escapeHtml(fmtLocal(al.timestamp))],
      ["Source", `${ipLink(al.source_ip)}${al.source_port ? `<span class="cell-muted">:${escapeHtml(al.source_port)}</span>` : ""}`],
      ["Target port", escapeHtml(al.target_port ?? "—")],
      ["Session", al.session_id ? `<span class="ip-link mono" data-filter-query="sid:${escapeHtml(al.session_id)}" data-filter-view="sessions">${escapeHtml(shortId(al.session_id, 16))}</span>` : "—"],
      al.technique ? ["MITRE", `${escapeHtml(al.technique)} · ${escapeHtml(al.technique_name || "")}${al.tactic ? ` <span class="cell-muted">(${escapeHtml(al.tactic)})</span>` : ""}`] : null,
      geo ? ["Location", escapeHtml(geo)] : null,
    ])}

    <div class="btn-group">
      <button class="btn sm" data-filter-query="ip:${escapeHtml(al.source_ip)}" data-filter-view="alerts">All alerts from this IP</button>
    </div>
  `;
}

/* ---------- Session ---------- */

function sessionStory(s) {
  const parts = [`${ipLink(s.source_ip)} connected over ${escapeHtml(s.protocol)}`];
  if (s.protocol === "HTTP") {
    const n = asList(s.http_requests).length;
    if (n) parts.push(`sent ${plural(n, "flagged request", "flagged requests")}`);
  } else {
    if (s.login_attempts) parts.push(`tried ${plural(s.login_attempts, "password", "passwords")}`);
    if (s.successful_login) parts.push(`<strong>logged in as ${escapeHtml(s.successful_login)}</strong>`);
    const cmds = asList(s.commands).length;
    if (cmds) parts.push(`ran ${plural(cmds, "command", "commands")}`);
    const dl = asList(s.downloads).length;
    if (dl) parts.push(`<strong>tried to download ${plural(dl, "file", "files")}</strong>`);
  }
  if (s.honeytoken_hit) parts.push(`<strong>read a decoy secret</strong>`);
  const last = parts.pop();
  return parts.length ? `${parts.join(", ")} and ${last}.` : `${last}.`;
}

function sessionBody(s, tab) {
  if (tab === "raw") return rawTab(s);

  if (tab === "replay") {
    if (s.protocol === "HTTP") {
      const reqs = asList(s.http_requests);
      if (!reqs.length) return `<div class="empty-state">No flagged HTTP requests for this connection.</div>`;
      return reqs
        .map(
          (r, i) => `
          <div class="http-req-item">
            <div class="http-req-head"><span>${i + 1}. ${escapeHtml(r.method || "GET")} ${escapeHtml(r.path || "/")}</span>${badgeSeverity(r.severity)}</div>
            <div class="cell-muted">${escapeHtml(fmtLocal(r.timestamp))}${r.user_agent ? ` · ${escapeHtml(r.user_agent)}` : ""}</div>
            <div>${escapeHtml(r.reason)}</div>
            ${credentialsBlock(r.credentials, "HTTP")}
            ${r.raw_data ? `<pre class="code-block">${escapeHtml(r.raw_data)}</pre>` : ""}
          </div>`
        )
        .join("");
    }

    const cmds = asList(s.commands);
    return `
      <div class="term-box">
        <div class="term-head">
          <span>${plural(cmds.length, "command", "commands")}</span>
          ${cmds.length ? `<button class="btn sm" data-copy="${escapeHtml(cmds.join("\n"))}">Copy all</button>` : ""}
        </div>
        <div class="term-body">
          ${s.successful_login ? `<div class="term-line"><span class="term-idx"></span><span class="term-cmd" style="color:var(--sev-critical);">Logged in as ${escapeHtml(s.successful_login)}</span></div>` : ""}
          ${
            cmds.length
              ? cmds
                  .map((cmd, idx) => {
                    const flag = classifyCommand(cmd);
                    return `<div class="term-line ${flag ? "flag-" + flag : ""}"><span class="term-idx">${idx + 1}</span><span class="term-cmd"><span class="term-prompt">#</span>${escapeHtml(cmd)}</span></div>`;
                  })
                  .join("")
              : `<div class="empty-state">No commands were typed in this session.</div>`
          }
        </div>
      </div>
      ${
        asList(s.downloads).length
          ? `<div class="section-title">Files it tried to download</div><pre class="code-block">${escapeHtml(asList(s.downloads).join("\n"))}</pre>`
          : ""
      }
      <p class="muted-note">Highlighted lines: red = decoy secret, orange = download or Mirai, yellow = crypto-miner checks.</p>
    `;
  }

  const stages = asList(s.stages);
  const related = asList(s.related_alerts);
  return `
    <div class="summary-box ${s.successful_login ? "crit" : ""}">${sessionStory(s)}</div>

    <div class="badge-row">
      ${badgeProtocol(s.protocol)}
      ${badgeSeverity(s.max_severity)}
      <span class="badge">Risk ${fmtNum(s.risk_score)}/100</span>
      ${asList(s.family_labels).map((f) => `<span class="badge">${escapeHtml(f)}</span>`).join("")}
    </div>

    ${kv([
      ["Started", escapeHtml(fmtLocal(s.start))],
      ["Ended", s.end ? escapeHtml(fmtLocal(s.end)) : '<span class="cell-muted">still open</span>'],
      ["Source", ipLink(s.source_ip)],
      ["How far", `${renderStagePips(stages)} <span class="cell-muted" style="margin-left:6px;">${escapeHtml(stages.map(stageLabel).join(" → ") || "—")}</span>`],
      ["Session ID", `<span class="mono">${escapeHtml(s.session_id)}</span>`],
    ])}

    ${
      asList(s.passwords).length
        ? `<div class="section-title" style="display:flex;justify-content:space-between;align-items:center;">
            <span>Passwords tried (${fmtNum(asList(s.passwords).length)})</span>
            <button class="btn sm ghost" data-action="toggle-mask">${maskPasswords ? "Show" : "Hide"}</button>
          </div>
          <div class="badge-row">${asList(s.passwords).slice(0, 60).map((p) => `<span class="badge mono">${escapeHtml(maskVal(p))}</span>`).join("")}</div>`
        : ""
    }

    ${
      related.length
        ? `<div class="section-title">Alerts in this session (${fmtNum(related.length)})</div>
          <div>${related
            .slice(0, 15)
            .map((a) => `<div style="display:flex;gap:8px;align-items:baseline;padding:4px 0;">${badgeSeverity(a.severity)}<span>${escapeHtml(a.alert_reason)}</span></div>`)
            .join("")}</div>`
        : ""
    }
  `;
}

/* ---------- Attacker ---------- */

function attackerBody(detail, tab, loading) {
  if (loading) return `<div class="empty-state">Loading ${escapeHtml(detail.ip)}…</div>`;
  if (detail.error) {
    return `<div class="error-panel"><h3>Could not load this IP</h3><p>${escapeHtml(detail.error)}</p></div>`;
  }
  const p = detail.profile || {};
  if (tab === "raw") return rawTab(detail);

  if (tab === "activity") {
    const cmds = asList(p.commands);
    const creds = asList(detail.credentials_seen);
    return `
      <div class="section-title" style="display:flex;justify-content:space-between;align-items:center;">
        <span>Logins tried (${fmtNum(creds.length)})</span>
        ${creds.length ? `<button class="btn sm ghost" data-action="toggle-mask">${maskPasswords ? "Show passwords" : "Hide passwords"}</button>` : ""}
      </div>
      ${
        creds.length
          ? `<table class="soc-table"><thead><tr><th>User</th><th>Password</th><th style="width:100px;">Result</th></tr></thead><tbody>
              ${creds
                .map(
                  (c) => `<tr><td class="mono">${escapeHtml(c.username)}</td><td class="mono">${escapeHtml(maskVal(c.password))}</td>
                  <td>${c.success ? '<span class="badge sev-CRITICAL">Accepted</span>' : '<span class="badge sev-NONE">Rejected</span>'}</td></tr>`
                )
                .join("")}
            </tbody></table>`
          : `<div class="muted-note">None recorded.</div>`
      }
      <div class="section-title">Commands (${fmtNum(cmds.length)})</div>
      ${cmds.length ? `<pre class="code-block">${escapeHtml(cmds.join("\n"))}</pre>` : `<div class="muted-note">None recorded.</div>`}
      ${
        asList(detail.user_agents).length
          ? `<div class="section-title">HTTP user agents</div><pre class="code-block">${escapeHtml(asList(detail.user_agents).join("\n"))}</pre>`
          : ""
      }
    `;
  }

  const okLogins = asList(p.successful_logins).length;
  const geo = p.geo ? [p.geo.country, p.geo.city].filter(Boolean).join(", ") : "";
  const story = [
    `First seen ${escapeHtml(timeAgo(p.first_seen))}, last seen ${escapeHtml(timeAgo(p.last_seen))}.`,
    `${plural(p.total_alerts || 0, "alert", "alerts")} across ${plural(p.sessions || 0, "session", "sessions")}.`,
    p.login_attempts ? `Tried ${plural(p.login_attempts, "login", "logins")}${okLogins ? `, <strong>${plural(okLogins, "succeeded", "succeeded")}</strong>` : ", none worked"}.` : "",
  ]
    .filter(Boolean)
    .join(" ");
  const stages = asList(p.stages);

  return `
    <div class="summary-box ${okLogins ? "crit" : ""}">${story}</div>

    <div class="badge-row">
      ${badgeSeverity(p.overall_severity || p.worst_severity)}
      <span class="badge">Score ${fmtNum(p.threat_score)}</span>
      ${asList(p.protocols).map(badgeProtocol).join("")}
      ${asList(detail.families).map((f) => `<span class="badge">${escapeHtml(f)}</span>`).join("")}
    </div>

    <div class="btn-group">
      <button class="btn sm primary" data-filter-query="ip:${escapeHtml(p.ip)}" data-filter-view="alerts">Show its alerts</button>
      <button class="btn sm" data-filter-query="ip:${escapeHtml(p.ip)}" data-filter-view="sessions">Show its sessions</button>
      <button class="btn sm" data-copy="${escapeHtml(p.ip)}">Copy IP</button>
    </div>

    ${kv([
      ["First seen", `${escapeHtml(fmtLocal(p.first_seen))}`],
      ["Last seen", agoCell(p.last_seen)],
      ["How far", `${renderStagePips(stages)} <span class="cell-muted" style="margin-left:6px;">${escapeHtml(stages.map(stageLabel).join(" → ") || "—")}</span>`],
      geo ? ["Location", escapeHtml(geo)] : null,
    ])}

    ${
      asList(p.recommendations).length
        ? `<div class="section-title">What to do</div>
          <ul style="margin:0;padding-left:18px;">${asList(p.recommendations).map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>`
        : ""
    }

    <div class="section-title">Block it</div>
    <pre class="code-block">iptables -I INPUT 1 -s ${escapeHtml(p.ip)} -j DROP</pre>
    <div class="btn-group"><button class="btn sm" data-copy="iptables -I INPUT 1 -s ${escapeHtml(p.ip)} -j DROP">Copy rule</button></div>
  `;
}

/* ---------- Campaign / family (from the Campaigns page or the graph) ---------- */

function groupBody(kind, g, tab) {
  if (tab === "raw") return rawTab(g);
  const ips = asList(g.ips).length ? asList(g.ips) : g.meta && g.meta.ip ? [g.meta.ip] : [];
  const reasons = asList(g.reasons).length ? asList(g.reasons) : asList(g.meta && g.meta.reasons);
  const traits = asList(g.common_behavior).length ? asList(g.common_behavior) : asList(g.meta && g.meta.traits);
  return `
    <div class="summary-box">
      ${
        kind === "campaign"
          ? `${plural(g.size || ips.length, "IP", "IPs")} working together. Linked by: ${escapeHtml(reasons.join("; ") || "shared infrastructure")}.`
          : kind === "family"
          ? `${plural(g.size || ips.length, "IP", "IPs")} that behave alike.`
          : kind === "server"
          ? `Malware server <span class="mono">${escapeHtml(g.label || "")}</span>, used by linked attackers to download files.`
          : `<span class="mono">${escapeHtml(g.label || "")}</span>`
      }
    </div>
    ${traits.length ? `<div class="section-title">Common behaviour</div><div class="badge-row">${traits.map((t) => `<span class="badge">${escapeHtml(t)}</span>`).join("")}</div>` : ""}
    ${asList(g.servers).length ? `<div class="section-title">Malware servers</div><pre class="code-block">${escapeHtml(asList(g.servers).join("\n"))}</pre>` : ""}
    ${ips.length ? `<div class="section-title">IPs (${fmtNum(ips.length)})</div><div class="chip-list">${ips.map(ipLink).join("")}</div>` : ""}
  `;
}

/* ---------- Panel ---------- */

const KINDS = {
  alert: (d) => ({
    kicker: "Alert",
    title: `${d.source_ip || "?"} · ${d.protocol || ""}`,
    tabs: [
      ["summary", "Summary"],
      ["payload", "Payload"],
      ["raw", "Raw JSON"],
    ],
  }),
  session: (d) => ({
    kicker: "Session",
    title: `${d.source_ip || "?"} · ${d.protocol || ""}`,
    tabs: [
      ["summary", "Summary"],
      ["replay", d.protocol === "HTTP" ? "Requests" : "Replay"],
      ["raw", "Raw JSON"],
    ],
  }),
  attacker: (d) => ({
    kicker: "Attacker",
    title: (d.profile && d.profile.ip) || d.ip || "?",
    tabs: [
      ["summary", "Summary"],
      ["activity", "Logins & commands"],
      ["raw", "Raw JSON"],
    ],
  }),
};

function groupMeta(kind, d) {
  const names = { campaign: "Campaign", family: "Behaviour family", server: "Malware server", ip: "IP" };
  return {
    kicker: names[kind] || "Details",
    title: d.name || d.label || "",
    tabs: [
      ["summary", "Summary"],
      ["raw", "Raw JSON"],
    ],
  };
}

function bodyFor(kind, data, tab, loading) {
  if (kind === "alert") return alertBody(data, tab);
  if (kind === "session") return sessionBody(data, tab);
  if (kind === "attacker") return attackerBody(data, tab, loading);
  return groupBody(kind, data, tab);
}

export function renderInspector() {
  const st = store.get();
  const pane = document.getElementById("inspector-pane");
  const resizer = document.getElementById("inspector-resizer");
  if (!pane || !resizer) return;

  if (!st.inspector.open || !st.inspector.data) {
    pane.classList.add("collapsed");
    resizer.classList.add("collapsed");
    return;
  }

  pane.classList.remove("collapsed");
  resizer.classList.remove("collapsed");

  const { kind, data, loading } = st.inspector;
  const meta = KINDS[kind] ? KINDS[kind](data) : groupMeta(kind, data);
  const tab = meta.tabs.some(([id]) => id === st.inspector.tab) ? st.inspector.tab : "summary";

  let body;
  try {
    body = bodyFor(kind, data, tab, loading);
  } catch (err) {
    console.error("[inspector]", err);
    body = `<div class="error-panel"><h3>Could not show these details</h3><p>Some data has an unexpected format. The Raw JSON tab still works.</p></div>`;
  }

  pane.innerHTML = `
    <div class="inspector-header">
      <div style="min-width:0;">
        <div class="inspector-kicker">${escapeHtml(meta.kicker)}</div>
        <div class="inspector-title" title="${escapeHtml(meta.title)}">${escapeHtml(meta.title)}</div>
      </div>
      <button class="btn sm ghost" data-action="close-inspector" title="Close (Esc)">Close</button>
    </div>
    <div class="inspector-tabs">
      ${meta.tabs.map(([id, label]) => `<button class="inspector-tab ${tab === id ? "active" : ""}" data-tab="${id}">${label}</button>`).join("")}
    </div>
    <div class="inspector-content">${body}</div>
  `;

  pane.querySelector('[data-action="close-inspector"]')?.addEventListener("click", () => store.closeInspector());

  pane.querySelectorAll(".inspector-tab").forEach((btn) => {
    btn.addEventListener("click", () => store.setInspectorTab(btn.dataset.tab));
  });

  pane.querySelectorAll("[data-action='toggle-mask']").forEach((btn) => {
    btn.addEventListener("click", () => {
      maskPasswords = !maskPasswords;
      renderInspector();
    });
  });

  pane.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", () => copyText(btn.dataset.copy));
  });

  pane.querySelectorAll("[data-inspect-ip]").forEach((el) => {
    el.addEventListener("click", () => inspectAttacker(el.dataset.inspectIp));
  });

  pane.querySelectorAll("[data-filter-query]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const expr = btn.dataset.filterQuery;
      if (btn.dataset.filterView) store.setView(btn.dataset.filterView);
      store.setQuery(expr);
      const qInput = document.getElementById("dsl-query-input");
      if (qInput) qInput.value = expr;
    });
  });
}

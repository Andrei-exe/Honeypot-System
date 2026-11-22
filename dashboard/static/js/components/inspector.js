/**
 * Resizable split-pane inspector (Alert / Session / Attacker / Campaign / Family).
 * Keeps `credentials` strictly apart from `raw_data` and offers SSH/Telnet terminal replay.
 */

import { api } from "../core/api.js";
import {
  badgeProtocol,
  badgeSeverity,
  badgeTag,
  classifyCommand,
  copyText,
  escapeHtml,
  fmtDateTime,
  fmtNum,
  renderStagePips,
  shortId,
} from "../core/escape.js";
import { store } from "../core/store.js";

let maskPasswords = false;

function maskVal(val) {
  if (!val) return "(empty)";
  return maskPasswords ? "*".repeat(Math.min(12, String(val).length)) : String(val);
}

export async function inspectAttacker(ip) {
  if (!ip) return;
  store.openInspector("attacker", { ip }, "summary", true);
  try {
    const detail = await api.getAttackerDetail(ip, false);
    store.openInspector("attacker", detail, "summary", false);
  } catch (err) {
    store.openInspector("attacker", { ip, error: err.message }, "summary", false);
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
    const nextW = Math.max(320, Math.min(window.innerWidth * 0.65, window.innerWidth - ev.clientX));
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

function renderCredentialsBlock(creds, protocol) {
  if (!creds) return "";
  const isOk = Boolean(creds.success);
  return `
    <div class="creds-box ${isOk ? "success" : ""}">
      <div class="creds-head">
        <span>EXTRACTED CREDENTIALS (${escapeHtml(protocol || "AUTH")})${isOk ? " // AUTH SUCCESS" : ""}</span>
        <div class="btn-group">
          <button class="btn" data-action="toggle-mask">${maskPasswords ? "UNMASK" : "MASK"}</button>
          <button class="btn" data-copy="${escapeHtml(`${creds.username}:${creds.password}`)}">COPY PAIR</button>
        </div>
      </div>
      <div class="creds-pair">
        <span class="cell-muted">USERNAME</span>
        <span class="cell-strong">${escapeHtml(creds.username || "(empty)")}</span>
        <span class="cell-muted">PASSWORD</span>
        <span class="cell-strong">${escapeHtml(maskVal(creds.password))}</span>
        <span class="cell-muted">RESULT</span>
        <span>${isOk ? '<span class="badge sev-CRITICAL">ACCEPTED</span>' : '<span class="badge sev-NONE">REJECTED</span>'}</span>
      </div>
    </div>
  `;
}

function renderAlertBody(al, tab) {
  const pd = al.payload_details || {};
  const geoStr = al.geo ? `${al.geo.country || "?"}${al.geo.city ? " / " + al.geo.city : ""}` : "N/A (GeoIP off)";

  if (tab === "raw") {
    return `
      <div class="btn-group">
        <button class="btn" data-copy="${escapeHtml(JSON.stringify(al, null, 2))}">COPY JSON</button>
      </div>
      <pre class="code-block tall">${escapeHtml(JSON.stringify(al, null, 2))}</pre>
    `;
  }

  if (tab === "payload") {
    return `
      ${renderCredentialsBlock(al.credentials, al.protocol)}
      <div class="panel">
        <div class="panel-head">
          <span class="panel-title">EXTRACTED PAYLOAD FIELDS</span>
          <span class="panel-meta">${escapeHtml(al.protocol)}</span>
        </div>
        <div class="panel-body flush">
          <div class="kv-grid">
            <div class="kv-k">COMMAND</div><div class="kv-v">${escapeHtml(pd.command || "-")}</div>
            <div class="kv-k">HTTP METHOD</div><div class="kv-v">${escapeHtml(pd.http_method || "-")}</div>
            <div class="kv-k">HTTP PATH</div><div class="kv-v">${escapeHtml(pd.http_path || "-")}</div>
            <div class="kv-k">USER-AGENT</div><div class="kv-v">${escapeHtml(pd.http_user_agent || "-")}</div>
            <div class="kv-k">MALWARE URL</div><div class="kv-v">${escapeHtml(pd.extracted_url || "-")}</div>
          </div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-head">
          <span class="panel-title">RAW_DATA (REDACTED HTTP PASSWORD SEPARATED)</span>
          <button class="btn" data-copy="${escapeHtml(pd.raw_data || "")}">COPY RAW</button>
        </div>
        <div class="panel-body flush">
          <pre class="code-block">${escapeHtml(pd.raw_data || "(no raw_data captured for this event)")}</pre>
        </div>
      </div>
    `;
  }

  // Summary tab
  return `
    <div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center;">
      ${badgeSeverity(al.severity)}
      ${badgeProtocol(al.protocol)}
      <span class="badge">SCORE ${fmtNum(al.score)}</span>
      ${al.technique ? `<span class="badge" style="color:var(--state-accent);">${escapeHtml(al.technique)} ${escapeHtml(al.technique_name)}</span>` : ""}
      ${(al.tags || []).map(badgeTag).join("")}
    </div>

    <div class="panel">
      <div class="panel-head">
        <span class="panel-title">DETECTION REASON</span>
      </div>
      <div class="panel-body mono" style="color:var(--text-bright);word-break:break-word;">
        ${escapeHtml(al.alert_reason || "-")}
      </div>
    </div>

    ${renderCredentialsBlock(al.credentials, al.protocol)}

    <div class="kv-grid">
      <div class="kv-k">TIMESTAMP</div><div class="kv-v">${escapeHtml(fmtDateTime(al.timestamp))}</div>
      <div class="kv-k">SOURCE IP</div>
      <div class="kv-v">
        <span class="ip-link" data-inspect-ip="${escapeHtml(al.source_ip)}">${escapeHtml(al.source_ip)}</span>
        ${al.source_port ? `:${escapeHtml(al.source_port)}` : ""}
        <button class="btn" style="margin-left:6px;height:18px;" data-filter-query="ip:${escapeHtml(al.source_ip)}">FILTER IP</button>
      </div>
      <div class="kv-k">TARGET PORT</div><div class="kv-v">${escapeHtml(al.target_port ?? "-")} (${escapeHtml(al.node_id)})</div>
      <div class="kv-k">SESSION ID</div>
      <div class="kv-v">
        ${al.session_id ? `<span class="ip-link" data-filter-query="sid:${escapeHtml(al.session_id)}">${escapeHtml(al.session_id)}</span>` : "-"}
      </div>
      <div class="kv-k">EVENT TYPE</div><div class="kv-v">${escapeHtml(al.event_type)}</div>
      <div class="kv-k">MITRE TACTIC</div><div class="kv-v">${escapeHtml(al.tactic || "-")}</div>
      <div class="kv-k">GEO LOCATION</div><div class="kv-v">${escapeHtml(geoStr)}</div>
    </div>

    ${pd.command ? `
      <div class="term-box">
        <div class="term-head"><span>CAPTURED COMMAND</span><button class="btn" data-copy="${escapeHtml(pd.command)}">COPY</button></div>
        <div class="term-body">
          <div class="term-line flag-${classifyCommand(pd.command)}">
            <span class="term-idx">$</span>
            <span class="term-cmd">${escapeHtml(pd.command)}</span>
          </div>
        </div>
      </div>
    ` : ""}

    ${al.recommendation ? `
      <div class="panel">
        <div class="panel-head"><span class="panel-title">MITIGATION GUIDANCE</span></div>
        <div class="panel-body mono" style="color:var(--text-secondary);">${escapeHtml(al.recommendation)}</div>
      </div>
    ` : ""}
  `;
}

function renderSessionBody(s, tab) {
  if (tab === "raw") {
    return `
      <div class="btn-group">
        <button class="btn" data-copy="${escapeHtml(JSON.stringify(s, null, 2))}">COPY JSON</button>
      </div>
      <pre class="code-block tall">${escapeHtml(JSON.stringify(s, null, 2))}</pre>
    `;
  }

  if (tab === "replay") {
    if (s.protocol === "HTTP") {
      const reqs = s.http_requests || [];
      if (!reqs.length) {
        return `<div class="empty-state">NO ALERTED HTTP REQUEST PAYLOADS LINKED TO THIS SESSION IN THE RECENT 500-ALERT BUFFER.</div>`;
      }
      return reqs
        .map(
          (r, i) => `
          <div class="http-req-item">
            <div class="http-req-head">
              <span class="cell-strong">#${i + 1} ${escapeHtml(r.method || "REQ")} ${escapeHtml(r.path || "/")}</span>
              ${badgeSeverity(r.severity)}
            </div>
            <div class="cell-muted">UTC: ${escapeHtml(fmtDateTime(r.timestamp))} | UA: ${escapeHtml(r.user_agent || "-")}</div>
            <div>${escapeHtml(r.reason)}</div>
            ${renderCredentialsBlock(r.credentials, "HTTP")}
            ${r.raw_data ? `<pre class="code-block">${escapeHtml(r.raw_data)}</pre>` : ""}
          </div>
        `
        )
        .join("");
    }

    // SSH / Telnet / FTP Terminal Replay
    const cmds = s.commands || [];
    return `
      <div class="term-box">
        <div class="term-head">
          <span>${escapeHtml(s.protocol)} // ${escapeHtml(s.node_id || "gateway")} (${cmds.length} COMMANDS)</span>
          <button class="btn" data-copy="${escapeHtml(cmds.join("\n"))}">COPY TRANSCRIPT</button>
        </div>
        <div class="term-body">
          ${s.successful_login ? `
            <div class="term-line">
              <span class="term-idx">AUTH</span>
              <span class="term-cmd" style="color:var(--sev-critical);">LOGIN ACCEPTED -> ${escapeHtml(s.successful_login)}</span>
            </div>` : ""}
          ${
            cmds.length
              ? cmds
                  .map((cmd, idx) => {
                    const flag = classifyCommand(cmd);
                    return `
                      <div class="term-line ${flag ? "flag-" + flag : ""}">
                        <span class="term-idx">${idx + 1}</span>
                        <span class="term-cmd"><span class="term-prompt">root@gateway:~#</span>${escapeHtml(cmd)}</span>
                      </div>`;
                  })
                  .join("")
              : `<div class="empty-state">NO SHELL COMMANDS EXECUTED IN THIS SESSION.</div>`
          }
        </div>
      </div>
      ${
        (s.downloads || []).length
          ? `<div class="panel">
              <div class="panel-head"><span class="panel-title">EXTRACTED MALWARE URLS (${s.downloads.length})</span></div>
              <div class="panel-body flush"><pre class="code-block">${escapeHtml(s.downloads.join("\n"))}</pre></div>
            </div>`
          : ""
      }
    `;
  }

  // Summary tab
  return `
    <div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center;">
      ${badgeProtocol(s.protocol)}
      ${badgeSeverity(s.max_severity)}
      <span class="badge">RISK ${fmtNum(s.risk_score)}/100</span>
      ${(s.family_labels || []).map((f) => `<span class="badge tag-SCANNER_WEB">${escapeHtml(f)}</span>`).join("")}
      ${(s.tags || []).map(badgeTag).join("")}
    </div>

    <div class="kv-grid">
      <div class="kv-k">SESSION ID</div><div class="kv-v">${escapeHtml(s.session_id)}</div>
      <div class="kv-k">SOURCE IP</div>
      <div class="kv-v">
        <span class="ip-link" data-inspect-ip="${escapeHtml(s.source_ip)}">${escapeHtml(s.source_ip)}</span>
        <button class="btn" style="margin-left:6px;height:18px;" data-filter-query="ip:${escapeHtml(s.source_ip)}">FILTER</button>
      </div>
      <div class="kv-k">WINDOW</div><div class="kv-v">${escapeHtml(fmtDateTime(s.start))} -> ${escapeHtml(fmtDateTime(s.end))}</div>
      <div class="kv-k">DURATION</div><div class="kv-v">${escapeHtml(s.duration_label)}</div>
      <div class="kv-k">LOGIN TRIES</div><div class="kv-v">${fmtNum(s.login_attempts)} ${s.successful_login ? `// OK: ${escapeHtml(s.successful_login)}` : ""}</div>
      <div class="kv-k">KILL CHAIN</div><div class="kv-v">${renderStagePips(s.stages)} <span class="cell-muted" style="margin-left:6px;">${escapeHtml((s.stages || []).join(" > "))}</span></div>
    </div>

    ${
      (s.passwords || []).length
        ? `<div class="panel">
            <div class="panel-head">
              <span class="panel-title">PASSWORDS ATTEMPTED (${s.passwords.length})</span>
              <button class="btn" data-action="toggle-mask">${maskPasswords ? "UNMASK" : "MASK"}</button>
            </div>
            <div class="panel-body mono" style="word-break:break-all;">
              ${s.passwords.map((p) => `<span class="badge" style="margin:2px;">${escapeHtml(maskVal(p))}</span>`).join("")}
            </div>
          </div>`
        : ""
    }

    <div class="panel">
      <div class="panel-head">
        <span class="panel-title">CORRELATED ALERTS (${(s.related_alerts || []).length})</span>
      </div>
      <div class="panel-body flush">
        ${
          (s.related_alerts || []).length
            ? `<table class="soc-table">
                <thead><tr><th style="width:68px;">SEV</th><th>REASON</th><th style="width:46px;" class="num">PTS</th></tr></thead>
                <tbody>
                  ${s.related_alerts
                    .slice(0, 20)
                    .map(
                      (a) => `<tr>
                        <td>${badgeSeverity(a.severity)}</td>
                        <td title="${escapeHtml(a.alert_reason)}">${escapeHtml(a.alert_reason)}</td>
                        <td class="num">${fmtNum(a.score)}</td>
                      </tr>`
                    )
                    .join("")}
                </tbody>
              </table>`
            : `<div class="empty-state">NO ALERTS LINKED IN RECENT 500-ALERT WINDOW</div>`
        }
      </div>
    </div>
  `;
}

function renderAttackerBody(detail, tab, loading) {
  if (loading) {
    return `<div class="empty-state">LOADING ATTACKER DOSSIER FOR ${escapeHtml(detail.ip)}...</div>`;
  }
  if (detail.error) {
    return `<div class="empty-state" style="color:var(--sev-critical);">${escapeHtml(detail.error)}</div>`;
  }
  const p = detail.profile || {};
  if (tab === "raw") {
    return `<pre class="code-block tall">${escapeHtml(JSON.stringify(detail, null, 2))}</pre>`;
  }

  if (tab === "activity") {
    const cmds = p.commands || [];
    const creds = detail.credentials_seen || [];
    return `
      <div class="panel">
        <div class="panel-head"><span class="panel-title">CAPTURED COMMANDS (${cmds.length})</span></div>
        <div class="panel-body flush">
          <pre class="code-block">${escapeHtml(cmds.length ? cmds.join("\n") : "(none)")}</pre>
        </div>
      </div>
      <div class="panel">
        <div class="panel-head"><span class="panel-title">CREDENTIALS TESTED (${creds.length})</span></div>
        <div class="panel-body flush">
          ${
            creds.length
              ? `<table class="soc-table">
                  <thead><tr><th>USER</th><th>PASSWORD</th><th style="width:66px;">AUTH</th></tr></thead>
                  <tbody>
                    ${creds
                      .map(
                        (c) => `<tr>
                          <td>${escapeHtml(c.username)}</td>
                          <td>${escapeHtml(maskVal(c.password))}</td>
                          <td>${c.success ? '<span class="badge sev-CRITICAL">OK</span>' : '<span class="badge sev-NONE">FAIL</span>'}</td>
                        </tr>`
                      )
                      .join("")}
                  </tbody>
                </table>`
              : `<div class="empty-state">NO CREDENTIALS RECORDED</div>`
          }
        </div>
      </div>
      ${
        (detail.user_agents || []).length
          ? `<div class="panel">
              <div class="panel-head"><span class="panel-title">HTTP USER-AGENTS (${detail.user_agents.length})</span></div>
              <div class="panel-body flush"><pre class="code-block">${escapeHtml(detail.user_agents.join("\n"))}</pre></div>
            </div>`
          : ""
      }
    `;
  }

  return `
    <div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center;">
      ${badgeSeverity(p.overall_severity || p.worst_severity)}
      <span class="badge">SCORE ${fmtNum(p.threat_score)}</span>
      <span class="badge">ALERTS ${fmtNum(p.total_alerts)}</span>
      <span class="badge">SESSIONS ${fmtNum(p.sessions)}</span>
      ${(p.protocols || []).map(badgeProtocol).join("")}
      ${(detail.families || []).map((f) => `<span class="badge tag-SCANNER_WEB">${escapeHtml(f)}</span>`).join("")}
    </div>

    <div class="btn-group">
      <button class="btn primary" data-filter-query="ip:${escapeHtml(p.ip)}">FILTER WORKSPACE BY IP</button>
      <button class="btn" data-copy="${escapeHtml(p.ip)}">COPY IP</button>
      <button class="btn" data-copy="iptables -I INPUT 1 -s ${escapeHtml(p.ip)} -j DROP">COPY IPTABLES DROP</button>
    </div>

    <div class="kv-grid">
      <div class="kv-k">IP ADDRESS</div><div class="kv-v cell-strong">${escapeHtml(p.ip)}</div>
      <div class="kv-k">FIRST SEEN</div><div class="kv-v">${escapeHtml(fmtDateTime(p.first_seen))}</div>
      <div class="kv-k">LAST SEEN</div><div class="kv-v">${escapeHtml(fmtDateTime(p.last_seen))}</div>
      <div class="kv-k">LOGIN TRIES</div><div class="kv-v">${fmtNum(p.login_attempts)} (OK: ${(p.successful_logins || []).length})</div>
      <div class="kv-k">KILL CHAIN</div><div class="kv-v">${renderStagePips(p.stages)} <span class="cell-muted">${escapeHtml((p.stages || []).join(" > "))}</span></div>
      <div class="kv-k">GEOIP</div><div class="kv-v">${p.geo ? escapeHtml(`${p.geo.country || "?"} / ${p.geo.city || "?"}`) : "N/A"}</div>
    </div>

    ${
      (p.recommendations || []).length
        ? `<div class="panel">
            <div class="panel-head"><span class="panel-title">RECOMMENDED ACTIONS</span></div>
            <div class="panel-body mono" style="display:flex;flex-direction:column;gap:5px;color:var(--text-secondary);">
              ${p.recommendations.map((r) => `<div>- ${escapeHtml(r)}</div>`).join("")}
            </div>
          </div>`
        : ""
    }
  `;
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

  const { kind, data, tab, loading } = st.inspector;
  let title = "INSPECTOR";
  let tabs = [];
  let bodyHtml = "";

  if (kind === "alert") {
    title = `ALERT // ${data.protocol} // ${data.source_ip}`;
    tabs = [
      { id: "summary", label: "SUMMARY" },
      { id: "payload", label: "PAYLOAD & CREDS" },
      { id: "raw", label: "RAW JSON" },
    ];
    bodyHtml = renderAlertBody(data, tab);
  } else if (kind === "session") {
    title = `SESSION // ${shortId(data.session_id, 14)} // ${data.protocol}`;
    tabs = [
      { id: "summary", label: "SUMMARY" },
      { id: "replay", label: data.protocol === "HTTP" ? "HTTP REQUESTS" : "TERMINAL REPLAY" },
      { id: "raw", label: "RAW JSON" },
    ];
    bodyHtml = renderSessionBody(data, tab);
  } else if (kind === "attacker") {
    const ip = (data.profile && data.profile.ip) || data.ip || "?";
    title = `ATTACKER DOSSIER // ${ip}`;
    tabs = [
      { id: "summary", label: "DOSSIER" },
      { id: "activity", label: "COMMANDS & CREDS" },
      { id: "raw", label: "RAW JSON" },
    ];
    bodyHtml = renderAttackerBody(data, tab, loading);
  } else {
    title = `${String(kind || "ITEM").toUpperCase()} INSPECTOR`;
    tabs = [{ id: "raw", label: "DETAILS" }];
    bodyHtml = `<pre class="code-block tall">${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
  }

  pane.innerHTML = `
    <div class="inspector-header">
      <span class="inspector-title" title="${escapeHtml(title)}">${escapeHtml(title)}</span>
      <button class="btn" data-action="close-inspector">CLOSE [ESC]</button>
    </div>
    <div class="inspector-tabs">
      ${tabs
        .map(
          (t) =>
            `<button class="inspector-tab ${tab === t.id ? "active" : ""}" data-tab="${t.id}">${t.label}</button>`
        )
        .join("")}
    </div>
    <div class="inspector-content">${bodyHtml}</div>
  `;

  pane.querySelector('[data-action="close-inspector"]')?.addEventListener("click", () => {
    store.closeInspector();
  });

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
      store.setQuery(btn.dataset.filterQuery);
      const qInput = document.getElementById("dsl-query-input");
      if (qInput) qInput.value = btn.dataset.filterQuery;
    });
  });
}

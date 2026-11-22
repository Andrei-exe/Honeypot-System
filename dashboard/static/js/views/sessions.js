/**
 * View 3: SESSIONS EXPLORER & REPLAY LAUNCHER
 * Explicitly supports HTTP sessions (session_id per TCP connection, without session_start/end)
 * and monitors SessionStore saturation (2000-session cap).
 */

import { inspectAttacker } from "../components/inspector.js";
import {
  badgeProtocol,
  badgeSeverity,
  badgeTag,
  escapeHtml,
  fmtNum,
  fmtTime,
  renderStagePips,
  shortId,
} from "../core/escape.js";
import { filterItems } from "../core/query.js";
import { store } from "../core/store.js";

let lastRows = [];

export function getSessionsRows() {
  return lastRows;
}

function sortSessions(list, sortCfg) {
  const { key, dir } = sortCfg || { key: "start", dir: "desc" };
  const mult = dir === "asc" ? 1 : -1;
  return [...list].sort((a, b) => {
    const va = a[key] ?? "";
    const vb = b[key] ?? "";
    if (typeof va === "number" && typeof vb === "number") return (va - vb) * mult;
    return String(va).localeCompare(String(vb)) * mult;
  });
}

export function renderSessions(container, state) {
  const data = state.data.sessions;
  if (!data) {
    container.innerHTML = `<div class="empty-state">LOADING SESSIONSTORE SUMMARIES...</div>`;
    lastRows = [];
    return;
  }

  const health = data.health || {};
  const protoCounts = health.by_protocol || {};
  const sampleN = Math.max(1, health.sample_size || 1);
  const segW = (p) => (((protoCounts[p] || 0) / sampleN) * 100).toFixed(1);

  let rows = data.sessions || [];
  if (state.sessionFilter === "interactive") {
    rows = rows.filter((s) => s.kind === "interactive");
  } else if (state.sessionFilter === "http") {
    rows = rows.filter((s) => s.protocol === "HTTP");
  } else if (state.sessionFilter === "no-scanners") {
    rows = rows.filter((s) => !s.is_web_scanner);
  }

  const { items: filtered } = filterItems(rows, state.query, "session");
  const sorted = sortSessions(filtered, state.sort.sessions);
  lastRows = sorted;

  const sortCfg = state.sort.sessions || { key: "start", dir: "desc" };
  const thCls = (k) =>
    `sortable${sortCfg.key === k ? (sortCfg.dir === "asc" ? " sort-asc" : " sort-desc") : ""}`;

  container.innerHTML = `
    <div class="stack-8">
      <!-- SESSIONSTORE PRESSURE + PROTOCOL TOGGLES -->
      <div class="panel">
        <div class="panel-head">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
            <span class="panel-title">SESSIONSTORE EXPLORER</span>
            <span class="badge">${fmtNum(sorted.length)} SHOWN / ${fmtNum(data.total || 0)} STORED (MAX ${fmtNum(health.capacity || 2000)})</span>
            ${
              health.eviction_risk
                ? `<span class="badge sev-CRITICAL">EVICTION RISK: HTTP SCANNERS AT ${health.http_share_pct}%</span>`
                : `<span class="badge ${health.pressure === "ELEVATED" ? "sev-MEDIUM" : "proto-HTTP"}">BUFFER ${health.saturation_pct || 0}% // ${escapeHtml(health.pressure || "NOMINAL")}</span>`
            }
          </div>
          <div class="btn-group">
            <a class="btn" href="/api/v1/export/sessions.csv">EXPORT CSV</a>
            <a class="btn" href="/api/v1/export/sessions.json">EXPORT JSON</a>
          </div>
        </div>
        <div class="panel-body stack-8">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;">
            <div class="btn-group">
              <button class="btn ${state.sessionFilter === "all" ? "active" : ""}" data-sfilter="all">ALL (${fmtNum(data.returned || 0)})</button>
              <button class="btn ${state.sessionFilter === "interactive" ? "active" : ""}" data-sfilter="interactive">INTERACTIVE SSH/TELNET/FTP</button>
              <button class="btn ${state.sessionFilter === "http" ? "active" : ""}" data-sfilter="http">HTTP SESSIONS (${fmtNum(protoCounts.HTTP || 0)})</button>
              <button class="btn ${state.sessionFilter === "no-scanners" ? "active" : ""}" data-sfilter="no-scanners">HIDE WEB SCANNERS</button>
            </div>
            <div style="display:flex;align-items:center;gap:10px;font-family:var(--font-mono);font-size:10px;color:var(--text-secondary);">
              <span>SSH:${protoCounts.SSH || 0}</span>
              <span>TELNET:${protoCounts.TELNET || 0}</span>
              <span>FTP:${protoCounts.FTP || 0}</span>
              <span>HTTP:${protoCounts.HTTP || 0}</span>
            </div>
          </div>
          <div class="meter-track">
            <div class="meter-seg ssh" style="width:${segW("SSH")}%"></div>
            <div class="meter-seg telnet" style="width:${segW("TELNET")}%"></div>
            <div class="meter-seg ftp" style="width:${segW("FTP")}%"></div>
            <div class="meter-seg http" style="width:${segW("HTTP")}%"></div>
          </div>
        </div>
      </div>

      <!-- SESSIONS TABLE -->
      <div class="panel">
        <div class="panel-body flush">
          <div class="table-scroll bounded-lg">
            <table class="soc-table">
              <thead>
                <tr>
                  <th style="width:74px;" class="${thCls("start")}" data-sort="start">START</th>
                  <th style="width:68px;" class="${thCls("protocol")}" data-sort="protocol">PROTO</th>
                  <th style="width:128px;" class="${thCls("source_ip")}" data-sort="source_ip">SOURCE IP</th>
                  <th style="width:112px;">SESSION ID</th>
                  <th style="width:86px;">DURATION</th>
                  <th style="width:110px;" class="${thCls("login_attempts")}" data-sort="login_attempts">AUTH</th>
                  <th style="width:52px;" class="num">CMDS</th>
                  <th style="width:82px;" class="${thCls("stage_count")}" data-sort="stage_count">STAGES</th>
                  <th>FAMILY / TAGS</th>
                  <th style="width:56px;" class="num ${thCls("risk_score")}" data-sort="risk_score">RISK</th>
                  <th style="width:72px;">ACTION</th>
                </tr>
              </thead>
              <tbody>
                ${
                  sorted.length
                    ? sorted
                        .map((s, idx) => {
                          const hasReplay = (s.commands || []).length > 0 || (s.http_requests || []).length > 0;
                          const authHtml = s.successful_login
                            ? `<span class="badge sev-CRITICAL" title="${escapeHtml(s.successful_login)}">OK (${fmtNum(s.login_attempts)})</span>`
                            : `<span class="cell-muted">${fmtNum(s.login_attempts)} tries</span>`;
                          return `
                            <tr class="sev-row-${escapeHtml(s.max_severity)} ${idx === state.selectedRowIndex ? "selected" : ""}" data-row-idx="${idx}">
                              <td class="cell-muted">${escapeHtml(fmtTime(s.start))}</td>
                              <td>${badgeProtocol(s.protocol)}</td>
                              <td><span class="ip-link" data-inspect-ip="${escapeHtml(s.source_ip)}">${escapeHtml(s.source_ip)}</span></td>
                              <td class="cell-muted" title="${escapeHtml(s.session_id)}">${escapeHtml(shortId(s.session_id, 13))}</td>
                              <td class="cell-muted">${escapeHtml(s.duration_label)}</td>
                              <td>${authHtml}</td>
                              <td class="num ${(s.commands || []).length > 0 ? "cell-strong" : "cell-muted"}">${fmtNum((s.commands || []).length)}</td>
                              <td>${renderStagePips(s.stages)}</td>
                              <td>
                                ${(s.family_labels || []).slice(0, 1).map((f) => `<span class="badge tag-SCANNER_WEB">${escapeHtml(f)}</span>`).join(" ")}
                                ${(s.tags || []).slice(0, 3).map(badgeTag).join(" ")}
                              </td>
                              <td class="num cell-strong">${fmtNum(s.risk_score)}</td>
                              <td>
                                <button class="btn ${hasReplay ? "primary" : ""}" style="height:19px;padding:0 5px;" data-replay-idx="${idx}">
                                  ${s.protocol === "HTTP" ? "HTTP" : "REPLAY"}
                                </button>
                              </td>
                            </tr>`;
                        })
                        .join("")
                    : `<tr><td colspan="11" class="empty-state">NO SESSIONS MATCH CURRENT FILTER</td></tr>`
                }
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `;

  container.querySelectorAll("[data-sfilter]").forEach((btn) => {
    btn.addEventListener("click", () => store.setSessionFilter(btn.dataset.sfilter));
  });

  container.querySelectorAll("th[data-sort]").forEach((th) => {
    th.addEventListener("click", () => store.setSort("sessions", th.dataset.sort));
  });

  container.querySelectorAll("[data-inspect-ip]").forEach((el) => {
    el.addEventListener("click", (ev) => {
      ev.stopPropagation();
      inspectAttacker(el.dataset.inspectIp);
    });
  });

  container.querySelectorAll("[data-replay-idx]").forEach((btn) => {
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const idx = Number(btn.dataset.replayIdx);
      const item = sorted[idx];
      if (!item) return;
      store.set({ selectedRowIndex: idx }, "selection");
      store.openInspector("session", item, "replay");
    });
  });

  container.querySelectorAll("tbody tr[data-row-idx]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const idx = Number(tr.dataset.rowIdx);
      const item = sorted[idx];
      if (!item) return;
      store.set({ selectedRowIndex: idx }, "selection");
      store.openInspector("session", item, "summary");
    });
  });
}

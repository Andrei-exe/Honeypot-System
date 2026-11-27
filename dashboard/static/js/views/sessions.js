/**
 * Sessions page: one row per connection, with replay of what the attacker typed.
 * HTTP sessions have one session_id per TCP connection and no start/end events.
 */

import { inspectAttacker } from "../components/inspector.js";
import {
  asList,
  badgeProtocol,
  escapeHtml,
  fmtNum,
  renderStagePips,
  timeCell,
} from "../core/escape.js";
import { findNewKeys } from "../core/fresh.js";
import { filterItems } from "../core/query.js";
import { rowKey } from "../core/selection.js";
import { store } from "../core/store.js";

const PAGE_SIZE = 100;
const KIND_TABS = [
  { id: "all", label: "All" },
  { id: "interactive", label: "SSH · Telnet · FTP" },
  { id: "http", label: "HTTP" },
  { id: "no-scanners", label: "Hide web scanners" },
];

let lastRows = [];
let shown = PAGE_SIZE;
let shownFor = "";

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

function durationText(s) {
  const d = s.duration_seconds;
  if (s.protocol === "HTTP") return d ? `${Number(d).toFixed(1)} s` : "1 request";
  if (d === null || d === undefined) return "still open";
  if (d < 60) return `${Number(d).toFixed(1)} s`;
  return `${Math.floor(d / 60)} min ${Math.round(d % 60)} s`;
}

function loginText(s) {
  if (s.successful_login) {
    return `<span class="badge sev-CRITICAL" title="${escapeHtml(s.successful_login)}">Logged in</span>`;
  }
  const n = s.login_attempts || 0;
  return n ? `<span class="cell-muted">${fmtNum(n)} tr${n === 1 ? "y" : "ies"}</span>` : `<span class="cell-muted">—</span>`;
}

export function renderSessions(container, state) {
  const data = state.data.sessions;
  if (!data) {
    container.innerHTML = `<div class="empty-state">Loading sessions…</div>`;
    lastRows = [];
    return;
  }

  const filterId = `${state.sessionFilter}|${state.query}`;
  if (filterId !== shownFor) {
    shown = PAGE_SIZE;
    shownFor = filterId;
  }

  const all = asList(data.sessions);
  const fresh = findNewKeys("sessions", all.map((s) => rowKey("sessions", s)));

  let rows = all;
  if (state.sessionFilter === "interactive") rows = rows.filter((s) => s.kind === "interactive");
  else if (state.sessionFilter === "http") rows = rows.filter((s) => s.protocol === "HTTP");
  else if (state.sessionFilter === "no-scanners") rows = rows.filter((s) => !s.is_web_scanner);

  const { items: filtered } = filterItems(rows, state.query, "session");
  const sorted = sortSessions(filtered, state.sort.sessions);
  lastRows = sorted.slice(0, shown);

  const health = data.health || {};
  const sortCfg = state.sort.sessions || { key: "start", dir: "desc" };
  const th = (k, label, width, extra = "") =>
    `<th style="width:${width}px;" class="sortable ${extra} ${sortCfg.key === k ? (sortCfg.dir === "asc" ? "sort-asc" : "sort-desc") : ""}" data-sort="${k}">${label}</th>`;

  const loggedIn = all.filter((s) => s.successful_login).length;
  const withCmds = all.filter((s) => asList(s.commands).length > 0).length;

  const storageNote = health.eviction_risk
    ? `<div class="honeytoken-banner"><div><strong>Session storage is almost full (${health.saturation_pct || 0}%).</strong> Mostly HTTP scanners (${health.http_share_pct || 0}%). Older sessions will be dropped first.</div></div>`
    : "";

  container.innerHTML = `
    <div class="stack-8">
      <div class="page-head">
        <div>
          <h1 class="page-title">Sessions</h1>
          <div class="inline-stats">
            <span><strong>${fmtNum(data.total || 0)}</strong> stored</span>
            <span class="${loggedIn ? "crit" : ""}"><strong>${fmtNum(loggedIn)}</strong> logged in</span>
            <span><strong>${fmtNum(withCmds)}</strong> ran commands</span>
          </div>
        </div>
        <div class="page-actions">
          <div class="seg">
            ${KIND_TABS.map(
              (t) => `<button class="${state.sessionFilter === t.id ? "active" : ""}" data-sfilter="${t.id}">${t.label}</button>`
            ).join("")}
          </div>
          <a class="btn" href="/api/v1/export/sessions.csv">Export CSV</a>
          <a class="btn ghost" href="/api/v1/export/sessions.json">JSON</a>
        </div>
      </div>

      ${storageNote}

      <div class="panel">
        <div class="panel-body flush">
          <div class="table-scroll bounded-lg" data-scroll-key="sessions-table">
            <table class="soc-table">
              <thead>
                <tr>
                  ${th("start", "Started", 110)}
                  ${th("protocol", "Protocol", 90)}
                  ${th("source_ip", "Source IP", 150)}
                  <th style="width:100px;">Duration</th>
                  ${th("login_attempts", "Login", 110)}
                  <th style="width:90px;" class="num">Commands</th>
                  ${th("stage_count", "How far", 100)}
                  <th>Notes</th>
                  ${th("risk_score", "Risk", 70, "num")}
                  <th style="width:90px;"></th>
                </tr>
              </thead>
              <tbody>
                ${
                  lastRows.length
                    ? lastRows
                        .map((s, idx) => {
                          const key = rowKey("sessions", s);
                          const cmds = asList(s.commands).length;
                          const hasReplay = cmds > 0 || asList(s.http_requests).length > 0;
                          const note = asList(s.family_labels)[0] || asList(s.tags)[0] || "";
                          return `
                            <tr class="sev-row-${escapeHtml(s.max_severity)} ${key === state.selectedKey ? "selected" : ""} ${fresh.has(key) ? "is-new" : ""}" data-row-idx="${idx}" data-row-key="${escapeHtml(key || "")}">
                              <td>${timeCell(s.start)}</td>
                              <td>${badgeProtocol(s.protocol)}</td>
                              <td><span class="ip-link" data-inspect-ip="${escapeHtml(s.source_ip)}">${escapeHtml(s.source_ip)}</span></td>
                              <td class="cell-muted">${escapeHtml(durationText(s))}</td>
                              <td>${loginText(s)}</td>
                              <td class="num ${cmds ? "cell-strong" : "cell-muted"}">${cmds ? fmtNum(cmds) : "—"}</td>
                              <td>${renderStagePips(s.stages)}</td>
                              <td class="cell-muted" title="${escapeHtml(asList(s.tags).join(", "))}">${escapeHtml(String(note).toLowerCase().replace(/_/g, " "))}</td>
                              <td class="num">${fmtNum(s.risk_score)}</td>
                              <td>${hasReplay ? `<button class="btn sm" data-replay-idx="${idx}">${s.protocol === "HTTP" ? "Requests" : "Replay"}</button>` : ""}</td>
                            </tr>`;
                        })
                        .join("")
                    : `<tr><td colspan="10" class="empty-state">No sessions match this filter</td></tr>`
                }
              </tbody>
            </table>
          </div>
          ${
            sorted.length > lastRows.length
              ? `<div class="table-foot">
                  <span>Showing ${fmtNum(lastRows.length)} of ${fmtNum(sorted.length)}</span>
                  <button class="btn sm" id="sessions-more">Show ${fmtNum(Math.min(PAGE_SIZE, sorted.length - lastRows.length))} more</button>
                </div>`
              : ""
          }
        </div>
      </div>
      <p class="muted-note">"How far" shows the attack stages reached: connected, tried to log in, logged in, ran commands, downloaded files, set up persistence.</p>
    </div>
  `;

  container.querySelectorAll("[data-sfilter]").forEach((btn) => {
    btn.addEventListener("click", () => store.setSessionFilter(btn.dataset.sfilter));
  });

  container.querySelector("#sessions-more")?.addEventListener("click", () => {
    shown += PAGE_SIZE;
    renderSessions(container, store.get());
  });

  container.querySelectorAll("th[data-sort]").forEach((el) => {
    el.addEventListener("click", () => store.setSort("sessions", el.dataset.sort));
  });

  container.querySelectorAll("[data-inspect-ip]").forEach((el) => {
    el.addEventListener("click", (ev) => {
      ev.stopPropagation();
      inspectAttacker(el.dataset.inspectIp);
    });
  });

  const open = (idx, tab) => {
    const item = lastRows[idx];
    if (!item) return;
    store.set({ selectedKey: rowKey("sessions", item) }, "selection");
    store.openInspector("session", item, tab);
  };

  container.querySelectorAll("[data-replay-idx]").forEach((btn) => {
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      open(Number(btn.dataset.replayIdx), "replay");
    });
  });

  container.querySelectorAll("tbody tr[data-row-idx]").forEach((tr) => {
    tr.addEventListener("click", () => open(Number(tr.dataset.rowIdx), "summary"));
  });
}

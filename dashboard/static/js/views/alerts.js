/**
 * View 2: ALERTS EXPLORER (DSL filtering, column sorting, CSV/JSON export)
 */

import { TimelineChart } from "../charts/timeline.js";
import { inspectAttacker } from "../components/inspector.js";
import {
  badgeProtocol,
  badgeSeverity,
  badgeTag,
  escapeHtml,
  fmtNum,
  fmtTime,
  shortId,
} from "../core/escape.js";
import { filterItems } from "../core/query.js";
import { store } from "../core/store.js";

let timelineInst = null;
let lastRows = [];

const PRESETS = [
  { label: "ALL", dsl: "" },
  { label: "HIGH+", dsl: "sev:high+" },
  { label: "CRITICAL", dsl: "sev:critical" },
  { label: "NO HTTP", dsl: "-proto:http" },
  { label: "HTTP", dsl: "proto:http" },
  { label: "HAS CREDS", dsl: "has:creds" },
  { label: "AUTH OK", dsl: "tag:auth_ok" },
  { label: "HONEYTOKEN", dsl: "has:honeytoken" },
  { label: "MIRAI", dsl: "tag:mirai" },
  { label: "MINER", dsl: "tag:cryptominer" },
];

export function destroyAlerts() {
  if (timelineInst) {
    timelineInst.destroy();
    timelineInst = null;
  }
}

export function getAlertsRows() {
  return lastRows;
}

function sortAlerts(list, sortCfg) {
  const { key, dir } = sortCfg || { key: "timestamp", dir: "desc" };
  const mult = dir === "asc" ? 1 : -1;
  return [...list].sort((a, b) => {
    const va = a[key] ?? "";
    const vb = b[key] ?? "";
    if (typeof va === "number" && typeof vb === "number") return (va - vb) * mult;
    return String(va).localeCompare(String(vb)) * mult;
  });
}

export function renderAlerts(container, state) {
  destroyAlerts();
  const data = state.data.alerts;
  if (!data) {
    container.innerHTML = `<div class="empty-state">LOADING RECENT ALERTS BUFFER...</div>`;
    lastRows = [];
    return;
  }

  const { items: filtered } = filterItems(data.alerts || [], state.query, "alert");
  const sorted = sortAlerts(filtered, state.sort.alerts);
  lastRows = sorted;

  const sortCfg = state.sort.alerts || { key: "timestamp", dir: "desc" };
  const thCls = (k) =>
    `sortable${sortCfg.key === k ? (sortCfg.dir === "asc" ? " sort-asc" : " sort-desc") : ""}`;

  container.innerHTML = `
    <div class="stack-8">
      <div class="panel">
        <div class="panel-head">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
            <span class="panel-title">ALERTS EXPLORER</span>
            <span class="badge">${fmtNum(sorted.length)} / ${fmtNum(data.returned || 0)} IN WINDOW (TOTAL ${fmtNum(data.total || 0)})</span>
            <div class="btn-group">
              ${PRESETS.map(
                (p) =>
                  `<button class="btn ${state.query.trim() === p.dsl ? "active" : ""}" data-preset="${escapeHtml(p.dsl)}">${p.label}</button>`
              ).join("")}
            </div>
          </div>
          <div class="btn-group">
            <a class="btn" href="/api/v1/export/alerts.csv">EXPORT CSV</a>
            <a class="btn" href="/api/v1/export/alerts.json">EXPORT JSON</a>
          </div>
        </div>
        <div class="panel-body">
          <div id="al-timeline-chart"></div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-body flush">
          <div class="table-scroll bounded-lg">
            <table class="soc-table">
              <thead>
                <tr>
                  <th style="width:74px;" class="${thCls("timestamp")}" data-sort="timestamp">UTC</th>
                  <th style="width:78px;" class="${thCls("severity_rank")}" data-sort="severity_rank">SEV</th>
                  <th style="width:68px;" class="${thCls("protocol")}" data-sort="protocol">PROTO</th>
                  <th style="width:128px;" class="${thCls("source_ip")}" data-sort="source_ip">SOURCE IP</th>
                  <th style="width:105px;">SESSION</th>
                  <th style="width:86px;" class="${thCls("technique")}" data-sort="technique">MITRE</th>
                  <th style="width:130px;">CREDENTIALS</th>
                  <th>DETECTION REASON & PAYLOAD</th>
                  <th style="width:48px;" class="num ${thCls("score")}" data-sort="score">PTS</th>
                </tr>
              </thead>
              <tbody>
                ${
                  sorted.length
                    ? sorted
                        .map((al, idx) => {
                          const creds = al.credentials;
                          const credStr = creds ? `${creds.username}:${creds.password}` : "-";
                          return `
                            <tr class="sev-row-${escapeHtml(al.severity)} ${idx === state.selectedRowIndex ? "selected" : ""}" data-row-idx="${idx}">
                              <td class="cell-muted">${escapeHtml(fmtTime(al.timestamp))}</td>
                              <td>${badgeSeverity(al.severity)}</td>
                              <td>${badgeProtocol(al.protocol)}</td>
                              <td><span class="ip-link" data-inspect-ip="${escapeHtml(al.source_ip)}">${escapeHtml(al.source_ip)}</span></td>
                              <td class="cell-muted" title="${escapeHtml(al.session_id)}">${escapeHtml(shortId(al.session_id, 12))}</td>
                              <td style="color:var(--state-accent);" title="${escapeHtml(al.technique_name)}">${escapeHtml(al.technique || "-")}</td>
                              <td class="${creds && creds.success ? "cell-strong" : "cell-muted"}" title="${escapeHtml(credStr)}">${escapeHtml(credStr)}</td>
                              <td title="${escapeHtml(al.alert_reason)}">
                                ${(al.tags || []).slice(0, 2).map(badgeTag).join(" ")}
                                <span>${escapeHtml(al.alert_reason)}</span>
                              </td>
                              <td class="num cell-strong">${fmtNum(al.score)}</td>
                            </tr>`;
                        })
                        .join("")
                    : `<tr><td colspan="9" class="empty-state">NO ALERTS MATCH QUERY "${escapeHtml(state.query)}"</td></tr>`
                }
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `;

  const tlEl = container.querySelector("#al-timeline-chart");
  if (tlEl) {
    timelineInst = new TimelineChart(tlEl, { height: 120 });
    timelineInst.setData(data.timeline);
  }

  container.querySelectorAll("[data-preset]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const expr = btn.dataset.preset;
      store.setQuery(expr);
      const input = document.getElementById("dsl-query-input");
      if (input) input.value = expr;
    });
  });

  container.querySelectorAll("th[data-sort]").forEach((th) => {
    th.addEventListener("click", () => store.setSort("alerts", th.dataset.sort));
  });

  container.querySelectorAll("[data-inspect-ip]").forEach((el) => {
    el.addEventListener("click", (ev) => {
      ev.stopPropagation();
      inspectAttacker(el.dataset.inspectIp);
    });
  });

  container.querySelectorAll("tbody tr[data-row-idx]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const idx = Number(tr.dataset.rowIdx);
      const item = sorted[idx];
      if (!item) return;
      store.set({ selectedRowIndex: idx }, "selection");
      store.openInspector("alert", item, "summary");
    });
  });
}

/**
 * Alerts page: every recent alert, searchable and sortable, with exports.
 */

import { inspectAttacker } from "../components/inspector.js";
import {
  asList,
  badgeProtocol,
  badgeSeverity,
  badgeTag,
  escapeHtml,
  fmtNum,
  timeCell,
} from "../core/escape.js";
import { findNewKeys } from "../core/fresh.js";
import { filterItems } from "../core/query.js";
import { rowKey } from "../core/selection.js";
import { store } from "../core/store.js";

const PAGE_SIZE = 100;

let lastRows = [];
let shown = PAGE_SIZE;
let shownForQuery = "";

const SEVERITY_TABS = [
  { label: "All", dsl: "" },
  { label: "Critical", dsl: "sev:critical" },
  { label: "High & up", dsl: "sev:high+" },
  { label: "Logins", dsl: "has:creds" },
  { label: "Commands", dsl: "has:cmd" },
];

export function destroyAlerts() {
  // No charts on this page any more; kept so main.js can call it safely.
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
  const data = state.data.alerts;
  if (!data) {
    container.innerHTML = `<div class="empty-state">Loading alerts…</div>`;
    lastRows = [];
    return;
  }

  if (state.query !== shownForQuery) {
    shown = PAGE_SIZE;
    shownForQuery = state.query;
  }

  const all = asList(data.alerts);
  const fresh = findNewKeys("alerts", all.map((a) => rowKey("alerts", a)));
  const { items: filtered } = filterItems(all, state.query, "alert");
  const sorted = sortAlerts(filtered, state.sort.alerts);
  lastRows = sorted.slice(0, shown);

  const sortCfg = state.sort.alerts || { key: "timestamp", dir: "desc" };
  const th = (k, label, width, extra = "") =>
    `<th style="width:${width}px;" class="sortable ${extra} ${sortCfg.key === k ? (sortCfg.dir === "asc" ? "sort-asc" : "sort-desc") : ""}" data-sort="${k}">${label}</th>`;

  const sev = data.by_severity || {};
  const q = state.query.trim();

  container.innerHTML = `
    <div class="stack-8">
      <div class="page-head">
        <div>
          <h1 class="page-title">Alerts</h1>
          <div class="inline-stats">
            <span><strong>${fmtNum(data.total || 0)}</strong> total</span>
            <span class="${sev.CRITICAL ? "crit" : ""}"><strong>${fmtNum(sev.CRITICAL || 0)}</strong> critical</span>
            <span><strong>${fmtNum(sev.HIGH || 0)}</strong> high</span>
            <span><strong>${fmtNum(sev.MEDIUM || 0)}</strong> medium</span>
          </div>
        </div>
        <div class="page-actions">
          <div class="seg">
            ${SEVERITY_TABS.map(
              (t) => `<button class="${q === t.dsl ? "active" : ""}" data-preset="${escapeHtml(t.dsl)}">${t.label}</button>`
            ).join("")}
          </div>
          <a class="btn" href="/api/v1/export/alerts.csv">Export CSV</a>
          <a class="btn ghost" href="/api/v1/export/alerts.json">JSON</a>
        </div>
      </div>

      <div class="panel">
        <div class="panel-body flush">
          <div class="table-scroll bounded-lg" data-scroll-key="alerts-table">
            <table class="soc-table">
              <thead>
                <tr>
                  ${th("timestamp", "Time", 110)}
                  ${th("severity_rank", "Severity", 100)}
                  ${th("protocol", "Protocol", 90)}
                  ${th("source_ip", "Source IP", 150)}
                  <th>What happened</th>
                  <th style="width:160px;">Login used</th>
                  ${th("score", "Score", 70, "num")}
                </tr>
              </thead>
              <tbody>
                ${
                  lastRows.length
                    ? lastRows
                        .map((al, idx) => {
                          const key = rowKey("alerts", al);
                          const creds = al.credentials;
                          const credStr = creds ? `${creds.username}:${creds.password}` : "";
                          return `
                            <tr class="sev-row-${escapeHtml(al.severity)} ${key === state.selectedKey ? "selected" : ""} ${fresh.has(key) ? "is-new" : ""}" data-row-idx="${idx}" data-row-key="${escapeHtml(key || "")}">
                              <td>${timeCell(al.timestamp)}</td>
                              <td>${badgeSeverity(al.severity)}</td>
                              <td>${badgeProtocol(al.protocol)}</td>
                              <td><span class="ip-link" data-inspect-ip="${escapeHtml(al.source_ip)}">${escapeHtml(al.source_ip)}</span></td>
                              <td title="${escapeHtml(al.alert_reason)}">
                                ${asList(al.tags).slice(0, 1).map(badgeTag).join(" ")}
                                ${escapeHtml(al.alert_reason)}
                              </td>
                              <td class="mono ${creds && creds.success ? "cell-strong" : "cell-muted"}" title="${escapeHtml(credStr)}">${credStr ? escapeHtml(credStr) : "—"}</td>
                              <td class="num">${fmtNum(al.score)}</td>
                            </tr>`;
                        })
                        .join("")
                    : `<tr><td colspan="7" class="empty-state">${q ? "No alerts match this search" : "No alerts yet"}</td></tr>`
                }
              </tbody>
            </table>
          </div>
          ${
            sorted.length > lastRows.length
              ? `<div class="table-foot">
                  <span>Showing ${fmtNum(lastRows.length)} of ${fmtNum(sorted.length)}</span>
                  <button class="btn sm" id="alerts-more">Show ${fmtNum(Math.min(PAGE_SIZE, sorted.length - lastRows.length))} more</button>
                </div>`
              : sorted.length
              ? `<div class="table-foot"><span>${fmtNum(sorted.length)} alert${sorted.length === 1 ? "" : "s"}${q ? " match this search" : " in the recent window"}</span></div>`
              : ""
          }
        </div>
      </div>
    </div>
  `;

  container.querySelectorAll("[data-preset]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const expr = btn.dataset.preset;
      store.setQuery(expr);
      const input = document.getElementById("dsl-query-input");
      if (input) input.value = expr;
    });
  });

  container.querySelector("#alerts-more")?.addEventListener("click", () => {
    shown += PAGE_SIZE;
    renderAlerts(container, store.get());
  });

  container.querySelectorAll("th[data-sort]").forEach((el) => {
    el.addEventListener("click", () => store.setSort("alerts", el.dataset.sort));
  });

  container.querySelectorAll("[data-inspect-ip]").forEach((el) => {
    el.addEventListener("click", (ev) => {
      ev.stopPropagation();
      inspectAttacker(el.dataset.inspectIp);
    });
  });

  container.querySelectorAll("tbody tr[data-row-idx]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const item = lastRows[Number(tr.dataset.rowIdx)];
      if (!item) return;
      store.set({ selectedKey: rowKey("alerts", item) }, "selection");
      store.openInspector("alert", item, "summary");
    });
  });
}

/**
 * Attackers page: one row per source IP, worst first.
 */

import { inspectAttacker } from "../components/inspector.js";
import {
  agoCell,
  asList,
  badgeProtocol,
  badgeSeverity,
  copyText,
  escapeHtml,
  fmtNum,
} from "../core/escape.js";
import { findNewKeys } from "../core/fresh.js";
import { filterItems } from "../core/query.js";
import { rowKey } from "../core/selection.js";
import { store } from "../core/store.js";

let lastRows = [];

const TABS = [
  { label: "All", dsl: "" },
  { label: "High & up", dsl: "sev:high+" },
  { label: "Logged in", dsl: "has:login" },
  { label: "Ran commands", dsl: "has:commands" },
  { label: "Downloaded", dsl: "has:downloads" },
];

export function getAttackersRows() {
  return lastRows;
}

function sortAttackers(list, sortCfg) {
  const { key, dir } = sortCfg || { key: "score", dir: "desc" };
  const mult = dir === "asc" ? 1 : -1;
  return [...list].sort((a, b) => {
    const va = a[key] ?? "";
    const vb = b[key] ?? "";
    if (typeof va === "number" && typeof vb === "number") return (va - vb) * mult;
    return String(va).localeCompare(String(vb)) * mult;
  });
}

export function renderAttackers(container, state) {
  const data = state.data.attackers;
  if (!data) {
    container.innerHTML = `<div class="empty-state">Loading attackers…</div>`;
    lastRows = [];
    return;
  }

  const all = asList(data.attackers);
  const fresh = findNewKeys("attackers", all.map((a) => rowKey("attackers", a)));
  const { items: filtered } = filterItems(all, state.query, "attacker");
  const sorted = sortAttackers(filtered, state.sort.attackers);
  lastRows = sorted;

  const sortCfg = state.sort.attackers || { key: "score", dir: "desc" };
  const th = (k, label, width, extra = "") =>
    `<th style="width:${width}px;" class="sortable ${extra} ${sortCfg.key === k ? (sortCfg.dir === "asc" ? "sort-asc" : "sort-desc") : ""}" data-sort="${k}">${label}</th>`;

  const loggedIn = all.filter((a) => (a.successful_logins || 0) > 0).length;
  const ranCmds = all.filter((a) => (a.commands || 0) > 0).length;
  const honey = all.filter((a) => a.honeytoken_hit).length;
  const q = state.query.trim();

  container.innerHTML = `
    <div class="stack-8">
      <div class="page-head">
        <div>
          <h1 class="page-title">Attackers</h1>
          <div class="inline-stats">
            <span><strong>${fmtNum(data.total || all.length)}</strong> unique IPs</span>
            <span class="${loggedIn ? "crit" : ""}"><strong>${fmtNum(loggedIn)}</strong> logged in</span>
            <span><strong>${fmtNum(ranCmds)}</strong> ran commands</span>
            <span class="${honey ? "crit" : ""}"><strong>${fmtNum(honey)}</strong> touched a honeytoken</span>
          </div>
        </div>
        <div class="page-actions">
          <div class="seg">
            ${TABS.map(
              (t) => `<button class="${q === t.dsl ? "active" : ""}" data-preset="${escapeHtml(t.dsl)}">${t.label}</button>`
            ).join("")}
          </div>
          <button class="btn" id="btn-copy-ips" ${sorted.length ? "" : "disabled"}>Copy ${fmtNum(sorted.length)} IP${sorted.length === 1 ? "" : "s"}</button>
        </div>
      </div>

      <div class="panel">
        <div class="panel-body flush">
          <div class="table-scroll bounded-lg" data-scroll-key="attackers-table">
            <table class="soc-table">
              <thead>
                <tr>
                  ${th("ip", "IP address", 160)}
                  ${th("max_severity_rank", "Worst alert", 110)}
                  ${th("score", "Score", 80, "num")}
                  ${th("alerts", "Alerts", 80, "num")}
                  ${th("sessions", "Sessions", 90, "num")}
                  ${th("successful_logins", "Logins", 80, "num")}
                  ${th("commands", "Commands", 100, "num")}
                  <th>Protocols</th>
                  ${th("last_seen", "Last seen", 110)}
                </tr>
              </thead>
              <tbody>
                ${
                  sorted.length
                    ? sorted
                        .map((a, idx) => {
                          const key = rowKey("attackers", a);
                          const geo = a.geo ? [a.geo.country, a.geo.city].filter(Boolean).join(", ") : "";
                          return `
                            <tr class="sev-row-${escapeHtml(a.max_severity)} ${key === state.selectedKey ? "selected" : ""} ${fresh.has(key) ? "is-new" : ""}" data-row-idx="${idx}" data-row-key="${escapeHtml(key || "")}">
                              <td>
                                <span class="ip-link">${escapeHtml(a.ip)}</span>
                                ${a.honeytoken_hit ? `<span class="badge tag-HONEYTOKEN" title="Read a decoy secret">honeytoken</span>` : ""}
                                ${geo ? `<div class="cell-muted" style="font-size:12px;">${escapeHtml(geo)}</div>` : ""}
                              </td>
                              <td>${badgeSeverity(a.max_severity)}</td>
                              <td class="num">${fmtNum(a.score)}</td>
                              <td class="num">${fmtNum(a.alerts)}</td>
                              <td class="num">${fmtNum(a.sessions)}</td>
                              <td class="num ${a.successful_logins > 0 ? "cell-strong" : "cell-muted"}">${a.successful_logins ? fmtNum(a.successful_logins) : "—"}</td>
                              <td class="num ${a.commands > 0 ? "cell-strong" : "cell-muted"}">${a.commands ? fmtNum(a.commands) : "—"}</td>
                              <td>${asList(a.protocols).map(badgeProtocol).join(" ")}</td>
                              <td>${agoCell(a.last_seen)}</td>
                            </tr>`;
                        })
                        .join("")
                    : `<tr><td colspan="9" class="empty-state">${q ? "No attackers match this search" : "No attackers yet"}</td></tr>`
                }
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `;

  container.querySelector("#btn-copy-ips")?.addEventListener("click", () => {
    copyText(sorted.map((a) => a.ip).join("\n"), `Copied ${sorted.length} IP address${sorted.length === 1 ? "" : "es"}`);
  });

  container.querySelectorAll("[data-preset]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const expr = btn.dataset.preset;
      store.setQuery(expr);
      const qInput = document.getElementById("dsl-query-input");
      if (qInput) qInput.value = expr;
    });
  });

  container.querySelectorAll("th[data-sort]").forEach((el) => {
    el.addEventListener("click", () => store.setSort("attackers", el.dataset.sort));
  });

  container.querySelectorAll("tbody tr[data-row-idx]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const item = lastRows[Number(tr.dataset.rowIdx)];
      if (!item) return;
      store.set({ selectedKey: rowKey("attackers", item) }, "selection");
      inspectAttacker(item.ip);
    });
  });
}

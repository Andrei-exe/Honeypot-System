/**
 * View 5: ATTACKER DOSSIERS (IP INDEX & PROFILING)
 */

import { inspectAttacker } from "../components/inspector.js";
import {
  badgeProtocol,
  badgeSeverity,
  badgeTag,
  copyText,
  escapeHtml,
  fmtNum,
  fmtTime,
} from "../core/escape.js";
import { filterItems } from "../core/query.js";
import { store } from "../core/store.js";

let lastRows = [];

const PRESETS = [
  { label: "ALL IPS", dsl: "" },
  { label: "HIGH+", dsl: "sev:high+" },
  { label: "AUTH OK", dsl: "has:login" },
  { label: "EXECUTED CMDS", dsl: "has:commands" },
  { label: "DOWNLOADS", dsl: "has:downloads" },
  { label: "HONEYTOKEN", dsl: "has:honeytoken" },
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
    container.innerHTML = `<div class="empty-state">AGGREGATING ATTACKER PROFILES...</div>`;
    lastRows = [];
    return;
  }

  const { items: filtered } = filterItems(data.attackers || [], state.query, "attacker");
  const sorted = sortAttackers(filtered, state.sort.attackers);
  lastRows = sorted;

  const sortCfg = state.sort.attackers || { key: "score", dir: "desc" };
  const thCls = (k) =>
    `sortable${sortCfg.key === k ? (sortCfg.dir === "asc" ? " sort-asc" : " sort-desc") : ""}`;

  const compromisedIps = sorted.filter((a) => (a.successful_logins || 0) > 0).length;
  const cmdIps = sorted.filter((a) => (a.commands || 0) > 0).length;
  const honeyIps = sorted.filter((a) => a.honeytoken_hit).length;

  container.innerHTML = `
    <div class="stack-8">
      <div class="kpi-strip" style="grid-template-columns:repeat(4,minmax(0,1fr));">
        <div class="kpi-cell accent">
          <span class="kpi-label">INDEXED ATTACKER IPS</span>
          <span class="kpi-value">${fmtNum(sorted.length)}</span>
          <span class="kpi-sub">GLOBAL UNIQUE: ${fmtNum(data.total || sorted.length)}</span>
        </div>
        <div class="kpi-cell ${compromisedIps > 0 ? "crit" : ""}">
          <span class="kpi-label">IPS WITH LOGIN SUCCESS</span>
          <span class="kpi-value">${fmtNum(compromisedIps)}</span>
          <span class="kpi-sub">AUTHENTICATED INTO FAKE ROUTER</span>
        </div>
        <div class="kpi-cell ${cmdIps > 0 ? "high" : ""}">
          <span class="kpi-label">IPS WITH SHELL COMMANDS</span>
          <span class="kpi-value">${fmtNum(cmdIps)}</span>
          <span class="kpi-sub">INTERACTIVE POST-AUTH ACTIVITY</span>
        </div>
        <div class="kpi-cell ${honeyIps > 0 ? "crit" : "ok"}">
          <span class="kpi-label">HONEYTOKEN TRIGGERS</span>
          <span class="kpi-value">${fmtNum(honeyIps)}</span>
          <span class="kpi-sub">DECOY SECRET READ / REUSE</span>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
            <span class="panel-title">ATTACKER DOSSIER INDEX</span>
            <div class="btn-group">
              ${PRESETS.map(
                (p) =>
                  `<button class="btn ${state.query.trim() === p.dsl ? "active" : ""}" data-preset="${escapeHtml(p.dsl)}">${p.label}</button>`
              ).join("")}
            </div>
          </div>
          <button class="btn" id="btn-copy-ips">COPY FILTERED IPS (${sorted.length})</button>
        </div>
        <div class="panel-body flush">
          <div class="table-scroll bounded-lg">
            <table class="soc-table">
              <thead>
                <tr>
                  <th style="width:136px;" class="${thCls("ip")}" data-sort="ip">SOURCE IP</th>
                  <th style="width:78px;" class="${thCls("max_severity_rank")}" data-sort="max_severity_rank">MAX SEV</th>
                  <th style="width:66px;" class="num ${thCls("score")}" data-sort="score">SCORE</th>
                  <th style="width:64px;" class="num ${thCls("alerts")}" data-sort="alerts">ALERTS</th>
                  <th style="width:68px;" class="num ${thCls("sessions")}" data-sort="sessions">SESS</th>
                  <th style="width:54px;" class="num ${thCls("successful_logins")}" data-sort="successful_logins">AUTH</th>
                  <th style="width:54px;" class="num ${thCls("commands")}" data-sort="commands">CMDS</th>
                  <th style="width:140px;">PROTOCOLS</th>
                  <th>FAMILIES / GEO / FLAGS</th>
                  <th style="width:76px;" class="${thCls("last_seen")}" data-sort="last_seen">LAST UTC</th>
                </tr>
              </thead>
              <tbody>
                ${
                  sorted.length
                    ? sorted
                        .map((a, idx) => {
                          const geo = a.geo ? `${a.geo.country || "?"}${a.geo.city ? "/" + a.geo.city : ""}` : "";
                          return `
                            <tr class="sev-row-${escapeHtml(a.max_severity)} ${idx === state.selectedRowIndex ? "selected" : ""}" data-row-idx="${idx}">
                              <td><span class="ip-link cell-strong">${escapeHtml(a.ip)}</span></td>
                              <td>${badgeSeverity(a.max_severity)}</td>
                              <td class="num cell-strong">${fmtNum(a.score)}</td>
                              <td class="num">${fmtNum(a.alerts)}</td>
                              <td class="num">${fmtNum(a.sessions)}</td>
                              <td class="num ${a.successful_logins > 0 ? "cell-strong" : "cell-muted"}">${fmtNum(a.successful_logins)}</td>
                              <td class="num ${a.commands > 0 ? "cell-strong" : "cell-muted"}">${fmtNum(a.commands)}</td>
                              <td>${(a.protocols || []).map(badgeProtocol).join(" ")}</td>
                              <td>
                                ${a.honeytoken_hit ? badgeTag("HONEYTOKEN") + " " : ""}
                                ${(a.families || []).slice(0, 2).map((f) => `<span class="badge tag-SCANNER_WEB">${escapeHtml(f)}</span>`).join(" ")}
                                ${geo ? `<span class="badge">${escapeHtml(geo)}</span>` : ""}
                              </td>
                              <td class="cell-muted">${escapeHtml(fmtTime(a.last_seen))}</td>
                            </tr>`;
                        })
                        .join("")
                    : `<tr><td colspan="10" class="empty-state">NO ATTACKER IPS MATCH CURRENT QUERY</td></tr>`
                }
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `;

  container.querySelector("#btn-copy-ips")?.addEventListener("click", () => {
    copyText(sorted.map((a) => a.ip).join("\n"), `Copied ${sorted.length} attacker IP(s)`);
  });

  container.querySelectorAll("[data-preset]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const expr = btn.dataset.preset;
      store.setQuery(expr);
      const qInput = document.getElementById("dsl-query-input");
      if (qInput) qInput.value = expr;
    });
  });

  container.querySelectorAll("th[data-sort]").forEach((th) => {
    th.addEventListener("click", () => store.setSort("attackers", th.dataset.sort));
  });

  container.querySelectorAll("tbody tr[data-row-idx]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const idx = Number(tr.dataset.rowIdx);
      const item = sorted[idx];
      if (!item) return;
      store.set({ selectedRowIndex: idx }, "selection");
      inspectAttacker(item.ip);
    });
  });
}

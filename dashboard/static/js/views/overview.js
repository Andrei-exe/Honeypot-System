/**
 * Overview page: the few numbers that matter, one chart, the top attackers
 * and the latest alerts. Everything else lives on its own page.
 */

import { TimelineChart } from "../charts/timeline.js";
import { inspectAttacker } from "../components/inspector.js";
import {
  asList,
  badgeProtocol,
  badgeSeverity,
  badgeTag,
  escapeHtml,
  fmtLocal,
  fmtNum,
  timeCell,
} from "../core/escape.js";
import { findNewKeys } from "../core/fresh.js";
import { filterItems } from "../core/query.js";
import { rowKey } from "../core/selection.js";
import { store } from "../core/store.js";

export const OVERVIEW_ROW_LIMIT = 10;
const TOP_LIMIT = 5;

let timelineInst = null;
let lastRows = [];

function applyFilter(expr, view = null) {
  if (view) store.setView(view);
  store.setQuery(expr);
  const input = document.getElementById("dsl-query-input");
  if (input) input.value = expr;
}

export function destroyOverview() {
  if (timelineInst) {
    timelineInst.destroy();
    timelineInst = null;
  }
}

export function getOverviewRows() {
  return lastRows;
}

function statCard(label, value, sub, tone = "") {
  return `
    <div class="kpi-cell ${tone}">
      <span class="kpi-label">${escapeHtml(label)}</span>
      <span class="kpi-value">${value}</span>
      <span class="kpi-sub">${sub}</span>
    </div>`;
}

function rankedList(items, labelKey, { barClass = "neutral", clickIp = false, empty }) {
  if (!items.length) return `<div class="empty-state">${escapeHtml(empty)}</div>`;
  const max = Math.max(1, ...items.map((x) => x.count || 0));
  return items
    .map((item) => {
      const label = escapeHtml(item[labelKey]);
      const pct = Math.round(((item.count || 0) / max) * 100);
      const labelHtml = clickIp
        ? `<span class="inline-bar-label clickable" data-inspect-ip="${label}" title="Open details">${label}</span>`
        : `<span class="inline-bar-label" title="${label}">${label}</span>`;
      return `
        <div class="inline-bar-row">
          ${labelHtml}
          <div class="meter-track"><div class="meter-seg ${barClass}" style="width:${pct}%"></div></div>
          <span class="inline-bar-count">${fmtNum(item.count)}</span>
        </div>`;
    })
    .join("");
}

export function renderOverview(container, state) {
  destroyOverview();
  const data = state.data.overview;
  if (!data) {
    container.innerHTML = `<div class="empty-state">Loading data from the threat engine…</div>`;
    lastRows = [];
    return;
  }

  const stats = data.stats || {};
  const counters = data.counters || {};
  const sev = stats.alerts_by_severity || {};
  const honeytokens = asList(data.honeytokens);
  const campaigns = state.data.campaigns;
  const recent = asList(data.recent_alerts);

  const fresh = findNewKeys("overview", recent.map((a) => rowKey("overview", a)));
  const filtered = filterItems(recent, state.query, "alert").items;
  lastRows = filtered.slice(0, OVERVIEW_ROW_LIMIT);

  const crit = sev.CRITICAL || 0;
  const high = sev.HIGH || 0;
  const logins = counters.successful_logins || 0;

  const topIps = asList(stats.top_ips).slice(0, TOP_LIMIT);
  const topCreds = asList(stats.top_credentials).slice(0, TOP_LIMIT);
  const topCountries = asList(stats.top_countries).slice(0, TOP_LIMIT);

  const botBits = [];
  if (counters.mirai_hits) botBits.push(`${fmtNum(counters.mirai_hits)} Mirai`);
  if (counters.miner_hits) botBits.push(`${fmtNum(counters.miner_hits)} crypto-miner`);

  const honeytokenBanner = honeytokens.length
    ? `
      <div class="honeytoken-banner">
        <div>
          <strong>Decoy files were accessed ${fmtNum(honeytokens.length)} time${honeytokens.length === 1 ? "" : "s"}.</strong>
          Someone read a fake secret (honeytoken) planted on the honeypot. This usually means a real person, not a bot.
        </div>
        <button class="btn danger" data-filter="has:honeytoken" data-target="alerts">Review</button>
      </div>`
    : "";

  container.innerHTML = `
    <div class="stack-8">
      <div class="page-head">
        <div>
          <h1 class="page-title">Overview</h1>
          <p class="page-sub">What the honeypot has seen${stats.first_seen ? ` since ${escapeHtml(fmtLocal(stats.first_seen))}` : ""}.</p>
        </div>
        <div class="page-actions">
          <a class="btn" href="/api/v1/export/report.md">Download report</a>
        </div>
      </div>

      ${honeytokenBanner}

      <div class="kpi-strip">
        ${statCard("Events recorded", fmtNum(stats.total_events), "connections, logins and commands")}
        ${statCard(
          "Alerts",
          fmtNum(stats.total_alerts),
          crit || high ? `${fmtNum(crit)} critical · ${fmtNum(high)} high` : "nothing serious so far",
          crit ? "crit" : ""
        )}
        ${statCard(
          "Attacker IPs",
          fmtNum(stats.unique_attacker_ips),
          campaigns && campaigns.total_campaigns ? `grouped into ${fmtNum(campaigns.total_campaigns)} campaign${campaigns.total_campaigns === 1 ? "" : "s"}` : "unique sources"
        )}
        ${statCard(
          "Successful logins",
          fmtNum(logins),
          botBits.length ? botBits.join(" · ") + " detected" : "attackers who got a shell",
          logins ? "crit" : ""
        )}
      </div>

      <div class="panel">
        <div class="panel-head">
          <span class="panel-title">Alerts over time</span>
          <span class="panel-meta">by protocol · hover for details</span>
        </div>
        <div class="panel-body">
          <div id="ov-timeline-chart"></div>
        </div>
      </div>

      <div class="${topCountries.length ? "grid-3" : "grid-2"}">
        <div class="panel">
          <div class="panel-head">
            <span class="panel-title">Most active attackers</span>
            <button class="btn ghost sm" data-nav="attackers">See all</button>
          </div>
          <div class="panel-body">
            ${rankedList(topIps, "ip", { barClass: "crit", clickIp: true, empty: "No attackers yet" })}
          </div>
        </div>

        <div class="panel">
          <div class="panel-head">
            <span class="panel-title">Most tried logins</span>
            <span class="panel-meta">user / password</span>
          </div>
          <div class="panel-body">
            ${rankedList(topCreds, "credentials", { barClass: "high", empty: "No login attempts yet" })}
          </div>
        </div>

        ${
          topCountries.length
            ? `
        <div class="panel">
          <div class="panel-head">
            <span class="panel-title">Top countries</span>
          </div>
          <div class="panel-body">
            ${rankedList(topCountries, "country", { empty: "No location data" })}
          </div>
        </div>`
            : ""
        }
      </div>

      <div class="panel">
        <div class="panel-head">
          <span class="panel-title">Latest alerts</span>
          <button class="btn ghost sm" data-nav="alerts">See all alerts</button>
        </div>
        <div class="panel-body flush">
          <div class="table-scroll">
            <table class="soc-table">
              <thead>
                <tr>
                  <th style="width:110px;">Time</th>
                  <th style="width:100px;">Severity</th>
                  <th style="width:90px;">Protocol</th>
                  <th style="width:150px;">Source IP</th>
                  <th>What happened</th>
                  <th style="width:70px;" class="num">Score</th>
                </tr>
              </thead>
              <tbody>
                ${
                  lastRows.length
                    ? lastRows
                        .map((al, idx) => {
                          const key = rowKey("overview", al);
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
                      <td class="num">${fmtNum(al.score)}</td>
                    </tr>`;
                        })
                        .join("")
                    : `<tr><td colspan="6" class="empty-state">${state.query ? "No alerts match this search" : "No alerts yet"}</td></tr>`
                }
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `;

  const tlEl = container.querySelector("#ov-timeline-chart");
  if (tlEl) {
    timelineInst = new TimelineChart(tlEl, { height: 220 });
    timelineInst.setData(data.timeline);
  }

  container.querySelectorAll("[data-nav]").forEach((btn) => {
    btn.addEventListener("click", () => store.setView(btn.dataset.nav));
  });
  container.querySelectorAll("[data-filter]").forEach((btn) => {
    btn.addEventListener("click", () => applyFilter(btn.dataset.filter, btn.dataset.target || null));
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
      store.set({ selectedKey: rowKey("overview", item) }, "selection");
      store.openInspector("alert", item, "summary");
    });
  });
}

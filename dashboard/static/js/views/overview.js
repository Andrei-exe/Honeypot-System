/**
 * View 1: LIVE TELEMETRY COCKPIT
 */

import { KillChainFunnel } from "../charts/funnel.js";
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
let funnelInst = null;
let lastRows = [];

function setDslAndSwitch(expr, view = null) {
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
  if (funnelInst) {
    funnelInst.destroy();
    funnelInst = null;
  }
}

export function getOverviewRows() {
  return lastRows;
}

export function renderOverview(container, state) {
  destroyOverview();
  const data = state.data.overview;
  if (!data) {
    container.innerHTML = `<div class="empty-state">AWAITING TELEMETRY SNAPSHOT FROM THREAT-ENGINE...</div>`;
    lastRows = [];
    return;
  }

  const stats = data.stats || {};
  const counters = data.counters || {};
  const health = data.session_health || {};
  const sevMap = stats.alerts_by_severity || {};
  const protoMap = stats.alerts_by_protocol || {};
  const honeytokens = data.honeytokens || [];

  const filteredAlerts = filterItems(data.recent_alerts || [], state.query, "alert").items;
  lastRows = filteredAlerts;

  const critCount = sevMap.CRITICAL || 0;
  const highCount = sevMap.HIGH || 0;
  const medCount = sevMap.MEDIUM || 0;
  const lowCount = sevMap.LOW || 0;

  const protoTotals = health.by_protocol || {};
  const sampleN = Math.max(1, health.sample_size || 1);
  const segW = (p) => (((protoTotals[p] || 0) / sampleN) * 100).toFixed(1);

  const pressureClass =
    health.pressure === "CRITICAL" ? "crit" : health.pressure === "ELEVATED" ? "high" : "ok";

  const topIps = (stats.top_ips || []).slice(0, 8);
  const maxIpCount = Math.max(1, ...topIps.map((x) => x.count || 0));

  const topCreds = (stats.top_credentials || []).slice(0, 8);
  const maxCredCount = Math.max(1, ...topCreds.map((x) => x.count || 0));

  const topCountries = (stats.top_countries || []).slice(0, 8);
  const maxCountryCount = Math.max(1, ...topCountries.map((x) => x.count || 0));

  container.innerHTML = `
    <div class="stack-8">
      <!-- HONEYTOKEN WATCH BANNER -->
      <div class="honeytoken-banner ${honeytokens.length ? "" : "nominal"}">
        <div style="display:flex;align-items:center;gap:8px;min-width:0;">
          <span class="led ${honeytokens.length ? "crit" : "ok"}"></span>
          <span class="cell-strong">HONEYTOKEN WATCH</span>
          <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
            ${
              honeytokens.length
                ? `${honeytokens.length} DECOY SECRET ACCESS EVENT(S) DETECTED (/etc/hostapd.conf, /etc/ppp/chap-secrets)`
                : "NOMINAL // MONITORING /etc/hostapd.conf & /etc/ppp/chap-secrets FOR DECOY ACCESS"
            }
          </span>
        </div>
        <div class="btn-group">
          ${
            honeytokens.length
              ? `<button class="btn danger" data-dsl="has:honeytoken" data-target="alerts">INVESTIGATE (${honeytokens.length})</button>`
              : `<button class="btn" data-nav="killchain">MITRE & SIGNATURES</button>`
          }
          <a class="btn" href="/api/v1/export/report.md">EXPORT REPORT.MD</a>
        </div>
      </div>

      <!-- KPI STRIP (6 CELLS) -->
      <div class="kpi-strip">
        <div class="kpi-cell">
          <span class="kpi-label">TOTAL EVENTS</span>
          <span class="kpi-value">${fmtNum(stats.total_events)}</span>
          <span class="kpi-sub">FIRST ${escapeHtml(fmtTime(stats.first_seen))} UTC</span>
        </div>
        <div class="kpi-cell ${critCount > 0 ? "crit" : "high"}">
          <span class="kpi-label">TOTAL ALERTS</span>
          <span class="kpi-value">${fmtNum(stats.total_alerts)}</span>
          <span class="kpi-sub">CRIT:${fmtNum(critCount)} HIGH:${fmtNum(highCount)} MED:${fmtNum(medCount)}</span>
        </div>
        <div class="kpi-cell accent">
          <span class="kpi-label">UNIQUE ATTACKER IPS</span>
          <span class="kpi-value">${fmtNum(stats.unique_attacker_ips)}</span>
          <span class="kpi-sub">CAMPAIGNS:${fmtNum(counters.campaigns)} FAMILIES:${fmtNum(counters.families)}</span>
        </div>
        <div class="kpi-cell ${counters.successful_logins > 0 ? "crit" : ""}">
          <span class="kpi-label">COMPROMISED AUTH (500W)</span>
          <span class="kpi-value">${fmtNum(counters.successful_logins)}</span>
          <span class="kpi-sub">MIRAI:${fmtNum(counters.mirai_hits)} MINER:${fmtNum(counters.miner_hits)}</span>
        </div>
        <div class="kpi-cell ${pressureClass}">
          <span class="kpi-label">SESSIONSTORE BUFFER</span>
          <span class="kpi-value">${fmtNum(health.total_stored)}<span style="font-size:11px;color:var(--text-muted);">/${fmtNum(health.capacity || 2000)}</span></span>
          <span class="kpi-sub">${health.saturation_pct || 0}% // ${escapeHtml(health.pressure || "NOMINAL")}${health.eviction_risk ? " [EVICTION RISK]" : ""}</span>
        </div>
        <div class="kpi-cell">
          <span class="kpi-label">PROTOCOL MIX (SESSIONS)</span>
          <span class="kpi-value" style="font-size:14px;padding-top:4px;">INT ${health.interactive_share_pct || 0}% / HTTP ${health.http_share_pct || 0}%</span>
          <span class="kpi-sub">SSH:${protoTotals.SSH || 0} TEL:${protoTotals.TELNET || 0} FTP:${protoTotals.FTP || 0} HTTP:${protoTotals.HTTP || 0}</span>
        </div>
      </div>

      <!-- CHARTS ROW: TIMELINE + KILL-CHAIN & BUFFER -->
      <div class="grid-asymmetric">
        <div class="panel">
          <div class="panel-head">
            <span class="panel-title">ATTACK TELEMETRY TIMELINE (MULTI-PROTOCOL)</span>
            <span class="panel-meta">RECENT ${fmtNum(filteredAlerts.length)} ALERTS // RED CAP = CRITICAL</span>
          </div>
          <div class="panel-body">
            <div id="ov-timeline-chart"></div>
          </div>
        </div>

        <div class="stack-8">
          <div class="panel">
            <div class="panel-head">
              <span class="panel-title">KILL-CHAIN FUNNEL</span>
              <span class="panel-meta">CLICK STAGE TO FILTER SESSIONS</span>
            </div>
            <div class="panel-body">
              <div id="ov-funnel-chart"></div>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head">
              <span class="panel-title">SESSIONSTORE SATURATION & PROTOCOL SHARE</span>
              <span class="panel-meta">${escapeHtml(health.pressure || "NOMINAL")}</span>
            </div>
            <div class="panel-body stack-8">
              <div class="meter-track" title="SSH / TELNET / FTP / HTTP share in active SessionStore">
                <div class="meter-seg ssh" style="width:${segW("SSH")}%"></div>
                <div class="meter-seg telnet" style="width:${segW("TELNET")}%"></div>
                <div class="meter-seg ftp" style="width:${segW("FTP")}%"></div>
                <div class="meter-seg http" style="width:${segW("HTTP")}%"></div>
              </div>
              <div style="display:flex;justify-content:space-between;font-family:var(--font-mono);font-size:10px;color:var(--text-secondary);">
                <span>SSH:${protoTotals.SSH || 0}</span>
                <span>TELNET:${protoTotals.TELNET || 0}</span>
                <span>FTP:${protoTotals.FTP || 0}</span>
                <span>HTTP:${protoTotals.HTTP || 0}</span>
                <button class="btn" style="height:18px;" data-nav="sessions">OPEN SESSIONS</button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 3-COLUMN INTELLIGENCE STRIP -->
      <div class="grid-3">
        <div class="panel">
          <div class="panel-head">
            <span class="panel-title">TOP ATTACKER IPS</span>
            <span class="panel-meta">CLICK IP FOR DOSSIER</span>
          </div>
          <div class="panel-body">
            ${
              topIps.length
                ? topIps
                    .map((item) => {
                      const pct = Math.round(((item.count || 0) / maxIpCount) * 100);
                      return `
                        <div class="inline-bar-row">
                          <span class="inline-bar-label clickable" data-inspect-ip="${escapeHtml(item.ip)}">${escapeHtml(item.ip)}</span>
                          <div class="meter-track"><div class="meter-seg crit" style="width:${pct}%"></div></div>
                          <span class="inline-bar-count">${fmtNum(item.count)}</span>
                        </div>`;
                    })
                    .join("")
                : `<div class="empty-state">NO ATTACKER IPS YET</div>`
            }
          </div>
        </div>

        <div class="panel">
          <div class="panel-head">
            <span class="panel-title">TOP TARGETED CREDENTIALS</span>
            <span class="panel-meta">LOGIN_ATTEMPT PAIRS</span>
          </div>
          <div class="panel-body">
            ${
              topCreds.length
                ? topCreds
                    .map((item) => {
                      const pct = Math.round(((item.count || 0) / maxCredCount) * 100);
                      return `
                        <div class="inline-bar-row">
                          <span class="inline-bar-label" title="${escapeHtml(item.credentials)}">${escapeHtml(item.credentials)}</span>
                          <div class="meter-track"><div class="meter-seg high" style="width:${pct}%"></div></div>
                          <span class="inline-bar-count">${fmtNum(item.count)}</span>
                        </div>`;
                    })
                    .join("")
                : `<div class="empty-state">NO CREDENTIALS RECORDED</div>`
            }
          </div>
        </div>

        <div class="panel">
          <div class="panel-head">
            <span class="panel-title">${topCountries.length ? "TOP SOURCE COUNTRIES (GEOIP)" : "ALERTS BY PROTOCOL & SEVERITY"}</span>
            <span class="panel-meta">${stats.geoip ? "GEOIP ON" : "GEOIP OFF"}</span>
          </div>
          <div class="panel-body">
            ${
              topCountries.length
                ? topCountries
                    .map((item) => {
                      const pct = Math.round(((item.count || 0) / maxCountryCount) * 100);
                      return `
                        <div class="inline-bar-row">
                          <span class="inline-bar-label">${escapeHtml(item.country)}</span>
                          <div class="meter-track"><div class="meter-seg ssh" style="width:${pct}%"></div></div>
                          <span class="inline-bar-count">${fmtNum(item.count)}</span>
                        </div>`;
                    })
                    .join("")
                : Object.entries(protoMap)
                    .sort((a, b) => b[1] - a[1])
                    .map(([proto, cnt]) => {
                      const maxP = Math.max(1, ...Object.values(protoMap));
                      const pct = Math.round((cnt / maxP) * 100);
                      const segCls = ["ssh", "telnet", "ftp", "http"].includes(proto.toLowerCase())
                        ? proto.toLowerCase()
                        : "other";
                      return `
                        <div class="inline-bar-row">
                          <span class="inline-bar-label clickable" data-dsl="proto:${escapeHtml(proto.toLowerCase())}" data-target="alerts">${escapeHtml(proto)}</span>
                          <div class="meter-track"><div class="meter-seg ${segCls}" style="width:${pct}%"></div></div>
                          <span class="inline-bar-count">${fmtNum(cnt)}</span>
                        </div>`;
                    })
                    .join("") +
                  `<div style="margin-top:8px;padding-top:6px;border-top:1px solid var(--border-subtle);display:flex;gap:6px;flex-wrap:wrap;font-family:var(--font-mono);font-size:10px;">
                    <span class="badge sev-CRITICAL">CRIT ${fmtNum(critCount)}</span>
                    <span class="badge sev-HIGH">HIGH ${fmtNum(highCount)}</span>
                    <span class="badge sev-MEDIUM">MED ${fmtNum(medCount)}</span>
                    <span class="badge sev-LOW">LOW ${fmtNum(lowCount)}</span>
                  </div>`
            }
          </div>
        </div>
      </div>

      <!-- LIVE ALERT STREAM TABLE -->
      <div class="panel">
        <div class="panel-head">
          <span class="panel-title">LIVE ALERT STREAM (LATEST ${filteredAlerts.length})</span>
          <div class="panel-meta">
            <span>CLICK ROW = INSPECT // J/K + ENTER</span>
            <button class="btn" data-nav="alerts">FULL ALERTS EXPLORER</button>
          </div>
        </div>
        <div class="panel-body flush">
          <div class="table-scroll bounded-md">
            <table class="soc-table">
              <thead>
                <tr>
                  <th style="width:74px;">UTC</th>
                  <th style="width:76px;">SEV</th>
                  <th style="width:68px;">PROTO</th>
                  <th style="width:128px;">SOURCE IP</th>
                  <th style="width:105px;">SESSION</th>
                  <th style="width:86px;">MITRE</th>
                  <th>ALERT REASON / PAYLOAD</th>
                  <th style="width:46px;" class="num">PTS</th>
                </tr>
              </thead>
              <tbody>
                ${
                  filteredAlerts.length
                    ? filteredAlerts
                        .slice(0, 40)
                        .map(
                          (al, idx) => `
                          <tr class="sev-row-${escapeHtml(al.severity)} ${idx === state.selectedRowIndex ? "selected" : ""}" data-row-idx="${idx}">
                            <td class="cell-muted">${escapeHtml(fmtTime(al.timestamp))}</td>
                            <td>${badgeSeverity(al.severity)}</td>
                            <td>${badgeProtocol(al.protocol)}</td>
                            <td><span class="ip-link" data-inspect-ip="${escapeHtml(al.source_ip)}">${escapeHtml(al.source_ip)}</span></td>
                            <td class="cell-muted">${escapeHtml(shortId(al.session_id, 12))}</td>
                            <td style="color:var(--state-accent);">${escapeHtml(al.technique || "-")}</td>
                            <td title="${escapeHtml(al.alert_reason)}">
                              ${(al.tags || []).slice(0, 2).map(badgeTag).join(" ")}
                              <span>${escapeHtml(al.alert_reason)}</span>
                            </td>
                            <td class="num cell-strong">${fmtNum(al.score)}</td>
                          </tr>`
                        )
                        .join("")
                    : `<tr><td colspan="8" class="empty-state">NO ALERTS MATCH CURRENT FILTER</td></tr>`
                }
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `;

  // Mount Canvas charts
  const tlEl = container.querySelector("#ov-timeline-chart");
  if (tlEl) {
    timelineInst = new TimelineChart(tlEl, { height: 220 });
    timelineInst.setData(data.timeline);
  }
  const fnEl = container.querySelector("#ov-funnel-chart");
  if (fnEl) {
    funnelInst = new KillChainFunnel(fnEl, {
      height: 150,
      onStageClick: (stage) => setDslAndSwitch(`stage:"${stage}"`, "sessions"),
    });
    funnelInst.setData(data.funnel);
  }

  // Bind interactions
  container.querySelectorAll("[data-nav]").forEach((btn) => {
    btn.addEventListener("click", () => store.setView(btn.dataset.nav));
  });
  container.querySelectorAll("[data-dsl]").forEach((btn) => {
    btn.addEventListener("click", () => setDslAndSwitch(btn.dataset.dsl, btn.dataset.target || null));
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
      const item = filteredAlerts[idx];
      if (!item) return;
      store.set({ selectedRowIndex: idx }, "selection");
      store.openInspector("alert", item, "summary");
    });
  });
}

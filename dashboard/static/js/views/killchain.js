/**
 * View 6: KILL-CHAIN FUNNEL, MITRE ATT&CK MATRIX & HONEYTOKEN / BOT SIGNATURES
 */

import { KillChainFunnel } from "../charts/funnel.js";
import { inspectAttacker } from "../components/inspector.js";
import {
  badgeProtocol,
  badgeSeverity,
  escapeHtml,
  fmtNum,
  fmtTime,
} from "../core/escape.js";
import { store } from "../core/store.js";

let funnelInst = null;

export function destroyKillchain() {
  if (funnelInst) {
    funnelInst.destroy();
    funnelInst = null;
  }
}

function pivotDsl(expr, view) {
  store.setView(view);
  store.setQuery(expr);
  const qInput = document.getElementById("dsl-query-input");
  if (qInput) qInput.value = expr;
}

export function renderKillchain(container, state) {
  destroyKillchain();
  const data = state.data.killchain;
  if (!data) {
    container.innerHTML = `<div class="empty-state">BUILDING MITRE ATT&CK MATRIX & KILL-CHAIN TELEMETRY...</div>`;
    return;
  }

  const matrix = data.matrix || [];
  const honeytokens = data.honeytokens || [];
  const bots = data.bot_signatures || {};
  const techniques = (data.navigator && data.navigator.techniques) || [];
  const maxTechScore = Math.max(1, ...techniques.map((t) => t.score || 0));

  function heatClass(score) {
    const ratio = score / maxTechScore;
    if (ratio >= 0.6) return "mitre-heat-high";
    if (ratio >= 0.25) return "mitre-heat-med";
    return "mitre-heat-low";
  }

  const botSamples = [
    ...(bots.mirai_samples || []).map((a) => ({ ...a, _botKind: "MIRAI" })),
    ...(bots.miner_samples || []).map((a) => ({ ...a, _botKind: "CRYPTOMINER" })),
  ].slice(0, 25);

  container.innerHTML = `
    <div class="stack-8">
      <!-- TOP ROW: KILL-CHAIN FUNNEL + BOT/HONEYTOKEN COUNTERS -->
      <div class="grid-asymmetric">
        <div class="panel">
          <div class="panel-head">
            <span class="panel-title">SESSION KILL-CHAIN CONVERSION (${fmtNum(data.total_sessions || 0)} SESSIONS)</span>
            <span class="panel-meta">CLICK ANY STAGE TO PIVOT INTO SESSIONS</span>
          </div>
          <div class="panel-body">
            <div id="kc-funnel-canvas"></div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-head">
            <span class="panel-title">SPECIALIZED DETECTIONS (ROUTER PERSONA)</span>
            <a class="btn primary" href="/api/v1/export/navigator.json">EXPORT ATT&CK LAYER</a>
          </div>
          <div class="panel-body stack-8">
            <div class="kv-grid">
              <div class="kv-k">ATT&CK TECHS</div>
              <div class="kv-v cell-strong">${fmtNum(techniques.length)} OBSERVED TECHNIQUES</div>
              <div class="kv-k">HONEYTOKENS</div>
              <div class="kv-v ${honeytokens.length ? "cell-strong" : "cell-muted"}" style="${honeytokens.length ? "color:var(--sev-critical);" : ""}">
                ${fmtNum(honeytokens.length)} HIT(S) (/etc/hostapd.conf, /etc/ppp/chap-secrets)
              </div>
              <div class="kv-k">MIRAI PROBES</div>
              <div class="kv-v">
                ${fmtNum(bots.mirai_count || 0)} EVENT(S)
                <button class="btn" style="margin-left:8px;height:18px;" data-pivot="tag:mirai">FILTER</button>
              </div>
              <div class="kv-k">CRYPTOMINERS</div>
              <div class="kv-v">
                ${fmtNum(bots.miner_count || 0)} EVENT(S) (nproc / free / crontab)
                <button class="btn" style="margin-left:8px;height:18px;" data-pivot="tag:cryptominer">FILTER</button>
              </div>
            </div>
            <div class="mono" style="font-size:10px;color:var(--text-muted);">
              ATT&CK Navigator JSON layer matches v4.5 enterprise-attack format and can be imported directly into MITRE ATT&CK Navigator.
            </div>
          </div>
        </div>
      </div>

      <!-- MITRE ATT&CK TACTICS MATRIX -->
      <div class="panel">
        <div class="panel-head">
          <span class="panel-title">MITRE ATT&CK OBSERVED MATRIX</span>
          <span class="panel-meta">CLICK TECHNIQUE CELL TO FILTER ALERTS BY CODE</span>
        </div>
        <div class="panel-body">
          ${
            matrix.length
              ? `<div class="mitre-grid">
                  ${matrix
                    .map(
                      (col) => `
                      <div class="mitre-col">
                        <div class="mitre-col-head">
                          <span>${escapeHtml(col.tactic)}</span>
                          <span class="cell-muted">${col.techniques.length}</span>
                        </div>
                        ${col.techniques
                          .map(
                            (t) => `
                            <div class="mitre-cell ${heatClass(t.score)}" data-tech="${escapeHtml(t.id)}">
                              <div class="mitre-id">
                                <span>${escapeHtml(t.id)}</span>
                                <span>${fmtNum(t.score)}x</span>
                              </div>
                              <div class="mitre-name">${escapeHtml(t.name)}</div>
                            </div>`
                          )
                          .join("")}
                      </div>`
                    )
                    .join("")}
                </div>`
              : `<div class="empty-state">NO MITRE ATT&CK TECHNIQUES MAPPED YET</div>`
          }
        </div>
      </div>

      <!-- BOTTOM ROW: HONEYTOKEN EVENTS + MIRAI / CRYPTOMINER SAMPLES -->
      <div class="grid-2">
        <div class="panel">
          <div class="panel-head">
            <span class="panel-title">HONEYTOKEN ACCESS LOG (${honeytokens.length})</span>
            <span class="panel-meta">DECOY CREDENTIALS & CONFIG FILES</span>
          </div>
          <div class="panel-body flush">
            ${
              honeytokens.length
                ? `<table class="soc-table">
                    <thead><tr><th style="width:72px;">UTC</th><th style="width:120px;">IP</th><th style="width:62px;">PROTO</th><th>EVENT</th></tr></thead>
                    <tbody>
                      ${honeytokens
                        .map(
                          (h, idx) => `
                          <tr class="sev-row-CRITICAL" data-honey-idx="${idx}">
                            <td class="cell-muted">${escapeHtml(fmtTime(h.timestamp))}</td>
                            <td><span class="ip-link" data-inspect-ip="${escapeHtml(h.source_ip)}">${escapeHtml(h.source_ip)}</span></td>
                            <td>${badgeProtocol(h.protocol)}</td>
                            <td title="${escapeHtml(h.alert_reason)}">${escapeHtml(h.alert_reason)}</td>
                          </tr>`
                        )
                        .join("")}
                    </tbody>
                  </table>`
                : `<div class="empty-state">NO HONEYTOKEN READS OR REUSE EVENTS IN RECENT BUFFER</div>`
            }
          </div>
        </div>

        <div class="panel">
          <div class="panel-head">
            <span class="panel-title">MIRAI & CRYPTOMINER PROBE SAMPLES (${botSamples.length})</span>
            <span class="panel-meta">BUSYBOX / NPROC / CRONTAB / FREE</span>
          </div>
          <div class="panel-body flush">
            ${
              botSamples.length
                ? `<table class="soc-table">
                    <thead><tr><th style="width:72px;">UTC</th><th style="width:94px;">CLASS</th><th style="width:118px;">IP</th><th>COMMAND / REASON</th></tr></thead>
                    <tbody>
                      ${botSamples
                        .map(
                          (b, idx) => `
                          <tr class="sev-row-${escapeHtml(b.severity)}" data-bot-idx="${idx}">
                            <td class="cell-muted">${escapeHtml(fmtTime(b.timestamp))}</td>
                            <td><span class="badge tag-${b._botKind}">${b._botKind}</span></td>
                            <td><span class="ip-link" data-inspect-ip="${escapeHtml(b.source_ip)}">${escapeHtml(b.source_ip)}</span></td>
                            <td title="${escapeHtml(b.alert_reason)}">${escapeHtml((b.payload_details && b.payload_details.command) || b.alert_reason)}</td>
                          </tr>`
                        )
                        .join("")}
                    </tbody>
                  </table>`
                : `<div class="empty-state">NO MIRAI OR CRYPTOMINER SIGNATURES IN RECENT BUFFER</div>`
            }
          </div>
        </div>
      </div>
    </div>
  `;

  const fnEl = container.querySelector("#kc-funnel-canvas");
  if (fnEl) {
    funnelInst = new KillChainFunnel(fnEl, {
      height: 196,
      onStageClick: (stage) => pivotDsl(`stage:"${stage}"`, "sessions"),
    });
    funnelInst.setData(data.funnel);
  }

  container.querySelectorAll("[data-tech]").forEach((el) => {
    el.addEventListener("click", () => pivotDsl(`tech:${el.dataset.tech}`, "alerts"));
  });

  container.querySelectorAll("[data-pivot]").forEach((btn) => {
    btn.addEventListener("click", () => pivotDsl(btn.dataset.pivot, "alerts"));
  });

  container.querySelectorAll("[data-inspect-ip]").forEach((el) => {
    el.addEventListener("click", (ev) => {
      ev.stopPropagation();
      inspectAttacker(el.dataset.inspectIp);
    });
  });

  container.querySelectorAll("tr[data-honey-idx]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const item = honeytokens[Number(tr.dataset.honeyIdx)];
      if (item) store.openInspector("alert", item, "summary");
    });
  });

  container.querySelectorAll("tr[data-bot-idx]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const item = botSamples[Number(tr.dataset.botIdx)];
      if (item) store.openInspector("alert", item, "payload");
    });
  });
}

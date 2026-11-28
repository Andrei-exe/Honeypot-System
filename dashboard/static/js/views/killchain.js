/**
 * Attack techniques page: how far attackers got, which MITRE ATT&CK techniques
 * were seen, the decoy secret trail (honeytokens) and known bot signatures.
 */

import { KillChainFunnel } from "../charts/funnel.js";
import { honeytrailMarkup } from "../components/honeytrail.js";
import { inspectAttacker } from "../components/inspector.js";
import { asList, badgeProtocol, escapeHtml, fmtNum, timeCell } from "../core/escape.js";
import { store } from "../core/store.js";

let funnelInst = null;
let honeyMode = "trail"; // "trail" or "list", kept while the page is redrawn

export function destroyKillchain() {
  if (funnelInst) {
    funnelInst.destroy();
    funnelInst = null;
  }
}

function pivot(expr, view) {
  store.setView(view);
  store.setQuery(expr);
  const qInput = document.getElementById("dsl-query-input");
  if (qInput) qInput.value = expr;
}

export function renderKillchain(container, state) {
  destroyKillchain();
  const data = state.data.killchain;
  if (!data) {
    container.innerHTML = `<div class="empty-state">Loading attack techniques…</div>`;
    return;
  }

  const matrix = asList(data.matrix);
  const honeytokens = asList(data.honeytokens);
  const bots = data.bot_signatures || {};
  const techniques = asList(data.navigator && data.navigator.techniques);
  const maxTechScore = Math.max(1, ...techniques.map((t) => t.score || 0));

  const heatClass = (score) => {
    const ratio = (score || 0) / maxTechScore;
    if (ratio >= 0.6) return "mitre-heat-high";
    if (ratio >= 0.25) return "mitre-heat-med";
    return "mitre-heat-low";
  };

  let trail = { html: "", items: [], trail: { passedOn: 0 } };
  try {
    trail = honeytrailMarkup(honeytokens);
  } catch (err) {
    console.error("[honeytrail]", err);
    honeyMode = "list";
  }
  const passedOn = trail.trail.passedOn || 0;

  const botSamples = [
    ...asList(bots.mirai_samples).map((a) => ({ ...a, _bot: "Mirai" })),
    ...asList(bots.miner_samples).map((a) => ({ ...a, _bot: "Crypto-miner" })),
  ].slice(0, 20);

  container.innerHTML = `
    <div class="stack-8">
      <div class="page-head">
        <div>
          <h1 class="page-title">Attack techniques</h1>
          <div class="inline-stats">
            <span><strong>${fmtNum(techniques.length)}</strong> MITRE technique${techniques.length === 1 ? "" : "s"} seen</span>
            <span class="${honeytokens.length ? "crit" : ""}"><strong>${fmtNum(honeytokens.length)}</strong> honeytoken hit${honeytokens.length === 1 ? "" : "s"}</span>
            ${passedOn ? `<span class="crit"><strong>${fmtNum(passedOn)}</strong> secret${passedOn === 1 ? "" : "s"} passed on</span>` : ""}
            <span><strong>${fmtNum(bots.mirai_count || 0)}</strong> Mirai</span>
            <span><strong>${fmtNum(bots.miner_count || 0)}</strong> crypto-miner</span>
          </div>
        </div>
        <div class="page-actions">
          <a class="btn" href="/api/v1/export/navigator.json" title="Import this file in the MITRE ATT&CK Navigator">Export ATT&amp;CK layer</a>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <span class="panel-title">How far attackers got</span>
          <span class="panel-meta">${fmtNum(data.total_sessions || 0)} sessions · click a stage to see them</span>
        </div>
        <div class="panel-body">
          <div id="kc-funnel-canvas"></div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <span class="panel-title">MITRE ATT&amp;CK techniques</span>
          <span class="panel-meta">click a technique to see its alerts</span>
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
                          <span class="cell-muted">${asList(col.techniques).length}</span>
                        </div>
                        ${asList(col.techniques)
                          .map(
                            (t) => `
                            <div class="mitre-cell ${heatClass(t.score)}" data-tech="${escapeHtml(t.id)}" title="Show alerts for ${escapeHtml(t.id)}">
                              <div class="mitre-id"><span>${escapeHtml(t.id)}</span><span>${fmtNum(t.score)}×</span></div>
                              <div class="mitre-name">${escapeHtml(t.name)}</div>
                            </div>`
                          )
                          .join("")}
                      </div>`
                    )
                    .join("")}
                </div>`
              : `<div class="empty-state">No techniques mapped yet</div>`
          }
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <span class="panel-title">Decoy secrets</span>
          <div class="panel-meta">
            <span>who read a decoy file, and who logged in with its secret</span>
            <div class="seg" role="tablist" aria-label="Decoy secrets view">
              <button class="${honeyMode === "trail" ? "active" : ""}" data-honey-mode="trail">Trail</button>
              <button class="${honeyMode === "list" ? "active" : ""}" data-honey-mode="list">List</button>
            </div>
          </div>
        </div>
        <div class="panel-body ${honeyMode === "list" ? "flush" : ""}">
          ${
            honeyMode === "trail"
              ? trail.html
              : honeytokens.length
              ? `<div class="table-scroll bounded-md" data-scroll-key="kc-honey">
                  <table class="soc-table">
                    <thead><tr><th style="width:110px;">Time</th><th style="width:150px;">Source IP</th><th style="width:90px;">Protocol</th><th>What happened</th></tr></thead>
                    <tbody>
                      ${honeytokens
                        .map(
                          (h, idx) => `
                        <tr class="sev-row-CRITICAL" data-honey-idx="${idx}">
                          <td>${timeCell(h.timestamp)}</td>
                          <td><span class="ip-link" data-inspect-ip="${escapeHtml(h.source_ip)}">${escapeHtml(h.source_ip)}</span></td>
                          <td>${badgeProtocol(h.protocol)}</td>
                          <td title="${escapeHtml(h.alert_reason)}">${escapeHtml(h.alert_reason)}</td>
                        </tr>`
                        )
                        .join("")}
                    </tbody>
                  </table>
                </div>`
              : `<div class="empty-state">Nobody has opened the decoy files yet</div>`
          }
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <span class="panel-title">Known bots</span>
          <div class="panel-meta">
            <button class="btn sm" data-pivot="tag:mirai">Mirai alerts</button>
            <button class="btn sm" data-pivot="tag:cryptominer">Miner alerts</button>
          </div>
        </div>
        <div class="panel-body flush">
          ${
            botSamples.length
              ? `<div class="table-scroll bounded-md" data-scroll-key="kc-bots">
                  <table class="soc-table">
                    <thead><tr><th style="width:110px;">Time</th><th style="width:120px;">Bot</th><th style="width:150px;">Source IP</th><th>Command</th></tr></thead>
                    <tbody>
                      ${botSamples
                        .map(
                          (b, idx) => `
                        <tr data-bot-idx="${idx}">
                          <td>${timeCell(b.timestamp)}</td>
                          <td>${escapeHtml(b._bot)}</td>
                          <td><span class="ip-link" data-inspect-ip="${escapeHtml(b.source_ip)}">${escapeHtml(b.source_ip)}</span></td>
                          <td class="mono" title="${escapeHtml(b.alert_reason)}">${escapeHtml((b.payload_details && b.payload_details.command) || b.alert_reason)}</td>
                        </tr>`
                        )
                        .join("")}
                    </tbody>
                  </table>
                </div>`
              : `<div class="empty-state">No Mirai or crypto-miner activity seen</div>`
          }
        </div>
      </div>
    </div>
  `;

  const fnEl = container.querySelector("#kc-funnel-canvas");
  if (fnEl) {
    funnelInst = new KillChainFunnel(fnEl, {
      height: 210,
      onStageClick: (stage) => pivot(`stage:"${stage}"`, "sessions"),
    });
    funnelInst.setData(data.funnel);
  }

  container.querySelectorAll("[data-tech]").forEach((el) => {
    el.addEventListener("click", () => pivot(`tech:${el.dataset.tech}`, "alerts"));
  });

  container.querySelectorAll("[data-pivot]").forEach((btn) => {
    btn.addEventListener("click", () => pivot(btn.dataset.pivot, "alerts"));
  });

  container.querySelectorAll("[data-inspect-ip]").forEach((el) => {
    el.addEventListener("click", (ev) => {
      ev.stopPropagation();
      inspectAttacker(el.dataset.inspectIp);
    });
  });

  container.querySelectorAll("[data-honey-mode]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (honeyMode === btn.dataset.honeyMode) return;
      honeyMode = btn.dataset.honeyMode;
      renderKillchain(container, store.get());
    });
  });

  container.querySelectorAll("[data-ht-idx]").forEach((el) => {
    el.addEventListener("click", () => {
      const item = trail.items[Number(el.dataset.htIdx)];
      if (item) store.openInspector("alert", item, "summary");
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
      if (item) store.openInspector("alert", item, "summary");
    });
  });
}

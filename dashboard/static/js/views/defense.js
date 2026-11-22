/**
 * View 7: DEFENSE, FIREWALL RULESET GENERATOR & EXPORT CENTER
 */

import { inspectAttacker } from "../components/inspector.js";
import { badgeProtocol, copyText, escapeHtml, fmtNum } from "../core/escape.js";
import { store } from "../core/store.js";

const FORMATS = [
  { id: "nftables", label: "NFTABLES (.NFT)" },
  { id: "iptables", label: "IPTABLES (.SH)" },
  { id: "ufw", label: "UFW (.SH)" },
  { id: "fail2ban", label: "FAIL2BAN" },
  { id: "plain", label: "PLAIN IP LIST" },
];

export function renderDefense(container, state) {
  const data = state.data.defense;
  if (!data) {
    container.innerHTML = `<div class="empty-state">BUILDING BLOCKLIST RULESETS & MITIGATION RECOMMENDATIONS...</div>`;
    return;
  }

  const activeFmt = state.defenseFormat || "nftables";
  const formats = data.formats || {};
  const previewText = formats[activeFmt] || "# No rules generated";
  const recs = data.recommendations || [];
  const blockedIps = data.blocked_ips || [];

  container.innerHTML = `
    <div class="stack-8">
      <!-- EXPORT CENTER RIBBON -->
      <div class="panel">
        <div class="panel-head">
          <span class="panel-title">INCIDENT RESPONSE & EXPORT CENTER</span>
          <span class="panel-meta">IN-MEMORY GENERATION // ZERO DISK WRITES (READ-ONLY CONTAINER)</span>
        </div>
        <div class="panel-body" style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;">
          <div class="btn-group">
            <a class="btn primary" href="/api/v1/export/report.md">INCIDENT REPORT (.MD)</a>
            <a class="btn" href="/api/v1/export/alerts.csv">ALERTS (.CSV)</a>
            <a class="btn" href="/api/v1/export/alerts.json">ALERTS (.JSON)</a>
            <a class="btn" href="/api/v1/export/sessions.csv">SESSIONS (.CSV)</a>
            <a class="btn" href="/api/v1/export/sessions.json">SESSIONS (.JSON)</a>
            <a class="btn" href="/api/v1/export/navigator.json">MITRE ATT&CK LAYER (.JSON)</a>
          </div>
          <span class="badge sev-HIGH">BLOCKLIST TARGETS: ${fmtNum(data.blocked_ip_count || 0)} IP(S)</span>
        </div>
      </div>

      <!-- FIREWALL GENERATOR + RECOMMENDATIONS -->
      <div class="grid-asymmetric">
        <div class="panel">
          <div class="panel-head">
            <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
              <span class="panel-title">FIREWALL BLOCKLIST GENERATOR</span>
              <div class="btn-group">
                ${FORMATS.map(
                  (f) =>
                    `<button class="btn ${activeFmt === f.id ? "active" : ""}" data-def-fmt="${f.id}">${f.label}</button>`
                ).join("")}
              </div>
            </div>
            <div class="btn-group">
              <button class="btn" id="btn-copy-rules">COPY RULES</button>
              <a class="btn primary" href="/api/v1/export/blocklist?fmt=${encodeURIComponent(activeFmt)}">DOWNLOAD</a>
            </div>
          </div>
          <div class="panel-body flush">
            <pre class="code-block tall" id="defense-code-preview">${escapeHtml(previewText)}</pre>
          </div>
        </div>

        <div class="stack-8">
          <div class="panel">
            <div class="panel-head">
              <span class="panel-title">PRIORITIZED MITIGATIONS (${recs.length})</span>
              <span class="panel-meta">FROM RECENT ALERTS</span>
            </div>
            <div class="panel-body flush">
              <div class="table-scroll bounded-md">
                ${
                  recs.length
                    ? `<table class="soc-table">
                        <thead><tr><th style="width:48px;" class="num">HITS</th><th style="width:94px;">PROTOS</th><th>RECOMMENDATION</th></tr></thead>
                        <tbody>
                          ${recs
                            .map(
                              (r) => `
                              <tr>
                                <td class="num cell-strong">${fmtNum(r.count)}</td>
                                <td>${(r.protocols || []).slice(0, 2).map(badgeProtocol).join(" ")}</td>
                                <td style="white-space:normal;padding:4px 7px;">${escapeHtml(r.text)}</td>
                              </tr>`
                            )
                            .join("")}
                        </tbody>
                      </table>`
                    : `<div class="empty-state">NO MITIGATION RECOMMENDATIONS YET</div>`
                }
              </div>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head">
              <span class="panel-title">ACTIVE BLOCKLIST IPS (${blockedIps.length})</span>
              <span class="panel-meta">CLICK IP FOR DOSSIER</span>
            </div>
            <div class="panel-body">
              ${
                blockedIps.length
                  ? `<div style="display:flex;flex-wrap:wrap;gap:4px;">
                      ${blockedIps
                        .map(
                          (ip) =>
                            `<span class="badge ip-link" data-inspect-ip="${escapeHtml(ip)}">${escapeHtml(ip)}</span>`
                        )
                        .join("")}
                    </div>`
                  : `<div class="empty-state">NO IPS QUALIFY FOR BLOCKLIST YET</div>`
              }
            </div>
          </div>
        </div>
      </div>
    </div>
  `;

  container.querySelectorAll("[data-def-fmt]").forEach((btn) => {
    btn.addEventListener("click", () => {
      store.set({ defenseFormat: btn.dataset.defFmt }, "defenseFormat");
    });
  });

  container.querySelector("#btn-copy-rules")?.addEventListener("click", () => {
    copyText(previewText, `Copied ${activeFmt.toUpperCase()} ruleset`);
  });

  container.querySelectorAll("[data-inspect-ip]").forEach((el) => {
    el.addEventListener("click", () => inspectAttacker(el.dataset.inspectIp));
  });
}

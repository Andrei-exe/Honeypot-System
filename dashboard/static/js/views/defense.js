/**
 * Blocklist page: firewall rules for the attacker IPs, suggested fixes and downloads.
 * Nothing here is applied automatically: the user copies or downloads the rules.
 */

import { inspectAttacker } from "../components/inspector.js";
import { asList, badgeProtocol, copyText, escapeHtml, fmtNum } from "../core/escape.js";
import { store } from "../core/store.js";

const FORMATS = [
  { id: "nftables", label: "nftables" },
  { id: "iptables", label: "iptables" },
  { id: "ufw", label: "ufw" },
  { id: "fail2ban", label: "fail2ban" },
  { id: "plain", label: "IP list" },
];

const DOWNLOADS = [
  { href: "/api/v1/export/report.md", label: "Incident report", hint: "Markdown summary" },
  { href: "/api/v1/export/alerts.csv", label: "Alerts", hint: "CSV" },
  { href: "/api/v1/export/sessions.csv", label: "Sessions", hint: "CSV" },
  { href: "/api/v1/export/navigator.json", label: "ATT&CK layer", hint: "for MITRE Navigator" },
];

export function renderDefense(container, state) {
  const data = state.data.defense;
  if (!data) {
    container.innerHTML = `<div class="empty-state">Building firewall rules…</div>`;
    return;
  }

  const fmt = FORMATS.some((f) => f.id === state.defenseFormat) ? state.defenseFormat : "nftables";
  const formats = data.formats || {};
  const rules = formats[fmt] || "# No rules generated yet";
  const recs = asList(data.recommendations);
  const blockedIps = asList(data.blocked_ips);

  container.innerHTML = `
    <div class="stack-8">
      <div class="page-head">
        <div>
          <h1 class="page-title">Blocklist</h1>
          <p class="page-sub">${fmtNum(data.blocked_ip_count || blockedIps.length)} IP${(data.blocked_ip_count || blockedIps.length) === 1 ? "" : "s"} qualify for blocking. Rules are generated here; nothing is applied automatically.</p>
        </div>
      </div>

      <div class="grid-asymmetric">
        <div class="panel">
          <div class="panel-head">
            <div class="seg">
              ${FORMATS.map((f) => `<button class="${fmt === f.id ? "active" : ""}" data-def-fmt="${f.id}">${f.label}</button>`).join("")}
            </div>
            <div class="btn-group">
              <button class="btn" id="btn-copy-rules">Copy</button>
              <a class="btn primary" href="/api/v1/export/blocklist?fmt=${encodeURIComponent(fmt)}">Download</a>
            </div>
          </div>
          <div class="panel-body">
            <pre class="code-block tall" data-scroll-key="defense-rules">${escapeHtml(rules)}</pre>
            <p class="muted-note" style="margin:10px 0 0;">Review the list before applying it on a real firewall.</p>
          </div>
        </div>

        <div class="stack-8">
          <div class="panel">
            <div class="panel-head"><span class="panel-title">Downloads</span></div>
            <div class="panel-body flush">
              <div class="plain-list">
                ${DOWNLOADS.map(
                  (d) => `
                  <div class="plain-list-row">
                    <div><a href="${d.href}">${escapeHtml(d.label)}</a></div>
                    <span class="cell-muted" style="font-size:13px;">${escapeHtml(d.hint)}</span>
                  </div>`
                ).join("")}
              </div>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head"><span class="panel-title">IPs on the list</span></div>
            <div class="panel-body">
              ${
                blockedIps.length
                  ? `<div class="chip-list">
                      ${blockedIps
                        .slice(0, 60)
                        .map((ip) => `<span class="ip-link" data-inspect-ip="${escapeHtml(ip)}">${escapeHtml(ip)}</span>`)
                        .join("")}
                      ${blockedIps.length > 60 ? `<span class="cell-muted">+${fmtNum(blockedIps.length - 60)} more</span>` : ""}
                    </div>`
                  : `<div class="empty-state">No IPs qualify yet</div>`
              }
            </div>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <span class="panel-title">Suggested fixes</span>
          <span class="panel-meta">most frequent first</span>
        </div>
        <div class="panel-body flush">
          ${
            recs.length
              ? `<div class="plain-list">
                  ${recs
                    .map(
                      (r) => `
                    <div class="plain-list-row">
                      <div style="min-width:0;">
                        <div>${escapeHtml(r.text)}</div>
                        <div class="badge-row" style="margin-top:4px;">${asList(r.protocols).slice(0, 3).map(badgeProtocol).join("")}</div>
                      </div>
                      <span class="count" title="Alerts that suggested this">${fmtNum(r.count)}×</span>
                    </div>`
                    )
                    .join("")}
                </div>`
              : `<div class="empty-state">No suggestions yet</div>`
          }
        </div>
      </div>
    </div>
  `;

  container.querySelectorAll("[data-def-fmt]").forEach((btn) => {
    btn.addEventListener("click", () => store.set({ defenseFormat: btn.dataset.defFmt }, "defenseFormat"));
  });

  container.querySelector("#btn-copy-rules")?.addEventListener("click", () => {
    copyText(rules, `Copied ${fmt} rules`);
  });

  container.querySelectorAll("[data-inspect-ip]").forEach((el) => {
    el.addEventListener("click", () => inspectAttacker(el.dataset.inspectIp));
  });
}

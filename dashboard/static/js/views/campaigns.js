/**
 * Campaigns page: attackers that are linked to each other.
 * A campaign = IPs that share a malware server or most of their password list.
 * A family = IPs that behave alike (same protocols and commands).
 */

import { CorrelationGraph } from "../charts/graph.js";
import { inspectAttacker } from "../components/inspector.js";
import { asList, escapeHtml, fmtNum } from "../core/escape.js";
import { store } from "../core/store.js";

let graphInst = null;
let lastSignature = "";

export function destroyCampaigns() {
  lastSignature = "";
  if (graphInst) {
    graphInst.destroy();
    graphInst = null;
  }
}

function campaignName(idx) {
  return `Campaign ${idx + 1}`;
}

export function renderCampaigns(container, state) {
  const data = state.data.campaigns;
  if (!data) {
    destroyCampaigns();
    container.innerHTML = `<div class="empty-state">Grouping related attackers…</div>`;
    return;
  }

  // The live refresh brings the same groups most of the time. Redrawing would
  // restart the graph layout every 4 seconds, so skip it when nothing changed.
  const signature = JSON.stringify([data.campaigns, data.families]);
  if (signature === lastSignature && graphInst && container.contains(graphInst.container)) return;
  destroyCampaigns();
  lastSignature = signature;

  const campaigns = asList(data.campaigns);
  const families = asList(data.families);
  const graph = { nodes: asList(data.graph && data.graph.nodes), edges: asList(data.graph && data.graph.edges) };

  container.innerHTML = `
    <div class="stack-8">
      <div class="page-head">
        <div>
          <h1 class="page-title">Campaigns</h1>
          <p class="page-sub">Attackers that look like they work together or run the same tool.</p>
        </div>
        <div class="inline-stats">
          <span><strong>${fmtNum(data.total_campaigns || 0)}</strong> campaign${data.total_campaigns === 1 ? "" : "s"}</span>
          <span><strong>${fmtNum(data.total_families || 0)}</strong> behaviour famil${data.total_families === 1 ? "y" : "ies"}</span>
        </div>
      </div>

      ${
        graph.nodes.length
          ? `
      <div class="panel">
        <div class="panel-head">
          <span class="panel-title">How attackers are linked</span>
          <div class="panel-meta">
            <span>drag to move · scroll to zoom · click an IP for details</span>
            <button class="btn sm" id="btn-graph-reset">Reset view</button>
          </div>
        </div>
        <div class="panel-body">
          <div id="camp-graph-canvas"></div>
        </div>
      </div>`
          : ""
      }

      <div class="grid-2">
        <div class="panel">
          <div class="panel-head">
            <span class="panel-title">Campaigns</span>
            <span class="panel-meta">shared malware server or passwords</span>
          </div>
          <div class="panel-body flush">
            ${
              campaigns.length
                ? `<div class="plain-list">
                    ${campaigns
                      .map(
                        (c, idx) => `
                      <div class="plain-list-row" data-camp-idx="${idx}" style="cursor:pointer;">
                        <div style="min-width:0;">
                          <div class="cell-strong">${campaignName(idx)}</div>
                          <div class="cell-muted" style="font-size:13px;">${escapeHtml(asList(c.reasons).join("; ") || "linked activity")}</div>
                          <div class="chip-list" style="margin-top:6px;">
                            ${asList(c.ips)
                              .slice(0, 8)
                              .map((ip) => `<span class="ip-link" data-inspect-ip="${escapeHtml(ip)}">${escapeHtml(ip)}</span>`)
                              .join("")}
                            ${asList(c.ips).length > 8 ? `<span class="cell-muted">+${asList(c.ips).length - 8} more</span>` : ""}
                          </div>
                          ${
                            asList(c.servers).length
                              ? `<div class="cell-muted" style="font-size:13px;margin-top:6px;">Malware from: <span class="mono">${asList(c.servers).map(escapeHtml).join(", ")}</span></div>`
                              : ""
                          }
                        </div>
                        <span class="count">${fmtNum(c.size)} IPs</span>
                      </div>`
                      )
                      .join("")}
                  </div>`
                : `<div class="empty-state">No campaigns yet. They appear when 2 or more IPs share a malware server or most of their passwords.</div>`
            }
          </div>
        </div>

        <div class="panel">
          <div class="panel-head">
            <span class="panel-title">Behaviour families</span>
            <span class="panel-meta">same protocols and commands</span>
          </div>
          <div class="panel-body flush">
            ${
              families.length
                ? `<div class="plain-list">
                    ${families
                      .map(
                        (f, idx) => `
                      <div class="plain-list-row" data-fam-idx="${idx}" style="cursor:pointer;">
                        <div style="min-width:0;">
                          <div class="cell-strong">${escapeHtml(f.label || "Unnamed family")}</div>
                          <div class="badge-row" style="margin-top:6px;">
                            ${asList(f.common_behavior).slice(0, 5).map((b) => `<span class="badge">${escapeHtml(b)}</span>`).join("")}
                          </div>
                        </div>
                        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;">
                          <span class="count">${fmtNum(f.size)} IPs</span>
                          <button class="btn sm" data-fam-filter="${escapeHtml(f.label || "")}">Sessions</button>
                        </div>
                      </div>`
                      )
                      .join("")}
                  </div>`
                : `<div class="empty-state">No families yet. They appear when 2 or more IPs behave alike.</div>`
            }
          </div>
        </div>
      </div>
    </div>
  `;

  const host = container.querySelector("#camp-graph-canvas");
  if (host) {
    graphInst = new CorrelationGraph(host, {
      height: 380,
      onNodeClick: (node) => {
        if (node.kind === "ip" && node.meta && node.meta.ip) {
          inspectAttacker(node.meta.ip);
        } else {
          store.openInspector(node.kind, node, "summary");
        }
      },
    });
    graphInst.setData(graph);
  }

  container.querySelector("#btn-graph-reset")?.addEventListener("click", () => {
    if (graphInst) graphInst.resetView();
  });

  container.querySelectorAll("[data-inspect-ip]").forEach((el) => {
    el.addEventListener("click", (ev) => {
      ev.stopPropagation();
      inspectAttacker(el.dataset.inspectIp);
    });
  });

  container.querySelectorAll("[data-fam-filter]").forEach((btn) => {
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const expr = `family:"${btn.dataset.famFilter}"`;
      store.setView("sessions");
      store.setQuery(expr);
      const qInput = document.getElementById("dsl-query-input");
      if (qInput) qInput.value = expr;
    });
  });

  container.querySelectorAll("[data-camp-idx]").forEach((row) => {
    row.addEventListener("click", () => {
      const idx = Number(row.dataset.campIdx);
      const c = campaigns[idx];
      if (c) store.openInspector("campaign", { ...c, name: campaignName(idx) }, "summary");
    });
  });

  container.querySelectorAll("[data-fam-idx]").forEach((row) => {
    row.addEventListener("click", () => {
      const f = families[Number(row.dataset.famIdx)];
      if (f) store.openInspector("family", f, "summary");
    });
  });
}

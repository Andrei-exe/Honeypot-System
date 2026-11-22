/**
 * View 4: CAMPAIGNS, BEHAVIORAL FAMILIES & INTERACTIVE CORRELATION GRAPH
 */

import { CorrelationGraph } from "../charts/graph.js";
import { inspectAttacker } from "../components/inspector.js";
import { escapeHtml, fmtNum } from "../core/escape.js";
import { store } from "../core/store.js";

let graphInst = null;

export function destroyCampaigns() {
  if (graphInst) {
    graphInst.destroy();
    graphInst = null;
  }
}

export function renderCampaigns(container, state) {
  destroyCampaigns();
  const data = state.data.campaigns;
  if (!data) {
    container.innerHTML = `<div class="empty-state">COMPUTING CORRELATION GRAPH & BEHAVIORAL CLUSTERS...</div>`;
    return;
  }

  const campaigns = data.campaigns || [];
  const families = data.families || [];
  const graph = data.graph || { nodes: [], edges: [] };

  container.innerHTML = `
    <div class="stack-8">
      <!-- INTERACTIVE FORCE-DIRECTED GRAPH -->
      <div class="panel">
        <div class="panel-head">
          <div style="display:flex;align-items:center;gap:8px;">
            <span class="panel-title">BOTNET & BEHAVIORAL CORRELATION GRAPH</span>
            <span class="badge">${fmtNum(graph.nodes.length)} NODES // ${fmtNum(graph.edges.length)} EDGES</span>
            <span class="panel-meta">DRAG NODES // SCROLL ZOOM // CLICK IP TO OPEN DOSSIER</span>
          </div>
          <button class="btn" id="btn-graph-reset">RESET VIEW</button>
        </div>
        <div class="panel-body">
          <div id="camp-graph-canvas"></div>
        </div>
      </div>

      <!-- CAMPAIGNS + FAMILIES SIDE BY SIDE -->
      <div class="grid-2">
        <div class="panel">
          <div class="panel-head">
            <span class="panel-title">CORRELATED CAMPAIGNS (${fmtNum(data.total_campaigns || 0)})</span>
            <span class="panel-meta">SHARED MALWARE HOST / PASSWORD DICTIONARY</span>
          </div>
          <div class="panel-body flush">
            ${
              campaigns.length
                ? `<table class="soc-table">
                    <thead>
                      <tr>
                        <th style="width:74px;">ID</th>
                        <th style="width:52px;" class="num">IPS</th>
                        <th>LINK REASONS</th>
                        <th>MEMBERS / INFRASTRUCTURE</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${campaigns
                        .map(
                          (c, idx) => `
                          <tr data-camp-idx="${idx}">
                            <td class="cell-strong" style="color:var(--sev-critical);">CAMP-${String(idx + 1).padStart(2, "0")}</td>
                            <td class="num cell-strong">${fmtNum(c.size)}</td>
                            <td title="${escapeHtml((c.reasons || []).join(", "))}">${escapeHtml((c.reasons || []).join("; ") || "-")}</td>
                            <td>
                              ${(c.ips || [])
                                .slice(0, 6)
                                .map((ip) => `<span class="ip-link" style="margin-right:6px;" data-inspect-ip="${escapeHtml(ip)}">${escapeHtml(ip)}</span>`)
                                .join("")}
                              ${(c.servers || []).map((s) => `<span class="badge sev-HIGH">HOST:${escapeHtml(s)}</span>`).join(" ")}
                            </td>
                          </tr>`
                        )
                        .join("")}
                    </tbody>
                  </table>`
                : `<div class="empty-state">NO CORRELATED CAMPAIGNS YET (REQUIRES >= 2 IPS SHARING MALWARE OR >=60% PASSWORD OVERLAP)</div>`
            }
          </div>
        </div>

        <div class="panel">
          <div class="panel-head">
            <span class="panel-title">BEHAVIORAL FAMILIES (${fmtNum(data.total_families || 0)})</span>
            <span class="panel-meta">JACCARD CLUSTERING ON PROTOCOLS & COMMANDS</span>
          </div>
          <div class="panel-body flush">
            ${
              families.length
                ? `<table class="soc-table">
                    <thead>
                      <tr>
                        <th style="width:170px;">FAMILY LABEL</th>
                        <th style="width:50px;" class="num">IPS</th>
                        <th>COMMON SIGNATURES</th>
                        <th style="width:74px;">PIVOT</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${families
                        .map(
                          (f, idx) => `
                          <tr data-fam-idx="${idx}">
                            <td class="cell-strong" style="color:var(--state-accent);" title="${escapeHtml(f.label)}">${escapeHtml(f.label)}</td>
                            <td class="num cell-strong">${fmtNum(f.size)}</td>
                            <td title="${escapeHtml((f.common_behavior || []).join(", "))}">
                              ${(f.common_behavior || []).slice(0, 5).map((b) => `<span class="badge">${escapeHtml(b)}</span>`).join(" ")}
                            </td>
                            <td>
                              <button class="btn" style="height:19px;padding:0 5px;" data-fam-filter="${escapeHtml(f.label)}">FILTER</button>
                            </td>
                          </tr>`
                        )
                        .join("")}
                    </tbody>
                  </table>`
                : `<div class="empty-state">NO BEHAVIORAL FAMILIES CLUSTERED YET (REQUIRES >= 2 SIMILAR IPS)</div>`
            }
          </div>
        </div>
      </div>
    </div>
  `;

  const host = container.querySelector("#camp-graph-canvas");
  if (host) {
    graphInst = new CorrelationGraph(host, {
      height: 360,
      onNodeClick: (node) => {
        if (node.kind === "ip" && node.meta && node.meta.ip) {
          inspectAttacker(node.meta.ip);
        } else {
          store.openInspector(node.kind, node, "raw");
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

  container.querySelectorAll("tr[data-camp-idx]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const c = campaigns[Number(tr.dataset.campIdx)];
      if (c) store.openInspector("campaign", c, "raw");
    });
  });

  container.querySelectorAll("tr[data-fam-idx]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const f = families[Number(tr.dataset.famIdx)];
      if (f) store.openInspector("family", f, "raw");
    });
  });
}

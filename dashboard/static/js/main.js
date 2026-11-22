/**
 * Main entrypoint of the Honeypot SOC Console.
 * Coordinates API polling, routing between the 7 views, the telemetry bar,
 * the DSL engine, keyboard navigation and the split-pane inspector.
 */

import { inspectAttacker, initInspectorResizer, renderInspector } from "./components/inspector.js";
import { initCopilot } from "./components/copilot.js";
import { initCommandPalette } from "./components/palette.js";
import { api } from "./core/api.js";
import { fmtNum, fmtTime, showToast } from "./core/escape.js";
import { parseQuery } from "./core/query.js";
import { initShortcuts } from "./core/shortcuts.js";
import { store } from "./core/store.js";
import { destroyAlerts, getAlertsRows, renderAlerts } from "./views/alerts.js";
import { getAttackersRows, renderAttackers } from "./views/attackers.js";
import { destroyCampaigns, renderCampaigns } from "./views/campaigns.js";
import { renderDefense } from "./views/defense.js";
import { destroyKillchain, renderKillchain } from "./views/killchain.js";
import { destroyOverview, getOverviewRows, renderOverview } from "./views/overview.js";
import { getSessionsRows, renderSessions } from "./views/sessions.js";

let pollTimer = null;
let activeRenderedView = null;

function destroyCurrentCanvasViews() {
  destroyOverview();
  destroyAlerts();
  destroyCampaigns();
  destroyKillchain();
}

async function fetchForView(view, force = false) {
  try {
    switch (view) {
      case "overview": {
        const res = await api.getOverview(force);
        store.setData("overview", res);
        break;
      }
      case "alerts": {
        const res = await api.getAlerts(force);
        store.setData("alerts", res);
        break;
      }
      case "sessions": {
        const res = await api.getSessions(500, force);
        store.setData("sessions", res);
        break;
      }
      case "campaigns": {
        const res = await api.getCampaigns(force);
        store.setData("campaigns", res);
        break;
      }
      case "attackers": {
        const res = await api.getAttackers(force);
        store.setData("attackers", res);
        break;
      }
      case "killchain": {
        const res = await api.getKillchain(force);
        store.setData("killchain", res);
        break;
      }
      case "defense": {
        const res = await api.getDefense(force);
        store.setData("defense", res);
        break;
      }
    }
  } catch (err) {
    if (err && err.name === "AbortError") return;
    store.setError(err.message || "threat-engine unreachable");
  }
}

async function backgroundOverviewRefresh() {
  const st = store.get();
  if (st.view === "overview") return;
  try {
    const res = await api.getOverview(false);
    store.setData("overview", res);
  } catch {
    // The main error is already shown by the active view
  }
}

function schedulePolling() {
  if (pollTimer) {
    window.clearInterval(pollTimer);
    pollTimer = null;
  }
  const st = store.get();
  if (!st.live) return;
  pollTimer = window.setInterval(() => {
    const cur = store.get();
    if (!cur.live || document.hidden) return;
    fetchForView(cur.view, false);
  }, curRefreshMs());
}

function curRefreshMs() {
  return store.get().refreshMs || 4000;
}

function updateChrome(st) {
  // Top telemetry ribbon
  const led = document.getElementById("tel-status-led");
  const stText = document.getElementById("tel-status-text");
  const latEl = document.getElementById("tel-latency");
  const syncEl = document.getElementById("tel-sync");
  const geoEl = document.getElementById("tel-geoip");
  const bufEl = document.getElementById("tel-buffer");
  const liveBtn = document.getElementById("btn-live");

  if (led && stText) {
    led.className = `led ${st.telemetry.online ? "ok" : "crit"}`;
    stText.textContent = st.telemetry.online ? "ENGINE ONLINE" : "ENGINE OFFLINE";
    stText.style.color = st.telemetry.online ? "var(--state-ok)" : "var(--sev-critical)";
  }
  if (latEl) latEl.textContent = `${Number(st.telemetry.latencyMs || 0).toFixed(1)}ms`;
  if (syncEl) syncEl.textContent = fmtTime(st.telemetry.lastSync);
  if (geoEl) {
    geoEl.textContent = st.telemetry.geoip ? "ON" : "OFF";
    geoEl.style.color = st.telemetry.geoip ? "var(--state-ok)" : "var(--text-muted)";
  }

  const ov = st.data.overview;
  if (ov && bufEl) {
    const h = ov.session_health || {};
    bufEl.textContent = `${fmtNum(h.total_stored || 0)}/${fmtNum(h.capacity || 2000)} (${h.saturation_pct || 0}%)`;
    bufEl.style.color =
      h.pressure === "CRITICAL"
        ? "var(--sev-critical)"
        : h.pressure === "ELEVATED"
        ? "var(--sev-high)"
        : "var(--text-primary)";
  }

  if (liveBtn) {
    liveBtn.className = `btn ${st.live ? "live-on" : "live-paused"}`;
    liveBtn.textContent = st.live ? "LIVE 4S" : "PAUSED";
  }

  // Left rail active state & counters
  document.querySelectorAll(".nav-item[data-view]").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === st.view);
  });

  if (ov) {
    const setCnt = (id, val, isAlert = false) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.textContent = fmtNum(val || 0);
      el.classList.toggle("alert", Boolean(isAlert && val > 0));
    };
    const stats = ov.stats || {};
    const c = ov.counters || {};
    const h = ov.session_health || {};
    setCnt("nav-cnt-alerts", stats.total_alerts);
    setCnt("nav-cnt-sessions", h.total_stored);
    const campData = st.data.campaigns;
    if (campData) {
      setCnt("nav-cnt-campaigns", (campData.total_campaigns || 0) + (campData.total_families || 0));
    }
    setCnt("nav-cnt-attackers", stats.unique_attacker_ips);
    setCnt("nav-cnt-honeytokens", c.honeytokens, true);
  }

  // Query status indicator
  const qStatus = document.getElementById("dsl-query-status");
  if (qStatus) {
    const parsed = parseQuery(st.query);
    qStatus.textContent = parsed.empty ? "0 FILTERS" : `${parsed.clauses.length} CLAUSE(S)`;
    qStatus.style.color = parsed.empty ? "var(--text-muted)" : "var(--state-accent)";
  }

  // Footer
  const footView = document.getElementById("foot-view");
  const footErr = document.getElementById("foot-error");
  if (footView) footView.textContent = `MODULE: ${st.view.toUpperCase()}`;
  if (footErr) {
    footErr.textContent = st.telemetry.error ? `ERR: ${st.telemetry.error}` : "MEM-ONLY // ZERO-OUTBOUND";
    footErr.style.color = st.telemetry.error ? "var(--sev-critical)" : "var(--text-muted)";
  }
}

function renderWorkspace(st) {
  const host = document.getElementById("workspace-main");
  if (!host) return;

  if (activeRenderedView !== st.view) {
    destroyCurrentCanvasViews();
    host.scrollTop = 0;
    activeRenderedView = st.view;
  }

  switch (st.view) {
    case "overview":
      renderOverview(host, st);
      break;
    case "alerts":
      renderAlerts(host, st);
      break;
    case "sessions":
      renderSessions(host, st);
      break;
    case "campaigns":
      renderCampaigns(host, st);
      break;
    case "attackers":
      renderAttackers(host, st);
      break;
    case "killchain":
      renderKillchain(host, st);
      break;
    case "defense":
      renderDefense(host, st);
      break;
  }
}

function updateSelectedRowHighlight(index) {
  const host = document.getElementById("workspace-main");
  if (!host) return;
  host.querySelectorAll("tbody tr[data-row-idx]").forEach((tr) => {
    const isSel = Number(tr.dataset.rowIdx) === index;
    tr.classList.toggle("selected", isSel);
    if (isSel) {
      tr.scrollIntoView({ block: "nearest" });
    }
  });
}

function getActiveTableRows(view) {
  if (view === "overview") return getOverviewRows();
  if (view === "alerts") return getAlertsRows();
  if (view === "sessions") return getSessionsRows();
  if (view === "attackers") return getAttackersRows();
  return [];
}

function moveRowSelection(delta) {
  const st = store.get();
  const rows = getActiveTableRows(st.view);
  if (!rows.length) return false;
  const maxIdx = st.view === "overview" ? Math.min(39, rows.length - 1) : rows.length - 1;
  let next = st.selectedRowIndex + delta;
  if (st.selectedRowIndex < 0) next = delta > 0 ? 0 : maxIdx;
  next = Math.max(0, Math.min(maxIdx, next));
  store.set({ selectedRowIndex: next }, "selection");
  return true;
}

function openSelectedRow() {
  const st = store.get();
  const rows = getActiveTableRows(st.view);
  if (st.selectedRowIndex < 0 || st.selectedRowIndex >= rows.length) return false;
  const item = rows[st.selectedRowIndex];
  if (!item) return false;

  if (st.view === "overview" || st.view === "alerts") {
    store.openInspector("alert", item, "summary");
    return true;
  }
  if (st.view === "sessions") {
    store.openInspector("session", item, "summary");
    return true;
  }
  if (st.view === "attackers") {
    inspectAttacker(item.ip);
    return true;
  }
  return false;
}

function bindStaticControls() {
  // Left rail navigation
  document.querySelectorAll(".nav-item[data-view]").forEach((btn) => {
    btn.addEventListener("click", () => store.setView(btn.dataset.view));
  });

  // Topbar controls
  document.getElementById("btn-live")?.addEventListener("click", () => {
    store.toggleLive();
    showToast(store.get().live ? "Live polling resumed (4s)" : "Live polling paused");
  });

  document.getElementById("btn-refresh")?.addEventListener("click", () => {
    const view = store.get().view;
    fetchForView(view, true);
    backgroundOverviewRefresh();
    showToast(`Refreshed ${view.toUpperCase()}`);
  });

  document.getElementById("btn-palette")?.addEventListener("click", () => {
    store.setPalette(true);
  });

  // DSL query input (debounced 140ms)
  const qInput = document.getElementById("dsl-query-input");
  let qTimer = null;
  qInput?.addEventListener("input", () => {
    window.clearTimeout(qTimer);
    qTimer = window.setTimeout(() => {
      store.setQuery(qInput.value);
    }, 140);
  });

  document.getElementById("dsl-query-clear")?.addEventListener("click", () => {
    if (qInput) qInput.value = "";
    store.setQuery("");
  });

  // Quick DSL syntax chips
  document.querySelectorAll("[data-dsl-append]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const expr = btn.dataset.dslAppend;
      if (qInput) qInput.value = expr;
      store.setQuery(expr);
    });
  });
}

function bootstrap() {
  bindStaticControls();
  initInspectorResizer();
  initCommandPalette();
  initCopilot();

  initShortcuts({
    onForceRefresh: () => {
      fetchForView(store.get().view, true);
      showToast("Manual telemetry refresh");
    },
    onMoveRow: moveRowSelection,
    onOpenSelectedRow: openSelectedRow,
  });

  store.subscribe((st, reason) => {
    updateChrome(st);

    if (reason === "inspector") {
      renderInspector();
      return;
    }
    if (reason === "palette") {
      return;
    }
    if (reason === "selection") {
      updateSelectedRowHighlight(st.selectedRowIndex);
      return;
    }
    if (reason === "live") {
      schedulePolling();
      return;
    }
    if (reason === "view") {
      renderWorkspace(st);
      fetchForView(st.view, false);
      return;
    }
    if (
      reason === "query" ||
      reason === "sessionFilter" ||
      reason === "sort" ||
      reason === "defenseFormat" ||
      reason === `data:${st.view}` ||
      (st.view === "overview" && reason === "data:campaigns")
    ) {
      renderWorkspace(st);
    }
  });

  // Initial load
  updateChrome(store.get());
  renderWorkspace(store.get());
  fetchForView("overview", true);
  api.getCampaigns(false).then((res) => store.setData("campaigns", res)).catch(() => {});
  schedulePolling();
}

document.addEventListener("DOMContentLoaded", bootstrap);

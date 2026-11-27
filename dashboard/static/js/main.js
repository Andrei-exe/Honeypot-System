/**
 * Dashboard entry point.
 * Loads data from the API, switches between the 7 pages, keeps the top bar
 * and side menu up to date, and wires up search, shortcuts and the details panel.
 *
 * Safety nets:
 *  - a page that throws while rendering shows an error box instead of a blank screen
 *  - if the threat engine is unreachable, the last data stays visible with a banner
 *  - table scroll position survives the 4-second live refresh
 */

import { inspectAttacker, initInspectorResizer, renderInspector } from "./components/inspector.js";
import { initCopilot } from "./components/copilot.js";
import { initCommandPalette } from "./components/palette.js";
import { api } from "./core/api.js";
import { escapeHtml, fmtNum, fmtShort, showToast } from "./core/escape.js";
import { parseQuery } from "./core/query.js";
import { rowKey } from "./core/selection.js";
import { initShortcuts } from "./core/shortcuts.js";
import { store } from "./core/store.js";
import { destroyAlerts, getAlertsRows, renderAlerts } from "./views/alerts.js";
import { getAttackersRows, renderAttackers } from "./views/attackers.js";
import { destroyCampaigns, renderCampaigns } from "./views/campaigns.js";
import { renderDefense } from "./views/defense.js";
import { destroyKillchain, renderKillchain } from "./views/killchain.js";
import { destroyOverview, getOverviewRows, OVERVIEW_ROW_LIMIT, renderOverview } from "./views/overview.js";
import { getSessionsRows, renderSessions } from "./views/sessions.js";

const RENDERERS = {
  overview: renderOverview,
  alerts: renderAlerts,
  sessions: renderSessions,
  campaigns: renderCampaigns,
  attackers: renderAttackers,
  killchain: renderKillchain,
  defense: renderDefense,
};

const FETCHERS = {
  overview: (force) => api.getOverview(force),
  alerts: (force) => api.getAlerts(force),
  sessions: (force) => api.getSessions(500, force),
  campaigns: (force) => api.getCampaigns(force),
  attackers: (force) => api.getAttackers(force),
  killchain: (force) => api.getKillchain(force),
  defense: (force) => api.getDefense(force),
};

let pollTimer = null;
let activeRenderedView = null;

function destroyCurrentCanvasViews() {
  for (const destroy of [destroyOverview, destroyAlerts, destroyCampaigns, destroyKillchain]) {
    try {
      destroy();
    } catch (err) {
      console.error("[dashboard] cleanup failed", err);
    }
  }
}

async function fetchForView(view, force = false) {
  const fetcher = FETCHERS[view];
  if (!fetcher) return;
  try {
    const res = await fetcher(force);
    store.setData(view, res);
  } catch (err) {
    if (err && err.name === "AbortError") return;
    store.setError(err.message || "threat-engine unreachable");
  }
}

async function backgroundOverviewRefresh() {
  if (store.get().view === "overview") return;
  try {
    store.setData("overview", await api.getOverview(false));
  } catch {
    // The active page already shows the error
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
  }, st.refreshMs || 4000);
}

/* ---------- Top bar, side menu, offline banner ---------- */

function updateChrome(st) {
  const led = document.getElementById("tel-status-led");
  const stText = document.getElementById("tel-status-text");
  const pill = document.getElementById("tel-status");
  const syncEl = document.getElementById("tel-sync");
  const liveBtn = document.getElementById("btn-live");
  const tel = st.telemetry;

  if (led && stText) {
    led.className = `led ${tel.online ? "ok" : "crit"}`;
    stText.textContent = tel.online ? "Online" : "Offline";
  }

  if (pill) {
    const h = (st.data.overview && st.data.overview.session_health) || {};
    pill.title = [
      tel.error ? `Error: ${tel.error}` : "Connected to threat-engine",
      `API response: ${Number(tel.latencyMs || 0).toFixed(0)} ms`,
      `Sessions stored: ${fmtNum(h.total_stored || 0)} of ${fmtNum(h.capacity || 2000)}`,
      `GeoIP: ${tel.geoip ? "on" : "off"}`,
    ].join("\n");
  }

  if (syncEl) syncEl.textContent = tel.lastSync ? `Updated ${fmtShort(tel.lastSync)}` : "";

  if (liveBtn) {
    liveBtn.className = `btn ${st.live ? "live-on" : "live-paused"}`;
    liveBtn.textContent = st.live ? "Live" : "Paused";
  }

  const banner = document.getElementById("offline-banner");
  if (banner) {
    banner.classList.toggle("hidden", tel.online);
    if (!tel.online) {
      banner.textContent = tel.lastSync
        ? `Can't reach the threat engine. Showing data from ${fmtShort(tel.lastSync)}. Retrying automatically…`
        : "Can't reach the threat engine. Retrying automatically…";
    }
  }

  document.querySelectorAll(".nav-item[data-view]").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === st.view);
  });

  const ov = st.data.overview;
  if (ov) {
    const setCnt = (id, val, isAlert = false) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.textContent = fmtNum(val || 0);
      el.classList.toggle("alert", Boolean(isAlert && val > 0));
      el.style.display = val > 0 ? "" : "none";
    };
    const stats = ov.stats || {};
    const c = ov.counters || {};
    const h = ov.session_health || {};
    setCnt("nav-cnt-alerts", stats.total_alerts);
    setCnt("nav-cnt-sessions", h.total_stored);
    const campData = st.data.campaigns;
    if (campData) setCnt("nav-cnt-campaigns", (campData.total_campaigns || 0) + (campData.total_families || 0));
    setCnt("nav-cnt-attackers", stats.unique_attacker_ips);
    setCnt("nav-cnt-honeytokens", c.honeytokens, true);
  }

  const qStatus = document.getElementById("dsl-query-status");
  const parsed = parseQuery(st.query);
  if (qStatus) {
    qStatus.textContent = parsed.empty ? "" : `${parsed.clauses.length} filter${parsed.clauses.length === 1 ? "" : "s"}`;
  }
  document.querySelectorAll("[data-dsl-append]").forEach((chip) => {
    chip.classList.toggle("active", st.query.trim() === chip.dataset.dslAppend);
  });
}

/* ---------- Page rendering ---------- */

function renderWorkspace(st) {
  const host = document.getElementById("workspace-main");
  if (!host) return;

  const sameView = activeRenderedView === st.view;
  const pageScroll = host.scrollTop;
  const innerScroll = {};
  if (sameView) {
    host.querySelectorAll("[data-scroll-key]").forEach((el) => {
      innerScroll[el.dataset.scrollKey] = el.scrollTop;
    });
  } else {
    destroyCurrentCanvasViews();
    activeRenderedView = st.view;
  }

  const render = RENDERERS[st.view];
  try {
    if (render) render(host, st);
  } catch (err) {
    console.error(`[dashboard] page "${st.view}" failed to render`, err);
    destroyCurrentCanvasViews();
    host.innerHTML = `
      <div class="error-panel">
        <h3>This page could not be displayed</h3>
        <p>The rest of the dashboard still works. The data probably has a format this page did not expect.</p>
        <code>${escapeHtml(err && err.message ? err.message : String(err))}</code>
        <button class="btn" id="btn-retry-render">Try again</button>
      </div>`;
    host.querySelector("#btn-retry-render")?.addEventListener("click", () => {
      activeRenderedView = null;
      fetchForView(st.view, true);
      renderWorkspace(store.get());
    });
    return;
  }

  if (sameView) {
    host.querySelectorAll("[data-scroll-key]").forEach((el) => {
      const top = innerScroll[el.dataset.scrollKey];
      if (top) el.scrollTop = top;
    });
    host.scrollTop = pageScroll;
  } else {
    host.scrollTop = 0;
  }
}

function safeRenderInspector() {
  try {
    renderInspector();
  } catch (err) {
    console.error("[dashboard] details panel failed", err);
  }
}

/* ---------- Row selection (by key, not by position) ---------- */

function updateSelectedRowHighlight(key) {
  const host = document.getElementById("workspace-main");
  if (!host) return;
  host.querySelectorAll("tbody tr[data-row-key]").forEach((tr) => {
    const isSel = key !== null && tr.dataset.rowKey === key;
    tr.classList.toggle("selected", isSel);
    if (isSel) tr.scrollIntoView({ block: "nearest" });
  });
}

function getActiveTableRows(view) {
  if (view === "overview") return getOverviewRows();
  if (view === "alerts") return getAlertsRows();
  if (view === "sessions") return getSessionsRows();
  if (view === "attackers") return getAttackersRows();
  return [];
}

function findSelectedIndex(st, rows) {
  if (st.selectedKey === null || st.selectedKey === undefined) return -1;
  return rows.findIndex((r) => rowKey(st.view, r) === st.selectedKey);
}

function moveRowSelection(delta) {
  const st = store.get();
  const rows = getActiveTableRows(st.view);
  if (!rows.length) return false;
  const maxIdx = st.view === "overview" ? Math.min(OVERVIEW_ROW_LIMIT - 1, rows.length - 1) : rows.length - 1;
  const cur = findSelectedIndex(st, rows);
  let next = cur < 0 ? (delta > 0 ? 0 : maxIdx) : cur + delta;
  next = Math.max(0, Math.min(maxIdx, next));
  store.set({ selectedKey: rowKey(st.view, rows[next]) }, "selection");
  return true;
}

function openSelectedRow() {
  const st = store.get();
  const rows = getActiveTableRows(st.view);
  const idx = findSelectedIndex(st, rows);
  if (idx < 0) return false;
  const item = rows[idx];

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

/* ---------- Page in the URL (#alerts), so refresh and Back work ---------- */

function viewFromHash() {
  const v = decodeURIComponent(window.location.hash.replace(/^#\/?/, ""));
  return RENDERERS[v] ? v : null;
}

function syncHash(view) {
  if (viewFromHash() !== view) window.location.hash = view;
}

/* ---------- Static controls ---------- */

function bindHelpPopover() {
  const btn = document.getElementById("btn-help");
  const pop = document.getElementById("help-pop");
  if (!btn || !pop) return;
  btn.addEventListener("click", (ev) => {
    ev.stopPropagation();
    pop.classList.toggle("hidden");
  });
  document.addEventListener("click", (ev) => {
    if (!pop.contains(ev.target)) pop.classList.add("hidden");
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") pop.classList.add("hidden");
  });
}

function bindStaticControls() {
  document.querySelectorAll(".nav-item[data-view]").forEach((btn) => {
    btn.addEventListener("click", () => store.setView(btn.dataset.view));
  });

  document.getElementById("btn-live")?.addEventListener("click", () => {
    store.toggleLive();
    showToast(store.get().live ? "Live updates on" : "Live updates paused");
  });

  document.getElementById("btn-refresh")?.addEventListener("click", () => {
    fetchForView(store.get().view, true);
    backgroundOverviewRefresh();
    showToast("Refreshed");
  });

  document.getElementById("btn-palette")?.addEventListener("click", () => store.setPalette(true));

  const qInput = document.getElementById("dsl-query-input");
  let qTimer = null;
  qInput?.addEventListener("input", () => {
    window.clearTimeout(qTimer);
    qTimer = window.setTimeout(() => store.setQuery(qInput.value), 150);
  });

  document.getElementById("dsl-query-clear")?.addEventListener("click", () => {
    if (qInput) qInput.value = "";
    store.setQuery("");
  });

  document.querySelectorAll("[data-dsl-append]").forEach((chip) => {
    chip.addEventListener("click", () => {
      const expr = chip.dataset.dslAppend;
      const next = store.get().query.trim() === expr ? "" : expr;
      if (qInput) qInput.value = next;
      store.setQuery(next);
    });
  });

  window.addEventListener("hashchange", () => {
    const v = viewFromHash();
    if (v) store.setView(v);
  });

  bindHelpPopover();
}

function createOfflineBanner() {
  const host = document.getElementById("workspace-main");
  if (!host || document.getElementById("offline-banner")) return;
  const banner = document.createElement("div");
  banner.id = "offline-banner";
  banner.className = "offline-banner hidden";
  banner.setAttribute("role", "status");
  host.parentNode.insertBefore(banner, host);
}

function bootstrap() {
  createOfflineBanner();
  bindStaticControls();
  initInspectorResizer();
  initCommandPalette();
  initCopilot();

  initShortcuts({
    onForceRefresh: () => {
      fetchForView(store.get().view, true);
      showToast("Refreshed");
    },
    onMoveRow: moveRowSelection,
    onOpenSelectedRow: openSelectedRow,
  });

  // Open the page from the URL before anything is drawn
  const fromUrl = viewFromHash();
  if (fromUrl) store.setView(fromUrl);

  store.subscribe((st, reason) => {
    updateChrome(st);

    if (reason === "inspector") {
      safeRenderInspector();
      return;
    }
    if (reason === "palette") return;
    if (reason === "selection") {
      updateSelectedRowHighlight(st.selectedKey);
      return;
    }
    if (reason === "live") {
      schedulePolling();
      return;
    }
    if (reason === "view") {
      syncHash(st.view);
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

  const st = store.get();
  updateChrome(st);
  renderWorkspace(st);
  fetchForView("overview", true);
  if (st.view !== "overview") fetchForView(st.view, true);
  api.getCampaigns(false).then((res) => store.setData("campaigns", res)).catch(() => {});
  schedulePolling();
}

document.addEventListener("DOMContentLoaded", bootstrap);

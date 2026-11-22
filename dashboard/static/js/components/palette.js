/**
 * Command Palette (Ctrl+K) pentru navigare instanta, filtre DSL predefinite si exporturi.
 */

import { escapeHtml } from "../core/escape.js";
import { store } from "../core/store.js";

const COMMANDS = [
  { id: "v-overview",  label: "View: Live Telemetry Cockpit",            hint: "KEY 1", action: () => store.setView("overview") },
  { id: "v-alerts",    label: "View: Alerts Explorer",                   hint: "KEY 2", action: () => store.setView("alerts") },
  { id: "v-sessions",  label: "View: Sessions & Replay Inspector",       hint: "KEY 3", action: () => store.setView("sessions") },
  { id: "v-campaigns", label: "View: Campaigns, Families & Graph",       hint: "KEY 4", action: () => store.setView("campaigns") },
  { id: "v-attackers", label: "View: Attacker Dossiers (IP Index)",      hint: "KEY 5", action: () => store.setView("attackers") },
  { id: "v-killchain", label: "View: Kill-Chain, MITRE & Honeytokens",   hint: "KEY 6", action: () => store.setView("killchain") },
  { id: "v-defense",   label: "View: Defense, Blocklists & Exports",     hint: "KEY 7", action: () => store.setView("defense") },

  { id: "q-crit",      label: "Filter DSL: sev:high+ (High & Critical)", hint: "DSL",   action: () => applyDsl("sev:high+", "alerts") },
  { id: "q-nohttp",    label: "Filter DSL: -proto:http (Interactive Only)", hint: "DSL", action: () => applyDsl("-proto:http", "sessions") },
  { id: "q-creds",     label: "Filter DSL: has:creds (Captured Passwords)", hint: "DSL", action: () => applyDsl("has:creds", "alerts") },
  { id: "q-honey",     label: "Filter DSL: has:honeytoken (Decoy Access)",  hint: "DSL", action: () => applyDsl("has:honeytoken", "alerts") },
  { id: "q-mirai",     label: "Filter DSL: tag:mirai (IoT Botnet Probes)",  hint: "DSL", action: () => applyDsl("tag:mirai", "alerts") },
  { id: "q-miner",     label: "Filter DSL: tag:cryptominer (Miner Probes)", hint: "DSL", action: () => applyDsl("tag:cryptominer", "alerts") },
  { id: "q-clear",     label: "Filter DSL: Clear Active Query",             hint: "DSL", action: () => applyDsl("") },

  { id: "op-live",     label: "Telemetry: Toggle LIVE / PAUSED Polling", hint: "SPACE", action: () => store.toggleLive() },
  { id: "ex-report",   label: "Export: Download Incident Report (.md)",  hint: "EXPORT", action: () => window.location.assign("/api/v1/export/report.md") },
  { id: "ex-alerts",   label: "Export: Download Alerts (.csv)",          hint: "EXPORT", action: () => window.location.assign("/api/v1/export/alerts.csv") },
  { id: "ex-sessions", label: "Export: Download Sessions (.csv)",        hint: "EXPORT", action: () => window.location.assign("/api/v1/export/sessions.csv") },
  { id: "ex-mitre",    label: "Export: Download MITRE ATT&CK Layer (.json)", hint: "EXPORT", action: () => window.location.assign("/api/v1/export/navigator.json") },
];

function applyDsl(expr, targetView = null) {
  if (targetView) store.setView(targetView);
  store.setQuery(expr);
  const input = document.getElementById("dsl-query-input");
  if (input) input.value = expr;
}

let selectedIdx = 0;
let filtered = COMMANDS;

export function initCommandPalette() {
  const backdrop = document.getElementById("palette-backdrop");
  const input = document.getElementById("palette-input");
  const list = document.getElementById("palette-list");
  if (!backdrop || !input || !list) return;

  function drawList() {
    const q = input.value.trim().toLowerCase();
    filtered = q
      ? COMMANDS.filter((c) => c.label.toLowerCase().includes(q) || c.hint.toLowerCase().includes(q))
      : COMMANDS;
    if (selectedIdx >= filtered.length) selectedIdx = Math.max(0, filtered.length - 1);

    if (!filtered.length) {
      list.innerHTML = `<div class="empty-state">NO MATCHING COMMAND</div>`;
      return;
    }

    list.innerHTML = filtered
      .map(
        (cmd, i) => `
        <div class="palette-item ${i === selectedIdx ? "selected" : ""}" data-cmd-idx="${i}">
          <span>${escapeHtml(cmd.label)}</span>
          <span class="palette-hint">${escapeHtml(cmd.hint)}</span>
        </div>`
      )
      .join("");

    list.querySelectorAll(".palette-item").forEach((el) => {
      el.addEventListener("click", () => {
        const cmd = filtered[Number(el.dataset.cmdIdx)];
        if (cmd) {
          store.setPalette(false);
          cmd.action();
        }
      });
    });
  }

  backdrop.addEventListener("click", (ev) => {
    if (ev.target === backdrop) store.setPalette(false);
  });

  input.addEventListener("input", () => {
    selectedIdx = 0;
    drawList();
  });

  input.addEventListener("keydown", (ev) => {
    if (ev.key === "ArrowDown") {
      ev.preventDefault();
      selectedIdx = Math.min(filtered.length - 1, selectedIdx + 1);
      drawList();
    } else if (ev.key === "ArrowUp") {
      ev.preventDefault();
      selectedIdx = Math.max(0, selectedIdx - 1);
      drawList();
    } else if (ev.key === "Enter") {
      ev.preventDefault();
      const cmd = filtered[selectedIdx];
      if (cmd) {
        store.setPalette(false);
        cmd.action();
      }
    }
  });

  store.subscribe((st, reason) => {
    if (reason !== "palette") return;
    if (st.paletteOpen) {
      backdrop.classList.add("open");
      input.value = "";
      selectedIdx = 0;
      drawList();
      window.setTimeout(() => input.focus(), 10);
    } else {
      backdrop.classList.remove("open");
    }
  });
}

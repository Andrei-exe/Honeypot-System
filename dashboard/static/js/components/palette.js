/**
 * Command palette (Ctrl+K): jump to a page, apply a common filter or download an export.
 */

import { escapeHtml } from "../core/escape.js";
import { store } from "../core/store.js";

function applyFilter(expr, targetView = null) {
  if (targetView) store.setView(targetView);
  store.setQuery(expr);
  const input = document.getElementById("dsl-query-input");
  if (input) input.value = expr;
}

const download = (url) => () => window.location.assign(url);

const COMMANDS = [
  { group: "Go to", label: "Overview", hint: "1", action: () => store.setView("overview") },
  { group: "Go to", label: "Alerts", hint: "2", action: () => store.setView("alerts") },
  { group: "Go to", label: "Sessions", hint: "3", action: () => store.setView("sessions") },
  { group: "Go to", label: "Campaigns", hint: "4", action: () => store.setView("campaigns") },
  { group: "Go to", label: "Attackers", hint: "5", action: () => store.setView("attackers") },
  { group: "Go to", label: "Attack techniques", hint: "6", action: () => store.setView("killchain") },
  { group: "Go to", label: "Blocklist", hint: "7", action: () => store.setView("defense") },

  { group: "Filter", label: "High and critical alerts", hint: "sev:high+", action: () => applyFilter("sev:high+", "alerts") },
  { group: "Filter", label: "Alerts with a password", hint: "has:creds", action: () => applyFilter("has:creds", "alerts") },
  { group: "Filter", label: "Honeytoken (decoy) access", hint: "has:honeytoken", action: () => applyFilter("has:honeytoken", "alerts") },
  { group: "Filter", label: "Mirai bot activity", hint: "tag:mirai", action: () => applyFilter("tag:mirai", "alerts") },
  { group: "Filter", label: "Crypto-miner activity", hint: "tag:cryptominer", action: () => applyFilter("tag:cryptominer", "alerts") },
  { group: "Filter", label: "Sessions without HTTP", hint: "-proto:http", action: () => applyFilter("-proto:http", "sessions") },
  { group: "Filter", label: "Clear search", hint: "", action: () => applyFilter("") },

  { group: "Other", label: "Pause or resume live updates", hint: "Space", action: () => store.toggleLive() },
  { group: "Download", label: "Incident report", hint: ".md", action: download("/api/v1/export/report.md") },
  { group: "Download", label: "Alerts", hint: ".csv", action: download("/api/v1/export/alerts.csv") },
  { group: "Download", label: "Sessions", hint: ".csv", action: download("/api/v1/export/sessions.csv") },
  { group: "Download", label: "MITRE ATT&CK layer", hint: ".json", action: download("/api/v1/export/navigator.json") },
];

let selectedIdx = 0;
let filtered = COMMANDS;

export function initCommandPalette() {
  const backdrop = document.getElementById("palette-backdrop");
  const input = document.getElementById("palette-input");
  const list = document.getElementById("palette-list");
  if (!backdrop || !input || !list) return;

  function run(cmd) {
    if (!cmd) return;
    store.setPalette(false);
    cmd.action();
  }

  function drawList() {
    const q = input.value.trim().toLowerCase();
    filtered = q
      ? COMMANDS.filter((c) => `${c.group} ${c.label} ${c.hint}`.toLowerCase().includes(q))
      : COMMANDS;
    if (selectedIdx >= filtered.length) selectedIdx = Math.max(0, filtered.length - 1);

    if (!filtered.length) {
      list.innerHTML = `<div class="empty-state">Nothing matches "${escapeHtml(input.value)}"</div>`;
      return;
    }

    list.innerHTML = filtered
      .map(
        (cmd, i) => `
        <div class="palette-item ${i === selectedIdx ? "selected" : ""}" data-cmd-idx="${i}">
          <span><span class="palette-hint" style="display:inline-block;width:72px;">${escapeHtml(cmd.group)}</span>${escapeHtml(cmd.label)}</span>
          <span class="palette-hint">${escapeHtml(cmd.hint)}</span>
        </div>`
      )
      .join("");

    list.querySelectorAll(".palette-item").forEach((el) => {
      el.addEventListener("click", () => run(filtered[Number(el.dataset.cmdIdx)]));
    });
    list.querySelector(".palette-item.selected")?.scrollIntoView({ block: "nearest" });
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
      run(filtered[selectedIdx]);
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

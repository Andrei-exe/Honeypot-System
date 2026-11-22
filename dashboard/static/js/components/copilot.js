/**
 * Local SOC Copilot UI component (offline, zero-LLM).
 */

import { copyText, escapeHtml, showToast } from "../core/escape.js";
import { store } from "../core/store.js";
import { inspectAttacker } from "./inspector.js";

const QUICK_PROMPTS = [
  { label: "BRIEFING", q: "summary" },
  { label: "TOP IPS", q: "top attackers" },
  { label: "HONEYTOKENS", q: "honeytokens" },
  { label: "AUTH / CREDS", q: "credentials" },
  { label: "MIRAI / MINERS", q: "mirai" },
  { label: "T1110", q: "T1110" },
  { label: "HELP", q: "help" },
];

let isOpen = false;
let initialized = false;

function setDrawerState(open) {
  const drawer = document.getElementById("copilot-drawer");
  const backdrop = document.getElementById("copilot-backdrop");
  const btn = document.getElementById("btn-copilot");
  if (!drawer) return;
  isOpen = open;
  drawer.classList.toggle("hidden", !isOpen);
  if (backdrop) backdrop.classList.toggle("hidden", !isOpen);
  if (btn) btn.classList.toggle("active", isOpen);
  if (isOpen) {
    const input = document.getElementById("copilot-input");
    if (input) input.focus();
  }
}

function runAction(action) {
  if (!action) return;
  if (action.type === "inspect_ip" && action.value) {
    inspectAttacker(action.value);
    return;
  }
  if (action.type === "view" && action.value) {
    store.setView(action.value);
    return;
  }
  if (action.type === "dsl") {
    if (action.view) store.setView(action.view);
    const expr = action.value || "";
    store.setQuery(expr);
    const qInput = document.getElementById("dsl-query-input");
    if (qInput) qInput.value = expr;
    return;
  }
  if (action.type === "copy" && action.value) {
    copyText(action.value, "Copied firewall command");
  }
}

function appendMessage(role, payload) {
  const list = document.getElementById("copilot-messages");
  if (!list) return;

  const box = document.createElement("div");
  box.className = `copilot-msg ${role}`;

  if (role === "user") {
    box.innerHTML = `
      <div class="copilot-msg-role">ANALYST &gt;</div>
      <div>${escapeHtml(payload)}</div>
    `;
  } else {
    const facts = Array.isArray(payload.facts) ? payload.facts : [];
    const actions = Array.isArray(payload.actions) ? payload.actions : [];
    const factsHtml = facts.length
      ? `<div class="copilot-facts">
          ${facts
            .map(
              (f) =>
                `<div class="copilot-facts-k">${escapeHtml(f.label)}</div>
                 <div class="copilot-facts-v">${escapeHtml(f.value)}</div>`
            )
            .join("")}
        </div>`
      : "";
    const codeHtml = payload.code
      ? `<pre class="copilot-code">${escapeHtml(payload.code)}</pre>`
      : "";
    const actionsHtml = actions.length
      ? `<div class="copilot-actions">
          ${actions
            .map(
              (a, i) =>
                `<button type="button" class="btn" data-act-idx="${i}">${escapeHtml(a.label)}</button>`
            )
            .join("")}
        </div>`
      : "";

    box.innerHTML = `
      <div class="copilot-msg-role">SOC COPILOT // LIVE</div>
      <div>${escapeHtml(payload.reply || "No response")}</div>
      ${factsHtml}
      ${codeHtml}
      ${actionsHtml}
    `;

    box.querySelectorAll("[data-act-idx]").forEach((btn) => {
      btn.addEventListener("click", () => {
        runAction(actions[Number(btn.dataset.actIdx)]);
      });
    });
  }

  list.appendChild(box);
  list.scrollTop = list.scrollHeight;
}

async function sendPrompt(text) {
  const clean = (text || "").trim();
  if (!clean) return;
  appendMessage("user", clean);

  try {
    const resp = await fetch("/api/v1/copilot", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: clean }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      appendMessage("bot", { reply: data.error || "Copilot request failed." });
      return;
    }
    appendMessage("bot", data);
  } catch {
    appendMessage("bot", { reply: "Unable to reach dashboard copilot endpoint." });
    showToast("Copilot request failed");
  }
}

export function initCopilot() {
  if (initialized) return;
  initialized = true;

  const drawer = document.getElementById("copilot-drawer");
  const toggleBtn = document.getElementById("btn-copilot");
  if (!drawer || !toggleBtn) return;

  let backdrop = document.getElementById("copilot-backdrop");
  if (!backdrop) {
    backdrop = document.createElement("div");
    backdrop.id = "copilot-backdrop";
    backdrop.className = "copilot-backdrop hidden";
    drawer.parentNode.insertBefore(backdrop, drawer);
  }
  backdrop.addEventListener("click", () => setDrawerState(false));

  drawer.innerHTML = `
    <div class="copilot-head">
      <div style="display:flex;align-items:center;gap:6px;">
        <span class="led ok"></span>
        <span class="cell-strong">SOC COPILOT</span>
        <span class="cell-muted">OFFLINE // LIVE TELEMETRY</span>
      </div>
      <button type="button" class="btn" id="copilot-close">ESC</button>
    </div>
    <div class="copilot-chips" id="copilot-chips">
      ${QUICK_PROMPTS.map(
        (p) => `<button type="button" class="btn" data-quick-q="${escapeHtml(p.q)}">${escapeHtml(p.label)}</button>`
      ).join("")}
    </div>
    <div class="copilot-messages" id="copilot-messages"></div>
    <form class="copilot-form" id="copilot-form">
      <input
        type="text"
        id="copilot-input"
        class="copilot-input"
        maxlength="300"
        autocomplete="off"
        spellcheck="false"
        placeholder="Ask: summary, top IPs, T1110, block 172.21.0.3..."
      >
      <button type="submit" class="btn primary">ASK</button>
    </form>
  `;

  toggleBtn.addEventListener("click", () => setDrawerState(!isOpen));
  drawer.querySelector("#copilot-close")?.addEventListener("click", () => setDrawerState(false));

  drawer.querySelectorAll("[data-quick-q]").forEach((btn) => {
    btn.addEventListener("click", () => sendPrompt(btn.dataset.quickQ));
  });

  const form = drawer.querySelector("#copilot-form");
  const input = drawer.querySelector("#copilot-input");
  form?.addEventListener("submit", (ev) => {
    ev.preventDefault();
    if (!input) return;
    const val = input.value;
    input.value = "";
    sendPrompt(val);
  });

  document.addEventListener("keydown", (ev) => {
    if (ev.key === "F1") {
      ev.preventDefault();
      setDrawerState(!isOpen);
    } else if (ev.key === "Escape" && isOpen) {
      setDrawerState(false);
    }
  });

  appendMessage("bot", {
    reply: "SOC Copilot ready. Click a quick chip above or ask about any IP, MITRE code (e.g. T1110), honeytokens, or firewall rules.",
    facts: [],
    actions: [],
  });
}

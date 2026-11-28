/**
 * Terminal replay of a session: the attacker's commands are typed again, one by one,
 * in a terminal that looks like the honeypot's own shell (prompt root@gateway:~#).
 *
 * Only real data is shown. The honeypot stores what was typed, not what the shell answered,
 * so instead of invented output each command is followed by what the threat engine
 * detected for it (grey "↳" lines).
 *
 * The player lives outside the panel's HTML, so it keeps its place when the panel is redrawn.
 */

import { asList, classifyCommand, escapeHtml } from "../core/escape.js";

const SEV_CLASS = { CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low" };
const SPEEDS = [1, 2, 4];
const DOWNLOADERS = /\b(wget|curl|tftp|ftpget)\b/;

let state = null; // { sid, steps, step, chars, open, playing, speed, timer, el }

/* ---------- Building the script ---------- */

function relTime(start, ts) {
  const a = Date.parse(start);
  const b = Date.parse(ts);
  if (!Number.isFinite(a) || !Number.isFinite(b) || b < a) return "";
  const sec = Math.round((b - a) / 1000);
  const m = Math.floor(sec / 60);
  return `+${m}:${String(sec % 60).padStart(2, "0")}`;
}

/** Follows "cd" so the prompt shows the folder, like the real shell does. */
function nextCwd(cwd, cmd) {
  let dir = cwd;
  for (const part of String(cmd).split(/;|&&|\|\|/)) {
    const m = part.trim().match(/^cd(?:\s+(\S+))?$/);
    if (!m) continue;
    const target = m[1] || "/root";
    if (target === "~") dir = "/root";
    else if (target.startsWith("/")) dir = target;
    else if (target === "..") dir = dir.replace(/\/[^/]+$/, "") || "/";
    else if (target !== ".") dir = `${dir === "/" ? "" : dir}/${target}`;
  }
  return dir.length > 1 ? dir.replace(/\/+$/, "") : dir;
}

function prompt(protocol, cwd) {
  if (protocol === "FTP") return "ftp> ";
  const shown = cwd === "/root" ? "~" : cwd.startsWith("/root/") ? `~${cwd.slice(5)}` : cwd;
  return `root@gateway:${shown}# `;
}

function buildSteps(s) {
  const steps = [];
  const proto = String(s.protocol || "").toUpperCase();
  const alerts = asList(s.related_alerts);

  steps.push({ kind: "info", text: `${proto} connection from ${s.source_ip || "unknown IP"}` });

  const success = s.successful_login ? String(s.successful_login) : "";
  const tried = asList(s.passwords).filter((p) => !success || !success.endsWith(`:${p}`));
  tried.slice(0, 6).forEach((p) => steps.push({ kind: "info", text: `login with password "${p}" rejected` }));
  if (tried.length > 6) steps.push({ kind: "info", text: `… ${tried.length - 6} more passwords rejected` });
  else if (!tried.length && s.login_attempts > 1 && !success) {
    steps.push({ kind: "info", text: `${s.login_attempts} login attempts rejected` });
  }
  if (success) steps.push({ kind: "ok", text: `logged in as ${success}` });

  let cwd = "/root";
  asList(s.commands).forEach((cmd, idx) => {
    const text = String(cmd);
    steps.push({ kind: "cmd", prompt: prompt(proto, cwd), text, flag: classifyCommand(text), n: idx + 1 });
    cwd = nextCwd(cwd, text);

    const hits = alerts.filter((a) => a && a.payload_details && a.payload_details.command === text);
    hits.slice(0, 2).forEach((a) => {
      const at = relTime(s.start, a.timestamp);
      steps.push({
        kind: "note",
        sev: SEV_CLASS[String(a.severity || "").toUpperCase()] || "low",
        text: `${a.alert_reason || "flagged"}${at ? `  (${at})` : ""}`,
      });
    });
    if (DOWNLOADERS.test(text)) {
      steps.push({ kind: "note", sev: "low", text: "nothing was downloaded: the honeypot blocks every outgoing connection" });
    }
  });

  if (!asList(s.commands).length) {
    steps.push({ kind: "info", text: success ? "no commands were typed after logging in" : "the attacker never got a shell" });
  }
  steps.push({ kind: s.end ? "end" : "open", text: s.end ? "connection closed" : "session still open" });
  return steps;
}

/* ---------- Drawing ---------- */

function lineHtml(step, chars) {
  if (step.kind === "cmd") {
    const typed = chars == null ? step.text : step.text.slice(0, chars);
    return `<div class="rp-line rp-cmd ${step.flag ? "flag-" + step.flag : ""}"><span class="rp-prompt">${escapeHtml(step.prompt)}</span><span class="rp-typed">${escapeHtml(typed)}</span></div>`;
  }
  if (step.kind === "note") return `<div class="rp-line rp-note sev-${step.sev}">↳ ${escapeHtml(step.text)}</div>`;
  if (step.kind === "ok") return `<div class="rp-line rp-ok"># ${escapeHtml(step.text)}</div>`;
  if (step.kind === "end") return `<div class="rp-line rp-info">— ${escapeHtml(step.text)} —</div>`;
  if (step.kind === "open") return `<div class="rp-line rp-info">— ${escapeHtml(step.text)} —</div>`;
  return `<div class="rp-line rp-info"># ${escapeHtml(step.text)}</div>`;
}

function cmdCount() {
  return state.steps.filter((st) => st.kind === "cmd").length;
}

function doneCmds() {
  let n = 0;
  for (let i = 0; i < state.step && i < state.steps.length; i++) if (state.steps[i].kind === "cmd") n++;
  return n;
}

function finished() {
  return state.step >= state.steps.length;
}

function updateControls() {
  const el = state.el;
  if (!el) return;
  const play = el.querySelector('[data-rp="play"]');
  if (play) play.textContent = finished() ? "Replay" : state.playing ? "Pause" : "Play";
  const speed = el.querySelector('[data-rp="speed"]');
  if (speed) speed.textContent = `${state.speed}×`;
  const skip = el.querySelector('[data-rp="skip"]');
  if (skip) skip.disabled = finished();
  const prog = el.querySelector(".rp-progress");
  const total = cmdCount();
  if (prog) prog.textContent = total ? `${doneCmds()} / ${total} commands` : "no commands";
  const bar = el.querySelector(".rp-bar > span");
  if (bar) bar.style.width = `${Math.round((Math.min(state.step, state.steps.length) / Math.max(1, state.steps.length)) * 100)}%`;
}

/** Draws everything up to the current position (used on mount, skip and restart). */
function redrawScreen() {
  const screen = state.el && state.el.querySelector(".rp-screen");
  if (!screen) return;
  let html = "";
  for (let i = 0; i < state.steps.length && i <= state.step; i++) {
    if (i === state.step) {
      if (state.open && state.steps[i].kind === "cmd") html += lineHtml(state.steps[i], state.chars);
    } else {
      html += lineHtml(state.steps[i]);
    }
  }
  if (finished() && state.steps[state.steps.length - 1]?.kind === "open") {
    html += `<div class="rp-line rp-cmd"><span class="rp-prompt">${escapeHtml(lastPrompt())}</span></div>`;
  }
  screen.innerHTML = html;
  placeCursor(screen);
  screen.scrollTop = screen.scrollHeight;
  updateControls();
}

function lastPrompt() {
  for (let i = state.steps.length - 1; i >= 0; i--) if (state.steps[i].kind === "cmd") return state.steps[i].prompt;
  return "root@gateway:~# ";
}

function placeCursor(screen) {
  screen.querySelectorAll(".rp-cursor").forEach((c) => c.remove());
  const last = screen.lastElementChild;
  const showOnCmd = last && last.classList.contains("rp-cmd") && (!finished() || state.steps[state.steps.length - 1]?.kind === "open");
  if (showOnCmd) last.insertAdjacentHTML("beforeend", '<span class="rp-cursor"></span>');
}

/* ---------- Playing ---------- */

function stopTimer() {
  if (state && state.timer) clearTimeout(state.timer);
  if (state) state.timer = null;
}

function alive() {
  return state && state.el && state.el.isConnected;
}

function tick() {
  state.timer = null;
  if (!alive() || !state.playing) return;
  if (finished()) {
    state.playing = false;
    updateControls();
    return;
  }

  const screen = state.el.querySelector(".rp-screen");
  const nearBottom = screen.scrollHeight - screen.scrollTop - screen.clientHeight < 40;
  const step = state.steps[state.step];
  let delay;

  if (step.kind === "cmd") {
    const perChar = Math.max(6, Math.min(32, 1400 / Math.max(1, step.text.length)));
    if (!state.open) {
      // the prompt appears first, then the attacker starts typing
      screen.insertAdjacentHTML("beforeend", lineHtml(step, 0));
      state.open = true;
      delay = 300;
    } else if (state.chars < step.text.length) {
      const typedEl = screen.lastElementChild && screen.lastElementChild.querySelector(".rp-typed");
      // a few characters per tick for long lines, so a long command never drags
      const n = perChar < 12 ? 3 : 1;
      state.chars = Math.min(step.text.length, state.chars + n);
      if (typedEl) typedEl.textContent = step.text.slice(0, state.chars);
      delay = perChar * n;
    } else {
      state.step++;
      state.chars = 0;
      state.open = false;
      delay = 420;
    }
  } else {
    screen.insertAdjacentHTML("beforeend", lineHtml(step));
    state.step++;
    delay = step.kind === "note" ? 220 : 320;
    if (finished() && step.kind === "open") {
      screen.insertAdjacentHTML("beforeend", `<div class="rp-line rp-cmd"><span class="rp-prompt">${escapeHtml(lastPrompt())}</span></div>`);
    }
  }

  placeCursor(screen);
  if (nearBottom) screen.scrollTop = screen.scrollHeight;
  updateControls();
  state.timer = setTimeout(tick, delay / state.speed);
}

function play() {
  if (finished()) {
    state.step = 0;
    state.chars = 0;
    state.open = false;
    redrawScreen();
  }
  state.playing = true;
  stopTimer();
  state.timer = setTimeout(tick, 120);
  updateControls();
}

function pause() {
  state.playing = false;
  stopTimer();
  updateControls();
}

/* ---------- Public ---------- */

export function stopReplay() {
  if (state) {
    state.playing = false;
    stopTimer();
  }
}

export function replayMarkup(s) {
  const cmds = asList(s.commands);
  return `
    <div class="rp" data-replay>
      <div class="rp-head">
        <span class="rp-title">${escapeHtml(String(s.protocol || "").toUpperCase())} · ${escapeHtml(s.source_ip || "")}</span>
        <span class="rp-progress"></span>
      </div>
      <div class="rp-screen" role="log" aria-label="Session replay"></div>
      <div class="rp-bar"><span></span></div>
      <div class="rp-controls">
        <button class="btn sm" data-rp="play">Play</button>
        <button class="btn sm ghost" data-rp="restart" title="Start again">Restart</button>
        <button class="btn sm ghost" data-rp="speed" title="Playback speed">1×</button>
        <button class="btn sm ghost" data-rp="skip" title="Show everything now">Show all</button>
        ${cmds.length ? `<button class="btn sm ghost rp-copy" data-copy="${escapeHtml(cmds.join("\n"))}">Copy commands</button>` : ""}
      </div>
    </div>`;
}

/** Called after the panel HTML is in the page. Starts playing for a new session, resumes otherwise. */
export function mountReplay(root, s) {
  const el = root && root.querySelector("[data-replay]");
  if (!el || !s) return;
  const sid = s.session_id || `${s.source_ip}-${s.start}`;

  if (!state || state.sid !== sid) {
    stopReplay();
    const reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const steps = buildSteps(s);
    state = { sid, steps, step: reduced ? steps.length : 0, chars: 0, open: false, playing: !reduced, speed: state ? state.speed : 1, timer: null, el };
  } else {
    stopTimer();
    state.el = el;
  }

  redrawScreen();

  el.querySelector('[data-rp="play"]')?.addEventListener("click", () => (state.playing ? pause() : play()));
  el.querySelector('[data-rp="restart"]')?.addEventListener("click", () => {
    state.step = 0;
    state.chars = 0;
    state.open = false;
    redrawScreen();
    play();
  });
  el.querySelector('[data-rp="speed"]')?.addEventListener("click", () => {
    state.speed = SPEEDS[(SPEEDS.indexOf(state.speed) + 1) % SPEEDS.length];
    updateControls();
  });
  el.querySelector('[data-rp="skip"]')?.addEventListener("click", () => {
    pause();
    state.step = state.steps.length;
    state.chars = 0;
    state.open = false;
    redrawScreen();
  });

  if (state.playing && !finished()) state.timer = setTimeout(tick, 200);
}

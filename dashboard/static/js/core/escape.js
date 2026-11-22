/**
 * Sanitizare stricta XSS si utilitare de formatare tabulara.
 * Orice string venit de la atacatori (<, >, &, quotes) trece obligatoriu prin escapeHtml().
 */

const ESC_MAP = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
  "`": "&#96;",
};

export function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[&<>"'`]/g, (ch) => ESC_MAP[ch]);
}

export function fmtNum(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "0";
  return n.toLocaleString("en-US");
}

export function fmtTime(iso) {
  if (!iso) return "--:--:--";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso).slice(11, 19) || "--:--:--";
  return d.toISOString().slice(11, 19);
}

export function fmtDateTime(iso) {
  if (!iso) return "N/A";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toISOString().replace("T", " ").slice(0, 19) + "Z";
}

export function shortId(id, maxLen = 12) {
  if (!id) return "-";
  const s = String(id);
  return s.length > maxLen ? s.slice(0, maxLen) : s;
}

export function badgeSeverity(sev) {
  const s = (sev || "NONE").toUpperCase();
  const safe = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"].includes(s) ? s : "NONE";
  return `<span class="badge sev-${safe}">${safe}</span>`;
}

export function badgeProtocol(proto) {
  const p = (proto || "OTHER").toUpperCase();
  const known = ["SSH", "TELNET", "FTP", "HTTP"].includes(p) ? p : "OTHER";
  return `<span class="badge proto-${known}">${escapeHtml(p)}</span>`;
}

export function badgeTag(tag) {
  const raw = String(tag || "").toUpperCase().replace(/[^A-Z0-9_]/g, "_");
  return `<span class="badge tag-${raw}">${escapeHtml(tag)}</span>`;
}

const KILL_STAGES = [
  "conectare",
  "incercare login",
  "login reusit",
  "comenzi",
  "descarcare",
  "persistenta",
];

export function renderStagePips(stages) {
  const set = new Set(stages || []);
  const pips = KILL_STAGES.map((st, idx) => {
    const on = set.has(st) ? `on-${idx + 1}` : "";
    return `<span class="stage-pip ${on}" title="${escapeHtml(st)}"></span>`;
  }).join("");
  return `<span class="stage-pips">${pips}</span>`;
}

export function classifyCommand(cmd) {
  const low = String(cmd || "").toLowerCase();
  if (
    low.includes("hostapd.conf") ||
    low.includes("chap-secrets") ||
    low.includes("wpa_passphrase")
  ) {
    return "honeytoken";
  }
  if (
    low.includes("busybox") ||
    low.includes("ecchi") ||
    low.includes("mirai") ||
    low.includes(".arm7") ||
    low.includes(".mips")
  ) {
    return "mirai";
  }
  if (
    low.includes("nproc") ||
    low.includes("crontab") ||
    low.includes("cpuinfo") ||
    low.includes("xmrig") ||
    low.includes("free")
  ) {
    return "miner";
  }
  if (
    low.includes("wget") ||
    low.includes("curl") ||
    low.includes("tftp") ||
    low.includes("ftpget")
  ) {
    return "download";
  }
  return "";
}

export function showToast(message, isError = false) {
  let host = document.getElementById("toast-container");
  if (!host) {
    host = document.createElement("div");
    host.id = "toast-container";
    host.className = "toast-container";
    document.body.appendChild(host);
  }
  const el = document.createElement("div");
  el.className = `toast${isError ? " error" : ""}`;
  el.textContent = message;
  host.appendChild(el);
  window.setTimeout(() => {
    el.remove();
  }, 2600);
}

export async function copyText(text, label = "Copied to clipboard") {
  const val = String(text ?? "");
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(val);
    } else {
      const ta = document.createElement("textarea");
      ta.value = val;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    showToast(label);
  } catch {
    showToast("Clipboard write failed", true);
  }
}

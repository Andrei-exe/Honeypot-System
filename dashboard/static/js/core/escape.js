/**
 * XSS-safe escaping and formatting helpers.
 * Every string coming from attackers (<, >, &, quotes) must go through escapeHtml().
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

/** Always returns an array without empty entries, so malformed data never crashes a page. */
export function asList(value) {
  return Array.isArray(value) ? value.filter((x) => x !== null && x !== undefined) : [];
}

export function fmtNum(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "0";
  return n.toLocaleString("en-US");
}

function toDate(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** UTC clock time, used where the backend works in UTC. */
export function fmtTime(iso) {
  const d = toDate(iso);
  if (!d) return iso ? String(iso).slice(11, 19) || "--:--:--" : "--:--:--";
  return d.toISOString().slice(11, 19);
}

/** Full local date and time, e.g. "27 Nov 2026, 14:32:07". */
export function fmtLocal(iso) {
  const d = toDate(iso);
  if (!d) return iso ? String(iso) : "—";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/** Kept for older callers: now shows local time too. */
export function fmtDateTime(iso) {
  return fmtLocal(iso);
}

/** Short local time: "14:32:07" today, "27 Nov 14:32" on other days. */
export function fmtShort(iso) {
  const d = toDate(iso);
  if (!d) return "—";
  const now = new Date();
  const sameDay =
    d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
  if (sameDay) {
    return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

/** "just now", "5 min ago", "3 h ago", "2 d ago". */
export function timeAgo(iso) {
  const d = toDate(iso);
  if (!d) return "—";
  const sec = Math.round((Date.now() - d.getTime()) / 1000);
  if (sec < 45) return "just now";
  const min = Math.round(sec / 60);
  if (min < 60) return `${min} min ago`;
  const hours = Math.round(min / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  if (days < 7) return `${days} d ago`;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/** Table cell content: short local time, with relative + full time on hover. */
export function timeCell(iso) {
  return `<span class="time-cell" title="${escapeHtml(`${timeAgo(iso)} · ${fmtLocal(iso)}`)}">${escapeHtml(fmtShort(iso))}</span>`;
}

/** Relative time with the full time on hover. */
export function agoCell(iso) {
  return `<span class="time-cell" title="${escapeHtml(fmtLocal(iso))}">${escapeHtml(timeAgo(iso))}</span>`;
}

export function shortId(id, maxLen = 12) {
  if (!id) return "-";
  const s = String(id);
  return s.length > maxLen ? s.slice(0, maxLen) : s;
}

const SEVERITY_LABELS = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  NONE: "Info",
};

const PROTOCOL_LABELS = {
  SSH: "SSH",
  TELNET: "Telnet",
  FTP: "FTP",
  HTTP: "HTTP",
};

export function badgeSeverity(sev) {
  const s = String(sev || "NONE").toUpperCase();
  const safe = SEVERITY_LABELS[s] ? s : "NONE";
  return `<span class="badge sev-${safe}">${SEVERITY_LABELS[safe]}</span>`;
}

export function badgeProtocol(proto) {
  const p = String(proto || "OTHER").toUpperCase();
  const known = PROTOCOL_LABELS[p] ? p : "OTHER";
  const label = PROTOCOL_LABELS[p] || p;
  return `<span class="badge proto-${known}">${escapeHtml(label)}</span>`;
}

export function badgeTag(tag) {
  const raw = String(tag || "").toUpperCase().replace(/[^A-Z0-9_]/g, "_");
  const label = String(tag || "").toLowerCase().replace(/_/g, " ");
  return `<span class="badge tag-${raw}">${escapeHtml(label)}</span>`;
}

const KILL_STAGES = [
  "conectare",
  "incercare login",
  "login reusit",
  "comenzi",
  "descarcare",
  "persistenta",
];

const STAGE_LABELS = {
  conectare: "Connected",
  "incercare login": "Tried to log in",
  "login reusit": "Logged in",
  comenzi: "Ran commands",
  descarcare: "Downloaded files",
  persistenta: "Set up persistence",
};

export function stageLabel(stage) {
  return STAGE_LABELS[stage] || String(stage || "");
}

export function renderStagePips(stages) {
  const set = new Set(asList(stages));
  const pips = KILL_STAGES.map((st, idx) => {
    const on = set.has(st) ? `on-${idx + 1}` : "";
    return `<span class="stage-pip ${on}" title="${escapeHtml(stageLabel(st))}"></span>`;
  }).join("");
  return `<span class="stage-pips">${pips}</span>`;
}

export function classifyCommand(cmd) {
  const low = String(cmd || "").toLowerCase();
  if (low.includes("hostapd.conf") || low.includes("chap-secrets") || low.includes("wpa_passphrase")) {
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
  if (low.includes("wget") || low.includes("curl") || low.includes("tftp") || low.includes("ftpget")) {
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
  window.setTimeout(() => el.remove(), 2600);
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
    showToast("Could not copy to clipboard", true);
  }
}

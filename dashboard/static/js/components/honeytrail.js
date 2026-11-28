/**
 * Decoy secret trail: who read a decoy file, and who later logged in with the secret inside it.
 *
 * The honeypot's decoy files hold secrets that exist nowhere else (the Wi-Fi password in
 * /etc/hostapd.conf, the PPPoE account in /etc/ppp/chap-secrets). A login with one of them
 * proves the sender had read the file, so when the reader and the user are different IPs,
 * the secret was passed from one attacker to another.
 *
 * One lane per decoy file, on a shared time axis: hollow dots = read the file,
 * filled dots = logged in with the secret, a line joins each login to the last read before it
 * (red when the IPs differ). Everything is built from the honeytoken alerts already loaded.
 */

import { asList, escapeHtml, fmtLocal, fmtShort } from "../core/escape.js";

const SECRETS = [
  { id: "wifi", name: "Wi-Fi password", file: "/etc/hostapd.conf", markers: ["hostapd.conf", "wpa_passphrase"] },
  { id: "pppoe", name: "PPPoE account", file: "/etc/ppp/chap-secrets", markers: ["chap-secrets"] },
];

function secretOf(al) {
  const pd = al.payload_details || {};
  const text = [al.alert_reason, pd.command, pd.http_path, pd.raw_data].filter(Boolean).join(" ").toLowerCase();
  const found = SECRETS.find((s) => s.markers.some((m) => text.includes(m)));
  return found ? found.id : null;
}

function kindOf(al) {
  if (al.event_type === "login_attempt" || al.credentials) return "use";
  return "read";
}

function gap(ms) {
  const sec = Math.max(0, Math.round(ms / 1000));
  if (sec < 60) return `${sec} s`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min} min`;
  const h = Math.floor(min / 60);
  if (h < 48) return `${h} h ${min % 60} min`;
  return `${Math.round(h / 24)} days`;
}

/** Turns the honeytoken alerts into lanes with points and links. Pure function, easy to test. */
export function buildTrail(alerts) {
  const points = [];
  asList(alerts).forEach((al) => {
    if (!al || typeof al !== "object") return;
    const secret = secretOf(al);
    const t = Date.parse(al.timestamp);
    if (!secret || !Number.isFinite(t)) return;
    points.push({ al, secret, kind: kindOf(al), t, ip: String(al.source_ip || "?") });
  });
  points.sort((a, b) => a.t - b.t);

  const tMin = points.length ? points[0].t : 0;
  const tMax = points.length ? points[points.length - 1].t : 0;
  const span = tMax - tMin;
  const xOf = (t) => (span > 0 ? 4 + ((t - tMin) / span) * 92 : 50);

  const lanes = SECRETS.map((s) => {
    const pts = points.filter((p) => p.secret === s.id).map((p) => ({ ...p, x: xOf(p.t) }));
    const reads = pts.filter((p) => p.kind === "read");
    const links = [];
    pts
      .filter((p) => p.kind === "use")
      .forEach((use) => {
        let from = null;
        for (const r of reads) if (r.t <= use.t) from = r;
        links.push({ from, to: use, passedOn: Boolean(from && from.ip !== use.ip) });
      });
    return { ...s, points: pts, reads, uses: pts.filter((p) => p.kind === "use"), links };
  }).filter((lane) => lane.points.length);

  const passedOn = lanes.reduce((n, lane) => n + lane.links.filter((l) => l.passedOn).length, 0);
  return { lanes, tMin, tMax, passedOn, total: points.length };
}

function laneSvg(lane) {
  // viewBox is stretched to the lane's width; strokes keep their thickness (non-scaling-stroke)
  return `<svg class="ht-links" viewBox="0 0 100 60" preserveAspectRatio="none" aria-hidden="true">
    <line x1="0" y1="30" x2="100" y2="30" class="ht-axis" vector-effect="non-scaling-stroke"></line>
    ${lane.links
      .filter((l) => l.from)
      .map((l) => {
        const mid = (l.from.x + l.to.x) / 2;
        return `<path d="M ${l.from.x} 18 Q ${mid} 30 ${l.to.x} 42" class="ht-link ${l.passedOn ? "passed" : ""}" vector-effect="non-scaling-stroke"></path>`;
      })
      .join("")}
  </svg>`;
}

function dot(p, idx) {
  const what = p.kind === "use" ? "logged in with the secret" : "read the file";
  const cred = p.al.credentials ? ` as ${p.al.credentials.username || "?"}` : "";
  const title = `${p.ip} ${what}${p.kind === "use" ? cred : ""} · ${fmtLocal(p.al.timestamp)} · click for details`;
  return `<button class="ht-dot ${p.kind}" style="left:${p.x.toFixed(2)}%;" data-ht-idx="${idx}" title="${escapeHtml(title)}" aria-label="${escapeHtml(title)}"></button>`;
}

function stories(lane) {
  const lines = lane.links.slice(-3).reverse().map((l) => {
    const user = `<span class="ip-link" data-inspect-ip="${escapeHtml(l.to.ip)}">${escapeHtml(l.to.ip)}</span>`;
    if (!l.from) {
      return `<li>${user} logged in with the ${escapeHtml(lane.name)} at ${escapeHtml(fmtShort(l.to.al.timestamp))}. <span class="cell-muted">The read is older than the alerts loaded here.</span></li>`;
    }
    const reader = `<span class="ip-link" data-inspect-ip="${escapeHtml(l.from.ip)}">${escapeHtml(l.from.ip)}</span>`;
    const when = gap(l.to.t - l.from.t);
    return l.passedOn
      ? `<li class="passed">${reader} read the file, then <strong>another IP</strong>, ${user}, logged in with the ${escapeHtml(lane.name)} ${escapeHtml(when)} later. <strong>The secret was passed on.</strong></li>`
      : `<li>${user} read the file and came back ${escapeHtml(when)} later to log in with the ${escapeHtml(lane.name)}.</li>`;
  });
  if (!lane.uses.length) {
    const ips = [...new Set(lane.reads.map((r) => r.ip))];
    lines.push(`<li class="cell-muted">${ips.length === 1 ? "1 IP has" : `${ips.length} IPs have`} read this file. Nobody has used the secret yet.</li>`);
  } else if (lane.links.length > 3) {
    lines.push(`<li class="cell-muted">… and ${lane.links.length - 3} earlier logins with this secret.</li>`);
  }
  return `<ul class="ht-stories">${lines.join("")}</ul>`;
}

/** HTML for the trail plus the flat list of points (index = data-ht-idx). */
export function honeytrailMarkup(alerts) {
  const trail = buildTrail(alerts);
  if (!trail.lanes.length) {
    return {
      trail,
      items: [],
      html: `<div class="empty-state">Nobody has opened the decoy files yet. On the honeypot, <span class="mono">cat /etc/hostapd.conf</span> starts a trail; a later login with the Wi-Fi password from it completes one.</div>`,
    };
  }

  const items = [];
  const lanesHtml = trail.lanes
    .map((lane) => {
      const dots = lane.points
        .map((p) => {
          items.push(p.al);
          return dot(p, items.length - 1);
        })
        .join("");
      return `
        <div class="ht-lane">
          <div class="ht-lane-head">
            <span class="ht-name">${escapeHtml(lane.name)}</span>
            <span class="mono cell-muted">${escapeHtml(lane.file)}</span>
            <span class="cell-muted ht-counts">${lane.reads.length} read · ${lane.uses.length} used</span>
          </div>
          <div class="ht-track">${laneSvg(lane)}${dots}</div>
          ${stories(lane)}
        </div>`;
    })
    .join("");

  const html = `
    <div class="ht">
      ${lanesHtml}
      <div class="ht-foot">
        <span class="ht-key"><span class="ht-dot read static"></span>read the file</span>
        <span class="ht-key"><span class="ht-dot use static"></span>logged in with the secret</span>
        <span class="ht-key"><span class="ht-swatch passed"></span>another IP used it</span>
        <span class="cell-muted ht-range">${escapeHtml(fmtShort(new Date(trail.tMin).toISOString()))} → ${escapeHtml(fmtShort(new Date(trail.tMax).toISOString()))}</span>
      </div>
    </div>`;
  return { trail, items, html };
}

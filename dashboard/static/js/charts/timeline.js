/**
 * Stacked bar chart of alerts over time, split by protocol (HTML5 canvas, HiDPI).
 */

const PROTO_COLORS = {
  SSH: "#6b9ce8",
  TELNET: "#e8924a",
  FTP: "#a98be0",
  HTTP: "#4cb36b",
  OTHER: "#828c99",
};

const PROTO_LABELS = {
  SSH: "SSH",
  TELNET: "Telnet",
  FTP: "FTP",
  HTTP: "HTTP",
  OTHER: "Other",
};

const ORDER = ["SSH", "TELNET", "FTP", "HTTP", "OTHER"];

/** Bucket label in the viewer's local time (the backend sends UTC labels and a unix "ts"). */
function bucketLabel(b, full) {
  if (typeof b.ts !== "number") return full ? `${b.label} UTC` : b.label;
  const d = new Date(b.ts * 1000);
  return full
    ? d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

const FONT = '12px system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif';
const COLOR_AXIS_TEXT = "#77818e";
const COLOR_GRID = "#212730";
const COLOR_LEGEND = "#a3acb8";
const COLOR_CRITICAL = "#ef5b5b";

function roundedTopRect(ctx, x, y, w, h, r) {
  const rr = Math.min(r, w / 2, h);
  ctx.beginPath();
  ctx.moveTo(x, y + h);
  ctx.lineTo(x, y + rr);
  ctx.quadraticCurveTo(x, y, x + rr, y);
  ctx.lineTo(x + w - rr, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + rr);
  ctx.lineTo(x + w, y + h);
  ctx.closePath();
  ctx.fill();
}

export class TimelineChart {
  constructor(containerEl, { height = 200, onSelectBucket = null } = {}) {
    this.container = containerEl;
    this.height = height;
    this.onSelectBucket = onSelectBucket;
    this.data = null;
    this.hoverIdx = -1;

    this.container.innerHTML = "";
    this.container.classList.add("canvas-box");
    this.container.style.height = `${height}px`;

    this.canvas = document.createElement("canvas");
    this.tooltip = document.createElement("div");
    this.tooltip.className = "canvas-tooltip";
    this.container.appendChild(this.canvas);
    this.container.appendChild(this.tooltip);
    this.ctx = this.canvas.getContext("2d");

    this._onMove = (ev) => this._handleMove(ev);
    this._onLeave = () => {
      this.hoverIdx = -1;
      this.tooltip.style.display = "none";
      this.draw();
    };
    this._onClick = () => {
      if (this.hoverIdx >= 0 && this.data && this.data.buckets[this.hoverIdx] && this.onSelectBucket) {
        this.onSelectBucket(this.data.buckets[this.hoverIdx]);
      }
    };

    this.canvas.addEventListener("mousemove", this._onMove);
    this.canvas.addEventListener("mouseleave", this._onLeave);
    this.canvas.addEventListener("click", this._onClick);

    this._ro = new ResizeObserver(() => this.draw());
    this._ro.observe(this.container);
  }

  setData(timelineData) {
    this.data = timelineData;
    this.draw();
  }

  destroy() {
    this._ro.disconnect();
    this.canvas.removeEventListener("mousemove", this._onMove);
    this.canvas.removeEventListener("mouseleave", this._onLeave);
    this.canvas.removeEventListener("click", this._onClick);
  }

  _metrics() {
    const rect = this.container.getBoundingClientRect();
    return {
      w: Math.max(240, Math.floor(rect.width)),
      h: this.height,
      padL: 36,
      padR: 8,
      padT: 30,
      padB: 26,
    };
  }

  _handleMove(ev) {
    if (!this.data || !this.data.buckets || !this.data.buckets.length) return;
    const rect = this.canvas.getBoundingClientRect();
    const mx = ev.clientX - rect.left;
    const my = ev.clientY - rect.top;
    const m = this._metrics();
    const plotW = m.w - m.padL - m.padR;

    if (mx < m.padL || mx > m.w - m.padR || my < m.padT || my > m.h - m.padB) {
      this._onLeave();
      return;
    }

    const n = this.data.buckets.length;
    const idx = Math.max(0, Math.min(n - 1, Math.floor(((mx - m.padL) / plotW) * n)));
    this.hoverIdx = idx;

    const b = this.data.buckets[idx];
    const protoParts = ORDER.filter((p) => b[p]).map((p) => `${PROTO_LABELS[p]} ${b[p]}`);
    const lines = [
      bucketLabel(b, true),
      `${b.total} alert${b.total === 1 ? "" : "s"}${b.CRITICAL ? ` (${b.CRITICAL} critical)` : ""}`,
    ];
    if (protoParts.length) lines.push(protoParts.join(" · "));
    this.tooltip.textContent = lines.join("\n");
    this.tooltip.style.display = "block";

    const tipW = this.tooltip.offsetWidth || 180;
    const left = mx + 14 + tipW > m.w ? Math.max(4, mx - tipW - 12) : mx + 12;
    const top = Math.max(6, Math.min(m.h - 72, my - 12));
    this.tooltip.style.left = `${left}px`;
    this.tooltip.style.top = `${top}px`;

    this.draw();
  }

  draw() {
    const m = this._metrics();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    this.canvas.width = Math.floor(m.w * dpr);
    this.canvas.height = Math.floor(m.h * dpr);
    this.canvas.style.width = `${m.w}px`;
    this.canvas.style.height = `${m.h}px`;

    const ctx = this.ctx;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, m.w, m.h);
    ctx.font = FONT;

    const buckets = (this.data && this.data.buckets) || [];
    const plotW = m.w - m.padL - m.padR;
    const plotH = m.h - m.padT - m.padB;

    // Legend, top-left
    let lx = m.padL;
    for (const proto of ORDER.slice(0, 4)) {
      ctx.fillStyle = PROTO_COLORS[proto];
      ctx.beginPath();
      ctx.arc(lx + 4, 10, 4, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = COLOR_LEGEND;
      ctx.fillText(PROTO_LABELS[proto], lx + 12, 14);
      lx += ctx.measureText(PROTO_LABELS[proto]).width + 30;
    }

    if (!buckets.length) {
      ctx.fillStyle = COLOR_AXIS_TEXT;
      ctx.textAlign = "center";
      ctx.fillText("No alerts in this time range", m.padL + plotW / 2, m.padT + plotH / 2);
      ctx.textAlign = "left";
      return;
    }

    const maxTotal = Math.max(4, ...buckets.map((b) => b.total || 0));
    const yTicks = 4;

    // Grid lines and Y labels
    ctx.strokeStyle = COLOR_GRID;
    ctx.lineWidth = 1;
    ctx.textAlign = "right";
    for (let i = 0; i <= yTicks; i++) {
      const ratio = i / yTicks;
      const y = Math.round(m.padT + plotH * (1 - ratio)) + 0.5;
      ctx.beginPath();
      ctx.moveTo(m.padL, y);
      ctx.lineTo(m.w - m.padR, y);
      ctx.stroke();
      ctx.fillStyle = COLOR_AXIS_TEXT;
      ctx.fillText(String(Math.round(maxTotal * ratio)), m.padL - 8, y + 4);
    }
    ctx.textAlign = "left";

    const step = plotW / buckets.length;
    const gap = Math.max(2, Math.min(6, step * 0.25));
    const barW = Math.max(2, step - gap);

    for (let i = 0; i < buckets.length; i++) {
      const b = buckets[i];
      const x = m.padL + i * step + gap / 2;

      if (i === this.hoverIdx) {
        ctx.fillStyle = "rgba(107, 156, 232, 0.08)";
        ctx.fillRect(m.padL + i * step, m.padT, step, plotH);
      }

      const segments = ORDER.filter((p) => b[p]);
      let curY = m.padT + plotH;
      segments.forEach((proto, sIdx) => {
        const segH = Math.max(1, (b[proto] / maxTotal) * plotH);
        curY -= segH;
        ctx.fillStyle = PROTO_COLORS[proto];
        if (sIdx === segments.length - 1) {
          roundedTopRect(ctx, x, curY, barW, segH, 3);
        } else {
          ctx.fillRect(x, curY, barW, segH);
        }
      });

      // Small red dot above buckets that contain critical alerts
      if (b.CRITICAL > 0) {
        ctx.fillStyle = COLOR_CRITICAL;
        ctx.beginPath();
        ctx.arc(x + barW / 2, Math.max(m.padT + 3, curY - 6), 2.5, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    // X labels
    const xLabelCount = Math.min(6, buckets.length);
    ctx.fillStyle = COLOR_AXIS_TEXT;
    ctx.textAlign = "center";
    for (let k = 0; k < xLabelCount; k++) {
      const idx = Math.floor((k * (buckets.length - 1)) / Math.max(1, xLabelCount - 1));
      ctx.fillText(bucketLabel(buckets[idx], false), m.padL + idx * step + step / 2, m.h - 6);
    }
    ctx.textAlign = "left";
  }
}

/**
 * Line chart of alerts over time; hover shows the split by protocol (HTML5 canvas, HiDPI).
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
const COLOR_CRITICAL = "#ef5b5b";
const LINE_COLOR = "#6b9ce8";

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
      padT: 14,
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

    // One calm line with a soft fill: total alerts per time bucket
    const step = plotW / buckets.length;
    const pts = buckets.map((b, i) => ({
      x: m.padL + i * step + step / 2,
      y: m.padT + plotH - ((b.total || 0) / maxTotal) * plotH,
    }));
    const baseY = m.padT + plotH;

    const tracePath = () => {
      ctx.beginPath();
      ctx.moveTo(pts[0].x, pts[0].y);
      if (pts.length === 1) {
        ctx.lineTo(pts[0].x + 0.01, pts[0].y);
        return;
      }
      // Quadratic curves through midpoints: smooth, and never dips below the data
      for (let i = 1; i < pts.length - 1; i++) {
        const mx = (pts[i].x + pts[i + 1].x) / 2;
        const my = (pts[i].y + pts[i + 1].y) / 2;
        ctx.quadraticCurveTo(pts[i].x, pts[i].y, mx, my);
      }
      const last = pts[pts.length - 1];
      ctx.lineTo(last.x, last.y);
    };

    if (pts.length > 1) {
      tracePath();
      ctx.lineTo(pts[pts.length - 1].x, baseY);
      ctx.lineTo(pts[0].x, baseY);
      ctx.closePath();
      const fill = ctx.createLinearGradient(0, m.padT, 0, baseY);
      fill.addColorStop(0, "rgba(107, 156, 232, 0.28)");
      fill.addColorStop(1, "rgba(107, 156, 232, 0.02)");
      ctx.fillStyle = fill;
      ctx.fill();
    }

    tracePath();
    ctx.strokeStyle = LINE_COLOR;
    ctx.lineWidth = 2;
    ctx.lineJoin = "round";
    ctx.lineCap = "round";
    ctx.stroke();

    // Red dots on buckets that contain critical alerts
    for (let i = 0; i < buckets.length; i++) {
      if (buckets[i].CRITICAL > 0) {
        ctx.fillStyle = COLOR_CRITICAL;
        ctx.beginPath();
        ctx.arc(pts[i].x, pts[i].y, 3.5, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    // Hover: a thin guide line and a dot on the current bucket
    if (this.hoverIdx >= 0 && pts[this.hoverIdx]) {
      const p = pts[this.hoverIdx];
      ctx.strokeStyle = "rgba(163, 172, 184, 0.35)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(Math.round(p.x) + 0.5, m.padT);
      ctx.lineTo(Math.round(p.x) + 0.5, baseY);
      ctx.stroke();
      ctx.fillStyle = "#0f1319";
      ctx.strokeStyle = LINE_COLOR;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(p.x, p.y, 4.5, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();
    }

    // X labels
    const xLabelCount = Math.min(6, buckets.length);
    ctx.fillStyle = COLOR_AXIS_TEXT;
    ctx.textAlign = "center";
    for (let k = 0; k < xLabelCount; k++) {
      const idx = Math.floor((k * (buckets.length - 1)) / Math.max(1, xLabelCount - 1));
      ctx.fillText(bucketLabel(buckets[idx], false), pts[idx].x, m.h - 6);
    }
    ctx.textAlign = "left";
  }
}

/**
 * Grafic multi-protocol pe HTML5 Canvas 2D (HiDPI, colțuri 90°, crosshair interactiv).
 */

const PROTO_COLORS = {
  SSH: "#4b91d9",
  TELNET: "#e07b24",
  FTP: "#a371f7",
  HTTP: "#2ea043",
  OTHER: "#7d8a9c",
};

const ORDER = ["SSH", "TELNET", "FTP", "HTTP", "OTHER"];

export class TimelineChart {
  constructor(containerEl, { height = 185, onSelectBucket = null } = {}) {
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
    const w = Math.max(240, Math.floor(rect.width));
    const h = this.height;
    return {
      w,
      h,
      padL: 38,
      padR: 12,
      padT: 20,
      padB: 24,
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
    const lines = [
      `UTC  ${b.label}`,
      `TOT  ${b.total} (CRIT:${b.CRITICAL || 0} HIGH:${b.HIGH || 0})`,
      `SSH:${b.SSH || 0} TEL:${b.TELNET || 0} FTP:${b.FTP || 0} HTTP:${b.HTTP || 0}`,
    ];
    this.tooltip.textContent = lines.join("\n");
    this.tooltip.style.display = "block";

    const tipW = this.tooltip.offsetWidth || 180;
    const left = mx + 14 + tipW > m.w ? Math.max(4, mx - tipW - 12) : mx + 12;
    const top = Math.max(6, Math.min(m.h - 68, my - 12));
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
    ctx.fillStyle = "#06080b";
    ctx.fillRect(0, 0, m.w, m.h);

    const buckets = (this.data && this.data.buckets) || [];
    const plotW = m.w - m.padL - m.padR;
    const plotH = m.h - m.padT - m.padB;

    // Legenda compacta sus-dreapta
    ctx.font = '10px "IBM Plex Mono", ui-monospace, monospace';
    let lx = m.w - m.padR;
    for (let i = ORDER.length - 2; i >= 0; i--) {
      const proto = ORDER[i];
      const tw = ctx.measureText(proto).width;
      lx -= tw + 16;
      ctx.fillStyle = PROTO_COLORS[proto];
      ctx.fillRect(lx, 6, 7, 7);
      ctx.fillStyle = "#8d9bb0";
      ctx.fillText(proto, lx + 10, 13);
    }

    if (!buckets.length) {
      ctx.fillStyle = "#647285";
      ctx.fillText("NO TELEMETRY BUCKETS IN BUFFER", m.padL + 10, m.padT + plotH / 2);
      return;
    }

    const maxTotal = Math.max(4, ...buckets.map((b) => b.total || 0));
    const yTicks = 4;

    // Linii de grila orizontale + etichete Y
    ctx.strokeStyle = "#161d27";
    ctx.lineWidth = 1;
    ctx.textAlign = "right";
    for (let i = 0; i <= yTicks; i++) {
      const ratio = i / yTicks;
      const y = Math.round(m.padT + plotH * (1 - ratio)) + 0.5;
      ctx.beginPath();
      ctx.moveTo(m.padL, y);
      ctx.lineTo(m.w - m.padR, y);
      ctx.stroke();

      const val = Math.round(maxTotal * ratio);
      ctx.fillStyle = "#647285";
      ctx.fillText(String(val), m.padL - 5, y + 3);
    }
    ctx.textAlign = "left";

    // Bare stivuite pe protocoale (0px border-radius)
    const step = plotW / buckets.length;
    const barW = Math.max(2, Math.floor(step - 2));

    for (let i = 0; i < buckets.length; i++) {
      const b = buckets[i];
      const x = Math.floor(m.padL + i * step) + 1;

      if (i === this.hoverIdx) {
        ctx.fillStyle = "rgba(88, 166, 255, 0.12)";
        ctx.fillRect(Math.floor(m.padL + i * step), m.padT, Math.ceil(step), plotH);
      }

      let curY = m.padT + plotH;
      for (const proto of ORDER) {
        const v = b[proto] || 0;
        if (!v) continue;
        const segH = Math.max(1, (v / maxTotal) * plotH);
        curY -= segH;
        ctx.fillStyle = PROTO_COLORS[proto];
        ctx.fillRect(x, Math.round(curY), barW, Math.ceil(segH));
      }

      // Marcaj 2px rosu deasupra barei daca exista alerte CRITICAL in bucket
      if (b.CRITICAL > 0) {
        ctx.fillStyle = "#e5484d";
        ctx.fillRect(x, Math.max(m.padT, Math.round(curY) - 3), barW, 2);
      }
    }

    // Axe X / Y (hairline 1px)
    ctx.strokeStyle = "#2b3647";
    ctx.beginPath();
    ctx.moveTo(m.padL + 0.5, m.padT);
    ctx.lineTo(m.padL + 0.5, m.padT + plotH + 0.5);
    ctx.lineTo(m.w - m.padR, m.padT + plotH + 0.5);
    ctx.stroke();

    // Etichete X (6 repere)
    const xLabelCount = Math.min(6, buckets.length);
    ctx.fillStyle = "#647285";
    ctx.textAlign = "center";
    for (let k = 0; k < xLabelCount; k++) {
      const idx = Math.floor((k * (buckets.length - 1)) / Math.max(1, xLabelCount - 1));
      const x = m.padL + idx * step + step / 2;
      ctx.fillText(buckets[idx].label, x, m.h - 7);
    }
    ctx.textAlign = "left";

    // Crosshair vertical la hover
    if (this.hoverIdx >= 0) {
      const cx = Math.round(m.padL + this.hoverIdx * step + step / 2) + 0.5;
      ctx.strokeStyle = "rgba(216, 222, 233, 0.35)";
      ctx.beginPath();
      ctx.moveTo(cx, m.padT);
      ctx.lineTo(cx, m.padT + plotH);
      ctx.stroke();
    }
  }
}

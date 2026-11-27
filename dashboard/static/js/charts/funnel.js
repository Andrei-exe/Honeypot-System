/**
 * "How far attackers got": one horizontal bar per attack stage (HTML5 canvas, HiDPI).
 */

const STAGE_COLORS = ["#6b9ce8", "#6b9ce8", "#d6b347", "#e8924a", "#ef5b5b", "#ef5b5b"];

const STAGE_LABELS = {
  conectare: "Connected",
  "incercare login": "Tried to log in",
  "login reusit": "Logged in",
  comenzi: "Ran commands",
  descarcare: "Downloaded files",
  persistenta: "Set up persistence",
};

const FONT = '13px system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif';

function roundRect(ctx, x, y, w, h, r) {
  const rr = Math.min(r, h / 2, w / 2);
  ctx.beginPath();
  ctx.moveTo(x + rr, y);
  ctx.lineTo(x + w - rr, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + rr);
  ctx.lineTo(x + w, y + h - rr);
  ctx.quadraticCurveTo(x + w, y + h, x + w - rr, y + h);
  ctx.lineTo(x + rr, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - rr);
  ctx.lineTo(x, y + rr);
  ctx.quadraticCurveTo(x, y, x + rr, y);
  ctx.closePath();
  ctx.fill();
}

export class KillChainFunnel {
  constructor(containerEl, { height = 200, onStageClick = null } = {}) {
    this.container = containerEl;
    this.height = height;
    this.onStageClick = onStageClick;
    this.stages = [];
    this.hoverIdx = -1;

    this.container.innerHTML = "";
    this.container.classList.add("canvas-box");
    this.container.style.height = `${height}px`;

    this.canvas = document.createElement("canvas");
    this.container.appendChild(this.canvas);
    this.ctx = this.canvas.getContext("2d");

    this._onMove = (ev) => {
      if (!this.stages.length) return;
      const rect = this.canvas.getBoundingClientRect();
      const rowH = this.height / this.stages.length;
      const idx = Math.floor((ev.clientY - rect.top) / rowH);
      const next = idx >= 0 && idx < this.stages.length ? idx : -1;
      if (next !== this.hoverIdx) {
        this.hoverIdx = next;
        this.canvas.style.cursor = next >= 0 ? "pointer" : "default";
        this.draw();
      }
    };
    this._onLeave = () => {
      this.hoverIdx = -1;
      this.draw();
    };
    this._onClick = () => {
      if (this.hoverIdx >= 0 && this.stages[this.hoverIdx] && this.onStageClick) {
        this.onStageClick(this.stages[this.hoverIdx].stage);
      }
    };

    this.canvas.addEventListener("mousemove", this._onMove);
    this.canvas.addEventListener("mouseleave", this._onLeave);
    this.canvas.addEventListener("click", this._onClick);

    this._ro = new ResizeObserver(() => this.draw());
    this._ro.observe(this.container);
  }

  setData(funnelArray) {
    this.stages = Array.isArray(funnelArray) ? funnelArray : [];
    this.draw();
  }

  destroy() {
    this._ro.disconnect();
    this.canvas.removeEventListener("mousemove", this._onMove);
    this.canvas.removeEventListener("mouseleave", this._onLeave);
    this.canvas.removeEventListener("click", this._onClick);
  }

  draw() {
    const rect = this.container.getBoundingClientRect();
    const w = Math.max(240, Math.floor(rect.width));
    const h = this.height;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);

    this.canvas.width = Math.floor(w * dpr);
    this.canvas.height = Math.floor(h * dpr);
    this.canvas.style.width = `${w}px`;
    this.canvas.style.height = `${h}px`;

    const ctx = this.ctx;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    ctx.font = FONT;
    ctx.textBaseline = "middle";

    if (!this.stages.length) {
      ctx.fillStyle = "#77818e";
      ctx.textAlign = "center";
      ctx.fillText("No sessions yet", w / 2, h / 2);
      ctx.textAlign = "left";
      return;
    }

    const labelW = 150;
    const rightW = 110;
    const barMaxW = Math.max(40, w - labelW - rightW);
    const first = Math.max(1, this.stages[0].sessions || 0);
    const maxVal = Math.max(first, ...this.stages.map((s) => s.sessions || 0));
    const rowH = h / this.stages.length;
    const barH = Math.min(14, rowH * 0.5);

    this.stages.forEach((item, idx) => {
      const cy = idx * rowH + rowH / 2;
      const count = item.sessions || 0;
      const pct = Math.round((count / first) * 100);
      const barW = count > 0 ? Math.max(4, (count / maxVal) * barMaxW) : 0;
      const hover = idx === this.hoverIdx;

      if (hover) {
        ctx.fillStyle = "rgba(255,255,255,0.03)";
        ctx.fillRect(0, idx * rowH, w, rowH);
      }

      ctx.fillStyle = hover ? "#f2f4f7" : "#a3acb8";
      ctx.fillText(STAGE_LABELS[item.stage] || String(item.stage || ""), 4, cy);

      ctx.fillStyle = "#1f252d";
      roundRect(ctx, labelW, cy - barH / 2, barMaxW, barH, barH / 2);
      if (barW > 0) {
        ctx.fillStyle = STAGE_COLORS[idx % STAGE_COLORS.length];
        roundRect(ctx, labelW, cy - barH / 2, barW, barH, barH / 2);
      }

      ctx.textAlign = "right";
      ctx.fillStyle = count > 0 ? "#d5dae1" : "#77818e";
      ctx.fillText(`${count.toLocaleString("en-US")}`, w - 52, cy);
      ctx.fillStyle = "#77818e";
      ctx.fillText(`${pct}%`, w - 4, cy);
      ctx.textAlign = "left";
    });
  }
}

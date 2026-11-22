/**
 * Kill-chain funnel on an HTML5 2D Canvas (6 stages, conversion rates, 0px rounding).
 */

const STAGE_COLORS = [
  "#3b82c4",
  "#4b91d9",
  "#cfa82b",
  "#e07b24",
  "#e5484d",
  "#ff2e4c",
];

export class KillChainFunnel {
  constructor(containerEl, { height = 195, onStageClick = null } = {}) {
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
      const my = ev.clientY - rect.top;
      const rowH = (this.height - 16) / this.stages.length;
      const idx = Math.floor((my - 8) / rowH);
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
    const w = Math.max(220, Math.floor(rect.width));
    const h = this.height;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);

    this.canvas.width = Math.floor(w * dpr);
    this.canvas.height = Math.floor(h * dpr);
    this.canvas.style.width = `${w}px`;
    this.canvas.style.height = `${h}px`;

    const ctx = this.ctx;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.fillStyle = "#06080b";
    ctx.fillRect(0, 0, w, h);

    if (!this.stages.length) {
      ctx.font = '11px "IBM Plex Mono", ui-monospace, monospace';
      ctx.fillStyle = "#647285";
      ctx.fillText("NO KILL-CHAIN SESSION DATA", 12, h / 2);
      return;
    }

    const labelW = 118;
    const rightW = 86;
    const barMaxW = Math.max(40, w - labelW - rightW - 14);
    const maxVal = Math.max(1, this.stages[0].sessions || 0, ...this.stages.map((s) => s.sessions || 0));
    const rowH = (h - 16) / this.stages.length;

    ctx.font = '10px "IBM Plex Mono", ui-monospace, monospace';

    this.stages.forEach((item, idx) => {
      const y = Math.floor(8 + idx * rowH);
      const count = item.sessions || 0;
      const pct = maxVal > 0 ? Math.round((count / maxVal) * 100) : 0;
      const barW = count > 0 ? Math.max(3, Math.round((count / maxVal) * barMaxW)) : 0;

      if (idx === this.hoverIdx) {
        ctx.fillStyle = "#121822";
        ctx.fillRect(2, y, w - 4, rowH - 2);
      }

      // Left label
      ctx.fillStyle = idx === this.hoverIdx ? "#f0f4fa" : "#9aa7b8";
      ctx.fillText(`${idx + 1}. ${String(item.stage || "").toUpperCase()}`, 8, y + rowH * 0.62);

      // Background track
      const barY = Math.floor(y + (rowH - 12) / 2);
      ctx.fillStyle = "#11161e";
      ctx.fillRect(labelW, barY, barMaxW, 12);
      ctx.strokeStyle = "#1e2633";
      ctx.strokeRect(labelW + 0.5, barY + 0.5, barMaxW - 1, 11);

      // Actual bar
      if (barW > 0) {
        ctx.fillStyle = STAGE_COLORS[idx % STAGE_COLORS.length];
        ctx.fillRect(labelW, barY, barW, 12);
      }

      // Value + percentage on the right
      ctx.textAlign = "right";
      ctx.fillStyle = count > 0 ? "#d8dee9" : "#647285";
      ctx.fillText(`${count} (${pct}%)`, w - 8, y + rowH * 0.62);
      ctx.textAlign = "left";
    });
  }
}

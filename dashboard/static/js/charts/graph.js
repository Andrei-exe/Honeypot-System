/**
 * Graf interactiv force-directed pe Canvas 2D pentru campanii, familii si corelari IP.
 * Suporta: drag pe noduri, pan (drag pe fundal), zoom (scroll) si click-to-inspect.
 */

const NODE_STYLE = {
  campaign: { fill: "#291215", stroke: "#e5484d", text: "#ff8c8f", size: 11 },
  family:   { fill: "#101e2e", stroke: "#4b91d9", text: "#79c0ff", size: 10 },
  server:   { fill: "#261b0b", stroke: "#e07b24", text: "#f2a65a", size: 10 },
  ip:       { fill: "#141a24", stroke: "#8d9bb0", text: "#d8dee9", size: 7 },
};

const EDGE_COLOR = {
  campaign_member: "rgba(229, 72, 77, 0.45)",
  malware_host:    "rgba(224, 123, 36, 0.55)",
  behavior_cluster:"rgba(75, 145, 217, 0.38)",
};

export class CorrelationGraph {
  constructor(containerEl, { height = 410, onNodeClick = null } = {}) {
    this.container = containerEl;
    this.height = height;
    this.onNodeClick = onNodeClick;

    this.nodes = [];
    this.edges = [];
    this.nodeById = new Map();
    this.hovered = null;
    this.dragNode = null;
    this.panning = false;
    this.panStart = { x: 0, y: 0 };
    this.offset = { x: 0, y: 0 };
    this.scale = 1;
    this._raf = null;
    this._ticks = 0;

    this.container.innerHTML = "";
    this.container.classList.add("canvas-box");
    this.container.style.height = `${height}px`;

    this.canvas = document.createElement("canvas");
    this.tooltip = document.createElement("div");
    this.tooltip.className = "canvas-tooltip";
    this.container.appendChild(this.canvas);
    this.container.appendChild(this.tooltip);
    this.ctx = this.canvas.getContext("2d");

    this._bindEvents();
    this._ro = new ResizeObserver(() => this.draw());
    this._ro.observe(this.container);
  }

  _bindEvents() {
    this._onDown = (ev) => {
      const p = this._screenToWorld(ev);
      const hit = this._hitTest(p.x, p.y);
      this._downPos = { x: ev.clientX, y: ev.clientY };
      if (hit) {
        this.dragNode = hit;
        this._ticks = Math.max(this._ticks, 45);
        this._ensureLoop();
      } else {
        this.panning = true;
        this.panStart = { x: ev.clientX - this.offset.x, y: ev.clientY - this.offset.y };
      }
    };

    this._onMove = (ev) => {
      const p = this._screenToWorld(ev);
      if (this.dragNode) {
        this.dragNode.x = p.x;
        this.dragNode.y = p.y;
        this.dragNode.vx = 0;
        this.dragNode.vy = 0;
        this.draw();
        return;
      }
      if (this.panning) {
        this.offset.x = ev.clientX - this.panStart.x;
        this.offset.y = ev.clientY - this.panStart.y;
        this.draw();
        return;
      }

      const hit = this._hitTest(p.x, p.y);
      if (hit !== this.hovered) {
        this.hovered = hit;
        this.canvas.style.cursor = hit ? "pointer" : "grab";
        this.draw();
      }
      if (hit) {
        const rect = this.canvas.getBoundingClientRect();
        const mx = ev.clientX - rect.left;
        const my = ev.clientY - rect.top;
        const metaLines = [`[${hit.kind.toUpperCase()}] ${hit.label}`];
        if (hit.meta && hit.meta.reasons && hit.meta.reasons.length) {
          metaLines.push(`Link: ${hit.meta.reasons.join(", ")}`);
        }
        if (hit.meta && hit.meta.traits && hit.meta.traits.length) {
          metaLines.push(`Traits: ${hit.meta.traits.slice(0, 4).join(", ")}`);
        }
        metaLines.push("Click to inspect / pivot");
        this.tooltip.textContent = metaLines.join("\n");
        this.tooltip.style.display = "block";
        this.tooltip.style.left = `${Math.min(rect.width - 210, mx + 12)}px`;
        this.tooltip.style.top = `${Math.max(6, my - 10)}px`;
      } else {
        this.tooltip.style.display = "none";
      }
    };

    this._onUp = (ev) => {
      const moved = this._downPos
        ? Math.hypot(ev.clientX - this._downPos.x, ev.clientY - this._downPos.y)
        : 99;
      if (this.dragNode && moved < 5 && this.onNodeClick) {
        this.onNodeClick(this.dragNode);
      }
      this.dragNode = null;
      this.panning = false;
    };

    this._onWheel = (ev) => {
      ev.preventDefault();
      const factor = ev.deltaY < 0 ? 1.12 : 0.89;
      this.scale = Math.max(0.45, Math.min(2.6, this.scale * factor));
      this.draw();
    };

    this.canvas.addEventListener("mousedown", this._onDown);
    window.addEventListener("mousemove", this._onMove);
    window.addEventListener("mouseup", this._onUp);
    this.canvas.addEventListener("wheel", this._onWheel, { passive: false });
  }

  destroy() {
    if (this._raf) cancelAnimationFrame(this._raf);
    this._ro.disconnect();
    this.canvas.removeEventListener("mousedown", this._onDown);
    window.removeEventListener("mousemove", this._onMove);
    window.removeEventListener("mouseup", this._onUp);
    this.canvas.removeEventListener("wheel", this._onWheel);
  }

  setData(graphData) {
    const rawNodes = (graphData && graphData.nodes) || [];
    const rawEdges = (graphData && graphData.edges) || [];

    const prevMap = new Map(this.nodes.map((n) => [n.id, n]));
    const count = Math.max(1, rawNodes.length);

    this.nodes = rawNodes.map((n, idx) => {
      const prev = prevMap.get(n.id);
      const angle = (idx / count) * Math.PI * 2;
      const radius = n.kind === "ip" ? 130 : 55;
      return {
        ...n,
        x: prev ? prev.x : Math.cos(angle) * radius + (idx % 5) * 7,
        y: prev ? prev.y : Math.sin(angle) * radius + (idx % 3) * 7,
        vx: 0,
        vy: 0,
      };
    });

    this.nodeById = new Map(this.nodes.map((n) => [n.id, n]));
    this.edges = rawEdges
      .map((e) => ({
        source: this.nodeById.get(e.source),
        target: this.nodeById.get(e.target),
        kind: e.kind,
      }))
      .filter((e) => e.source && e.target);

    this._ticks = 110;
    this._ensureLoop();
  }

  resetView() {
    this.offset = { x: 0, y: 0 };
    this.scale = 1;
    this.draw();
  }

  _ensureLoop() {
    if (this._raf) return;
    const step = () => {
      if (this._ticks > 0) {
        this._simulate();
        this._ticks -= 1;
        this.draw();
        this._raf = requestAnimationFrame(step);
      } else {
        this._raf = null;
        this.draw();
      }
    };
    this._raf = requestAnimationFrame(step);
  }

  _simulate() {
    const nodes = this.nodes;
    const n = nodes.length;
    if (!n) return;

    // Respingere Coulomb simplificata
    for (let i = 0; i < n; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < n; j++) {
        const b = nodes[j];
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        const dist2 = dx * dx + dy * dy + 25;
        const force = 1600 / dist2;
        const dist = Math.sqrt(dist2);
        dx /= dist;
        dy /= dist;
        a.vx -= dx * force;
        a.vy -= dy * force;
        b.vx += dx * force;
        b.vy += dy * force;
      }
    }

    // Atractie pe muchii
    for (const e of this.edges) {
      const dx = e.target.x - e.source.x;
      const dy = e.target.y - e.source.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const desired = 78;
      const k = (dist - desired) * 0.035;
      const fx = (dx / dist) * k;
      const fy = (dy / dist) * k;
      e.source.vx += fx;
      e.source.vy += fy;
      e.target.vx -= fx;
      e.target.vy -= fy;
    }

    // Gravitatie usoara spre centru + amortizare
    for (const node of nodes) {
      if (node === this.dragNode) continue;
      node.vx += -node.x * 0.012;
      node.vy += -node.y * 0.012;
      node.vx *= 0.78;
      node.vy *= 0.78;
      node.x += Math.max(-14, Math.min(14, node.vx));
      node.y += Math.max(-14, Math.min(14, node.vy));
    }
  }

  _screenToWorld(ev) {
    const rect = this.canvas.getBoundingClientRect();
    const cx = rect.width / 2 + this.offset.x;
    const cy = rect.height / 2 + this.offset.y;
    return {
      x: (ev.clientX - rect.left - cx) / this.scale,
      y: (ev.clientY - rect.top - cy) / this.scale,
    };
  }

  _hitTest(wx, wy) {
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const n = this.nodes[i];
      const st = NODE_STYLE[n.kind] || NODE_STYLE.ip;
      const r = st.size + 4;
      if (Math.abs(wx - n.x) <= r && Math.abs(wy - n.y) <= r) {
        return n;
      }
    }
    return null;
  }

  draw() {
    const rect = this.container.getBoundingClientRect();
    const w = Math.max(260, Math.floor(rect.width));
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

    // Grid tehnic discret 24px
    ctx.strokeStyle = "#0e131b";
    ctx.lineWidth = 1;
    for (let gx = 0; gx < w; gx += 28) {
      ctx.beginPath();
      ctx.moveTo(gx + 0.5, 0);
      ctx.lineTo(gx + 0.5, h);
      ctx.stroke();
    }
    for (let gy = 0; gy < h; gy += 28) {
      ctx.beginPath();
      ctx.moveTo(0, gy + 0.5);
      ctx.lineTo(w, gy + 0.5);
      ctx.stroke();
    }

    if (!this.nodes.length) {
      ctx.font = '11px "IBM Plex Mono", ui-monospace, monospace';
      ctx.fillStyle = "#647285";
      ctx.fillText("NO CORRELATED CAMPAIGNS OR FAMILIES YET (NEED >= 2 LINKED IPS)", 16, h / 2);
      return;
    }

    ctx.save();
    ctx.translate(w / 2 + this.offset.x, h / 2 + this.offset.y);
    ctx.scale(this.scale, this.scale);

    // Muchii
    for (const e of this.edges) {
      const highlight = this.hovered && (e.source === this.hovered || e.target === this.hovered);
      ctx.strokeStyle = highlight ? "#d8dee9" : (EDGE_COLOR[e.kind] || "#354357");
      ctx.lineWidth = highlight ? 1.5 : 1;
      ctx.beginPath();
      ctx.moveTo(e.source.x, e.source.y);
      ctx.lineTo(e.target.x, e.target.y);
      ctx.stroke();
    }

    // Noduri (patrate/diamante stricte, 0 rotunjiri)
    ctx.font = '10px "IBM Plex Mono", ui-monospace, monospace';
    for (const node of this.nodes) {
      const st = NODE_STYLE[node.kind] || NODE_STYLE.ip;
      const sz = st.size;
      const isHover = node === this.hovered;

      ctx.fillStyle = st.fill;
      ctx.strokeStyle = isHover ? "#f0f4fa" : st.stroke;
      ctx.lineWidth = isHover ? 2 : 1.2;

      if (node.kind === "campaign" || node.kind === "server") {
        // Diamant (patrat rotit la 45°)
        ctx.beginPath();
        ctx.moveTo(node.x, node.y - sz);
        ctx.lineTo(node.x + sz, node.y);
        ctx.lineTo(node.x, node.y + sz);
        ctx.lineTo(node.x - sz, node.y);
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
      } else {
        ctx.fillRect(node.x - sz, node.y - sz, sz * 2, sz * 2);
        ctx.strokeRect(node.x - sz, node.y - sz, sz * 2, sz * 2);
      }

      ctx.fillStyle = isHover ? "#ffffff" : st.text;
      ctx.fillText(node.label, node.x + sz + 5, node.y + 3);
    }

    ctx.restore();

    // Legenda fixa jos-stanga
    ctx.font = '10px "IBM Plex Mono", ui-monospace, monospace';
    const items = [
      ["CAMPAIGN", "#e5484d"],
      ["FAMILY", "#4b91d9"],
      ["MALWARE HOST", "#e07b24"],
      ["ATTACKER IP", "#8d9bb0"],
    ];
    let lx = 10;
    for (const [label, col] of items) {
      ctx.fillStyle = col;
      ctx.fillRect(lx, h - 16, 7, 7);
      ctx.fillStyle = "#8d9bb0";
      ctx.fillText(label, lx + 11, h - 9);
      lx += ctx.measureText(label).width + 24;
    }
  }
}

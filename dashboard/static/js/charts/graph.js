/**
 * Force-directed graph (HTML5 canvas) of campaigns, behaviour families and attacker IPs.
 * Drag a node to move it, drag the background to pan, scroll to zoom, click for details.
 */

const NODE_STYLE = {
  campaign: { fill: "rgba(239, 91, 91, 0.18)", stroke: "#ef5b5b", text: "#f4a3a3", size: 10 },
  family:   { fill: "rgba(107, 156, 232, 0.18)", stroke: "#6b9ce8", text: "#a9c6f1", size: 9 },
  server:   { fill: "rgba(232, 146, 74, 0.18)", stroke: "#e8924a", text: "#f1bb8d", size: 9 },
  ip:       { fill: "#1f252d", stroke: "#828c99", text: "#d5dae1", size: 6 },
};

const NODE_NAMES = { campaign: "Campaign", family: "Behaviour family", server: "Malware server", ip: "Attacker IP" };

const EDGE_COLOR = {
  campaign_member: "rgba(239, 91, 91, 0.35)",
  malware_host: "rgba(232, 146, 74, 0.45)",
  behavior_cluster: "rgba(107, 156, 232, 0.3)",
};

const FONT = '12px system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif';

export class CorrelationGraph {
  constructor(containerEl, { height = 380, onNodeClick = null } = {}) {
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
    this.canvas.style.cursor = "grab";
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
      if (ev.target !== this.canvas) {
        if (this.hovered) {
          this.hovered = null;
          this.tooltip.style.display = "none";
          this.draw();
        }
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
        const lines = [`${NODE_NAMES[hit.kind] || "Node"}: ${hit.label}`];
        if (hit.meta && hit.meta.reasons && hit.meta.reasons.length) lines.push(`Linked by: ${hit.meta.reasons.join(", ")}`);
        if (hit.meta && hit.meta.traits && hit.meta.traits.length) lines.push(`Behaviour: ${hit.meta.traits.slice(0, 4).join(", ")}`);
        lines.push("Click for details");
        this.tooltip.textContent = lines.join("\n");
        this.tooltip.style.display = "block";
        this.tooltip.style.left = `${Math.max(4, Math.min(rect.width - 240, ev.clientX - rect.left + 12))}px`;
        this.tooltip.style.top = `${Math.max(6, ev.clientY - rect.top - 10)}px`;
      } else {
        this.tooltip.style.display = "none";
      }
    };

    this._onUp = (ev) => {
      const moved = this._downPos ? Math.hypot(ev.clientX - this._downPos.x, ev.clientY - this._downPos.y) : 99;
      if (this.dragNode && moved < 5 && this.onNodeClick) this.onNodeClick(this.dragNode);
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
    this._raf = null;
    this._ro.disconnect();
    this.canvas.removeEventListener("mousedown", this._onDown);
    window.removeEventListener("mousemove", this._onMove);
    window.removeEventListener("mouseup", this._onUp);
    this.canvas.removeEventListener("wheel", this._onWheel);
  }

  setData(graphData) {
    const rawNodes = Array.isArray(graphData && graphData.nodes) ? graphData.nodes : [];
    const rawEdges = Array.isArray(graphData && graphData.edges) ? graphData.edges : [];

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
      .map((e) => ({ source: this.nodeById.get(e.source), target: this.nodeById.get(e.target), kind: e.kind }))
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

    for (const e of this.edges) {
      const dx = e.target.x - e.source.x;
      const dy = e.target.y - e.source.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const k = (dist - 78) * 0.035;
      const fx = (dx / dist) * k;
      const fy = (dy / dist) * k;
      e.source.vx += fx;
      e.source.vy += fy;
      e.target.vx -= fx;
      e.target.vy -= fy;
    }

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
    return { x: (ev.clientX - rect.left - cx) / this.scale, y: (ev.clientY - rect.top - cy) / this.scale };
  }

  _hitTest(wx, wy) {
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const n = this.nodes[i];
      const st = NODE_STYLE[n.kind] || NODE_STYLE.ip;
      const r = st.size + 4;
      if ((wx - n.x) ** 2 + (wy - n.y) ** 2 <= r * r) return n;
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
    ctx.clearRect(0, 0, w, h);
    ctx.font = FONT;

    if (!this.nodes.length) {
      ctx.fillStyle = "#77818e";
      ctx.textAlign = "center";
      ctx.fillText("No linked attackers yet", w / 2, h / 2);
      ctx.textAlign = "left";
      return;
    }

    ctx.save();
    ctx.translate(w / 2 + this.offset.x, h / 2 + this.offset.y);
    ctx.scale(this.scale, this.scale);

    for (const e of this.edges) {
      const highlight = this.hovered && (e.source === this.hovered || e.target === this.hovered);
      ctx.strokeStyle = highlight ? "#d5dae1" : EDGE_COLOR[e.kind] || "#3a4350";
      ctx.lineWidth = highlight ? 1.5 : 1;
      ctx.beginPath();
      ctx.moveTo(e.source.x, e.source.y);
      ctx.lineTo(e.target.x, e.target.y);
      ctx.stroke();
    }

    for (const node of this.nodes) {
      const st = NODE_STYLE[node.kind] || NODE_STYLE.ip;
      const isHover = node === this.hovered;
      ctx.fillStyle = st.fill;
      ctx.strokeStyle = isHover ? "#f2f4f7" : st.stroke;
      ctx.lineWidth = isHover ? 2 : 1.4;
      ctx.beginPath();
      ctx.arc(node.x, node.y, st.size, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();

      // Only label group nodes, hovered nodes, or IPs when zoomed in: keeps the graph readable
      if (node.kind !== "ip" || isHover || this.scale >= 1.4) {
        ctx.fillStyle = isHover ? "#ffffff" : st.text;
        ctx.fillText(node.label, node.x + st.size + 5, node.y + 4);
      }
    }

    ctx.restore();

    const items = [
      ["Campaign", "#ef5b5b"],
      ["Family", "#6b9ce8"],
      ["Malware server", "#e8924a"],
      ["Attacker IP", "#828c99"],
    ];
    let lx = 4;
    for (const [label, col] of items) {
      ctx.fillStyle = col;
      ctx.beginPath();
      ctx.arc(lx + 4, h - 12, 4, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = "#a3acb8";
      ctx.fillText(label, lx + 12, h - 8);
      lx += ctx.measureText(label).width + 30;
    }
  }
}

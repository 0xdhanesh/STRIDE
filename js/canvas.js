// Interactive infinite canvas: pan/zoom, select, move, resize, draw shapes,
// connect data flows, bend lines, erase and edit labels in place.

import { store } from './store.js';
import { renderElements, orderedElements, diagramBounds, FONTS } from './render.js';
import { threatBadges } from './engine.js';
import {
  clamp, center, isLine, lineGeom, quadPolyline, distToSeg, pointInRect, elementBounds, unionBounds, measureText, distToShape,
} from './util.js';
import { makeElement, deleteElements, autoBend, containedIn, fitNote } from './ops.js';

const ACCENT = '#6965db';
const CONNECTABLE = ['process', 'external', 'store'];
const NODE_TOOLS = ['process', 'external', 'store', 'boundary'];

export class Canvas {
  constructor(wrap) {
    this.wrap = wrap;
    this.svg = wrap.querySelector('svg');
    this.svg.innerHTML = '<g class="viewport"><g class="content"></g><g class="overlay"></g></g>';
    this.viewport = this.svg.querySelector('.viewport');
    this.content = this.svg.querySelector('.content');
    this.overlay = this.svg.querySelector('.overlay');
    this.editor = wrap.querySelector('#inline-editor');
    this.state = null;
    this.editingId = null;
    this.spaceDown = false;
    this.raf = 0;
    this.pointers = new Map();

    this.svg.addEventListener('pointerdown', (e) => this.onDown(e));
    window.addEventListener('pointermove', (e) => this.onMove(e));
    window.addEventListener('pointerup', (e) => this.onUp(e));
    window.addEventListener('pointercancel', (e) => this.onUp(e));
    this.svg.addEventListener('pointerleave', () => { if (this.hoverNode && !this.state) { this.hoverNode = null; this.schedule(); } });
    this.svg.addEventListener('wheel', (e) => this.onWheel(e), { passive: false });
    this.svg.addEventListener('dblclick', (e) => this.onDblClick(e));
    this.svg.addEventListener('contextmenu', (e) => this.onContextMenu(e));
    this.editor.addEventListener('keydown', (e) => this.onEditorKey(e));
    this.editor.addEventListener('input', () => this.sizeEditor());
    this.editor.addEventListener('blur', () => this.finishEdit());
    window.addEventListener('resize', () => this.schedule());

    store.on((type) => { if (['change', 'render', 'ui', 'prefs', 'loaded'].includes(type)) this.schedule(); });
  }

  /* ----------------------------------------------------------- coordinates */

  get zoom() { return store.view.zoom; }
  toWorld(e) {
    const r = this.svg.getBoundingClientRect();
    const v = store.view;
    return { x: (e.clientX - r.left - v.x) / v.zoom, y: (e.clientY - r.top - v.y) / v.zoom };
  }
  toScreen(p) {
    const v = store.view;
    return { x: p.x * v.zoom + v.x, y: p.y * v.zoom + v.y };
  }
  viewportCenter() {
    const r = this.svg.getBoundingClientRect();
    return this.toWorld({ clientX: r.left + r.width / 2, clientY: r.top + r.height / 2 });
  }

  zoomAt(screenX, screenY, factor) {
    const v = store.view;
    const z = clamp(v.zoom * factor, 0.1, 5);
    v.x = screenX - (screenX - v.x) * (z / v.zoom);
    v.y = screenY - (screenY - v.y) * (z / v.zoom);
    v.zoom = z;
    store.emit('view');
    this.schedule();
  }
  zoomBy(factor) {
    const r = this.svg.getBoundingClientRect();
    this.zoomAt(r.width / 2, r.height / 2, factor);
  }
  resetZoom() { this.zoomBy(1 / this.zoom); }

  fit(elements = null) {
    const d = store.diagram;
    const byId = store.byId();
    const b = elements ? unionBounds(elements.map((e) => elementBounds(e, byId))) : diagramBounds(d);
    const r = this.svg.getBoundingClientRect();
    const v = store.view;
    if (!b) { Object.assign(v, { x: r.width / 2, y: r.height / 2, zoom: 1 }); }
    else {
      const pad = Math.min(80, r.width * 0.06);
      const z = clamp(Math.min((r.width - pad * 2) / Math.max(b.w, 1), (r.height - pad * 2) / Math.max(b.h, 1)), 0.1, elements ? 2 : 1);
      Object.assign(v, { zoom: z, x: r.width / 2 - (b.x + b.w / 2) * z, y: r.height / 2 - (b.y + b.h / 2) * z });
    }
    store.emit('view');
    this.schedule();
  }

  /* ------------------------------------------------------------- rendering */

  schedule() {
    if (!this.raf) this.raf = requestAnimationFrame(() => { this.raf = 0; this.draw(); });
  }

  draw() {
    const v = store.view;
    const d = store.diagram;
    this.viewport.setAttribute('transform', `translate(${v.x} ${v.y}) scale(${v.zoom})`);
    const g = 20 * v.zoom;
    this.wrap.style.backgroundSize = `${g}px ${g}px`;
    this.wrap.style.backgroundPosition = `${v.x}px ${v.y}px`;
    this.wrap.classList.toggle('grid', !!store.prefs.grid && v.zoom > 0.3);
    this.wrap.dataset.tool = store.ui.tool;
    this.content.innerHTML = renderElements(d, {
      sketchy: store.prefs.sketchy, ink: '#1e1e1e', bg: '#ffffff',
      font: store.prefs.sketchy ? FONTS.sketchy : FONTS.clean,
      badges: store.ui.analysis ? threatBadges(store.model, d.id) : null,
      hidden: this.editingId && d.elements.find((e) => e.id === this.editingId)?.type === 'note' ? this.editingId : null,
    });
    this.overlay.innerHTML = this.renderOverlay();
    this.wrap.classList.toggle('empty', d.elements.length === 0);
    if (this.editingId) this.positionEditor();
  }

  renderOverlay() {
    const z = this.zoom;
    const sw = 1.5 / z;
    const byId = store.byId();
    const sel = store.selected();
    let out = '';

    // Highlight the element behind the active threat in Analysis view.
    const t = store.ui.analysis && store.ui.activeThreat ? store.model.threats[store.ui.activeThreat] : null;
    const focusEl = t && t.diagramId === store.diagram.id ? byId.get(t.flowId || t.elementId) : null;
    if (focusEl) {
      if (isLine(focusEl)) {
        const g = lineGeom(focusEl, byId);
        out += `<path d="M${g.s.x} ${g.s.y}Q${g.c.x} ${g.c.y} ${g.t.x} ${g.t.y}" fill="none" stroke="#fab005" stroke-opacity=".45" stroke-width="${12}" stroke-linecap="round"/>`;
      } else {
        out += `<rect x="${focusEl.x - 8}" y="${focusEl.y - 8}" width="${focusEl.w + 16}" height="${focusEl.h + 16}" rx="10" fill="none" stroke="#fab005" stroke-opacity=".6" stroke-width="${6}"/>`;
      }
    }

    for (const el of sel) {
      if (isLine(el)) {
        const g = lineGeom(el, byId);
        out += `<path d="M${g.s.x} ${g.s.y}Q${g.c.x} ${g.c.y} ${g.t.x} ${g.t.y}" fill="none" stroke="${ACCENT}" stroke-opacity=".35" stroke-width="${6 / z}" stroke-linecap="round"/>`;
      } else {
        const p = 6 / z;
        out += `<rect x="${el.x - p}" y="${el.y - p}" width="${el.w + p * 2}" height="${el.h + p * 2}" fill="none" stroke="${ACCENT}" stroke-width="${sw}" stroke-dasharray="${4 / z} ${3 / z}"/>`;
      }
    }
    if (sel.length === 1 && !this.state?.mode?.startsWith('create')) {
      for (const h of this.handles(sel[0])) {
        const r = 5 / z;
        out += h.kind === 'resize'
          ? `<rect x="${h.x - r}" y="${h.y - r}" width="${r * 2}" height="${r * 2}" rx="${r / 2.5}" fill="#fff" stroke="${ACCENT}" stroke-width="${sw}"/>`
          : `<circle cx="${h.x}" cy="${h.y}" r="${r * (h.kind === 'bend' ? 1 : 1.2)}" fill="${h.kind === 'bend' ? ACCENT : '#fff'}" stroke="${ACCENT}" stroke-width="${sw}"/>`;
      }
    }
    const hn = !this.state && ['select', 'flow'].includes(store.ui.tool) && this.hoverNode && byId.get(this.hoverNode.id);
    if (hn) {
      for (const d of this.connectDots(hn)) {
        out += `<circle cx="${d.x}" cy="${d.y}" r="${4.5 / z}" fill="#fff" stroke="${ACCENT}" stroke-width="${sw}"/>`;
      }
    }
    const hover = this.state?.hover;
    if (hover) {
      out += `<rect x="${hover.x - 6}" y="${hover.y - 6}" width="${hover.w + 12}" height="${hover.h + 12}" rx="${hover.type === 'process' ? Math.min(hover.w, hover.h) / 2 : 8}" fill="${ACCENT}" fill-opacity=".08" stroke="${ACCENT}" stroke-width="${2 / z}"/>`;
    }
    if (this.state?.mode === 'marquee') {
      const { a, b } = this.state;
      out += `<rect x="${Math.min(a.x, b.x)}" y="${Math.min(a.y, b.y)}" width="${Math.abs(a.x - b.x)}" height="${Math.abs(a.y - b.y)}" fill="${ACCENT}" fill-opacity=".08" stroke="${ACCENT}" stroke-width="${sw}"/>`;
    }
    return out;
  }

  handles(el) {
    const z = this.zoom;
    if (isLine(el)) {
      const g = lineGeom(el, store.byId());
      return [{ kind: 'start', x: g.s.x, y: g.s.y }, { kind: 'end', x: g.t.x, y: g.t.y }, { kind: 'bend', x: g.mid.x, y: g.mid.y }];
    }
    if (el.type === 'note') return [];
    const p = 6 / z;
    return [
      { kind: 'resize', corner: 'nw', x: el.x - p, y: el.y - p }, { kind: 'resize', corner: 'ne', x: el.x + el.w + p, y: el.y - p },
      { kind: 'resize', corner: 'sw', x: el.x - p, y: el.y + el.h + p }, { kind: 'resize', corner: 'se', x: el.x + el.w + p, y: el.y + el.h + p },
    ];
  }

  /* ----------------------------------------------------------- hit testing */

  hitHandle(p) {
    const sel = store.selected();
    if (sel.length !== 1) return null;
    const tol = 9 / this.zoom;
    const h = this.handles(sel[0]).find((h) => Math.hypot(h.x - p.x, h.y - p.y) <= tol);
    return h ? { ...h, el: sel[0] } : null;
  }

  hitElement(el, p, byId, tol) {
    if (isLine(el)) {
      const g = lineGeom(el, byId);
      const pts = quadPolyline(g.s, g.c, g.t, 20);
      for (let i = 0; i < pts.length - 1; i++) if (distToSeg(p, pts[i], pts[i + 1]) <= tol + 2) return true;
      if (el.name) {
        const m = measureText(el.name, 14);
        const w = Math.min(m.w, 180);
        if (Math.abs(p.x - g.mid.x) <= w / 2 + 4 && Math.abs(p.y - g.mid.y) <= m.h / 2 + 4) return true;
      }
      return false;
    }
    if (el.type === 'process') {
      const c = center(el);
      const rx = el.w / 2 + tol, ry = el.h / 2 + tol;
      return ((p.x - c.x) / rx) ** 2 + ((p.y - c.y) / ry) ** 2 <= 1;
    }
    if (el.type === 'boundary') {
      const outer = { x: el.x - tol, y: el.y - tol, w: el.w + tol * 2, h: el.h + tol * 2 };
      const inner = { x: el.x + tol, y: el.y + tol, w: el.w - tol * 2, h: el.h - tol * 2 };
      const label = { x: el.x, y: el.y, w: Math.min(el.w, measureText(el.name, 15).w + 50), h: 32 };
      return (pointInRect(p, outer) && !pointInRect(p, inner)) || pointInRect(p, label);
    }
    return pointInRect(p, { x: el.x - tol, y: el.y - tol, w: el.w + tol * 2, h: el.h + tol * 2 });
  }

  hitTest(p) {
    const byId = store.byId();
    const tol = 6 / this.zoom;
    const els = orderedElements(store.diagram).reverse();
    return els.find((el) => this.hitElement(el, p, byId, tol)) || null;
  }

  // Shape a connector end should attach to: the shape under the pointer, or
  // (magnetic) the nearest shape outline within `snap` screen pixels.
  hitConnectable(p, excludeId = null, snap = 28) {
    const byId = store.byId();
    const z = this.zoom;
    const els = orderedElements(store.diagram).reverse().filter((el) => CONNECTABLE.includes(el.type) && el.id !== excludeId);
    const direct = els.find((el) => this.hitElement(el, p, byId, 4 / z));
    if (direct) return direct;
    let best = null, bestD = snap / z;
    for (const el of els) {
      const d = distToShape(el, p);
      if (d < bestD) { bestD = d; best = el; }
    }
    return best;
  }

  // Connection points shown around a hovered shape; dragging one starts a data flow.
  connectDots(el) {
    const o = 14 / this.zoom;
    const c = center(el);
    return [{ x: c.x, y: el.y - o }, { x: el.x + el.w + o, y: c.y }, { x: c.x, y: el.y + el.h + o }, { x: el.x - o, y: c.y }];
  }

  hitConnectDot(p) {
    const el = this.hoverNode && store.diagram.elements.find((e) => e.id === this.hoverNode.id);
    if (!el) return null;
    return this.connectDots(el).some((d) => Math.hypot(d.x - p.x, d.y - p.y) <= 10 / this.zoom) ? el : null;
  }

  // Attach loose flow ends that now lie on a shape (e.g. after moving the shape onto them).
  attachLooseEnds() {
    const d = store.diagram;
    const at = (pt, exclude) => d.elements.find((n) => CONNECTABLE.includes(n.type) && n.id !== exclude && distToShape(n, pt) === 0);
    for (const f of d.elements) {
      if (f.type !== 'flow') continue;
      if (!f.sourceId) { const n = at({ x: f.x1, y: f.y1 }, f.targetId); if (n) f.sourceId = n.id; }
      if (!f.targetId) { const n = at({ x: f.x2, y: f.y2 }, f.sourceId); if (n) f.targetId = n.id; }
    }
  }

  startFlow(src, p) {
    const el = makeElement(store.model, 'flow', src ? center(src) : p);
    if (src) el.sourceId = src.id;
    el.x2 = p.x; el.y2 = p.y;
    store.diagram.elements.push(el);
    store.ui.selection = new Set([el.id]);
    this.hoverNode = null;
    this.state = { mode: 'create-line', el, start: p, moved: false, hover: null };
  }

  /* ---------------------------------------------------------- interactions */

  onDown(e) {
    if (e.button === 2) return;
    e.preventDefault(); // no text selection / focus stealing; inputs are blurred explicitly below
    this.pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (this.pointers.size === 2) { this.startPinch(); return; }
    if (this.editingId) this.editor.blur();
    document.activeElement?.blur?.();
    store.emit('canvas-pointerdown');
    const p = this.toWorld(e);
    const tool = store.ui.tool;
    const d = store.diagram;

    if (e.button === 1 || this.spaceDown || tool === 'hand') {
      e.preventDefault();
      this.state = { mode: 'pan', sx: e.clientX, sy: e.clientY, vx: store.view.x, vy: store.view.y };
      this.wrap.classList.add('panning');
      return;
    }

    if (tool === 'select') {
      const h = this.hitHandle(p);
      if (h) {
        this.state = { mode: h.kind, el: h.el, corner: h.corner, orig: { x: h.el.x, y: h.el.y, w: h.el.w, h: h.el.h }, start: p };
        return;
      }
      const dotNode = this.hitConnectDot(p);
      if (dotNode) { this.startFlow(dotNode, p); return; }
      const hit = this.hitTest(p);
      if (hit) {
        const sel = new Set(store.ui.selection);
        if (e.shiftKey) {
          sel.has(hit.id) ? sel.delete(hit.id) : sel.add(hit.id);
          store.select(sel);
          if (!sel.has(hit.id)) return;
        } else if (!sel.has(hit.id)) {
          store.select([hit.id]);
        }
        this.startMove(p, e.altKey);
      } else {
        const base = e.shiftKey ? new Set(store.ui.selection) : new Set();
        if (!e.shiftKey) store.select([]);
        this.state = { mode: 'marquee', a: p, b: p, base };
      }
      return;
    }

    if (tool === 'eraser') {
      this.state = { mode: 'erase', removed: new Set() };
      this.eraseAt(p);
      return;
    }

    if (tool === 'flow') { this.startFlow(this.hitConnectDot(p) || this.hitConnectable(p), p); return; }
    if (tool === 'boundaryLine') {
      const el = makeElement(store.model, tool, p);
      d.elements.push(el);
      store.ui.selection = new Set([el.id]);
      this.state = { mode: 'create-line', el, start: p, moved: false, hover: null };
      return;
    }

    if (tool === 'note') {
      const el = makeElement(store.model, 'note', p);
      d.elements.push(el);
      store.select([el.id]);
      this.startEdit(el, true);
      if (!store.ui.toolLock) store.setUI({ tool: 'select' });
      return;
    }

    if (NODE_TOOLS.includes(tool)) {
      this.state = { mode: 'create-node', tool, start: p, el: null };
    }
  }

  startMove(p, alt) {
    const d = store.diagram;
    const moving = new Set(store.ui.selection);
    if (!alt) for (const el of store.selected()) if (el.type === 'boundary') for (const c of containedIn(d, el)) moving.add(c.id);
    const orig = new Map();
    for (const el of d.elements) {
      if (!moving.has(el.id)) continue;
      orig.set(el.id, isLine(el) ? { x1: el.x1, y1: el.y1, x2: el.x2, y2: el.y2 } : { x: el.x, y: el.y });
    }
    this.state = { mode: 'move', start: p, orig, moved: false };
  }

  onMove(e) {
    if (this.pointers.has(e.pointerId)) this.pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (this.state?.mode === 'pinch') { this.updatePinch(); return; }
    const s = this.state;
    if (!s) { if (e.target === this.svg || this.svg.contains(e.target)) this.updateCursor(e); return; }
    const p = this.toWorld(e);
    const d = store.diagram;
    const byId = store.byId();

    switch (s.mode) {
      case 'pan': {
        const v = store.view;
        v.x = s.vx + (e.clientX - s.sx);
        v.y = s.vy + (e.clientY - s.sy);
        store.emit('view');
        break;
      }
      case 'move': {
        const dx = p.x - s.start.x, dy = p.y - s.start.y;
        if (!s.moved && Math.hypot(dx, dy) * this.zoom < 3) return;
        s.moved = true;
        for (const el of d.elements) {
          const o = s.orig.get(el.id);
          if (!o) continue;
          if (isLine(el)) {
            if (!el.sourceId) { el.x1 = o.x1 + dx; el.y1 = o.y1 + dy; }
            if (!el.targetId) { el.x2 = o.x2 + dx; el.y2 = o.y2 + dy; }
          } else { el.x = o.x + dx; el.y = o.y + dy; }
        }
        break;
      }
      case 'resize': {
        // The corner opposite the dragged handle stays fixed.
        const { orig: o, corner, el } = s;
        const fx = corner.includes('w') ? o.x + o.w : o.x;
        const fy = corner.includes('n') ? o.y + o.h : o.y;
        let w = Math.max(30, Math.abs(p.x - fx)), h = Math.max(30, Math.abs(p.y - fy));
        if (e.shiftKey) w = h = Math.max(w, h);
        el.x = p.x < fx ? fx - w : fx;
        el.y = p.y < fy ? fy - h : fy;
        el.w = w; el.h = h;
        break;
      }
      case 'start':
      case 'end': {
        const el = s.el;
        const isStart = s.mode === 'start';
        s.hover = el.type === 'flow' ? this.hitConnectable(p, isStart ? el.targetId : el.sourceId) : null;
        if (isStart) { el.sourceId = s.hover?.id ?? null; el.x1 = p.x; el.y1 = p.y; } else { el.targetId = s.hover?.id ?? null; el.x2 = p.x; el.y2 = p.y; }
        break;
      }
      case 'bend': {
        const el = s.el;
        const g = lineGeom({ ...el, bend: 0 }, byId);
        const mid = { x: (g.s.x + g.t.x) / 2, y: (g.s.y + g.t.y) / 2 };
        let bend = (p.x - mid.x) * g.n.x + (p.y - mid.y) * g.n.y;
        if (Math.abs(bend) < 8 / this.zoom) bend = 0;
        el.bend = Math.round(bend);
        break;
      }
      case 'marquee': {
        s.b = p;
        const r = { x: Math.min(s.a.x, p.x), y: Math.min(s.a.y, p.y), w: Math.abs(s.a.x - p.x), h: Math.abs(s.a.y - p.y) };
        const ids = new Set(s.base);
        for (const el of d.elements) {
          const bb = elementBounds(el, byId);
          if (bb.x >= r.x && bb.y >= r.y && bb.x + bb.w <= r.x + r.w && bb.y + bb.h <= r.y + r.h) ids.add(el.id);
        }
        store.ui.selection = ids;
        store.emit('ui', { source: 'selection' });
        break;
      }
      case 'create-line': {
        const el = s.el;
        el.x2 = p.x; el.y2 = p.y;
        if (Math.hypot(p.x - s.start.x, p.y - s.start.y) * this.zoom > 6) s.moved = true;
        s.hover = el.type === 'flow' && s.moved ? this.hitConnectable(p, el.sourceId) : null;
        if (el.type === 'flow') el.targetId = s.hover?.id ?? null; // preview the attached arrow
        break;
      }
      case 'create-node': {
        const dx = p.x - s.start.x, dy = p.y - s.start.y;
        if (!s.el) {
          if (Math.hypot(dx, dy) * this.zoom < 5) return;
          s.el = makeElement(store.model, s.tool, s.start, { w: 1, h: 1 });
          d.elements.push(s.el);
          store.ui.selection = new Set([s.el.id]);
        }
        let w = Math.abs(dx), h = Math.abs(dy);
        if (e.shiftKey) w = h = Math.max(w, h);
        s.el.x = dx < 0 ? s.start.x - w : s.start.x;
        s.el.y = dy < 0 ? s.start.y - h : s.start.y;
        s.el.w = Math.max(20, w); s.el.h = Math.max(20, h);
        break;
      }
      case 'erase':
        this.eraseAt(p);
        return;
    }
    store.render();
  }

  onUp(e) {
    this.pointers.delete(e.pointerId);
    const s = this.state;
    if (!s) return;
    if (s.mode === 'pinch') { if (this.pointers.size < 2) this.state = null; return; }
    this.state = null;
    this.wrap.classList.remove('panning');
    const d = store.diagram;
    const keepTool = store.ui.toolLock;

    switch (s.mode) {
      case 'move': if (s.moved) { this.attachLooseEnds(); store.commit('move'); } break;
      case 'resize': this.attachLooseEnds(); store.commit('resize'); break;
      case 'bend': store.commit('bend'); break;
      case 'start': case 'end': {
        if (s.hover && !s.el.bend) autoBend(d, s.el);
        store.commit('connect');
        break;
      }
      case 'marquee': store.select(store.ui.selection); break;
      case 'create-line': {
        const el = s.el;
        if (!s.moved) {
          d.elements = d.elements.filter((x) => x !== el);
          store.select([]);
          break;
        }
        if (el.targetId) autoBend(d, el);
        store.select([el.id]);
        store.commit('create');
        if (!keepTool) store.setUI({ tool: 'select' });
        break;
      }
      case 'create-node': {
        let el = s.el;
        if (!el) {
          el = makeElement(store.model, s.tool, s.start);
          d.elements.push(el);
        }
        store.select([el.id]);
        this.attachLooseEnds();
        store.commit('create');
        if (!keepTool) store.setUI({ tool: 'select' });
        break;
      }
      case 'erase': if (s.removed.size) store.commit('erase'); break;
    }
    store.render();
  }

  eraseAt(p) {
    const hit = this.hitTest(p);
    if (!hit) return;
    this.state.removed.add(hit.id);
    deleteElements(store.diagram, new Set([hit.id]));
    store.render();
  }

  updateCursor(e) {
    const p = this.toWorld(e);
    const tool = store.ui.tool;
    const hn = ['select', 'flow'].includes(tool) && !this.spaceDown ? this.hitConnectable(p, null, 26) : null;
    if ((hn?.id || null) !== (this.hoverNode?.id || null)) { this.hoverNode = hn; this.schedule(); }
    if (tool !== 'select' || this.spaceDown) { this.svg.style.cursor = ''; return; }
    const h = this.hitHandle(p);
    if (h) {
      this.svg.style.cursor = h.kind === 'resize' ? (h.corner === 'nw' || h.corner === 'se' ? 'nwse-resize' : 'nesw-resize') : 'grab';
      return;
    }
    if (this.hitConnectDot(p)) { this.svg.style.cursor = 'crosshair'; return; }
    this.svg.style.cursor = this.hitTest(p) ? 'move' : '';
  }

  onWheel(e) {
    e.preventDefault();
    const r = this.svg.getBoundingClientRect();
    if (e.ctrlKey || e.metaKey) {
      this.zoomAt(e.clientX - r.left, e.clientY - r.top, Math.exp(-e.deltaY * (e.deltaMode ? 0.05 : 0.01)));
    } else {
      const v = store.view;
      const k = e.deltaMode ? 20 : 1;
      if (e.shiftKey && !e.deltaX) v.x -= e.deltaY * k; else { v.x -= e.deltaX * k; v.y -= e.deltaY * k; }
      store.emit('view');
      this.schedule();
    }
  }

  startPinch() {
    const [a, b] = [...this.pointers.values()];
    const d = store.diagram;
    if (this.state?.mode === 'create-node' && this.state.el) d.elements = d.elements.filter((x) => x !== this.state.el);
    if (this.state?.mode === 'create-line') d.elements = d.elements.filter((x) => x !== this.state.el);
    this.state = { mode: 'pinch', dist: Math.hypot(a.x - b.x, a.y - b.y), mid: { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 } };
  }
  updatePinch() {
    const [a, b] = [...this.pointers.values()];
    const s = this.state;
    const dist = Math.hypot(a.x - b.x, a.y - b.y);
    const mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
    const r = this.svg.getBoundingClientRect();
    const v = store.view;
    v.x += mid.x - s.mid.x; v.y += mid.y - s.mid.y;
    this.zoomAt(mid.x - r.left, mid.y - r.top, dist / (s.dist || dist));
    s.dist = dist; s.mid = mid;
  }

  onDblClick(e) {
    const p = this.toWorld(e);
    const hit = this.hitTest(p);
    if (hit) { store.select([hit.id]); this.startEdit(hit); return; }
    if (store.ui.tool !== 'select') return;
    const el = makeElement(store.model, 'note', p);
    store.diagram.elements.push(el);
    store.select([el.id]);
    this.startEdit(el, true);
  }

  onContextMenu(e) {
    e.preventDefault();
    const p = this.toWorld(e);
    const hit = this.hitTest(p);
    if (hit && !store.ui.selection.has(hit.id)) store.select([hit.id]);
    if (!hit) store.select([]);
    store.emit('contextmenu', { x: e.clientX, y: e.clientY, world: p, hit });
  }

  /* ------------------------------------------------------ inline label edit */

  startEdit(el, isNew = false) {
    this.editingId = el.id;
    this.editingNew = isNew;
    const ed = this.editor;
    ed.value = el.name || '';
    ed.dataset.type = el.type;
    ed.hidden = false;
    this.draw();
    ed.focus();
    ed.select();
  }

  positionEditor() {
    const el = store.diagram.elements.find((e) => e.id === this.editingId);
    if (!el) { this.cancelEdit(); return; }
    const z = this.zoom;
    const ed = this.editor;
    const size = (el.type === 'note' ? 18 : el.type === 'flow' ? 14 : el.type === 'boundary' || el.type === 'boundaryLine' ? 15 : 16) * z;
    ed.style.fontSize = `${size}px`;
    ed.style.fontFamily = store.prefs.sketchy ? FONTS.sketchy : FONTS.clean;
    let x, y, w, align = 'center';
    if (el.type === 'note') { const s = this.toScreen({ x: el.x, y: el.y }); x = s.x; y = s.y; w = null; align = 'left'; }
    else if (el.type === 'boundary') { const s = this.toScreen({ x: el.x + 6, y: el.y + 4 }); x = s.x; y = s.y; w = Math.max(160, (el.w - 12) * z); align = 'left'; }
    else if (isLine(el)) { const g = lineGeom(el, store.byId()); const s = this.toScreen(g.mid); w = 200; x = s.x - w / 2; y = s.y - size * 0.8; }
    else { const s = this.toScreen(center(el)); w = Math.max(120, (el.type === 'process' ? el.w * 0.8 : el.w - 8) * z); x = s.x - w / 2; y = s.y - size * 0.8; }
    ed.style.left = `${x}px`;
    ed.style.top = `${y}px`;
    ed.style.textAlign = align;
    ed.style.width = w ? `${w}px` : 'auto';
    this.sizeEditor();
  }

  sizeEditor() {
    const ed = this.editor;
    if (ed.dataset.type === 'note') {
      const lines = ed.value.split('\n');
      ed.style.width = `${Math.max(40, Math.max(...lines.map((l) => l.length)) * parseFloat(ed.style.fontSize) * 0.6 + 24)}px`;
    }
    ed.style.height = 'auto';
    ed.style.height = `${ed.scrollHeight}px`;
  }

  onEditorKey(e) {
    e.stopPropagation();
    const isNote = this.editor.dataset.type === 'note';
    if (e.key === 'Escape' || (e.key === 'Enter' && (!isNote && !e.shiftKey || e.metaKey || e.ctrlKey))) {
      e.preventDefault();
      this.editor.blur();
    }
  }

  finishEdit() {
    if (!this.editingId) return;
    const id = this.editingId;
    this.editingId = null;
    this.editor.hidden = true;
    const d = store.diagram;
    const el = d.elements.find((e) => e.id === id);
    if (!el) return;
    const value = this.editor.value.replace(/\s+$/, '');
    if (el.type === 'note') {
      if (!value.trim()) {
        d.elements = d.elements.filter((e) => e !== el);
        store.ui.selection.delete(id);
        if (this.editingNew) { store.render(); return; }
      } else { el.name = value; fitNote(el); }
    } else {
      el.name = value.trim() || el.name;
    }
    store.commit('rename');
  }

  cancelEdit() {
    this.editingId = null;
    this.editor.hidden = true;
  }
}

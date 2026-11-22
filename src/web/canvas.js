// Excalidraw-style SVG canvas for editing data flow diagrams.

import {
  GENERIC,
  addElement,
  bendFromMidpoint,
  center,
  diagramBounds,
  elementIndex,
  isNodeGeneric,
  lineGeometry,
  moveElements,
  quadPoint,
  rectContains,
  rectOf,
  rectsOverlap,
  removeElements,
  SVG_STYLE,
  renderDiagramContent,
  uid,
} from '../core/index.js';
import { h, icon, toast } from './dom.js';

const SVG_NS = 'http://www.w3.org/2000/svg';
const OPEN_STATES = new Set(['NotStarted', 'NeedsInvestigation']);

export const TOOLS = [
  { id: 'select', label: 'Select', key: 'V', num: '1', icon: 'select' },
  { id: 'hand', label: 'Pan', key: 'H', icon: 'hand' },
  { id: 'GE.P', label: 'Process', key: 'P', num: '2', icon: 'process' },
  { id: 'GE.EI', label: 'External interactor', key: 'E', num: '3', icon: 'external' },
  { id: 'GE.DS', label: 'Data store', key: 'D', num: '4', icon: 'store' },
  { id: 'GE.DF', label: 'Data flow — drag from one element to another', key: 'F', num: '5', icon: 'flow' },
  { id: 'GE.TB.L', label: 'Trust boundary (arc) — drag across flows', key: 'L', num: '6', icon: 'line-boundary' },
  { id: 'GE.TB.B', label: 'Trust boundary (box) — drag a rectangle', key: 'B', num: '7', icon: 'box-boundary' },
  { id: 'GE.A', label: 'Annotation', key: 'T', num: '8', icon: 'annotation' },
];

function svgEl(tag, attrs = {}) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

export class Canvas {
  constructor(store, stage) {
    this.store = store;
    this.stage = stage;
    this.drag = null;
    this.clipboard = null;
    this.spaceDown = false;
    this.build();
    store.on('model', () => this.requestRender());
    store.on('selection', () => this.requestRender());
    store.on('processed', () => this.requestRender());
    store.on('tool', () => this.syncTool());
    new ResizeObserver(() => this.requestRender()).observe(stage);
  }

  // ------------------------------------------------------------ DOM
  build() {
    this.svg = svgEl('svg', { id: 'canvas', class: 'dg', role: 'application', 'aria-label': 'Data flow diagram canvas', tabindex: '0' });
    const defs = svgEl('defs');
    const pat = svgEl('pattern', { id: 'grid-dots', width: '20', height: '20', patternUnits: 'userSpaceOnUse' });
    pat.appendChild(svgEl('circle', { cx: '1', cy: '1', r: '1', fill: 'var(--grid)' }));
    defs.appendChild(pat);
    const style = svgEl('style');
    style.textContent = SVG_STYLE;
    defs.appendChild(style);
    this.gridPattern = pat;
    this.svg.appendChild(defs);
    this.gridRect = svgEl('rect', { x: '-50000', y: '-50000', width: '100000', height: '100000', fill: 'url(#grid-dots)' });
    this.world = svgEl('g');
    this.content = svgEl('g');
    this.overlay = svgEl('g');
    this.world.append(this.gridRect, this.content, this.overlay);
    this.svg.appendChild(this.world);

    this.toolbar = h(
      'div',
      { class: 'toolbar', role: 'toolbar', 'aria-label': 'Drawing tools' },
      TOOLS.map((t) =>
        h(
          'button',
          {
            class: 'tool',
            type: 'button',
            title: `${t.label} — ${t.key}${t.num ? ` or ${t.num}` : ''}`,
            'aria-label': t.label,
            'data-tool': t.id,
            onClick: () => this.store.setTool(t.id === 'select' || t.id === 'hand' ? { kind: t.id } : { kind: 'place', typeId: t.id }),
          },
          icon(t.icon),
          t.num ? h('span', { class: 'key' }, t.num) : null,
        ),
      ),
    );
    this.zoomLabel = h('span', null, '100%');
    this.zoombar = h(
      'div',
      { class: 'zoombar' },
      h('button', { class: 'btn small', type: 'button', title: 'Zoom out (−)', 'aria-label': 'Zoom out', onClick: () => this.zoomBy(1 / 1.2) }, icon('minus', 16)),
      this.zoomLabel,
      h('button', { class: 'btn small', type: 'button', title: 'Zoom in (+)', 'aria-label': 'Zoom in', onClick: () => this.zoomBy(1.2) }, icon('plus', 16)),
      h('button', { class: 'btn small', type: 'button', title: 'Zoom to fit (Shift+1)', 'aria-label': 'Zoom to fit', onClick: () => this.zoomToFit() }, icon('fit', 16)),
    );
    this.hint = h(
      'div',
      { class: 'stage-hint' },
      'Pick a shape from the toolbar or the stencil list,',
      h('br'),
      'connect elements with data flows (F),',
      h('br'),
      'then draw trust boundaries (B / L) across the flows.',
      h('br'),
      h('small', null, 'Threats are generated automatically as you draw.'),
    );
    this.status = h('div', { class: 'status', 'aria-live': 'polite' });
    this.stage.append(this.svg, this.toolbar, this.zoombar, this.hint, this.status);

    this.svg.addEventListener('pointerdown', (e) => this.onDown(e));
    this.svg.addEventListener('pointermove', (e) => this.onMove(e));
    this.svg.addEventListener('pointerup', (e) => this.onUp(e));
    this.svg.addEventListener('pointercancel', (e) => this.onUp(e, true));
    this.svg.addEventListener('dblclick', (e) => this.onDblClick(e));
    this.svg.addEventListener('wheel', (e) => this.onWheel(e), { passive: false });
    this.svg.addEventListener('dragover', (e) => e.preventDefault());
    this.svg.addEventListener('drop', (e) => this.onDrop(e));
    window.addEventListener('keydown', (e) => this.onKey(e));
    window.addEventListener('keyup', (e) => {
      if (e.code === 'Space') {
        this.spaceDown = false;
        this.syncTool();
      }
    });
    this.syncTool();
  }

  get cam() {
    const id = this.store.activeDiagramId;
    let c = this.store.camera.get(id);
    if (!c) {
      c = { x: 0, y: 0, z: 1, fresh: true };
      this.store.camera.set(id, c);
    }
    return c;
  }

  syncTool() {
    const t = this.store.tool;
    const active = t.kind === 'place' ? t.typeId : t.kind;
    const generic = t.kind === 'place' ? this.store.kb.genericOf(t.typeId) : null;
    for (const b of this.toolbar.querySelectorAll('.tool')) b.setAttribute('aria-pressed', String(b.dataset.tool === active || b.dataset.tool === generic));
    this.svg.classList.toggle('tool-hand', t.kind === 'hand' || this.spaceDown);
    this.svg.classList.toggle('tool-place', t.kind === 'place');
    this.updateStatus();
  }

  // ------------------------------------------------------------ rendering
  requestRender() {
    if (this._raf) return;
    this._raf = requestAnimationFrame(() => {
      this._raf = null;
      this.render();
    });
  }

  badges() {
    const map = new Map();
    for (const t of this.store.model.threats) {
      if (t.orphan || !OPEN_STATES.has(t.state)) continue;
      map.set(t.flowId, (map.get(t.flowId) || 0) + 1);
    }
    return map;
  }

  render() {
    const { model, diagram } = this.store;
    const cam = this.cam;
    if (cam.fresh && diagram.elements.length) {
      cam.fresh = false;
      this.zoomToFit(false);
    }
    this.world.setAttribute('transform', `translate(${cam.x} ${cam.y}) scale(${cam.z})`);
    this.gridRect.style.display = this.store.prefs.grid ? '' : 'none';
    this.content.innerHTML = renderDiagramContent(model, diagram, {
      sketch: this.store.prefs.sketch,
      selected: this.store.selection,
      highlighted: this.store.highlight,
      badges: this.badges(),
    });
    this.renderOverlay();
    this.hint.classList.toggle('hidden', diagram.elements.length > 0);
    this.zoomLabel.textContent = `${Math.round(cam.z * 100)}%`;
    this.updateStatus();
  }

  updateStatus() {
    const { model, diagram, tool } = this.store;
    const open = model.threats.filter((t) => t.diagramId === diagram.id && !t.orphan && OPEN_STATES.has(t.state)).length;
    const toolHint =
      tool.kind === 'place'
        ? { 'GE.DF': 'Drag from a source element to a target', 'GE.TB.L': 'Drag a line across the flows that change trust', 'GE.TB.B': 'Drag a rectangle around elements' }[this.store.kb.genericOf(tool.typeId)] ||
          'Click to place'
        : '';
    this.status.textContent = `${diagram.elements.length} elements · ${open} open threats${toolHint ? ` · ${toolHint}` : ''}`;
  }

  renderOverlay() {
    const o = this.overlay;
    while (o.firstChild) o.removeChild(o.firstChild);
    const { model, diagram, selection } = this.store;
    const z = this.cam.z;
    const hs = 8 / z;
    const sel = diagram.elements.filter((e) => selection.has(e.id));
    for (const el of sel) {
      if (el.w !== undefined) {
        o.appendChild(svgEl('rect', { class: 'sel-outline', x: el.x - 5 / z, y: el.y - 5 / z, width: el.w + 10 / z, height: el.h + 10 / z, 'stroke-width': 1 / z }));
        if (sel.length === 1) {
          const pts = { nw: [el.x, el.y], ne: [el.x + el.w, el.y], sw: [el.x, el.y + el.h], se: [el.x + el.w, el.y + el.h] };
          for (const [k, [x, y]] of Object.entries(pts)) {
            const r = svgEl('rect', { class: 'handle', x: x - hs / 2 + (k.includes('w') ? -5 / z : 5 / z), y: y - hs / 2 + (k.includes('n') ? -5 / z : 5 / z), width: hs, height: hs, rx: 2 / z, 'stroke-width': 1.5 / z, 'data-handle': k, 'data-id': el.id });
            r.style.cursor = k === 'nw' || k === 'se' ? 'nwse-resize' : 'nesw-resize';
            o.appendChild(r);
          }
        }
      } else if (sel.length === 1) {
        const g = lineGeometry(model, diagram, el);
        const mid = quadPoint(g.p0, g.c, g.p1, 0.5);
        const isFlow = el.generic === GENERIC.FLOW;
        const ends = [
          [isFlow ? 'source' : 'a', g.p0],
          [isFlow ? 'target' : 'b', g.p1],
        ];
        for (const [k, p] of ends) {
          const c = svgEl('circle', { class: 'handle end', cx: p.x, cy: p.y, r: 6 / z, 'stroke-width': 1.5 / z, 'data-handle': k, 'data-id': el.id });
          c.style.cursor = 'move';
          o.appendChild(c);
        }
        const b = svgEl('circle', { class: 'handle bend', cx: mid.x, cy: mid.y, r: 5 / z, 'stroke-width': 1.5 / z, 'data-handle': 'bend', 'data-id': el.id });
        b.style.cursor = 'grab';
        o.appendChild(b);
      }
    }
    const d = this.drag;
    if (d?.kind === 'marquee') {
      const r = normRect(d.start, d.cur);
      o.appendChild(svgEl('rect', { class: 'marquee', x: r.x, y: r.y, width: r.w, height: r.h, 'stroke-width': 1 / z }));
    } else if (d?.kind === 'create-flow' || d?.kind === 'create-line') {
      const from = d.fromId ? center(rectOf(diagram.elements.find((e) => e.id === d.fromId))) : d.start;
      o.appendChild(svgEl('path', { class: 'draft', d: `M${from.x} ${from.y}L${d.cur.x} ${d.cur.y}`, 'stroke-width': 1.6 / z }));
    } else if (d?.kind === 'create-box') {
      const r = normRect(d.start, d.cur);
      o.appendChild(svgEl('rect', { class: 'draft', x: r.x, y: r.y, width: r.w, height: r.h, 'stroke-width': 1.6 / z }));
    }
    if (d?.snapId) {
      const t = diagram.elements.find((e) => e.id === d.snapId);
      if (t) o.appendChild(svgEl('rect', { class: 'snap-target', x: t.x - 6, y: t.y - 6, width: t.w + 12, height: t.h + 12, rx: 8 }));
    }
  }

  // ------------------------------------------------------------ coordinates
  toWorld(e) {
    const r = this.svg.getBoundingClientRect();
    const c = this.cam;
    return { x: (e.clientX - r.left - c.x) / c.z, y: (e.clientY - r.top - c.y) / c.z };
  }
  toScreen(p) {
    const r = this.svg.getBoundingClientRect();
    const c = this.cam;
    return { x: p.x * c.z + c.x + r.left, y: p.y * c.z + c.y + r.top };
  }
  zoomAt(screen, factor) {
    const c = this.cam;
    const r = this.svg.getBoundingClientRect();
    const nz = Math.max(0.1, Math.min(4, c.z * factor));
    const sx = screen.x - r.left;
    const sy = screen.y - r.top;
    c.x = sx - ((sx - c.x) * nz) / c.z;
    c.y = sy - ((sy - c.y) * nz) / c.z;
    c.z = nz;
    this.requestRender();
  }
  zoomBy(f) {
    const r = this.svg.getBoundingClientRect();
    this.zoomAt({ x: r.left + r.width / 2, y: r.top + r.height / 2 }, f);
  }
  zoomToFit(render = true) {
    const { model, diagram } = this.store;
    const r = this.svg.getBoundingClientRect();
    if (!r.width || !r.height) return;
    const c = this.cam;
    if (!diagram.elements.length) {
      Object.assign(c, { x: 0, y: 0, z: 1 });
    } else {
      const b = diagramBounds(model, diagram, 60);
      const z = Math.max(0.15, Math.min(1.4, Math.min(r.width / b.w, (r.height - 60) / b.h)));
      c.z = z;
      c.x = (r.width - b.w * z) / 2 - b.x * z;
      c.y = (r.height - b.h * z) / 2 - b.y * z + 20;
    }
    if (render) this.requestRender();
  }

  // ------------------------------------------------------------ hit testing
  hitId(e) {
    const t = e.target.closest?.('[data-id]');
    return t && this.content.contains(t) ? t.getAttribute('data-id') : null;
  }
  nodeAt(p, exceptId) {
    const nodes = this.store.diagram.elements.filter((el) => isNodeGeneric(el.generic) && el.id !== exceptId);
    for (let i = nodes.length - 1; i >= 0; i--) if (rectContains(rectOf(nodes[i]), p, 6)) return nodes[i];
    return null;
  }

  // ------------------------------------------------------------ pointer
  onDown(e) {
    if (this.inlineEditor) this.finishInlineEdit(true);
    this.svg.focus({ preventScroll: true });
    const p = this.toWorld(e);
    const tool = this.store.tool;
    if (e.button === 1 || tool.kind === 'hand' || this.spaceDown) {
      this.startDrag(e, { kind: 'pan', sx: e.clientX, sy: e.clientY, cx: this.cam.x, cy: this.cam.y });
      this.svg.classList.add('panning');
      return;
    }
    if (e.button !== 0) return;
    const handle = e.target.closest?.('[data-handle]');
    if (handle && this.overlay.contains(handle)) {
      const id = handle.getAttribute('data-id');
      const kind = handle.getAttribute('data-handle');
      const el = this.store.diagram.elements.find((x) => x.id === id);
      this.store.begin();
      if (['nw', 'ne', 'sw', 'se'].includes(kind)) this.startDrag(e, { kind: 'resize', id, corner: kind, orig: rectOf(el) });
      else if (kind === 'bend') this.startDrag(e, { kind: 'bend', id });
      else this.startDrag(e, { kind: 'endpoint', id, end: kind, cur: p });
      return;
    }

    if (tool.kind === 'place') {
      const generic = this.store.kb.genericOf(tool.typeId);
      if (generic === GENERIC.FLOW) {
        const from = this.nodeAt(p);
        this.startDrag(e, { kind: 'create-flow', typeId: tool.typeId, fromId: from?.id, start: p, cur: p });
      } else if (generic === GENERIC.LINE_BOUNDARY) this.startDrag(e, { kind: 'create-line', typeId: tool.typeId, start: p, cur: p });
      else if (generic === GENERIC.BOX_BOUNDARY) this.startDrag(e, { kind: 'create-box', typeId: tool.typeId, start: p, cur: p });
      else this.placeShape(tool.typeId, p);
      return;
    }

    const id = this.hitId(e);
    if (id) {
      const sel = this.store.selection;
      if (e.shiftKey || e.metaKey || e.ctrlKey) this.store.select([id], { toggle: true });
      else if (!sel.has(id)) this.store.select([id]);
      if (this.store.selection.has(id)) {
        this.store.begin();
        this.startDrag(e, { kind: 'move', last: p, moved: false, alt: e.altKey });
      }
    } else {
      if (!e.shiftKey) this.store.clearSelection();
      this.startDrag(e, { kind: 'marquee', start: p, cur: p, add: e.shiftKey });
    }
  }

  startDrag(e, d) {
    this.drag = d;
    try {
      this.svg.setPointerCapture(e.pointerId);
    } catch {
      /* ignore */
    }
  }

  onMove(e) {
    const d = this.drag;
    if (!d) return;
    const p = this.toWorld(e);
    const { model, diagram } = this.store;
    switch (d.kind) {
      case 'pan':
        this.cam.x = d.cx + (e.clientX - d.sx);
        this.cam.y = d.cy + (e.clientY - d.sy);
        this.requestRender();
        break;
      case 'move': {
        const dx = p.x - d.last.x;
        const dy = p.y - d.last.y;
        if (!d.moved && Math.hypot(dx, dy) * this.cam.z < 3) return;
        if (!d.moved && d.alt) this.duplicateSelection(0);
        d.moved = true;
        moveElements(model, [...this.store.selection], dx, dy);
        d.last = p;
        this.store.preview();
        break;
      }
      case 'resize': {
        const el = diagram.elements.find((x) => x.id === d.id);
        const o = d.orig;
        let x0 = o.x,
          y0 = o.y,
          x1 = o.x + o.w,
          y1 = o.y + o.h;
        if (d.corner.includes('w')) x0 = Math.min(p.x, x1 - 30);
        if (d.corner.includes('e')) x1 = Math.max(p.x, x0 + 30);
        if (d.corner.includes('n')) y0 = Math.min(p.y, y1 - 24);
        if (d.corner.includes('s')) y1 = Math.max(p.y, y0 + 24);
        Object.assign(el, { x: Math.round(x0), y: Math.round(y0), w: Math.round(x1 - x0), h: Math.round(y1 - y0) });
        this.store.preview();
        break;
      }
      case 'bend': {
        const el = diagram.elements.find((x) => x.id === d.id);
        const g = lineGeometry(model, diagram, { ...el, bend: 0 });
        el.bend = Math.round(bendFromMidpoint(g.p0, g.p1, p));
        if (Math.abs(el.bend) < 6) el.bend = 0;
        this.store.preview();
        break;
      }
      case 'endpoint': {
        const el = diagram.elements.find((x) => x.id === d.id);
        const isFlow = el.generic === GENERIC.FLOW;
        const first = d.end === 'source' || d.end === 'a';
        if (isFlow) {
          const other = first ? el.target : el.source;
          const node = this.nodeAt(p, other);
          d.snapId = node?.id || null;
          el[first ? 'source' : 'target'] = undefined;
        }
        if (first) Object.assign(el, { x0: Math.round(p.x), y0: Math.round(p.y) });
        else Object.assign(el, { x1: Math.round(p.x), y1: Math.round(p.y) });
        this.store.preview();
        break;
      }
      case 'marquee':
      case 'create-line':
      case 'create-box':
        d.cur = p;
        this.requestRender();
        break;
      case 'create-flow': {
        d.cur = p;
        const node = this.nodeAt(p, d.fromId);
        d.snapId = node?.id || null;
        this.requestRender();
        break;
      }
    }
  }

  onUp(e, cancelled = false) {
    const d = this.drag;
    this.drag = null;
    this.svg.classList.remove('panning');
    try {
      this.svg.releasePointerCapture(e.pointerId);
    } catch {
      /* ignore */
    }
    if (!d) return;
    const { model, diagram } = this.store;
    if (cancelled) {
      if (['move', 'resize', 'bend', 'endpoint'].includes(d.kind)) this.store.cancel();
      this.requestRender();
      return;
    }
    switch (d.kind) {
      case 'move':
      case 'resize':
      case 'bend':
        this.store.end();
        break;
      case 'endpoint': {
        const el = diagram.elements.find((x) => x.id === d.id);
        if (el.generic === GENERIC.FLOW && d.snapId) el[d.end] = d.snapId;
        this.store.end();
        break;
      }
      case 'marquee': {
        const r = normRect(d.start, d.cur);
        if (r.w * this.cam.z < 4 && r.h * this.cam.z < 4) break;
        const ids = diagram.elements
          .filter((el) => {
            const b = el.w !== undefined ? rectOf(el) : boundsOfPoints(lineGeometry(model, diagram, el).points);
            return rectsOverlap(b, r) && b.x >= r.x && b.y >= r.y && b.x + b.w <= r.x + r.w && b.y + b.h <= r.y + r.h;
          })
          .map((el) => el.id);
        this.store.select(ids, { add: d.add });
        break;
      }
      case 'create-flow': {
        const to = d.snapId;
        if (!d.fromId && !to && Math.hypot(d.cur.x - d.start.x, d.cur.y - d.start.y) < 20) {
          toast('Drag from one element to another to draw a data flow.');
          break;
        }
        const spec = { type: d.typeId, name: defaultFlowName(this.store, d.typeId) };
        if (d.fromId) spec.source = d.fromId;
        else Object.assign(spec, { x0: d.start.x, y0: d.start.y });
        if (to) spec.target = to;
        else Object.assign(spec, { x1: d.cur.x, y1: d.cur.y });
        const el = this.store.commit((m) => addElement(m, diagram.id, spec), { immediate: true });
        this.afterCreate(el);
        break;
      }
      case 'create-line': {
        if (Math.hypot(d.cur.x - d.start.x, d.cur.y - d.start.y) < 20) {
          toast('Drag a line across the data flows that cross this trust boundary.');
          break;
        }
        const el = this.store.commit((m) => addElement(m, diagram.id, { type: d.typeId, x0: d.start.x, y0: d.start.y, x1: d.cur.x, y1: d.cur.y }), { immediate: true });
        this.afterCreate(el);
        break;
      }
      case 'create-box': {
        let r = normRect(d.start, d.cur);
        if (r.w < 30 || r.h < 30) r = { x: d.start.x - 170, y: d.start.y - 120, w: 340, h: 240 };
        const el = this.store.commit((m) => addElement(m, diagram.id, { type: d.typeId, ...roundRect(r) }), { immediate: true });
        this.afterCreate(el);
        break;
      }
    }
    this.requestRender();
  }

  placeShape(typeId, p, name) {
    const { diagram } = this.store;
    const el = this.store.commit((m) => {
      const e = addElement(m, diagram.id, { type: typeId, x: 0, y: 0, name });
      e.x = Math.round(p.x - e.w / 2);
      e.y = Math.round(p.y - e.h / 2);
      return e;
    }, { immediate: true });
    this.afterCreate(el);
    return el;
  }

  afterCreate(el) {
    if (!this.store.prefs.toolLock) this.store.setTool({ kind: 'select' });
    this.store.select([el.id]);
    // Name it right away: names appear in generated threat titles.
    requestAnimationFrame(() => this.startInlineEdit(el.id));
  }

  onDblClick(e) {
    const id = this.hitId(e);
    if (id) {
      this.startInlineEdit(id);
      return;
    }
    // Double-click on empty canvas adds an annotation, like Excalidraw text.
    if (this.store.tool.kind === 'select') this.placeShape('GE.A', this.toWorld(e), 'Note');
  }

  onWheel(e) {
    e.preventDefault();
    if (e.ctrlKey || e.metaKey) {
      this.zoomAt({ x: e.clientX, y: e.clientY }, Math.exp(-e.deltaY * 0.0022));
    } else {
      this.cam.x -= e.shiftKey && !e.deltaX ? e.deltaY : e.deltaX;
      this.cam.y -= e.shiftKey && !e.deltaX ? 0 : e.deltaY;
      this.requestRender();
    }
  }

  onDrop(e) {
    e.preventDefault();
    const typeId = e.dataTransfer?.getData('application/x-stride-type');
    if (!typeId || !this.store.kb.element(typeId)) return;
    const p = this.toWorld(e);
    const generic = this.store.kb.genericOf(typeId);
    if (generic === GENERIC.FLOW || generic === GENERIC.LINE_BOUNDARY) {
      this.store.setTool({ kind: 'place', typeId });
      toast(generic === GENERIC.FLOW ? 'Now drag from a source element to a target.' : 'Now drag a line across the flows.');
      return;
    }
    if (generic === GENERIC.BOX_BOUNDARY) {
      const el = this.store.commit((m) => addElement(m, this.store.diagram.id, { type: typeId, x: Math.round(p.x - 170), y: Math.round(p.y - 120) }), { immediate: true });
      this.afterCreate(el);
      return;
    }
    this.placeShape(typeId, p);
  }

  // ------------------------------------------------------------ inline rename
  startInlineEdit(id) {
    const { model, diagram } = this.store;
    const el = diagram.elements.find((x) => x.id === id);
    if (!el) return;
    let rect;
    if (el.w !== undefined && el.generic !== GENERIC.BOX_BOUNDARY) rect = rectOf(el);
    else if (el.generic === GENERIC.BOX_BOUNDARY) rect = { x: el.x, y: el.y, w: Math.min(el.w, 240), h: 34 };
    else {
      const g = lineGeometry(model, diagram, el);
      const m = quadPoint(g.p0, g.c, g.p1, 0.5);
      rect = { x: m.x - 90, y: m.y - 18, w: 180, h: 36 };
    }
    const tl = this.toScreen({ x: rect.x, y: rect.y });
    const stageRect = this.stage.getBoundingClientRect();
    const z = this.cam.z;
    const ta = h('textarea', { class: 'inline-edit', 'aria-label': 'Element name', rows: 2 });
    ta.value = el.name;
    Object.assign(ta.style, {
      left: `${tl.x - stageRect.left}px`,
      top: `${tl.y - stageRect.top + Math.max(0, (rect.h * z - 60) / 2)}px`,
      width: `${Math.max(120, rect.w * z)}px`,
      height: `${Math.min(Math.max(36, rect.h * z), 60)}px`,
    });
    this.stage.appendChild(ta);
    this.inlineEditor = { ta, id };
    ta.focus();
    ta.select();
    ta.addEventListener('keydown', (ev) => {
      ev.stopPropagation();
      if (ev.key === 'Enter' && !ev.shiftKey) {
        ev.preventDefault();
        this.finishInlineEdit(true);
      } else if (ev.key === 'Escape') this.finishInlineEdit(false);
    });
    ta.addEventListener('blur', () => this.finishInlineEdit(true));
  }

  finishInlineEdit(commit) {
    const ed = this.inlineEditor;
    if (!ed) return;
    this.inlineEditor = null;
    const name = ed.ta.value.replace(/\s+/g, ' ').trim();
    ed.ta.remove();
    if (commit && name) {
      this.store.commit((m) => {
        const el = elementIndex(m).get(ed.id)?.element;
        if (el) el.name = name;
      });
    }
    this.svg.focus({ preventScroll: true });
  }

  // ------------------------------------------------------------ clipboard
  copySelection() {
    const { diagram, selection } = this.store;
    const els = diagram.elements.filter((e) => selection.has(e.id));
    if (!els.length) return false;
    this.clipboard = JSON.parse(JSON.stringify(els));
    return true;
  }
  paste(offset = 24) {
    if (!this.clipboard?.length) return;
    const diagram = this.store.diagram;
    const map = new Map();
    const copies = JSON.parse(JSON.stringify(this.clipboard));
    for (const c of copies) map.set(c.id, (c.id = uid('el')));
    for (const c of copies) {
      if (c.w !== undefined) {
        c.x += offset;
        c.y += offset;
      } else {
        for (const end of ['source', 'target']) if (c[end]) c[end] = map.get(c[end]);
        if (!c.source) {
          c.x0 += offset;
          c.y0 += offset;
        }
        if (!c.target) {
          c.x1 += offset;
          c.y1 += offset;
        }
      }
    }
    this.store.commit(() => {
      diagram.elements.push(...copies);
    });
    this.store.select(copies.map((c) => c.id));
  }
  duplicateSelection(offset = 24) {
    if (this.copySelection()) this.paste(offset);
  }

  deleteSelection() {
    const ids = [...this.store.selection];
    if (!ids.length) return;
    this.store.commit((m) => removeElements(m, ids));
    this.store.clearSelection();
  }

  // ------------------------------------------------------------ keyboard
  onKey(e) {
    const tag = document.activeElement?.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || document.querySelector('dialog[open]')) return;
    const mod = e.metaKey || e.ctrlKey;
    const k = e.key.toLowerCase();
    if (e.code === 'Space' && !this.spaceDown) {
      this.spaceDown = true;
      this.syncTool();
      e.preventDefault();
      return;
    }
    if (mod && k === 'z') {
      e.preventDefault();
      if (e.shiftKey) this.store.redo();
      else this.store.undo();
      return;
    }
    if (mod && k === 'y') {
      e.preventDefault();
      this.store.redo();
      return;
    }
    if (mod && k === 'a') {
      e.preventDefault();
      this.store.select(this.store.diagram.elements.map((el) => el.id));
      return;
    }
    if (mod && k === 'c') {
      if (this.copySelection()) e.preventDefault();
      return;
    }
    if (mod && k === 'x') {
      if (this.copySelection()) {
        e.preventDefault();
        this.deleteSelection();
      }
      return;
    }
    if (mod && k === 'v') {
      if (this.clipboard) {
        e.preventDefault();
        this.paste();
      }
      return;
    }
    if (mod && k === 'd') {
      e.preventDefault();
      this.duplicateSelection();
      return;
    }
    if (mod) return;
    if (k === 'delete' || k === 'backspace') {
      e.preventDefault();
      this.deleteSelection();
      return;
    }
    if (k === 'escape') {
      this.store.setTool({ kind: 'select' });
      this.store.clearSelection();
      return;
    }
    if (k === 'enter' && this.store.selection.size === 1) {
      e.preventDefault();
      this.startInlineEdit([...this.store.selection][0]);
      return;
    }
    if (e.key === '!' || (e.shiftKey && e.code === 'Digit1')) {
      this.zoomToFit();
      return;
    }
    if (k === '+' || k === '=') return this.zoomBy(1.2);
    if (k === '-' || k === '_') return this.zoomBy(1 / 1.2);
    if (k.startsWith('arrow') && this.store.selection.size) {
      e.preventDefault();
      const step = e.shiftKey ? 20 : 2;
      const dx = k === 'arrowleft' ? -step : k === 'arrowright' ? step : 0;
      const dy = k === 'arrowup' ? -step : k === 'arrowdown' ? step : 0;
      this.store.commit((m) => moveElements(m, [...this.store.selection], dx, dy));
      return;
    }
    const tool = TOOLS.find((t) => t.key.toLowerCase() === k || t.num === e.key);
    if (tool && !e.altKey) {
      this.store.setTool(tool.id === 'select' || tool.id === 'hand' ? { kind: tool.id } : { kind: 'place', typeId: tool.id });
    }
  }

  /** Center the view on an element (used when jumping from a threat). */
  reveal(id) {
    const { model, diagram } = this.store;
    const el = diagram.elements.find((x) => x.id === id);
    if (!el) return;
    const b = el.w !== undefined ? rectOf(el) : boundsOfPoints(lineGeometry(model, diagram, el).points);
    const r = this.svg.getBoundingClientRect();
    const c = this.cam;
    const cx = b.x + b.w / 2;
    const cy = b.y + b.h / 2;
    const sx = cx * c.z + c.x;
    const sy = cy * c.z + c.y;
    if (sx < 60 || sy < 60 || sx > r.width - 60 || sy > r.height - 60) {
      c.x = r.width / 2 - cx * c.z;
      c.y = r.height / 2 - cy * c.z;
    }
    this.requestRender();
  }
}

function normRect(a, b) {
  return { x: Math.min(a.x, b.x), y: Math.min(a.y, b.y), w: Math.abs(a.x - b.x), h: Math.abs(a.y - b.y) };
}
function roundRect(r) {
  return { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.w), h: Math.round(r.h) };
}
function boundsOfPoints(pts) {
  const xs = pts.map((p) => p.x);
  const ys = pts.map((p) => p.y);
  const x = Math.min(...xs);
  const y = Math.min(...ys);
  return { x, y, w: Math.max(...xs) - x, h: Math.max(...ys) - y };
}
function defaultFlowName(store, typeId) {
  const def = store.kb.element(typeId);
  return def && typeId !== GENERIC.FLOW ? def.name : 'Data flow';
}

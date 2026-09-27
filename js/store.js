// Application state: the threat model document, undo/redo history, UI state
// and autosave to localStorage. Everything stays in the user's browser.

import { uid, debounce } from './util.js';
import { syncThreats } from './engine.js';
import { STENCILS, defaultProps } from './stencils.js';

const LS_MODEL = 'stride-tm:model:v1';
const LS_PREFS = 'stride-tm:prefs:v1';
const HISTORY_LIMIT = 200;

export function newDiagram(name = 'Diagram 1') {
  return { id: uid('d_'), name, elements: [] };
}

export function newModel() {
  const now = new Date().toISOString();
  return {
    app: 'stride-threat-modeler', version: 1,
    meta: {
      title: 'Untitled threat model', owner: '', reviewer: '', contributors: '',
      description: '', assumptions: '', dependencies: '', created: now, modified: now,
    },
    diagrams: [newDiagram()],
    threats: {}, nextThreatId: 1, template: null,
  };
}

// Make any loaded document safe to use (older files, hand-edited JSON, imports).
export function normalizeModel(m) {
  if (!m || typeof m !== 'object' || !Array.isArray(m.diagrams)) throw new Error('Not a threat model file.');
  const base = newModel();
  m.meta = { ...base.meta, ...(m.meta || {}) };
  if (!m.diagrams.length) m.diagrams = base.diagrams;
  for (const d of m.diagrams) {
    d.id ||= uid('d_');
    d.name ||= 'Diagram';
    d.elements = Array.isArray(d.elements) ? d.elements.filter((e) => e && STENCILS[e.type]) : [];
    for (const e of d.elements) {
      e.id ||= uid('e_');
      e.props = { ...defaultProps(e.type), ...(e.props || {}) };
      e.style ||= {};
      if (e.name == null) e.name = '';
      for (const k of ['x', 'y', 'w', 'h', 'x1', 'y1', 'x2', 'y2', 'bend']) if (e[k] != null) e[k] = Number(e[k]) || 0;
    }
  }
  m.threats = m.threats && typeof m.threats === 'object' ? m.threats : {};
  const maxId = Math.max(0, ...Object.values(m.threats).map((t) => t.id || 0));
  m.nextThreatId = Math.max(m.nextThreatId || 1, maxId + 1);
  m.template = Array.isArray(m.template) ? m.template : null;
  m.app = 'stride-threat-modeler';
  m.version = 1;
  return m;
}

function readLS(key) {
  try { const s = localStorage.getItem(key); return s ? JSON.parse(s) : null; } catch { return null; }
}
function writeLS(key, value) {
  try { localStorage.setItem(key, typeof value === 'string' ? value : JSON.stringify(value)); return true; } catch { return false; }
}

class Store {
  constructor() {
    let model;
    try { model = normalizeModel(readLS(LS_MODEL)); } catch { model = newModel(); }
    syncThreats(model);
    this.model = model;
    this.snapshot = JSON.stringify(model);
    this.past = [];
    this.future = [];
    this.listeners = new Set();
    this.prefs = { theme: 'light', sketchy: true, grid: true, ...(readLS(LS_PREFS) || {}) };
    this.ui = {
      diagramId: model.diagrams[0].id,
      selection: new Set(),
      tool: 'select',
      toolLock: false,
      analysis: false,
      views: {},               // per diagram: {x, y, zoom}
      activeThreat: null,      // threat key being edited
      filter: { text: '', state: '', category: '', priority: '', scope: 'selection' },
    };
    this.persist = debounce(() => {
      if (!writeLS(LS_MODEL, this.snapshot)) this.emit('toast', { text: 'Autosave failed (browser storage full or blocked).', kind: 'error' });
    }, 400);
  }

  get diagram() {
    return this.model.diagrams.find((d) => d.id === this.ui.diagramId) || this.model.diagrams[0];
  }
  get view() {
    const id = this.diagram.id;
    return (this.ui.views[id] ||= { x: 0, y: 0, zoom: 1 });
  }
  byId(diagram = this.diagram) {
    return new Map(diagram.elements.map((e) => [e.id, e]));
  }
  selected() {
    return this.diagram.elements.filter((e) => this.ui.selection.has(e.id));
  }

  on(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }
  emit(type, detail = {}) { for (const fn of this.listeners) fn(type, detail); }

  // Record a finished user action: regenerate threats, push history, autosave.
  commit(source = '') {
    syncThreats(this.model);
    this.model.meta.modified = new Date().toISOString();
    const snap = JSON.stringify(this.model);
    if (snap !== this.snapshot) {
      this.past.push(this.snapshot);
      if (this.past.length > HISTORY_LIMIT) this.past.shift();
      this.future = [];
      this.snapshot = snap;
      this.persist();
    }
    this.emit('change', { source });
  }

  // Transient visual update (e.g. while dragging) — no history entry.
  render() { this.emit('render'); }

  setUI(patch, source = '') {
    Object.assign(this.ui, patch);
    this.emit('ui', { source });
  }

  select(ids) {
    this.ui.selection = new Set(ids);
    this.emit('ui', { source: 'selection' });
  }

  undo() { this.#travel(this.past, this.future); }
  redo() { this.#travel(this.future, this.past); }
  #travel(from, to) {
    if (!from.length) return;
    to.push(this.snapshot);
    this.snapshot = from.pop();
    this.model = JSON.parse(this.snapshot);
    this.#afterReplace();
    this.persist();
    this.emit('change', { source: 'history' });
  }

  replaceModel(m) {
    normalizeModel(m);
    syncThreats(m);
    this.past.push(this.snapshot);
    this.future = [];
    this.model = m;
    this.snapshot = JSON.stringify(m);
    this.ui.views = {};
    this.#afterReplace();
    this.persist();
    this.emit('change', { source: 'load' });
    this.emit('loaded');
  }

  #afterReplace() {
    if (!this.model.diagrams.some((d) => d.id === this.ui.diagramId)) this.ui.diagramId = this.model.diagrams[0].id;
    const ids = new Set(this.diagram.elements.map((e) => e.id));
    this.ui.selection = new Set([...this.ui.selection].filter((id) => ids.has(id)));
    if (this.ui.activeThreat && !this.model.threats[this.ui.activeThreat]) this.ui.activeThreat = null;
  }

  setPref(key, value) {
    this.prefs[key] = value;
    writeLS(LS_PREFS, this.prefs);
    this.emit('prefs', { key });
  }
}

export const store = new Store();

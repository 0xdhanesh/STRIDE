// Application state: the model, selection, view, undo/redo history and the
// debounced "process model" pass (validation + threat generation), mirroring
// MTMT's ProcessModelDeferred timer.

import { DEFAULT_TEMPLATE, createModel, generateThreats, kbOf, loadModel, serializeModel, validateModel } from '../core/index.js';

const AUTOSAVE_KEY = 'stride:autosave:v1';
const PREFS_KEY = 'stride:prefs:v1';
const HISTORY_LIMIT = 80;

function storageGet(key) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}
function storageSet(key, value) {
  try {
    localStorage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}

export class Store extends EventTarget {
  constructor() {
    super();
    this.prefs = { theme: 'auto', grid: true, sketch: true, drawerH: 230, ...safeParse(storageGet(PREFS_KEY)) };
    this.view = 'design';
    this.tool = { kind: 'select' };
    this.selection = new Set();
    this.highlight = new Set();
    this.selectedThreatKey = null;
    this.camera = new Map(); // diagramId -> {x, y, z}
    this.messages = [];
    this.lastGeneration = null;
    this.undoStack = [];
    this.redoStack = [];
    this.fileName = null;
    this.fileHandle = null;
    this.dirty = false;
    this._txn = null;
    this._processTimer = null;
    this._saveTimer = null;

    let model = null;
    const saved = storageGet(AUTOSAVE_KEY);
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        model = loadModel(parsed.model);
        this.fileName = typeof parsed.fileName === 'string' ? parsed.fileName : null;
      } catch {
        model = null;
      }
    }
    this.model = model || createModel({ template: DEFAULT_TEMPLATE, name: 'Untitled threat model' });
    this.activeDiagramId = this.model.diagrams[0].id;
    this.processNow();
  }

  get kb() {
    return kbOf(this.model);
  }
  get diagram() {
    return this.model.diagrams.find((d) => d.id === this.activeDiagramId) || this.model.diagrams[0];
  }

  emit(type, detail) {
    this.dispatchEvent(new CustomEvent(type, { detail }));
  }
  on(type, fn) {
    this.addEventListener(type, (e) => fn(e.detail));
  }

  savePrefs() {
    storageSet(PREFS_KEY, JSON.stringify(this.prefs));
  }

  // ------------------------------------------------------------ transactions
  begin() {
    if (!this._txn) this._txn = serializeModel(this.model);
  }
  /** Finish a transaction: record undo if anything changed, then reprocess. */
  end({ immediate = false } = {}) {
    if (!this._txn) return;
    const before = this._txn;
    this._txn = null;
    if (before === serializeModel(this.model)) return;
    this.undoStack.push(before);
    if (this.undoStack.length > HISTORY_LIMIT) this.undoStack.shift();
    this.redoStack = [];
    this.changed({ immediate });
  }
  cancel() {
    if (!this._txn) return;
    this.restore(this._txn);
    this._txn = null;
  }
  /** Run fn inside a transaction. Errors roll back and are rethrown. */
  commit(fn, opts) {
    const outer = !this._txn;
    this.begin();
    try {
      const r = fn(this.model);
      if (outer) this.end(opts);
      return r;
    } catch (e) {
      if (outer) this.cancel();
      throw e;
    }
  }
  /** Live preview during a drag (no history entry until end()). */
  preview() {
    this.emit('model', { preview: true });
  }

  changed({ immediate = false } = {}) {
    this.dirty = true;
    this.pruneSelection();
    this.emit('model', {});
    if (immediate) this.processNow();
    else this.scheduleProcess();
    this.scheduleAutosave();
  }

  restore(json) {
    this.model = loadModel(json);
    if (!this.model.diagrams.some((d) => d.id === this.activeDiagramId)) this.activeDiagramId = this.model.diagrams[0].id;
    this.pruneSelection();
  }

  undo() {
    if (!this.undoStack.length) return;
    this.redoStack.push(serializeModel(this.model));
    this.restore(this.undoStack.pop());
    this.changed({ immediate: true });
  }
  redo() {
    if (!this.redoStack.length) return;
    this.undoStack.push(serializeModel(this.model));
    this.restore(this.redoStack.pop());
    this.changed({ immediate: true });
  }

  // ------------------------------------------------------------ processing
  scheduleProcess() {
    clearTimeout(this._processTimer);
    this._processTimer = setTimeout(() => this.processNow(), 220);
  }
  processNow() {
    clearTimeout(this._processTimer);
    this.lastGeneration = generateThreats(this.model);
    this.messages = validateModel(this.model);
    this.emit('processed', this.lastGeneration);
  }

  scheduleAutosave() {
    clearTimeout(this._saveTimer);
    this._saveTimer = setTimeout(() => this.autosave(), 600);
  }
  autosave() {
    const ok = storageSet(AUTOSAVE_KEY, JSON.stringify({ fileName: this.fileName, model: this.model }));
    if (!ok && !this._warnedStorage) {
      this._warnedStorage = true;
      this.emit('notice', 'Autosave is unavailable in this browser (storage blocked or full). Save to a file to keep your work.');
    }
  }

  // ------------------------------------------------------------ model lifecycle
  setModel(model, { fileName = null, fileHandle = null } = {}) {
    this.model = model;
    this.fileName = fileName;
    this.fileHandle = fileHandle;
    this.activeDiagramId = model.diagrams[0].id;
    this.selection.clear();
    this.highlight.clear();
    this.selectedThreatKey = null;
    this.undoStack = [];
    this.redoStack = [];
    this.dirty = false;
    this.processNow();
    this.emit('model', { replaced: true });
    this.emit('selection');
    this.autosave();
  }

  // ------------------------------------------------------------ selection / view
  pruneSelection() {
    const ids = new Set(this.diagram.elements.map((e) => e.id));
    for (const id of [...this.selection]) if (!ids.has(id)) this.selection.delete(id);
  }
  select(ids, { add = false, toggle = false } = {}) {
    if (!add && !toggle) this.selection.clear();
    for (const id of ids) {
      if (toggle && this.selection.has(id)) this.selection.delete(id);
      else this.selection.add(id);
    }
    this.emit('selection');
  }
  clearSelection() {
    if (!this.selection.size && !this.highlight.size) return;
    this.selection.clear();
    this.highlight.clear();
    this.emit('selection');
  }
  setHighlight(ids) {
    this.highlight = new Set(ids);
    this.emit('selection');
  }
  setDiagram(id) {
    if (this.activeDiagramId === id) return;
    this.activeDiagramId = id;
    this.selection.clear();
    this.highlight.clear();
    this.emit('model', { diagramChanged: true });
    this.emit('selection');
  }
  setTool(tool) {
    this.tool = tool;
    this.emit('tool');
  }
  setView(view) {
    this.view = view;
    this.emit('view');
  }
  selectThreat(key) {
    this.selectedThreatKey = key;
    this.emit('threat');
  }
}

function safeParse(s) {
  try {
    const v = JSON.parse(s);
    return v && typeof v === 'object' ? v : {};
  } catch {
    return {};
  }
}

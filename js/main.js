// App bootstrap: wires the toolbar, menu, tabs, footer, dialogs, keyboard
// shortcuts and clipboard to the store, canvas and panels.

import { store, newModel, newDiagram } from './store.js';
import { Canvas } from './canvas.js';
import { initPropsPanel, initThreatPanel } from './panels.js';
import { hydrateIcons, icon } from './icons.js';
import { esc, uid, isLine, isNode, download, slug, elementBounds, unionBounds } from './util.js';
import { validate, threatList, isOpen, activeRules, syncThreats } from './engine.js';
import { validateRules } from './rules.js';
import { sampleModel } from './sample.js';
import { deleteElements, duplicateElements, copyPayload, pastePayload, reorder, makeFromLibrary } from './ops.js';
import { LIBRARY, STENCILS, SUBTYPE_GLYPH } from './stencils.js';
import { glyphIcon } from './glyphs.js';
import {
  saveModelFile, readModelFile, exportPNG, exportSVG, exportCSV, openReport, shareLink, modelFromHash, exportReport,
} from './io.js';

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

// Restore before constructing interactive views, so startup cannot overwrite
// recovered work with edits made to a temporary empty model.
await store.restore();
document.body.inert = false;

const canvas = new Canvas($('#canvas-wrap'));
const props = initPropsPanel(canvas);
const threats = initThreatPanel(canvas);
hydrateIcons();

/* ------------------------------------------------------------------ toasts */

function toast(text, kind = '') {
  const t = document.createElement('div');
  t.className = `toast ${kind}`;
  t.textContent = text;
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), kind === 'error' ? 6000 : 3200);
}
store.on((type, d) => { if (type === 'toast') toast(d.text, d.kind); });

function renderSaveStatus() {
  const labels = {
    loading: 'Restoring local model…', saving: 'Saving locally…', saved: 'Autosaved locally',
    ready: 'Local autosave ready',
    fallback: 'Recovery copy only — save a .stride file',
    error: 'Autosave failed — save a .stride file',
    'recovery-error': 'Recovery unreadable — open a .stride file',
  };
  const el = $('#autosave-status');
  el.textContent = labels[store.saveStatus];
  el.dataset.state = store.saveStatus;
  el.title = 'Stored only in this browser. Save a .stride file for a portable backup. Browser data can be cleared or evicted.';
}
store.on((type) => { if (type === 'autosave') renderSaveStatus(); });
renderSaveStatus();

/* ----------------------------------------------------------------- toolbar */

const TOOL_KEYS = {
  h: 'hand', v: 'select', 1: 'select', p: 'process', 2: 'process', e: 'external', 3: 'external', d: 'store', 4: 'store',
  a: 'flow', 5: 'flow', b: 'boundary', 6: 'boundary', l: 'boundaryLine', 7: 'boundaryLine', t: 'note', 8: 'note', x: 'eraser', 0: 'eraser',
};

function setTool(tool) {
  if (tool !== 'select' && tool !== 'hand') store.ui.selection = new Set();
  store.setUI({ tool }, 'tool');
}

$('.toolbar').addEventListener('click', (e) => {
  const b = e.target.closest('button');
  if (!b) return;
  if (b.dataset.tool) setTool(b.dataset.tool);
  if (b.dataset.action === 'tool-lock') store.setUI({ toolLock: !store.ui.toolLock }, 'tool');
  if (b.dataset.action === 'library') toggleLibrary();
});

/* ----------------------------------------------------------- symbol library */

const TYPE_GLYPH = { process: 'orchestrator', external: 'user', store: 'database', boundary: 'kubernetes' };
function renderLibrary() {
  const q = $('#lib-search').value.trim().toLowerCase();
  $('#lib-items').innerHTML = LIBRARY.map(({ group, items }) => {
    const shown = items.filter(([type, sub]) => !q || `${group} ${sub} ${STENCILS[type].label}`.toLowerCase().includes(q));
    if (!shown.length) return '';
    return `<h3>${esc(group)}</h3><div class="lib-grid">${shown.map(([type, sub]) =>
      `<button class="lib-item" draggable="true" data-type="${type}" data-sub="${esc(sub)}" title="${esc(STENCILS[type].label)}: ${esc(sub)}">` +
      `${glyphIcon(SUBTYPE_GLYPH[sub] || TYPE_GLYPH[type], 26)}<span>${esc(sub)}</span><small>${esc(STENCILS[type].label)}</small></button>`).join('')}</div>`;
  }).join('') || '<p class="muted">No symbols match.</p>';
}
function toggleLibrary(force) {
  const lib = $('#library');
  lib.hidden = force === undefined ? !lib.hidden : !force;
  $('.toolbar [data-action="library"]').classList.toggle('active', !lib.hidden);
  if (!lib.hidden) { renderLibrary(); $('#lib-search').focus(); }
}
let libPlaced = 0;
function placeFromLibrary(type, sub, at) {
  if (!at) {
    const c = canvas.viewportCenter();
    at = { x: c.x + (libPlaced % 5) * 24, y: c.y + (libPlaced % 5) * 24 };
    libPlaced++;
  }
  const el = makeFromLibrary(store.model, type, sub, at);
  store.diagram.elements.push(el);
  store.ui.tool = 'select';
  store.select([el.id]);
  store.commit();
  toggleLibrary(false);
}
$('#lib-search').addEventListener('input', renderLibrary);

/* --------------------------------------------------- quick search ("/") */

const PALETTE_TOOLS = [
  ['select', 'Select', 'pointer', 'V'], ['hand', 'Hand (pan)', 'hand', 'H'], ['process', 'Process', 'process', 'P'],
  ['external', 'External Entity', 'external', 'E'], ['store', 'Data Store', 'store', 'D'], ['flow', 'Data Flow', 'flow', 'A'],
  ['boundary', 'Trust Boundary', 'boundary', 'B'], ['boundaryLine', 'Trust Boundary (line)', 'boundaryLine', 'L'],
  ['note', 'Note / Text', 'text', 'T'], ['eraser', 'Eraser', 'eraser', 'X'],
];

// Everything searchable: drawing tools, library presets, then every other stencil subtype.
function paletteEntries() {
  const out = PALETTE_TOOLS.map(([tool, label, ic, key]) => ({ kind: 'tool', tool, label, sub: 'Tool', icon: icon(ic, 20), key }));
  const seen = new Set();
  for (const { group, items } of LIBRARY) {
    for (const [type, sub] of items) {
      seen.add(`${type}|${sub}`);
      out.push({ kind: 'symbol', type, subtype: sub, label: sub, sub: `${group} · ${STENCILS[type].label}`, icon: glyphIcon(SUBTYPE_GLYPH[sub] || TYPE_GLYPH[type], 20) });
    }
  }
  for (const type of ['process', 'external', 'store', 'boundary']) {
    for (const sub of STENCILS[type].subtypes) {
      if (seen.has(`${type}|${sub}`)) continue;
      out.push({ kind: 'symbol', type, subtype: sub, label: sub, sub: STENCILS[type].label, icon: SUBTYPE_GLYPH[sub] ? glyphIcon(SUBTYPE_GLYPH[sub], 20) : icon(type, 20) });
    }
  }
  return out;
}

const palette = { items: [], index: 0 };
function renderPalette() {
  const q = $('#palette-input').value.trim().toLowerCase();
  const words = q.split(/\s+/).filter(Boolean);
  const scored = paletteEntries()
    .map((it) => {
      const hay = `${it.label} ${it.sub} ${it.kind}`.toLowerCase();
      if (!words.every((w) => hay.includes(w))) return null;
      const l = it.label.toLowerCase();
      return { it, score: !q ? 0 : l === q ? 3 : l.startsWith(q) ? 2 : l.split(/[\s/()-]+/).some((w) => w.startsWith(words[0])) ? 1 : 0 };
    })
    .filter(Boolean)
    .sort((a, b) => b.score - a.score);
  palette.items = scored.map((x) => x.it);
  palette.index = Math.min(palette.index, Math.max(0, palette.items.length - 1));
  $('#palette-list').innerHTML = palette.items.length
    ? palette.items.map((it, i) =>
      `<div class="pal-item${i === palette.index ? ' active' : ''}" role="option" aria-selected="${i === palette.index}" data-i="${i}">` +
      `${it.icon}<span class="pal-label">${esc(it.label)}</span><span class="pal-sub">${esc(it.sub)}</span>${it.key ? `<kbd>${it.key}</kbd>` : ''}</div>`).join('')
    : '<div class="muted" style="padding:14px">Nothing found.</div>';
  $('#palette-list .pal-item.active')?.scrollIntoView({ block: 'nearest' });
}
function openPalette() {
  toggleLibrary(false);
  $('#palette').hidden = false;
  $('#palette-input').value = '';
  palette.index = 0;
  renderPalette();
  $('#palette-input').focus();
}
function closePalette() { $('#palette').hidden = true; }
function choosePalette(i) {
  const it = palette.items[i];
  if (!it) return;
  closePalette();
  if (it.kind === 'tool') setTool(it.tool);
  else placeFromLibrary(it.type, it.subtype, canvas.lastPointer || null);
}
$('#palette-input').addEventListener('input', () => { palette.index = 0; renderPalette(); });
$('#palette-input').addEventListener('keydown', (e) => {
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault();
    const n = palette.items.length;
    if (n) palette.index = (palette.index + (e.key === 'ArrowDown' ? 1 : n - 1)) % n;
    renderPalette();
  } else if (e.key === 'Enter') { e.preventDefault(); choosePalette(palette.index); }
  else if (e.key === 'Escape') { e.preventDefault(); closePalette(); }
});
$('#palette-input').addEventListener('blur', () => setTimeout(() => { if (!$('#palette').contains(document.activeElement)) closePalette(); }, 150));
$('#palette-list').addEventListener('pointerdown', (e) => e.preventDefault()); // keep focus in the input
$('#palette-list').addEventListener('click', (e) => { const r = e.target.closest('.pal-item'); if (r) choosePalette(+r.dataset.i); });
$('#palette-list').addEventListener('pointermove', (e) => {
  const r = e.target.closest('.pal-item');
  if (r && +r.dataset.i !== palette.index) { palette.index = +r.dataset.i; renderPalette(); }
});
$('#lib-search').addEventListener('keydown', (e) => { if (e.key === 'Escape') toggleLibrary(false); });
$('#lib-items').addEventListener('click', (e) => {
  const b = e.target.closest('.lib-item');
  if (b) placeFromLibrary(b.dataset.type, b.dataset.sub);
});
$('#lib-items').addEventListener('dragstart', (e) => {
  const b = e.target.closest('.lib-item');
  if (!b) return;
  e.dataTransfer.setData('application/x-stride-symbol', JSON.stringify([b.dataset.type, b.dataset.sub]));
  e.dataTransfer.effectAllowed = 'copy';
});
$('#canvas-wrap').addEventListener('dragover', (e) => {
  if (e.dataTransfer.types.includes('application/x-stride-symbol')) { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; }
});
$('#canvas-wrap').addEventListener('drop', (e) => {
  const data = e.dataTransfer.getData('application/x-stride-symbol');
  if (!data) return;
  e.preventDefault();
  const [type, sub] = JSON.parse(data);
  placeFromLibrary(type, sub, canvas.toWorld(e));
});

function syncChrome() {
  for (const b of $$('.toolbar [data-tool]')) b.classList.toggle('active', b.dataset.tool === store.ui.tool);
  const lock = $('.toolbar [data-action="tool-lock"]');
  lock.classList.toggle('active', store.ui.toolLock);
  lock.dataset.icon = store.ui.toolLock ? 'lock' : 'unlock';
  hydrateIcons(lock.parentElement);
  for (const b of $$('[data-view]')) b.classList.toggle('active', (b.dataset.view === 'analysis') === store.ui.analysis);
  $('#undo').disabled = !store.past.length;
  $('#redo').disabled = !store.future.length;
  const open = threatList(store.model).filter((t) => isOpen(t) && !t.orphan).length;
  const pill = $('#threat-count');
  pill.textContent = open;
  pill.title = `${open} open threat(s)`;
  pill.classList.toggle('alert', open > 0);
  for (const c of $$('[data-pref]')) {
    const k = c.dataset.pref;
    c.classList.toggle('on', k === 'theme' ? store.prefs.theme === 'dark' : !!store.prefs[k]);
  }
  document.documentElement.dataset.theme = store.prefs.theme;
  document.title = `${store.model.meta.title} · STRIDE Threat Modeler`;
}

$('.top-right').addEventListener('click', (e) => {
  const b = e.target.closest('[data-view]');
  if (b) setAnalysis(b.dataset.view === 'analysis');
});

function setAnalysis(on) {
  store.setUI({ analysis: on, activeThreat: on ? store.ui.activeThreat : null }, 'analysis');
}

/* -------------------------------------------------------------- zoom/undo */

const zoomLabel = () => { $('#zoom-reset').textContent = `${Math.round(store.view.zoom * 100)}%`; };
$('#zoom-in').onclick = () => canvas.zoomBy(1.2);
$('#zoom-out').onclick = () => canvas.zoomBy(1 / 1.2);
$('#zoom-reset').onclick = () => canvas.resetZoom();
$('#zoom-reset').ondblclick = () => canvas.fit();
$('#undo').onclick = () => store.undo();
$('#redo').onclick = () => store.redo();

/* ------------------------------------------------------------ diagram tabs */

function renderTabs() {
  const nav = $('#tabs');
  nav.innerHTML = store.model.diagrams.map((d) =>
    `<button class="tab${d.id === store.diagram.id ? ' active' : ''}" data-d="${esc(d.id)}" title="Double-click to rename · right-click for more">${esc(d.name)}</button>`,
  ).join('') + '<button class="tab tab-add" data-add title="Add diagram">+</button>';
}

$('#tabs').addEventListener('click', (e) => {
  const b = e.target.closest('button');
  if (!b || b.querySelector('input')) return;
  if (b.dataset.add !== undefined) return addDiagram();
  if (b.dataset.d && b.dataset.d !== store.diagram.id) switchDiagram(b.dataset.d);
});
$('#tabs').addEventListener('dblclick', (e) => { const b = e.target.closest('[data-d]'); if (b) renameDiagramInline(b); });
$('#tabs').addEventListener('contextmenu', (e) => {
  const b = e.target.closest('[data-d]');
  if (!b) return;
  e.preventDefault();
  switchDiagram(b.dataset.d);
  const idx = store.model.diagrams.findIndex((d) => d.id === b.dataset.d);
  showContextMenu(e.clientX, e.clientY, [
    ['Rename', () => renameDiagramInline($(`[data-d="${b.dataset.d}"]`))],
    ['Duplicate', duplicateDiagram],
    ['Move left', () => moveDiagram(idx, -1), idx === 0],
    ['Move right', () => moveDiagram(idx, 1), idx === store.model.diagrams.length - 1],
    null,
    ['Delete diagram', deleteDiagram, store.model.diagrams.length < 2, 'danger'],
  ]);
});

function switchDiagram(id) {
  store.ui.selection = new Set();
  store.setUI({ diagramId: id, activeThreat: null });
}

function addDiagram() {
  const d = newDiagram(`Diagram ${store.model.diagrams.length + 1}`);
  store.model.diagrams.push(d);
  store.ui.diagramId = d.id;
  store.ui.selection = new Set();
  store.commit();
}

function duplicateDiagram() {
  const src = store.diagram;
  const map = new Map();
  const d = { id: uid('d_'), name: `${src.name} (copy)`, elements: structuredClone(src.elements) };
  for (const e of d.elements) map.set(e.id, (e.id = uid('e_')));
  for (const e of d.elements) if (isLine(e)) { e.sourceId = map.get(e.sourceId) ?? null; e.targetId = map.get(e.targetId) ?? null; }
  store.model.diagrams.splice(store.model.diagrams.indexOf(src) + 1, 0, d);
  store.ui.views[d.id] = { ...store.view };
  store.ui.diagramId = d.id;
  store.commit();
}

function moveDiagram(idx, dir) {
  const arr = store.model.diagrams;
  [arr[idx], arr[idx + dir]] = [arr[idx + dir], arr[idx]];
  store.commit();
}

function deleteDiagram() {
  const d = store.diagram;
  if (store.model.diagrams.length < 2) return;
  if (!confirm(`Delete diagram "${d.name}" and all of its threats? You can undo this.`)) return;
  store.model.diagrams = store.model.diagrams.filter((x) => x !== d);
  for (const [k, t] of Object.entries(store.model.threats)) if (t.diagramId === d.id) delete store.model.threats[k];
  store.ui.diagramId = store.model.diagrams[0].id;
  store.ui.selection = new Set();
  store.commit();
}

function renameDiagramInline(btn) {
  const d = store.model.diagrams.find((x) => x.id === btn.dataset.d);
  if (!d) return;
  btn.innerHTML = `<input value="${esc(d.name)}" aria-label="Diagram name">`;
  const input = btn.querySelector('input');
  input.focus();
  input.select();
  const done = (save) => {
    if (save && input.value.trim()) { d.name = input.value.trim(); store.commit(); } else renderTabs();
  };
  input.addEventListener('keydown', (e) => {
    e.stopPropagation();
    if (e.key === 'Enter') input.blur();
    if (e.key === 'Escape') { input.value = ''; input.blur(); }
  });
  input.addEventListener('blur', () => done(true), { once: true });
}

/* ---------------------------------------------------------------- messages */

let messages = [];
function renderMessages() {
  messages = validate(store.model);
  const warn = messages.filter((m) => m.level === 'warning').length;
  $('#messages-count').textContent = messages.length;
  $('#messages-btn').classList.toggle('has-warn', warn > 0);
  $('#messages-btn').title = `${warn} warning(s), ${messages.length - warn} note(s)`;
  const pop = $('#messages');
  pop.innerHTML = messages.length
    ? messages.map((m, i) => `<button class="msg ${m.level}" data-i="${i}"><span class="dot"></span><span>${esc(m.text)}</span></button>`).join('')
    : '<div class="muted" style="padding:12px">No problems found. Nice diagram!</div>';
}
$('#messages-btn').onclick = (e) => { e.stopPropagation(); $('#messages').hidden = !$('#messages').hidden; };
$('#messages').addEventListener('click', (e) => {
  const b = e.target.closest('.msg');
  if (!b) return;
  const m = messages[+b.dataset.i];
  if (m.threatIds) { setAnalysis(true); return; }
  if (m.diagramId && m.diagramId !== store.diagram.id) switchDiagram(m.diagramId);
  if (m.elementId) {
    const el = store.diagram.elements.find((x) => x.id === m.elementId);
    if (el) { store.select([el.id]); canvas.fit([el]); }
  }
});

/* ------------------------------------------------------------ context menu */

function showContextMenu(x, y, items) {
  const menu = $('#ctxmenu');
  menu.innerHTML = items.map((it, i) => it
    ? `<button data-i="${i}"${it[2] ? ' disabled style="opacity:.4"' : ''}${it[3] ? ` class="${it[3]}"` : ''}>${esc(it[0])}${it[4] ? `<span class="kbd">${esc(it[4])}</span>` : ''}</button>`
    : '<hr>').join('');
  menu.hidden = false;
  const r = menu.getBoundingClientRect();
  menu.style.left = `${Math.min(x, innerWidth - r.width - 8)}px`;
  menu.style.top = `${Math.min(y, innerHeight - r.height - 8)}px`;
  menu.onclick = (e) => {
    const b = e.target.closest('button[data-i]');
    if (!b || b.disabled) return;
    menu.hidden = true;
    items[+b.dataset.i][1]();
  };
}

store.on((type, d) => {
  if (type !== 'contextmenu') return;
  const sel = store.selected();
  if (d.hit) {
    const el = sel[0];
    showContextMenu(d.x, d.y, [
      sel.length === 1 && ['Rename', () => canvas.startEdit(el), false, '', 'Enter'],
      ['Duplicate', doDuplicate, false, '', 'Ctrl+D'],
      ['Copy', () => doCopy(), false, '', 'Ctrl+C'],
      ['Bring to front', () => { reorder(store.diagram, store.ui.selection, true); store.commit(); }, false, '', 'Ctrl+]'],
      ['Send to back', () => { reorder(store.diagram, store.ui.selection, false); store.commit(); }, false, '', 'Ctrl+['],
      sel.length === 1 && el.type !== 'note' && [el.outOfScope ? 'Mark in scope' : 'Mark out of scope', () => { el.outOfScope = !el.outOfScope; store.commit(); }],
      sel.length === 1 && ['process', 'external', 'store', 'flow'].includes(el.type) && ['Show threats', () => { store.ui.filter.scope = 'selection'; setAnalysis(true); }],
      ['Zoom to selection', () => canvas.fit(sel), false, '', 'Shift+2'],
      null,
      ['Delete', doDelete, false, 'danger', 'Del'],
    ].filter((x) => x !== false));
  } else {
    showContextMenu(d.x, d.y, [
      ['Paste', () => doPaste(null, d.world), !clipboard, '', 'Ctrl+V'],
      ['Select all', selectAll, false, '', 'Ctrl+A'],
      null,
      ['Zoom to fit', () => canvas.fit(), false, '', 'Shift+1'],
      ['Reset zoom', () => canvas.resetZoom(), false, '', 'Shift+0'],
      [store.prefs.grid ? 'Hide grid' : 'Show grid', () => store.setPref('grid', !store.prefs.grid)],
      null,
      ['Model properties…', () => runAction('model-props')],
      ['Export diagram as PNG', () => runAction('export-png')],
    ]);
  }
});

/* ---------------------------------------------------------- selection ops */

let clipboard = null;
let pasteCount = 0;

function selectAll() { store.select(store.diagram.elements.map((e) => e.id)); }
function doDelete() {
  if (!store.ui.selection.size) return;
  deleteElements(store.diagram, new Set(store.ui.selection));
  store.select([]);
  store.commit();
}
function doDuplicate() {
  if (!store.ui.selection.size) return;
  store.select(duplicateElements(store.diagram, new Set(store.ui.selection)));
  store.commit();
}
function doCopy(e) {
  if (!store.ui.selection.size) return false;
  clipboard = copyPayload(store.diagram, [...store.ui.selection]);
  pasteCount = 0;
  const text = JSON.stringify(clipboard);
  if (e?.clipboardData) { e.clipboardData.setData('text/plain', text); e.preventDefault(); }
  else navigator.clipboard?.writeText(text).catch(() => {});
  return true;
}
function doPaste(payload, at = null) {
  payload ||= clipboard;
  if (!payload?.elements?.length) return;
  const byId = new Map(payload.elements.map((x) => [x.id, x]));
  const b = unionBounds(payload.elements.map((x) => elementBounds(x, byId)));
  let dx, dy;
  if (at) { dx = at.x - (b.x + b.w / 2); dy = at.y - (b.y + b.h / 2); }
  else { pasteCount++; dx = dy = 24 * pasteCount; }
  store.select(pastePayload(store.diagram, payload, dx, dy));
  store.commit();
}

document.addEventListener('copy', (e) => { if (!isTyping(e)) doCopy(e); });
document.addEventListener('cut', (e) => { if (!isTyping(e) && doCopy(e)) doDelete(); });
document.addEventListener('paste', (e) => {
  if (isTyping(e)) return;
  const text = e.clipboardData?.getData('text/plain');
  let payload = null;
  try { const p = JSON.parse(text); if (p?.kind === 'clipboard') payload = p; } catch { /* not ours */ }
  e.preventDefault();
  doPaste(payload, canvas.lastPointer || null);
});
$('#canvas').addEventListener('pointermove', (e) => { canvas.lastPointer = canvas.toWorld(e); });
$('#canvas').addEventListener('pointerleave', () => { canvas.lastPointer = null; });

function nudge(dx, dy) {
  const sel = store.selected();
  if (!sel.length) return;
  for (const el of sel) {
    if (isNode(el)) { el.x += dx; el.y += dy; }
    else {
      if (!el.sourceId) { el.x1 += dx; el.y1 += dy; }
      if (!el.targetId) { el.x2 += dx; el.y2 += dy; }
    }
  }
  store.commit('nudge');
}

/* ----------------------------------------------------------------- actions */

const fileInput = $('#file-input');
let fileHandler = null;
function pickFile(accept, handler) {
  fileInput.accept = accept;
  fileHandler = handler;
  fileInput.value = '';
  fileInput.click();
}
fileInput.addEventListener('change', async () => {
  const file = fileInput.files[0];
  if (file && fileHandler) {
    try { await fileHandler(file); } catch (err) { toast(err.message || String(err), 'error'); }
  }
});

function loadModel(m, message) {
  const note = m.importNote;
  store.replaceModel(m);
  store.ui.selection = new Set();
  store.ui.activeThreat = null;
  store.setUI({}, 'load');
  requestAnimationFrame(() => canvas.fit());
  toast(note || message || `Opened "${store.model.meta.title}". Undo (Ctrl+Z) to go back.`);
  if (store.model.importWarnings?.length) $('#messages').hidden = false;
}

async function runAction(name) {
  const sketchy = store.prefs.sketchy;
  switch (name) {
    case 'open': return pickFile('.stride,.json,.tm7,application/json', async (f) => loadModel(await readModelFile(f)));
    case 'save':
      canvas.finishEdit();
      try { saveModelFile(store.model); toast('Local .stride download started.'); }
      catch (e) { toast(`Save failed: ${e.message}`, 'error'); }
      return;
    case 'export-png':
      if (!store.diagram.elements.length) return toast('Nothing to export yet.');
      return exportPNG(store.model, store.diagram, sketchy).catch((e) => toast(`PNG export failed: ${e.message}`, 'error'));
    case 'export-svg':
      if (!store.diagram.elements.length) return toast('Nothing to export yet.');
      return exportSVG(store.model, store.diagram, sketchy);
    case 'report': return openReport(store.model, sketchy);
    case 'report-pdf':
    case 'report-markdown':
    case 'report-json': {
      canvas.finishEdit();
      document.activeElement?.blur();
      const format = name.slice(7);
      toast(`Preparing ${format === 'markdown' ? 'Markdown' : format.toUpperCase()} report locally…`);
      try {
        await exportReport(store.model, format, { sketchy });
        toast('Report download started.');
      } catch (e) { toast(`Report export failed: ${e.message}`, 'error'); }
      return;
    }
    case 'export-csv': return exportCSV(store.model);
    case 'share': {
      try {
        const link = await shareLink(store.model);
        await navigator.clipboard.writeText(link);
        toast(link.length > 30000 ? `Link copied (${Math.round(link.length / 1000)} KB, which is long; consider sharing the file).` : 'Share link copied. The whole model is inside the link; nothing is uploaded.');
      } catch (e) { toast(`Could not create link: ${e.message}`, 'error'); }
      return;
    }
    case 'model-props': return openModelDialog();
    case 'template': return openTemplateDialog();
    case 'sample': {
      if (store.diagram.elements.length && !confirm('Replace the current model with the example? (You can undo.)')) return;
      const example = sampleModel();
      syncThreats(example);
      return loadModel(example, 'Loaded the example model. Switch to Analysis to see its threats.');
    }
    case 'new':
      if (!confirm('Start a new, empty model? Unsaved work can still be restored with Undo.')) return;
      return loadModel(newModel(), 'New model created.');
    case 'toggle-sketchy': return store.setPref('sketchy', !store.prefs.sketchy);
    case 'toggle-grid': return store.setPref('grid', !store.prefs.grid);
    case 'toggle-theme': return store.setPref('theme', store.prefs.theme === 'dark' ? 'light' : 'dark');
    case 'help': return $('#dlg-help').showModal();
    case 'add-threat': return threats.addThreat();
    case 'close-analysis': return setAnalysis(false);
  }
}

document.addEventListener('click', (e) => {
  const b = e.target.closest('[data-action]');
  const menu = $('#menu');
  if (b && !b.closest('.toolbar') && !b.closest('#dlg-template')) {
    menu.hidden = true;
    $('#menu-btn').setAttribute('aria-expanded', 'false');
    runAction(b.dataset.action);
  }
  if (!e.target.closest('#menu') && !e.target.closest('#menu-btn')) menu.hidden = true;
  if (!e.target.closest('#ctxmenu')) $('#ctxmenu').hidden = true;
  if (!e.target.closest('#messages') && !e.target.closest('#messages-btn')) $('#messages').hidden = true;
});
$('#menu-btn').addEventListener('click', () => {
  const m = $('#menu');
  m.hidden = !m.hidden;
  $('#menu-btn').setAttribute('aria-expanded', String(!m.hidden));
});
store.on((type) => { if (type === 'canvas-pointerdown') { $('#menu').hidden = true; $('#ctxmenu').hidden = true; $('#messages').hidden = true; } });

/* ----------------------------------------------------------------- dialogs */

function openModelDialog() {
  const dlg = $('#dlg-model');
  const form = $('#model-form');
  for (const [k, v] of Object.entries(store.model.meta)) if (form.elements[k]) form.elements[k].value = v;
  dlg.returnValue = '';
  dlg.showModal();
}
$('#dlg-model').addEventListener('close', () => {
  const dlg = $('#dlg-model');
  if (dlg.returnValue !== 'ok') return;
  const form = $('#model-form');
  for (const k of ['title', 'owner', 'reviewer', 'contributors', 'description', 'assumptions', 'dependencies']) store.model.meta[k] = form.elements[k].value;
  store.commit();
});

function openTemplateDialog() {
  const rules = activeRules(store.model);
  $('#template-json').value = JSON.stringify(rules, null, 2);
  $('#template-status').textContent = store.model.template ? `Custom template · ${rules.length} rules` : `Built-in STRIDE template · ${rules.length} rules`;
  $('#dlg-template').showModal();
}
$('#dlg-template').addEventListener('click', (e) => {
  const a = e.target.closest('[data-action]')?.dataset.action;
  if (!a) return;
  try {
    if (a === 'template-apply') {
      const rules = validateRules(JSON.parse($('#template-json').value));
      store.model.template = rules;
      store.commit();
      openTemplateDialog();
      toast(`Template applied: ${rules.length} rules, ${threatList(store.model).length} threats.`);
    } else if (a === 'template-export') {
      download(`${slug(store.model.meta.title)}-template.json`, $('#template-json').value, 'application/json');
    } else if (a === 'template-import') {
      pickFile('.json,application/json', async (f) => {
        const rules = validateRules(JSON.parse(await f.text()));
        $('#template-json').value = JSON.stringify(rules, null, 2);
        toast('Template loaded into the editor; press Apply to use it.');
      });
    } else if (a === 'template-reset') {
      store.model.template = null;
      store.commit();
      openTemplateDialog();
      toast('Built-in template restored.');
    }
  } catch (err) {
    toast(`Template error: ${err.message}`, 'error');
  }
});

/* ---------------------------------------------------------------- keyboard */

function isTyping(e) {
  const t = e.target;
  return t instanceof HTMLElement && (t.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName));
}

window.addEventListener('keydown', (e) => {
  const mod = e.metaKey || e.ctrlKey;
  const k = e.key.toLowerCase();
  if (mod && ['s', 'o'].includes(k) && !$('dialog[open]')) {
    e.preventDefault();
    document.activeElement?.blur();
    runAction(k === 's' ? 'save' : 'open');
    return;
  }
  if ($('dialog[open]')) return;
  if (isTyping(e)) { if (e.key === 'Escape') e.target.blur(); return; }

  if (mod) {
    const handled = {
      z: () => (e.shiftKey ? store.redo() : store.undo()),
      y: () => store.redo(),
      s: () => runAction('save'),
      o: () => runAction('open'),
      d: doDuplicate,
      a: selectAll,
      '=': () => canvas.zoomBy(1.2), '+': () => canvas.zoomBy(1.2), '-': () => canvas.zoomBy(1 / 1.2), 0: () => canvas.resetZoom(),
      ']': () => { reorder(store.diagram, store.ui.selection, true); store.commit(); },
      '[': () => { reorder(store.diagram, store.ui.selection, false); store.commit(); },
    }[k];
    if (handled) { e.preventDefault(); handled(); }
    return; // let copy/cut/paste events fire
  }
  if (e.altKey) return;

  if (e.key === ' ') { canvas.spaceDown = true; canvas.wrap.classList.add('panning'); e.preventDefault(); return; }
  if (e.shiftKey && e.code === 'Digit1') return canvas.fit();
  if (e.shiftKey && e.code === 'Digit2') return store.ui.selection.size && canvas.fit(store.selected());
  if (e.shiftKey && e.code === 'Digit0') return canvas.resetZoom();
  if (e.shiftKey && e.code === 'KeyA') return setAnalysis(!store.ui.analysis);
  if (e.key === '?') return runAction('help');
  if (e.key === '/') { e.preventDefault(); return openPalette(); }

  switch (e.key) {
    case 'Delete': case 'Backspace': e.preventDefault(); return doDelete();
    case 'Escape':
      if (!$('#menu').hidden || !$('#ctxmenu').hidden) { $('#menu').hidden = $('#ctxmenu').hidden = true; return; }
      if (!$('#library').hidden) return toggleLibrary(false);
      if (store.ui.activeThreat) return store.setUI({ activeThreat: null }, 'threat');
      if (store.ui.selection.size) return store.select([]);
      return setTool('select');
    case 'Enter': {
      const sel = store.selected();
      if (sel.length === 1) { e.preventDefault(); canvas.startEdit(sel[0]); }
      return;
    }
    case 'ArrowLeft': case 'ArrowRight': case 'ArrowUp': case 'ArrowDown': {
      if (!store.ui.selection.size) return;
      e.preventDefault();
      const s = e.shiftKey ? 10 : 1;
      return nudge(e.key === 'ArrowLeft' ? -s : e.key === 'ArrowRight' ? s : 0, e.key === 'ArrowUp' ? -s : e.key === 'ArrowDown' ? s : 0);
    }
  }
  if (e.shiftKey) return;
  if (k === 'q') return store.setUI({ toolLock: !store.ui.toolLock }, 'tool');
  if (k === 'y') { e.preventDefault(); return toggleLibrary(); }
  if (TOOL_KEYS[k]) setTool(TOOL_KEYS[k]);
});
window.addEventListener('keyup', (e) => {
  if (e.key === ' ') { canvas.spaceDown = false; canvas.wrap.classList.remove('panning'); }
});
window.addEventListener('blur', () => { canvas.spaceDown = false; canvas.wrap.classList.remove('panning'); });

/* ------------------------------------------------------------ store wiring */

store.on((type) => {
  if (type === 'change' || type === 'loaded') { renderTabs(); renderMessages(); syncChrome(); }
  if (type === 'ui' || type === 'prefs') { renderTabs(); syncChrome(); zoomLabel(); }
  if (type === 'view') zoomLabel();
});

function checkpoint() {
  canvas.finishEdit();
  document.activeElement?.blur();
  // Write the recovery journal synchronously; unload cannot await IndexedDB.
  if (store.saveStatus !== 'recovery-error') store.persist();
}
window.addEventListener('pagehide', checkpoint);
document.addEventListener('visibilitychange', () => { if (document.hidden) checkpoint(); });
window.addEventListener('beforeunload', (event) => {
  checkpoint();
  if (store.saveStatus === 'saving' || store.saveStatus === 'error') {
    // Only warn when even the synchronous recovery copy could not be written.
    if (!store.autosave.journaled) { event.preventDefault(); event.returnValue = ''; }
  }
});
// Don't leave focus on clicked buttons: Space/Enter are canvas shortcuts.
document.addEventListener('pointerup', (e) => {
  const b = e.target.closest?.('button');
  if (b && !b.closest('dialog')) setTimeout(() => b.blur(), 0);
});

/* ------------------------------------------------------------------ start */

async function start() {
  renderTabs();
  renderMessages();
  syncChrome();
  props.render();
  threats.render();
  if (location.hash.includes('model=')) {
    try {
      const m = await modelFromHash(location.hash);
      history.replaceState(null, '', location.pathname + location.search);
      if (m && confirm(`Open the shared threat model "${m.meta?.title || 'Untitled'}"? Your current model can be restored with Undo.`)) {
        loadModel(m, 'Opened shared model.');
        return;
      }
    } catch (e) { toast(`Could not open the shared link: ${e.message}`, 'error'); }
  }
  if (store.diagram.elements.length) canvas.fit();
  else { const r = canvas.svg.getBoundingClientRect(); Object.assign(store.view, { x: r.width / 2 - 300, y: r.height / 2 - 200, zoom: 1 }); canvas.schedule(); }
  zoomLabel();
}
start();

// Expose for debugging in the console.
window.strideApp = { store, canvas, icon };

// App entry: layout, top bar, file handling, reports, settings.

import {
  DEFAULT_TEMPLATE,
  addDiagram,
  applyTemplate,
  createModel,
  createSampleModel,
  loadModel,
  parseTemplateText,
  removeDiagram,
  REPORT_FONTS,
  renderDiagramSvg,
  renderExecutiveReport,
  renderHtmlReport,
  resolveFont,
  renderMarkdownReport,
  serializeModel,
  threatsToCsv,
} from '../core/index.js';
import * as core from '../core/index.js';
import { Canvas } from './canvas.js';
import { clear, confirmDialog, downloadText, field, h, icon, modal, openBlob, pickFile, promptDialog, select, toast } from './dom.js';
import { Drawer, Inspector, Palette } from './panels.js';
import { Store } from './state.js';
import { openTemplateEditor } from './template-editor.js';

const store = new Store();
const app = document.getElementById('app');
const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
const MOD = isMac ? '⌘' : 'Ctrl+';

const slug = (s) => String(s || 'threat-model').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'threat-model';

// ------------------------------------------------------------ layout
const topbar = h('header', { class: 'topbar' });
const palette = h('aside', { class: 'palette', 'aria-label': 'Stencils' });
const stage = h('main', { class: 'stage' });
const inspector = h('aside', { class: 'inspector', 'aria-label': 'Properties' });
const drawer = h('section', { class: 'drawer', 'aria-label': 'Threats, messages and notes' });
clear(app).append(topbar, palette, stage, inspector, drawer);

function setFocus(on) {
  app.classList.toggle('focus', on);
  closeMenu();
  requestAnimationFrame(() => {
    ui.canvas.zoomToFit();
    ui.canvas.svg.focus({ preventScroll: true });
  });
}
function applyPaletteCollapsed() {
  app.classList.toggle('palette-collapsed', !!store.prefs.paletteCollapsed);
  requestAnimationFrame(() => ui.canvas?.requestRender());
}
function applyInspectorCollapsed() {
  app.classList.toggle('inspector-collapsed', !!store.prefs.inspectorCollapsed);
  requestAnimationFrame(() => ui.canvas?.requestRender());
}
function toggleInspector() {
  store.prefs.inspectorCollapsed = !store.prefs.inspectorCollapsed;
  store.savePrefs();
  applyInspectorCollapsed();
  renderTopbar();
}
function togglePalette() {
  store.prefs.paletteCollapsed = !store.prefs.paletteCollapsed;
  store.savePrefs();
  applyPaletteCollapsed();
  renderTopbar();
}
const toggleFocus = () => setFocus(!app.classList.contains('focus'));

const ui = {
  openTemplate: (focus) => openTemplateEditor(store, focus),
};
ui.canvas = new Canvas(store, stage);
ui.palette = new Palette(store, palette);
ui.inspector = new Inspector(store, inspector, ui);
ui.drawer = new Drawer(store, drawer, ui);
stage.append(h('div', { class: 'focus-hint', 'aria-hidden': 'true' }, 'Press ', h('kbd', null, 'H'), ' for hand mode'));
stage.append(h('button', { class: 'btn focus-exit', type: 'button', title: `Exit focus mode (Esc or ${MOD}.)`, onClick: () => setFocus(false) }, icon('x', 16), h('span', null, 'Exit focus')));

// ------------------------------------------------------------ theme
function applyTheme() {
  const t = store.prefs.theme;
  if (t === 'auto') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', t);
}
applyTheme();
applyPaletteCollapsed();
applyInspectorCollapsed();

// ------------------------------------------------------------ menus
let openMenu = null;
function closeMenu() {
  openMenu?.remove();
  openMenu = null;
}
document.addEventListener('pointerdown', (e) => {
  if (openMenu && !openMenu.contains(e.target) && !e.target.closest?.('.menu > .btn')) closeMenu();
});
document.addEventListener('keydown', (e) => e.key === 'Escape' && closeMenu());

function menu(label, iconName, items, title) {
  const wrap = h('div', { class: 'menu' });
  const btn = h('button', { class: 'btn', type: 'button', 'aria-haspopup': 'menu', title: title || label }, iconName ? icon(iconName) : null, label ? h('span', { class: iconName ? 'hide-sm' : '' }, label) : null);
  btn.addEventListener('click', () => {
    const wasOpen = openMenu?.parentElement === wrap;
    closeMenu();
    if (wasOpen) return;
    const list = h(
      'div',
      { class: 'menu-list', role: 'menu' },
      (typeof items === 'function' ? items() : items).map((it) =>
        it === '-'
          ? h('hr')
          : h(
              'button',
              {
                type: 'button',
                role: 'menuitem',
                onClick: () => {
                  closeMenu();
                  it.run();
                },
              },
              h('span', null, it.label),
              it.kbd ? h('kbd', null, it.kbd) : null,
            ),
      ),
    );
    wrap.appendChild(list);
    openMenu = list;
  });
  wrap.appendChild(btn);
  return wrap;
}

// ------------------------------------------------------------ file actions
async function confirmDiscard() {
  if (!store.dirty) return true;
  return confirmDialog('Discard changes?', 'The current model has changes that were not saved to a file. It is kept in browser autosave only until you replace it.', 'Continue', true);
}

async function newModel() {
  if (!(await confirmDiscard())) return;
  store.setModel(createModel({ template: store.model.template || DEFAULT_TEMPLATE, name: 'Untitled threat model' }));
  toast('New model created with the current template.');
}

async function openSample() {
  if (!(await confirmDiscard())) return;
  store.setModel(createSampleModel());
  requestAnimationFrame(() => ui.canvas.zoomToFit());
}

/** A saved model, or an architecture spec (zones/elements/flows, as used by `stride sync`) that is built into a new model. */
function modelFromText(text) {
  const raw = JSON.parse(text);
  if (raw && raw.format !== 'stride-model' && (Array.isArray(raw.elements) || Array.isArray(raw.zones))) {
    const m = createModel({ template: DEFAULT_TEMPLATE, name: String(raw.name || 'Imported architecture spec').slice(0, 200) });
    core.syncModel(m, raw);
    core.generateThreats(m);
    return m;
  }
  return loadModel(raw);
}

async function openModel() {
  if (!(await confirmDiscard())) return;
  const f = await pickFile('.json,.stride.json,application/json');
  if (!f) return;
  try {
    store.setModel(modelFromText(f.text), { fileName: f.name });
    requestAnimationFrame(() => ui.canvas.zoomToFit());
    toast(`Opened ${f.name}`);
  } catch (e) {
    toast(`Could not open ${f.name}: ${e.message}`, 5000);
  }
}

async function saveModel(saveAs = false) {
  const text = serializeModel(store.model) + '\n';
  const suggested = store.fileName || `${slug(store.model.meta.name)}.stride.json`;
  if (window.showSaveFilePicker) {
    try {
      let handle = !saveAs && store.fileHandle;
      if (!handle) {
        handle = await window.showSaveFilePicker({ suggestedName: suggested, types: [{ description: 'STRIDE threat model', accept: { 'application/json': ['.json'] } }] });
      }
      const w = await handle.createWritable();
      await w.write(text);
      await w.close();
      store.fileHandle = handle;
      store.fileName = handle.name;
      store.dirty = false;
      store.autosave();
      renderTopbar();
      toast(`Saved ${handle.name}`);
      return;
    } catch (e) {
      if (e?.name === 'AbortError') return;
      // Fall back to download below.
    }
  }
  downloadText(suggested, text, 'application/json');
  store.fileName = suggested;
  store.dirty = false;
  renderTopbar();
}

async function importTemplate() {
  const f = await pickFile('.tb7,.json,application/json,text/xml');
  if (!f) return;
  try {
    const tpl = parseTemplateText(f.text);
    const ok = await confirmDialog(
      'Apply template',
      `Apply “${tpl.manifest.name}” (${tpl.threatTypes.length} threat types, ${tpl.elements.length} element types) to this model? Threats are regenerated; your triage is kept.`,
      'Apply',
    );
    if (!ok) return;
    store.commit((m) => applyTemplate(m, tpl), { immediate: true });
    store.emit('template');
    toast(`Template “${tpl.manifest.name}” applied.`);
  } catch (e) {
    toast(`Could not import template: ${e.message}`, 5000);
  }
}

function exportReport(kind, font) {
  const m = store.model;
  const base = slug(m.meta.name);
  if (kind === 'html') openBlob(renderHtmlReport(m, { font }));
  else if (kind === 'html-download') downloadText(`${base}-report.html`, renderHtmlReport(m, { font }), 'text/html');
  else if (kind === 'exec') openBlob(renderExecutiveReport(m, { font }));
  else if (kind === 'exec-download') downloadText(`${base}-executive-summary.html`, renderExecutiveReport(m, { font }), 'text/html');
  else if (kind === 'md') downloadText(`${base}-report.md`, renderMarkdownReport(m), 'text/markdown');
  else if (kind === 'csv') downloadText(`${base}-threats.csv`, threatsToCsv(m), 'text/csv');
  else if (kind === 'svg') downloadText(`${base}-${slug(store.diagram.name)}.svg`, renderDiagramSvg(m, store.diagram, { sketch: store.prefs.sketch }), 'image/svg+xml');
}

/** Choose the report type and the font, then open or download it. */
async function reportDialog() {
  const types = [
    { value: 'exec', label: 'Executive summary — large print, plain language (for senior management)', fonts: true },
    { value: 'html', label: 'Technical report — every threat, with evidence', fonts: true },
    { value: 'md', label: 'Markdown summary', fonts: false },
    { value: 'csv', label: 'Threat list (CSV)', fonts: false },
    { value: 'svg', label: 'Current diagram (SVG)', fonts: false },
  ];
  const CUSTOM = '__custom';
  const typeSel = select(types.map(({ value, label }) => ({ value, label })), store.prefs.reportType || 'exec', null, { 'aria-label': 'Report type' });
  const fontSel = select([...Object.entries(REPORT_FONTS).map(([value, f]) => ({ value, label: f.label })), { value: CUSTOM, label: 'Other font installed on this computer…' }], store.prefs.reportFont || 'system', null, { 'aria-label': 'Font' });
  const custom = h('input', { type: 'text', placeholder: 'Font name, e.g. Segoe UI', maxlength: 40, 'aria-label': 'Custom font name', value: store.prefs.reportFontCustom || '' });
  const sample = h('p', { class: 'font-sample' }, 'The quick brown fox jumps over the lazy dog — 0123456789');
  const fontBox = h('div', null, field('Font', fontSel), h('div', { class: 'hidden', 'data-custom': '' }, field('Font name', custom)), sample);
  const customRow = fontBox.querySelector('[data-custom]');
  const chosenFont = () => {
    if (fontSel.value !== CUSTOM) return fontSel.value;
    return custom.value.trim() || 'system';
  };
  const refresh = () => {
    const t = types.find((x) => x.value === typeSel.value);
    fontBox.classList.toggle('hidden', !t.fonts);
    customRow.classList.toggle('hidden', fontSel.value !== CUSTOM);
    try {
      sample.style.fontFamily = resolveFont(chosenFont()).stack;
      sample.classList.remove('bad');
    } catch {
      sample.classList.add('bad');
    }
  };
  for (const el of [typeSel, fontSel, custom]) el.addEventListener('input', refresh);
  refresh();
  const choice = await modal({
    title: 'Download report',
    content: h('div', null, field('Report', typeSel), fontBox, h('p', { class: 'small muted' }, 'Fonts are used by the reader’s computer, so pick one that is installed where the report will be opened. Reports can be printed or saved as PDF from the browser.')),
    buttons: [
      { label: 'Cancel', value: null },
      { label: 'Open in new tab', value: 'open' },
      { label: 'Download', value: 'download', class: 'primary' },
    ],
  });
  if (!choice) return;
  const type = typeSel.value;
  let font;
  if (types.find((x) => x.value === type).fonts) {
    try {
      font = resolveFont(chosenFont()).id === 'custom' ? chosenFont() : fontSel.value;
    } catch (e) {
      return toast(e.message, 5000);
    }
    Object.assign(store.prefs, { reportType: type, reportFont: fontSel.value, reportFontCustom: custom.value });
    store.savePrefs();
  }
  const kind = type === 'exec' || type === 'html' ? (choice === 'open' ? type : `${type}-download`) : type;
  exportReport(kind, font);
}

async function renameModel() {
  const name = await promptDialog('Rename model', 'Model name', store.model.meta.name);
  if (name && name.trim()) store.commit((m) => (m.meta.name = name.trim()));
}

// ------------------------------------------------------------ diagrams
async function newDiagram() {
  const d = store.commit((m) => addDiagram(m));
  store.setDiagram(d.id);
}
async function renameDiagramUi(d) {
  const name = await promptDialog('Rename diagram', 'Diagram name', d.name);
  if (name && name.trim()) store.commit(() => (d.name = name.trim()));
}
async function deleteDiagramUi(d) {
  if (store.model.diagrams.length < 2) return toast('A model needs at least one diagram.');
  if (!(await confirmDialog('Delete diagram', `Delete diagram “${d.name}” and its ${d.elements.length} element(s)?`, 'Delete', true))) return;
  store.commit((m) => removeDiagram(m, d.id), { immediate: true });
  store.setDiagram(store.model.diagrams[0].id);
}

// ------------------------------------------------------------ dialogs
function shortcutsDialog() {
  const rows = [
    ['V / 1', 'Select'],
    ['H, Space+drag', 'Pan'],
    ['P / 2', 'Process'],
    ['E / 3', 'External interactor'],
    ['D / 4', 'Data store'],
    ['F / 5', 'Data flow (drag from source to target)'],
    ['L / 6', 'Trust boundary — arc'],
    ['B / 7', 'Trust boundary — box'],
    ['T / 8', 'Annotation'],
    ['Double-click / Enter', 'Rename'],
    ['Delete / Backspace', 'Delete selection'],
    [`${MOD}C, ${MOD}V, ${MOD}D`, 'Copy, paste, duplicate (Alt-drag also duplicates)'],
    [`${MOD}Z, ${MOD}⇧Z`, 'Undo, redo'],
    [`${MOD}A`, 'Select all'],
    ['Arrows (⇧ for 20px)', 'Nudge'],
    ['Wheel, ⇧Wheel', 'Pan'],
    [`${MOD}Wheel, +, −`, 'Zoom'],
    ['⇧1', 'Zoom to fit'],
    ['G, ⇧G (or ' + MOD + 'G, ' + MOD + '⇧G)', 'Group, ungroup selection'],
    ['/', 'Search stencils (floating box when the stencil pane is hidden)'],
    [`${MOD}.`, 'Focus mode: hide every menu (Esc exits)'],
    [`${MOD}S`, 'Save'],
  ];
  modal({ title: 'Keyboard shortcuts', content: h('table', { class: 'kbd-table' }, rows.map(([k, v]) => h('tr', null, h('td', null, k), h('td', null, v)))) });
}

function aboutDialog() {
  modal({
    title: 'About STRIDE Threat Modeler',
    content: h(
      'div',
      null,
      h('p', null, 'A client-first threat modeling tool with the data flow diagram, template and STRIDE rule engine semantics of the Microsoft Threat Modeling Tool, drawn on an Excalidraw-style canvas.'),
      h('p', null, 'Everything runs locally in your browser: no account, no server, no telemetry. Models autosave to this browser; use Save to keep a file.'),
      h('p', null, 'Microsoft Threat Modeling Tool templates (.tb7) can be imported from File → Import template. The same engine is available as a CLI and an MCP server: ', h('code', null, 'npx stride mcp'), '.'),
      h('p', { class: 'small muted' }, 'Generated threats are a starting point for expert review, not a guarantee of security.'),
    ),
  });
}

// ------------------------------------------------------------ top bar
function renderTopbar() {
  const { model } = store;
  const tabs = h(
    'div',
    { class: 'dtabs', role: 'tablist', 'aria-label': 'Diagrams' },
    model.diagrams.map((d) => {
      const b = h(
        'button',
        {
          class: 'dtab',
          type: 'button',
          role: 'tab',
          'aria-selected': String(d.id === store.activeDiagramId),
          title: 'Double-click to rename, right-click to delete',
          onClick: () => store.setDiagram(d.id),
          onDblclick: () => renameDiagramUi(d),
        },
        d.name,
      );
      b.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        deleteDiagramUi(d);
      });
      return b;
    }),
    h('button', { class: 'btn small', type: 'button', title: 'Add diagram', 'aria-label': 'Add diagram', onClick: newDiagram }, icon('plus', 15)),
  );
  const viewSeg = h(
    'div',
    { class: 'seg', role: 'group', 'aria-label': 'View' },
    [
      ['design', 'Design'],
      ['analyze', 'Analyze'],
    ].map(([v, label]) => h('button', { type: 'button', 'aria-pressed': String(store.view === v), onClick: () => setView(v) }, label)),
  );
  const fileMenu = menu('File', 'menu', [
    { label: 'New model', run: newModel },
    { label: 'Open… (model or architecture spec)', kbd: `${MOD}O`, run: openModel },
    { label: 'Save', kbd: `${MOD}S`, run: () => saveModel(false) },
    { label: 'Save as…', kbd: `${MOD}⇧S`, run: () => saveModel(true) },
    '-',
    { label: 'Open example model', run: openSample },
    '-',
    { label: 'Import template (.tb7 / .json)…', run: importTemplate },
    { label: 'Template & rules…', run: () => ui.openTemplate() },
    '-',
    { label: 'Rename model…', run: renameModel },
    { label: 'Rename diagram…', run: () => renameDiagramUi(store.diagram) },
    { label: 'Delete diagram…', run: () => deleteDiagramUi(store.diagram) },
  ]);
  const reportMenu = menu('Report', 'report', [
    { label: 'Download report… (type and font)', run: reportDialog },
    '-',
    { label: 'Open executive summary (for management)', run: () => exportReport('exec') },
    { label: 'Open full report (HTML)', run: () => exportReport('html') },
    { label: 'Download full report (HTML)', run: () => exportReport('html-download') },
    { label: 'Download Markdown summary', run: () => exportReport('md') },
    { label: 'Export threats to CSV', run: () => exportReport('csv') },
    { label: 'Export diagram as SVG', run: () => exportReport('svg') },
  ]);
  const openDoc = (rel) => window.open(rel, '_blank', 'noopener');
  const helpMenu = menu('Help', 'book', [
    { label: 'Learn threat modeling (start here)', run: () => openDoc('learn/index.html') },
    { label: 'How to use this tool', run: () => openDoc('how-to/index.html') },
    { label: 'What is STRIDE, and why it matters', run: () => openDoc('what-is/index.html') },
    { label: 'Worked examples (web app, microservices, IVR…)', run: () => openDoc('how-to-max/index.html') },
    { label: 'Practice scenarios', run: () => openDoc('practice/index.html') },
    { label: 'Thinking like an attacker', run: () => openDoc('think/index.html') },
    '-',
    { label: 'Keyboard shortcuts', kbd: '?', run: shortcutsDialog },
  ]);
  const settingsMenu = menu('', store.prefs.theme === 'dark' ? 'moon' : 'sun', () => [
    { label: `Theme: ${store.prefs.theme}`, run: cycleTheme },
    { label: 'Focus on diagram (hide all menus)', kbd: `${MOD}.`, run: toggleFocus },
    { label: `Grid: ${store.prefs.grid ? 'on' : 'off'}`, run: () => togglePref('grid') },
    { label: `Hand-drawn style: ${store.prefs.sketch ? 'on' : 'off'}`, run: () => togglePref('sketch') },
    { label: `Keep tool after drawing: ${store.prefs.toolLock ? 'on' : 'off'}`, run: () => togglePref('toolLock') },
    '-',
    { label: 'Keyboard shortcuts', kbd: '?', run: shortcutsDialog },
    { label: 'About', run: aboutDialog },
  ], 'Settings');
  clear(topbar).append(
    h('button', { class: 'btn show-sm', type: 'button', 'aria-label': 'Stencils', onClick: () => app.classList.toggle('show-palette') }, icon('menu')),
    h('button', { class: 'btn hide-sm', type: 'button', title: store.prefs.paletteCollapsed ? 'Show stencils' : 'Hide stencils', 'aria-label': 'Toggle stencils', 'aria-pressed': String(!store.prefs.paletteCollapsed), onClick: togglePalette }, icon('menu')),
    h('div', { class: 'brand' }, h('img', { src: 'assets/logo-64.png', alt: '', width: 28, height: 28 }), h('span', { class: 'hide-sm' }, 'STRIDE'), h('button', { class: 'btn model-name', type: 'button', title: 'Rename model', onClick: renameModel }, model.meta.name + (store.dirty && store.fileName ? ' •' : ''))),
    fileMenu,
    h('div', { class: 'sep hide-sm' }),
    tabs,
    h('div', { class: 'spacer' }),
    viewSeg,
    h('button', { class: 'btn', type: 'button', title: `Focus on diagram (${MOD}.)`, 'aria-label': 'Focus on diagram', onClick: toggleFocus }, icon('fit')),
    h('button', { class: 'btn', type: 'button', title: `Undo (${MOD}Z)`, 'aria-label': 'Undo', disabled: !store.undoStack.length || undefined, onClick: () => store.undo() }, icon('undo')),
    h('button', { class: 'btn', type: 'button', title: `Redo (${MOD}⇧Z)`, 'aria-label': 'Redo', disabled: !store.redoStack.length || undefined, onClick: () => store.redo() }, icon('redo')),
    reportMenu,
    helpMenu,
    h('button', { class: 'btn hide-sm', type: 'button', title: store.prefs.inspectorCollapsed ? 'Show threat model panel' : 'Hide threat model panel', 'aria-label': 'Toggle threat model panel', 'aria-pressed': String(!store.prefs.inspectorCollapsed), onClick: toggleInspector }, icon('panel')),
    h('button', { class: 'btn hide-sm', type: 'button', title: 'Show/hide threat panel', 'aria-label': 'Toggle threat panel', onClick: () => ui.drawer.toggle() }, icon('chevron')),
    settingsMenu,
    h('button', { class: 'btn show-sm', type: 'button', 'aria-label': 'Properties', onClick: () => app.classList.toggle('show-inspector') }, icon('panel')),
  );
}

function setView(v) {
  store.setView(v);
  app.dataset.view = v;
  renderTopbar();
  if (v === 'analyze') ui.drawer.show('threats');
  requestAnimationFrame(() => ui.canvas.requestRender());
}
function cycleTheme() {
  const order = ['auto', 'light', 'dark'];
  store.prefs.theme = order[(order.indexOf(store.prefs.theme) + 1) % order.length];
  store.savePrefs();
  applyTheme();
  renderTopbar();
}
function togglePref(k) {
  store.prefs[k] = !store.prefs[k];
  store.savePrefs();
  ui.canvas.requestRender();
}

store.on('model', (d) => !d?.preview && renderTopbar());
store.on('selection', () => {
  if (store.selection.size) app.classList.remove('show-palette');
});
store.on('notice', (msg) => toast(msg, 6000));
renderTopbar();

window.addEventListener('keydown', (e) => {
  const mod = e.metaKey || e.ctrlKey;
  const k = e.key.toLowerCase();
  if (mod && k === 's') {
    e.preventDefault();
    saveModel(e.shiftKey);
  } else if (mod && k === 'o') {
    e.preventDefault();
    openModel();
  } else if (mod && e.key === '.') {
    e.preventDefault();
    toggleFocus();
  } else if (e.key === 'Escape' && app.classList.contains('focus') && !document.querySelector('dialog[open]') && !['INPUT', 'TEXTAREA'].includes(document.activeElement?.tagName)) {
    setFocus(false);
  } else if (e.key === '?' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName) && !document.querySelector('dialog[open]')) {
    shortcutsDialog();
  }
});
window.addEventListener('beforeunload', () => store.autosave());

// First run: show the example so the canvas is not empty.
let seen = false;
try {
  seen = !!localStorage.getItem('stride:seen');
  localStorage.setItem('stride:seen', '1');
} catch {
  seen = true;
}
if (!store.model.diagrams.some((d) => d.elements.length) && !seen) {
  store.setModel(createSampleModel());
  requestAnimationFrame(() => ui.canvas.zoomToFit());
}

// Expose for debugging and automated UI checks.
window.__stride = { store, ui, core };

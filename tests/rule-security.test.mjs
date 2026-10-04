import test from 'node:test';
import assert from 'node:assert/strict';
import { evalCond, interpolate, syncThreats, threatList } from '../js/engine.js';
import { validateRules } from '../js/rules.js';
import { store, normalizeModel } from '../js/store.js';
import { sampleModel } from '../js/sample.js';
import { initThreatPanel } from '../js/panels.js';
import { createReport, buildMarkdown } from '../js/reports.js';
import { buildReport, exportCSV, readModelFile } from '../js/io.js';
import { pdfDefinition } from '../js/pdf-report.js';
import { esc } from '../js/util.js';
import { updateThreat, effectiveThreatStatus } from '../js/threats.js';

test('resolver refuses inherited and dangerous properties in both conditions and interpolation', () => {
  const props = Object.create({ inherited: 'secret' }); props.own = 'visible';
  const ctx = { source: { name: 'Alice', props }, target: null };
  for (const path of ['source.__proto__.name', 'source.constructor.name', 'source.props.prototype.x', 'source.props.inherited', 'source.props.toString', 'target.name']) {
    assert.equal(evalCond([path, 'exists', true], ctx), false, path);
    assert.equal(interpolate(`{${path}}`, ctx), `{${path}}`);
  }
  for (const segment of ['__proto__', 'prototype', 'constructor']) {
    Object.defineProperty(props, segment, { get() { throw new Error('Blocked getter reached'); } });
    assert.doesNotThrow(() => interpolate(`{source.props.${segment}}`, ctx));
  }
  assert.equal(interpolate('{source.name}: {source.props.own}', ctx), 'Alice: visible');
  assert.equal(evalCond(['source.props.own', 'eq', 'visible'], ctx), true);
  assert.equal(evalCond(['source.name', 'eq', 'inherited'], Object.create({ source: { name: 'inherited' } })), false);
});

const payload = '<img src=x onerror=alert(1)>';
function hostileModel() {
  const m = normalizeModel(sampleModel());
  m.diagrams[0].elements.find((e) => e.type === 'external').name = payload;
  m.template = validateRules([{ id: 'UNTRUSTED', category: 'T', dedupeKey: 'target',
    title: '{source.name} " autofocus onfocus="alert(1)',
    description: '</textarea><script>alert(1)</script> {source.name}',
    mitigation: '<svg onload=alert(1)> {source.name}',
    when: [['source.type', 'eq', 'external']],
  }]);
  syncThreats(m);
  return m;
}

function pendingReviewModel() {
  const m = hostileModel(), t = threatList(m)[0];
  updateThreat(t, 'status', 'mitigated'); updateThreat(t, 'notes', 'Keep reviewed evidence');
  const diagram = m.diagrams.find((d) => d.id === t.diagramId);
  const flow = diagram.elements.find((e) => e.id === t.contributingFlows[0].id);
  diagram.elements.push({ ...structuredClone(flow), id: 'new-review-flow', name: payload });
  syncThreats(m);
  return m;
}

test('pending review notice escapes new flow names and the panel can confirm the unchanged status', () => {
  const nodes = new Map(), oldDocument = globalThis.document, oldModel = store.model, oldUI = store.ui, oldCommit = store.commit;
  const listeners = new Set(store.listeners);
  globalThis.document = { querySelector: (selector) => {
    if (!nodes.has(selector)) nodes.set(selector, { innerHTML: '', handlers: {}, addEventListener(name, fn) { this.handlers[name] = fn; }, showModal() {} });
    return nodes.get(selector);
  } };
  try {
    store.model = pendingReviewModel();
    const t = threatList(store.model)[0];
    store.ui = { ...oldUI, diagramId: t.diagramId, analysis: true, activeThreat: t.key };
    // Replace the persistence/history boundary; use the real panel handler,
    // updateThreat, regeneration and change notification.
    store.commit = (source = '') => { syncThreats(store.model); store.emit('change', { source }); };
    initThreatPanel({}).render();
    for (const selector of ['#threat-list', '#threat-editor']) {
      const html = nodes.get(selector).innerHTML;
      assert.ok(html.includes(`New flows since review: ${esc(payload)}`));
      assert.ok(html.includes('Recorded status: Mitigated'));
      assert.doesNotMatch(html, /<img\b|<script\b/i);
    }
    assert.match(nodes.get('#threat-list').innerHTML, /data-s="Open">Open/);
    assert.ok(nodes.get('#threat-editor').innerHTML.includes('Keep reviewed evidence'));
    nodes.get('#threat-editor').handlers.click({ target: { closest: () => ({ dataset: { t: 'review-flows' } }) } });
    assert.equal(t.needsReview, false); assert.equal(effectiveThreatStatus(t), 'mitigated');
    assert.ok(t.reviewedFlowIds.includes('new-review-flow'));
    assert.doesNotMatch(nodes.get('#threat-editor').innerHTML, /New flows since review/);
  } finally {
    globalThis.document = oldDocument; store.model = oldModel; store.ui = oldUI; store.commit = oldCommit; store.listeners = listeners;
  }
});

test('review notices remain inert in every export, including CSV', async () => {
  const m = pendingReviewModel(), bundle = createReport(m);
  const html = buildReport(m), md = buildMarkdown(bundle);
  assert.ok(html.includes(`New flows since review: ${esc(payload)}`));
  assert.ok(md.includes('New flows since review:'));
  for (const output of [html, md]) assert.doesNotMatch(output, /<img\b|<script\b/i);
  assert.ok(JSON.stringify(pdfDefinition(bundle).content).includes(`New flows since review: ${payload}`));
  const oldDocument = globalThis.document, oldURL = URL.createObjectURL; let blob;
  try {
    URL.createObjectURL = (value) => { blob = value; return 'blob:test'; };
    globalThis.document = { body: { appendChild() {} }, createElement: () => ({ click() {}, remove() {} }) };
    exportCSV(m);
    const csv = await blob.text();
    assert.ok(csv.includes(`New flows since review: ${payload}`));
    assert.ok(csv.includes('"Mitigated","New flows since review:'));
    assert.ok(csv.includes('"Open"'));
  } finally { globalThis.document = oldDocument; URL.createObjectURL = oldURL; }
});

test('actual panel HTML sinks escape interpolated names and imported rule text', () => {
  // Capture exactly the markup assigned by the real panel. This verifies sink
  // escaping under Node; tests/security.html additionally checks browser DOMs.
  const nodes = new Map(), oldDocument = globalThis.document, oldModel = store.model, oldUI = store.ui;
  const listeners = new Set(store.listeners);
  globalThis.document = { querySelector: (selector) => {
    if (!nodes.has(selector)) nodes.set(selector, { innerHTML: '', addEventListener() {}, showModal() {} });
    return nodes.get(selector);
  } };
  try {
    store.model = hostileModel();
    const t = threatList(store.model).find((t) => t.title.includes(payload));
    store.ui = { ...oldUI, diagramId: store.model.diagrams[0].id, analysis: true, activeThreat: t.key };
    initThreatPanel({}).render();
    for (const selector of ['#threat-list', '#threat-editor']) {
      const html = nodes.get(selector).innerHTML;
      assert.ok(html.includes(esc(payload)), selector);
      assert.doesNotMatch(html, /<img\b|<script\b|<svg\s+onload/i);
      assert.doesNotMatch(html, /" autofocus onfocus="alert/);
    }
    assert.ok(nodes.get('#threat-editor').innerHTML.includes(esc(t.description)));
    assert.ok(nodes.get('#threat-editor').innerHTML.includes(esc(t.mitigationHint)));
  } finally { globalThis.document = oldDocument; store.model = oldModel; store.ui = oldUI; store.listeners = listeners; }
});

test('HTML, SVG, Markdown and PDF treat imported text as data; JSON round-trips it unchanged', async () => {
  const m = hostileModel(), bundle = createReport(m), html = buildReport(m), md = buildMarkdown(bundle);
  assert.ok(html.includes(esc(payload)));
  for (const output of [html, md, bundle.report.diagrams[0].image.svg]) {
    assert.doesNotMatch(output, /<img\b|<script\b|<svg\s+onload/i);
  }
  const definition = pdfDefinition(bundle);
  const strings = [];
  const walk = (node) => {
    if (typeof node === 'string') strings.push(node);
    else if (Array.isArray(node)) node.forEach(walk);
    else if (node && typeof node === 'object') {
      for (const forbidden of ['link', 'attachment', 'image']) assert.ok(!Object.hasOwn(node, forbidden));
      Object.values(node).forEach(walk);
    }
  };
  walk(definition.content);
  assert.ok(strings.some((s) => s.includes(payload)), 'PDF keeps malicious-looking names as literal text');
  assert.deepEqual(await readModelFile({ name: 'report.json', text: async () => JSON.stringify(bundle) }), m);
});

test('CSV neutralizes formulas in untrusted threat text', async () => {
  const m = hostileModel(); threatList(m)[0].title = '=HYPERLINK("https://example.test","click")';
  const oldDocument = globalThis.document, oldURL = URL.createObjectURL; let blob;
  try {
    URL.createObjectURL = (value) => { blob = value; return 'blob:test'; };
    globalThis.document = { body: { appendChild() {} }, createElement: () => ({ click() {}, remove() {} }) };
    exportCSV(m);
    assert.ok((await blob.text()).includes('"\'=HYPERLINK('));
  } finally { globalThis.document = oldDocument; URL.createObjectURL = oldURL; }
});

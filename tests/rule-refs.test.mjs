import test from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_RULES, validateRules } from '../js/rules.js';
import { generateThreats, syncThreats, threatList } from '../js/engine.js';
import { store, normalizeModel } from '../js/store.js';
import { updateThreat } from '../js/threats.js';
import { sampleModel } from '../js/sample.js';
import { initThreatPanel } from '../js/panels.js';
import { createReport, buildMarkdown, threatDetails } from '../js/reports.js';
import { buildReport, readModelFile, serializeModel } from '../js/io.js';
import { buildPDF, pdfDefinition } from '../js/pdf-report.js';
import { esc } from '../js/util.js';

function fixture(mode = 'flow') {
  const model = sampleModel();
  const diagram = model.diagrams[0];
  diagram.elements.push({ ...structuredClone(diagram.elements.find((e) => e.id === 'f_1')), id: 'second-request', name: 'Second request' });
  model.template = [{ id: 'REFS', category: 'T', priority: 'High',
    scope: mode === 'element' ? 'element' : 'interaction',
    focus: mode === 'element' ? 'element' : 'target',
    ...(mode === 'source' || mode === 'target' ? { dedupeKey: mode } : {}),
    title: mode === 'element' ? 'Review {element.name}' : 'Review {target.name}',
    description: 'Review the modeled control.', mitigation: 'Verify the control and record evidence.',
    when: [[mode === 'element' ? 'element.type' : 'source.type', 'eq', mode === 'element' ? 'process' : 'external']],
  }];
  return model;
}

test('refs are optional and valid boundary lengths remain unchanged by validation', () => {
  for (const refs of [undefined, ['OWASP-LLM01'], ['CWE-79', 'ATLAS AML.T0051'], Array(8).fill('x'.repeat(40)), ['  CWE-79  ', 'Ω'.repeat(40)]]) {
    const model = fixture();
    if (refs !== undefined) model.template[0].refs = refs;
    const before = structuredClone(model.template);
    assert.equal(validateRules(model.template), model.template);
    assert.deepEqual(model.template, before);
    syncThreats(model);
    for (const t of threatList(model)) {
      if (refs === undefined) assert.ok(!Object.hasOwn(t, 'refs'));
      else assert.deepEqual(t.refs, refs);
    }
    assert.doesNotThrow(() => normalizeModel(model));
  }
});

for (const [name, refs] of [
  ['null', null], ['undefined field', undefined], ['string', 'CWE-79'], ['number', 3], ['boolean', true], ['object', {}],
  ['empty array', []], ['too many entries', Array(9).fill('CWE-79')], ['empty string', ['']],
  ['whitespace only', [' \t\n']], ['too long', ['x'.repeat(41)]], ['null entry', [null]],
  ['undefined entry', [undefined]], ['number entry', [79]], ['boolean entry', [false]],
  ['object entry', [{}]], ['nested array', [['CWE-79']]], ['sparse array', Array(2)],
  ['mixed valid/invalid', ['CWE-79', '']],
]) test(`refs validation rejects ${name} with the rule ID`, () => {
  const model = fixture(); model.template[0].refs = refs;
  const rejects = (error) => /Rule REFS: refs/.test(error.message) && /1-8/.test(error.message) && /40/.test(error.message);
  assert.throws(() => validateRules(model.template), rejects);
  assert.throws(() => normalizeModel(model), rejects);
  // Saved threat metadata is untrusted too; it need not come from a rule in
  // the currently active template (manual, orphaned and historical records).
  delete model.template[0].refs; syncThreats(model);
  threatList(model)[0].refs = refs;
  assert.throws(() => normalizeModel(model), /Invalid threat refs/);
});

test('A01–A16 carry OWASP 2025 references and the ATLAS inversion/extraction techniques', () => {
  const expected = {
    A01: ['OWASP-LLM01'], A02: ['OWASP-LLM01'], A03: ['OWASP-LLM05'], A04: ['OWASP-LLM07'],
    A05: ['OWASP-LLM06'], A06: ['OWASP-LLM02'], A07: ['OWASP-LLM10'], A08: ['OWASP-LLM08'],
    A09: ['OWASP-LLM04', 'OWASP-LLM08'], A10: ['OWASP-LLM08'], A11: ['OWASP-LLM04'], A12: ['OWASP-LLM02'],
    A13: ['OWASP-LLM03'], A14: ['OWASP-LLM10', 'ATLAS AML.T0024.001', 'ATLAS AML.T0024.002'],
    A15: ['OWASP-LLM06'], A16: ['OWASP-LLM09'],
  };
  assert.equal(validateRules(DEFAULT_RULES), DEFAULT_RULES);
  for (const [id, refs] of Object.entries(expected)) assert.deepEqual(DEFAULT_RULES.find((r) => r.id === id).refs, refs, id);
});

for (const mode of ['flow', 'source', 'target', 'element']) test(`${mode}: adding, replacing and removing refs preserves threat identities and all reviews`, async () => {
  const model = fixture(mode), rule = model.template[0];
  syncThreats(model);
  for (const t of threatList(model)) {
    for (const [field, value] of Object.entries({ status: 'mitigated', notes: 'Test evidence', mitigation: 'Verified control', owner: 'AppSec', justification: 'All current paths checked', severity: 'Low', title: 'Reviewed title', description: 'Reviewed description' })) updateThreat(t, field, value);
  }
  const fields = ['id', 'key', 'created', 'modified', 'status', 'state', 'notes', 'mitigation', 'owner', 'justification', 'severity', 'title', 'description', 'customText', 'reviewedFlowIds', 'needsReview', 'contributingFlows'];
  const reviews = () => threatList(model).map((t) => Object.fromEntries(fields.map((field) => [field, t[field]])));
  const before = structuredClone(reviews()), nextId = model.nextThreatId;
  const generatedBefore = generateThreats(model);
  for (const refs of [['OWASP-LLM01', 'CWE-79'], ['ATLAS AML.T0051'], undefined]) {
    if (refs === undefined) delete rule.refs; else rule.refs = refs;
    validateRules(model.template); syncThreats(model);
    assert.deepEqual(reviews(), before);
    assert.equal(model.nextThreatId, nextId);
    assert.ok(threatList(model).every((t) => !t.orphan));
    for (const t of threatList(model)) {
      if (refs === undefined) assert.ok(!Object.hasOwn(t, 'refs'));
      else { assert.deepEqual(t.refs, refs); assert.notEqual(t.refs, refs); }
    }
    assert.deepEqual(generateThreats(model).map(({ refs: omitted, ...t }) => t), generatedBefore);
    const saved = JSON.parse(serializeModel(model));
    assert.deepEqual(await readModelFile({ name: 'review.stride', text: async () => JSON.stringify(saved) }), saved);
  }
});

test('references are copied as literal metadata without interpolation or shared rule arrays', () => {
  const model = fixture(); model.template[0].refs = ['{source.name}', 'CWE-79'];
  const generated = generateThreats(model);
  assert.equal(generated.length, 2);
  assert.deepEqual(generated[0].refs, model.template[0].refs);
  generated[0].refs.push('LOCAL-ONLY');
  assert.deepEqual(model.template[0].refs, ['{source.name}', 'CWE-79']);
  assert.deepEqual(generated[1].refs, ['{source.name}', 'CWE-79']);
});

test('refs refresh without acknowledging new flows; orphaned reviews retain their last references', () => {
  const model = fixture('target'); model.template[0].refs = ['CWE-79']; syncThreats(model);
  const t = threatList(model)[0]; updateThreat(t, 'status', 'accepted'); updateThreat(t, 'notes', 'Prior assessment');
  const diagram = model.diagrams[0], original = diagram.elements.find((e) => e.id === 'f_1');
  diagram.elements.push({ ...structuredClone(original), id: 'new-path', name: 'New path' }); syncThreats(model);
  assert.equal(t.needsReview, true);
  const coverage = [...t.reviewedFlowIds];
  model.template[0].refs = ['OWASP-LLM05']; syncThreats(model);
  assert.equal(t.needsReview, true); assert.deepEqual(t.reviewedFlowIds, coverage);
  assert.equal(t.status, 'accepted'); assert.equal(t.notes, 'Prior assessment');
  for (const e of diagram.elements) if (e.type === 'flow') e.outOfScope = true;
  syncThreats(model); assert.equal(t.orphan, true); assert.deepEqual(t.refs, ['OWASP-LLM05']);
});

function renderDetail(model) {
  const nodes = new Map(), oldDocument = globalThis.document, oldModel = store.model, oldUI = store.ui;
  const listeners = new Set(store.listeners);
  globalThis.document = { querySelector: (selector) => {
    if (!nodes.has(selector)) nodes.set(selector, { innerHTML: '', addEventListener() {}, showModal() {} });
    return nodes.get(selector);
  } };
  try {
    store.model = model;
    const t = threatList(model)[0];
    store.ui = { ...oldUI, diagramId: t.diagramId, analysis: true, activeThreat: t.key };
    initThreatPanel({}).render();
    return nodes.get('#threat-editor').innerHTML;
  } finally { globalThis.document = oldDocument; store.model = oldModel; store.ui = oldUI; store.listeners = listeners; }
}

test('hostile refs stay text in the actual detail panel, Markdown, HTML and PDF, and round-trip in JSON', async () => {
  const refs = ['<img src=ref onerror=alert(1)>', '[link](https://example.test)', '![img](https://example.test/x)', '</textarea><script>bad()</script>'];
  const model = fixture('target'); model.template[0].refs = refs;
  validateRules(model.template); syncThreats(model);
  const panel = renderDetail(model), bundle = createReport(model), html = buildReport(model), md = buildMarkdown(bundle);
  for (const output of [panel, html]) {
    assert.match(output, /References/);
    for (const ref of refs) assert.ok(output.includes(esc(ref)), ref);
    assert.doesNotMatch(output, /<img\b|<script\b|<a\b/i);
  }
  assert.ok(md.includes('**References:**'));
  assert.doesNotMatch(md, /<img\b|<script\b|\[link\]\(|!\[img\]\(/i);
  assert.ok(md.includes('\\[link\\]\\(https://example\\.test\\)'));
  assert.ok(md.includes('&lt;img src=ref onerror=alert\\(1\\)&gt;'));
  const definition = pdfDefinition(bundle), strings = [];
  const walk = (value) => {
    if (typeof value === 'string') strings.push(value);
    else if (Array.isArray(value)) value.forEach(walk);
    else if (value && typeof value === 'object') {
      for (const key of ['link', 'attachment', 'image']) assert.ok(!Object.hasOwn(value, key));
      Object.values(value).forEach(walk);
    }
  };
  walk(definition.content);
  assert.ok(strings.includes('References: '));
  assert.ok(strings.includes(refs.join(', ')), 'PDF stores references in a literal text node');
  const pdf = await buildPDF(bundle);
  assert.equal(Buffer.from(pdf).subarray(0, 4).toString(), '%PDF');
  assert.deepEqual(await readModelFile({ name: 'report.json', text: async () => JSON.stringify(bundle) }), bundle.model);
});

test('templates and saved threats without refs retain their prior output without an empty reference field', async () => {
  const model = fixture(); syncThreats(model);
  const bundle = createReport(model);
  for (const t of threatList(model)) {
    assert.ok(!Object.hasOwn(t, 'refs'));
    assert.ok(!threatDetails(t).some(([label]) => label === 'References'));
  }
  assert.doesNotMatch(renderDetail(model), /References:/);
  assert.doesNotMatch(buildReport(model), /<dt>References<\/dt>/);
  assert.doesNotMatch(buildMarkdown(bundle), /\*\*References:\*\*/);
  assert.deepEqual(await readModelFile({ name: 'legacy.stride', text: async () => serializeModel(model) }), bundle.model);
});

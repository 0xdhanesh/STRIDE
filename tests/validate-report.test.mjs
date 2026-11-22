import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_TEMPLATE,
  addElement,
  createModel,
  generateThreats,
  normalizeTemplate,
  renderDiagramSvg,
  renderHtmlReport,
  renderMarkdownReport,
  suppressMessage,
  threatsToCsv,
  updateThreat,
  validateModel,
} from '../src/core/index.js';

const issues = (m) => validateModel(m).map((x) => x.issue);

test('validation finds unconnected flows, missing boundaries and DFD rule breaks', () => {
  const m = createModel({ template: DEFAULT_TEMPLATE });
  const a = addElement(m, null, { type: 'external', name: 'A', x: 0, y: 0 });
  const b = addElement(m, null, { type: 'external', name: 'B', x: 400, y: 0 });
  const s1 = addElement(m, null, { type: 'store', name: 'S1', x: 0, y: 300 });
  const s2 = addElement(m, null, { type: 'store', name: 'S2', x: 400, y: 300 });
  addElement(m, null, { type: 'process', name: 'Lonely', x: 800, y: 300 });
  addElement(m, null, { type: 'flow', source: a.id, target: b.id });
  addElement(m, null, { type: 'flow', source: s1.id, target: s2.id });
  addElement(m, null, { type: 'flow', source: a.id, target: s1.id });
  addElement(m, null, { type: 'flow', source: a.id });
  const found = issues(m);
  for (const i of ['flow.unconnected', 'flow.ei-ei', 'flow.ds-ds', 'flow.ei-ds', 'element.isolated', 'diagram.no-boundaries', 'external.no-boundary']) {
    assert.ok(found.includes(i), `expected ${i} in ${found}`);
  }
  const unconnected = validateModel(m).find((x) => x.issue === 'flow.unconnected');
  assert.equal(unconnected.mtmt, '102BE8A5-2C83-439A-9157-F7C7E9AC1321');
});

test('partial boundary coverage and duplicate arcs are reported', () => {
  const m = createModel({ template: DEFAULT_TEMPLATE });
  const a = addElement(m, null, { type: 'external', name: 'A', x: 0, y: 200 });
  const p = addElement(m, null, { type: 'process', name: 'P', x: 400, y: 200 });
  addElement(m, null, { type: 'flow', source: a.id, target: p.id, bend: -120 });
  addElement(m, null, { type: 'flow', source: p.id, target: a.id, bend: -120 });
  // A short arc that cuts only the first (upper) flow.
  addElement(m, null, { type: 'SE.TB.L.TMCore.Internet', x0: 270, y0: 60, x1: 270, y1: 160 });
  assert.ok(issues(m).includes('boundary.partial'));
  addElement(m, null, { type: 'SE.TB.L.TMCore.Internet', x0: 290, y0: 60, x1: 290, y1: 160 });
  assert.ok(issues(m).includes('flow.multiple-arc'));
});

test('messages can be suppressed and stay suppressed', () => {
  const m = createModel({ template: DEFAULT_TEMPLATE });
  addElement(m, null, { type: 'process', name: 'P' });
  const msg = validateModel(m).find((x) => x.issue === 'element.isolated');
  suppressMessage(m, msg.id);
  assert.equal(validateModel(m).find((x) => x.id === msg.id).suppressed, true);
});

test('rule errors in templates surface as validation errors', () => {
  const tpl = normalizeTemplate(DEFAULT_TEMPLATE);
  tpl.threatTypes.push({ id: 'BAD', title: 'bad', category: 'S', include: "source is 'GE.P' and", exclude: '', description: '', mitigation: '', priority: '', properties: {}, references: [] });
  const m = createModel({ template: tpl });
  const a = addElement(m, null, { type: 'process' });
  const b = addElement(m, null, { type: 'process' });
  addElement(m, null, { type: 'flow', source: a.id, target: b.id });
  const errs = validateModel(m).filter((x) => x.issue === 'rule.error');
  assert.equal(errs.length, 1);
  assert.match(errs[0].message, /BAD/);
});

function hostileModel() {
  const m = createModel({ template: DEFAULT_TEMPLATE, name: '<script>alert(1)</script>' });
  const a = addElement(m, null, { type: 'external', name: '<img src=x onerror=alert(1)>', x: 0, y: 0 });
  const b = addElement(m, null, { type: 'process', name: '=HYPERLINK("http://evil")', x: 400, y: 0 });
  addElement(m, null, { type: 'flow', source: a.id, target: b.id, name: '"><svg onload=alert(1)>' });
  m.notes.push({ id: 'n', text: '<b>note</b>', author: '<i>x</i>', date: '' });
  generateThreats(m);
  updateThreat(m, m.threats[0].key, { justification: '</p><script>x</script>' });
  return m;
}

test('HTML report and SVG escape all model text', () => {
  const m = hostileModel();
  const html = renderHtmlReport(m);
  assert.ok(!/<script>alert|<img src=x|<svg onload|<b>note|<script>x/.test(html), 'no raw markup from the model');
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
  const svg = renderDiagramSvg(m, m.diagrams[0]);
  assert.ok(!svg.includes('<img') && !svg.includes('<svg onload'));
});

test('CSV export neutralizes spreadsheet formulas and quotes fields', () => {
  const csv = threatsToCsv(hostileModel());
  assert.ok(!/(^|,)=HYPERLINK/m.test(csv));
  assert.ok(csv.split('\r\n')[0].startsWith('ID,Diagram'));
});

test('Markdown report escapes table metacharacters', () => {
  const m = createModel({ template: DEFAULT_TEMPLATE, name: 'a|b' });
  assert.match(renderMarkdownReport(m), /^# a\\\|b/);
});

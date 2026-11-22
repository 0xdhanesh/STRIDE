import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_TEMPLATE,
  ModelError,
  addElement,
  applyTemplate,
  changeType,
  createModel,
  effectiveProperties,
  generateThreats,
  kbOf,
  lineGeometry,
  loadModel,
  normalizeTemplate,
  removeElements,
  serializeModel,
  setProperties,
  updateThreat,
} from '../src/core/index.js';

const fresh = () => createModel({ template: DEFAULT_TEMPLATE, name: 'T' });

test('attribute inheritance: static overrides from the type, dynamic defaults to first value', () => {
  const m = fresh();
  const flow = addElement(m, null, { type: 'SE.DF.TMCore.HTTPS' });
  const props = effectiveProperties(kbOf(m), flow);
  assert.equal(props.get('providesConfidentiality'), 'Yes');
  assert.equal(props.get('authenticatesSource'), 'Not Selected');
  assert.equal(props.get('Cookies'), 'Yes');
  assert.throws(() => setProperties(m, flow, { providesConfidentiality: 'No' }), /fixed by type/);
  assert.throws(() => setProperties(m, flow, { JSON: 'Maybe' }), /Invalid value/);
  setProperties(m, flow, { 'JSON Payload': 'Yes' }); // by label
  assert.equal(flow.props.JSON, 'Yes');
});

test('flows must connect nodes; types resolve by id, alias or name', () => {
  const m = fresh();
  const p = addElement(m, null, { type: 'process', name: 'P' });
  const s = addElement(m, null, { type: 'SQL Database', name: 'S' });
  const a = addElement(m, null, { type: 'annotation', name: 'note' });
  assert.equal(s.typeId, 'SE.DS.TMCore.SQL');
  assert.throws(() => addElement(m, null, { type: 'flow', source: p.id, target: a.id }), /process, external interactor or data store/);
  const f = addElement(m, null, { type: 'flow', source: 'P', target: 'S' });
  assert.equal(f.target, s.id);
  assert.throws(() => addElement(m, null, { type: 'nope' }), ModelError);
});

test('auto-placement avoids overlaps', () => {
  const m = fresh();
  const a = addElement(m, null, { type: 'process' });
  const b = addElement(m, null, { type: 'process' });
  assert.ok(a.x !== b.x || a.y !== b.y);
});

test('change type stays within the family and drops invalid values', () => {
  const m = fresh();
  const p = addElement(m, null, { type: 'GE.P', props: { codeType: 'Unmanaged' } });
  changeType(m, p, 'SE.P.TMCore.NetApp');
  assert.deepEqual(p.props, {});
  assert.throws(() => changeType(m, p, 'GE.DS'), /different element family/);
});

test('removing a shape detaches flows (loose connector) unless cascading', () => {
  const m = fresh();
  const a = addElement(m, null, { type: 'process', x: 0, y: 0 });
  const b = addElement(m, null, { type: 'process', x: 400, y: 0 });
  const f = addElement(m, null, { type: 'flow', source: a.id, target: b.id });
  removeElements(m, [b.id]);
  assert.equal(f.target, undefined);
  assert.ok(f.x1 > 300, 'loose end keeps its last position');
  removeElements(m, [a.id], { cascade: true });
  assert.equal(m.diagrams[0].elements.length, 0);
});

test('flow endpoints sit on the shape perimeter', () => {
  const m = fresh();
  const a = addElement(m, null, { type: 'external', x: 0, y: 0, w: 100, h: 60 });
  const b = addElement(m, null, { type: 'process', x: 400, y: 0, w: 100, h: 60 });
  const f = addElement(m, null, { type: 'flow', source: a.id, target: b.id });
  const g = lineGeometry(m, m.diagrams[0], f);
  assert.ok(Math.abs(g.p0.x - 102) < 1, `source edge ${g.p0.x}`);
  assert.ok(Math.abs(g.p1.x - 396) < 1, `target edge ${g.p1.x}`);
});

test('round trip through JSON preserves the model', () => {
  const m = fresh();
  const a = addElement(m, null, { type: 'process', name: 'A' });
  const b = addElement(m, null, { type: 'external', name: 'B' });
  addElement(m, null, { type: 'flow', source: b.id, target: a.id, name: 'f' });
  generateThreats(m);
  assert.ok(m.threats.length > 0);
  updateThreat(m, m.threats[0].key, { state: 'NotApplicable', justification: 'n/a' });
  const back = loadModel(serializeModel(m));
  assert.deepStrictEqual(JSON.parse(serializeModel(back)), JSON.parse(serializeModel(m)));
});

test('loading untrusted JSON drops prototype-polluting keys and invalid references', () => {
  const m = fresh();
  const a = addElement(m, null, { type: 'process', name: 'A' });
  const raw = JSON.parse(serializeModel(m));
  raw.diagrams[0].elements[0].props = JSON.parse('{"__proto__": {"polluted": "yes"}, "codeType": "Managed"}');
  raw.diagrams[0].elements.push({ id: '__proto__', typeId: 'GE.P', x: 0, y: 0, w: 1, h: 1 });
  raw.diagrams[0].elements.push({ id: 'f1', typeId: 'GE.DF', source: a.id, target: 'missing' });
  raw.threats.push({ key: 'k', state: 'Bogus' });
  const back = loadModel(raw);
  assert.equal({}.polluted, undefined);
  assert.equal(Object.getPrototypeOf(back.diagrams[0].elements[0].props), Object.prototype);
  assert.equal(back.diagrams[0].elements.some((e) => e.id === '__proto__'), false);
  assert.equal(back.diagrams[0].elements.find((e) => e.id === 'f1').target, undefined);
  assert.equal(back.threats[0].state, 'NotStarted');
  assert.throws(() => loadModel({ format: 'other' }), /Not a STRIDE model/);
});

test('templates are validated on load', () => {
  assert.throws(() => normalizeTemplate({ elements: [] }), /missing generic element/);
});

test('applyTemplate falls back to generic types for unknown element types', () => {
  const m = fresh();
  const s = addElement(m, null, { type: 'SE.DS.TMCore.SQL' });
  const tpl = normalizeTemplate(DEFAULT_TEMPLATE);
  tpl.elements = tpl.elements.filter((e) => e.id !== 'SE.DS.TMCore.SQL');
  applyTemplate(m, tpl);
  assert.equal(s.typeId, 'GE.DS');
});

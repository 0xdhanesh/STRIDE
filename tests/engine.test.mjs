// Run with: node tests/engine.test.mjs
import assert from 'node:assert/strict';
import { sampleModel } from '../js/sample.js';
import { syncThreats, threatList, validate, generateThreats, evalCond } from '../js/engine.js';
import { DEFAULT_RULES, validateRules } from '../js/rules.js';

validateRules(DEFAULT_RULES);

assert.equal(evalCond([['a', 'eq', 1], { any: [['b', 'eq', 2], ['c', 'eq', 3]] }], { a: 1, c: 3 }), true);
assert.equal(evalCond({ not: ['a', 'eq', 1] }, { a: 1 }), false);
assert.equal(evalCond([['x.props.k', 'ne', 'Yes']], { x: { props: {} } }), true);

const m = sampleModel();
syncThreats(m);
const list = threatList(m);
assert.ok(list.length > 20, `expected many threats, got ${list.length}`);
// Boundary crossing: Customer -> Web crosses the VNet box, Web -> API does not.
const keys = Object.keys(m.threats);
assert.ok(keys.some((k) => k.includes('|f_1|D02')), 'f_1 crosses boundary');
assert.ok(!keys.some((k) => k.includes('|f_3|D02')), 'f_3 does not cross boundary');
// Encrypted flow -> no sniffing threat; SQL DB -> injection threat.
assert.ok(!keys.some((k) => k.includes('|f_1|I01')));
assert.ok(keys.some((k) => k.includes('|f_4|T03')));
// Unresolved placeholders should not remain.
for (const t of list) assert.ok(!/\{[a-z]+\.[a-z.]+\}/i.test(t.title + t.description), `placeholder left in ${t.title}`);

// Edits survive regeneration; untouched stale threats disappear; edited become orphans.
const t = m.threats[keys.find((k) => k.includes('|f_1|S01'))];
t.state = 'Mitigated'; t.justification = 'MFA enforced';
const id = t.id;
syncThreats(m);
assert.equal(m.threats[t.key].id, id);
m.diagrams[0].elements = m.diagrams[0].elements.filter((e) => e.id !== 'f_1');
syncThreats(m);
assert.equal(m.threats[t.key].orphan, true);
assert.ok(!Object.keys(m.threats).some((k) => k.includes('|f_1|') && k !== t.key));

// Out-of-scope target suppresses its threats.
const m2 = sampleModel();
m2.diagrams[0].elements.find((e) => e.id === 's_db').outOfScope = true;
assert.ok(!generateThreats(m2).some((g) => g.elementId === 's_db'));

console.log('validation:', validate(sampleModel()).map((x) => x.text));
console.log(`OK – ${list.length} threats in sample`);

// Curved trust-boundary lines count as crossings too.
{
  const m = sampleModel();
  const d = m.diagrams[0];
  d.elements = d.elements.filter((e) => e.type !== 'boundary');
  d.elements.push({ id: 'bl', type: 'boundaryLine', name: 'Edge', x1: 280, y1: 0, x2: 280, y2: 600, bend: 20, props: {}, style: {} });
  const keys = generateThreats(m).map((g) => g.key);
  assert.ok(keys.some((k) => k.endsWith('|f_1|D02')), 'flow crossing a boundary line is boundary-crossing');
  assert.ok(!keys.some((k) => k.endsWith('|f_3|D02')), 'flow not crossing the line is not');
  console.log('OK – boundary line crossing');
}

// Technology-specific rules and orthogonal anchoring.
{
  const { lineGeom } = await import('../js/util.js');
  const { defaultProps } = await import('../js/stencils.js');
  const n = (id, type, subtype, x, y, w = 130, h = 130) => ({ id, type, name: id, subtype, x, y, w, h, props: defaultProps(type), style: {} });
  const f = (id, s, t) => ({ id, type: 'flow', name: id, subtype: 'MCP (JSON-RPC)', sourceId: s, targetId: t, bend: 0, props: defaultProps('flow'), style: {} });
  const m = { diagrams: [{ id: 'd', elements: [
    n('mcp', 'process', 'MCP Server', 0, 0), n('agent', 'process', 'AI Agent / LLM App', 300, 40),
    n('kafka', 'store', 'Kafka Topic / Event Log', 300, 400, 190, 70), n('caller', 'external', 'Phone Caller (PSTN)', -400, 0, 160, 80),
    n('ivr', 'process', 'IVR System', -200, 0), n('pod', 'process', 'Kubernetes Pod', 600, 0),
    f('f1', 'mcp', 'agent'), f('f2', 'agent', 'mcp'), f('f3', 'agent', 'kafka'), f('f4', 'caller', 'ivr'),
  ] }], threats: {} };
  const rules = new Set(generateThreats(m).map((g) => g.ruleId));
  for (const r of ['M01', 'M02', 'M03', 'K01', 'K02', 'V01', 'V03', 'C01']) assert.ok(rules.has(r), `rule ${r} fires`);

  // Shapes overlapping vertically → horizontal connector (same y at both ends).
  const byId = new Map(m.diagrams[0].elements.map((e) => [e.id, e]));
  const g = lineGeom(byId.get('f1'), byId);
  assert.ok(Math.abs(g.s.y - g.t.y) < 0.01, 'horizontal connector');
  assert.ok(g.s.x > 129 && g.t.x < 301, 'ends sit on the shape outlines');
  console.log('OK – technology rules & orthogonal anchors');
}

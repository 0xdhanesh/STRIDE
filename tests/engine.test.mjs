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

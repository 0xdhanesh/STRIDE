import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createModel, DEFAULT_TEMPLATE, addElement, flowColor, entityColor, groupElements, ungroupElements, expandGroups, lineGeometry, loadModel, serializeModel, renderDiagramSvg, updateElement } from '../src/core/index.js';

function hub() {
  const m = createModel({ template: DEFAULT_TEMPLATE, name: 't' });
  const d = m.diagrams[0];
  const a = addElement(m, d.id, { type: 'GE.P', name: 'A', x: 0, y: 200, w: 130, h: 90 });
  const b = addElement(m, d.id, { type: 'GE.P', name: 'B', x: 500, y: 0, w: 130, h: 90 });
  const c = addElement(m, d.id, { type: 'GE.P', name: 'C', x: 500, y: 200, w: 130, h: 90 });
  const e = addElement(m, d.id, { type: 'GE.P', name: 'E', x: 500, y: 400, w: 130, h: 90 });
  const f1 = addElement(m, d.id, { type: 'GE.DF', name: 'one', source: a.id, target: b.id });
  const f2 = addElement(m, d.id, { type: 'GE.DF', name: 'two', source: a.id, target: c.id });
  const f3 = addElement(m, d.id, { type: 'GE.DF', name: 'three', source: a.id, target: e.id });
  const back1 = addElement(m, d.id, { type: 'GE.DF', name: 'back1', source: b.id, target: a.id });
  const back2 = addElement(m, d.id, { type: 'GE.DF', name: 'back2', source: c.id, target: a.id });
  return { m, d, a, b, c, e, f1, f2, f3, back1, back2 };
}

test('egress from one entity shares a start port; ingress ports are all separate', () => {
  const { m, d, f1, f2, f3, back1, back2 } = hub();
  const g = (f) => lineGeometry(m, d, f);
  assert.deepEqual(g(f1).p0, g(f2).p0);
  assert.deepEqual(g(f2).p0, g(f3).p0);
  const ends = [g(back1).p1, g(back2).p1];
  assert.notDeepEqual(ends[0], ends[1]);
  const aIngress = [g(back1).p1, g(back2).p1, g(f1).p0];
  for (let i = 0; i < aIngress.length; i++) for (let j = i + 1; j < aIngress.length; j++) assert.ok(Math.hypot(aIngress[i].x - aIngress[j].x, aIngress[i].y - aIngress[j].y) > 8 || (i === 2 || j === 2));
});

test('flows of one entity share its colour; different entities differ; overrides win', () => {
  const { m, d, a, b, f1, f2, back1 } = hub();
  assert.equal(flowColor(d, f1), flowColor(d, f2));
  assert.equal(flowColor(d, f1), entityColor(d, a));
  assert.notEqual(flowColor(d, f1), flowColor(d, back1));
  updateElement(m, f1.id, { color: '#112233' });
  assert.equal(flowColor(d, f1), '#112233');
  assert.ok(renderDiagramSvg(m, d).includes('--flow:#112233'));
  assert.throws(() => updateElement(m, f1.id, { color: 'red;x' }));
  updateElement(m, f1.id, { color: '' });
  assert.equal(flowColor(d, f1), entityColor(d, a));
});

test('different entities never run flows on top of each other', () => {
  const { m, d, back1, back2 } = hub();
  const p1 = lineGeometry(m, d, back1).points;
  const p2 = lineGeometry(m, d, back2).points;
  for (const p of p1) for (let i = 0; i < p2.length; i++) assert.ok(Math.hypot(p.x - p2[i].x, p.y - p2[i].y) > 1 || i === p2.length - 1);
});

test('groups: group, expand, ungroup, and persist through save/load; bad colours are dropped', () => {
  const { m, d, a, b, c } = hub();
  assert.throws(() => groupElements(m, d.id, [a.id]));
  const gid = groupElements(m, d.id, [a.id, b.id]);
  assert.deepEqual([...expandGroups(d, [a.id])].sort(), [a.id, b.id].sort());
  const gid2 = groupElements(m, d.id, [b.id, c.id]);
  assert.notEqual(gid, gid2);
  assert.equal(a.groupId, gid2);
  a.color = '#abcdef';
  const m2 = loadModel(serializeModel(m));
  const a2 = m2.diagrams[0].elements.find((e) => e.id === a.id);
  assert.equal(a2.groupId, gid2);
  assert.equal(a2.color, '#abcdef');
  const raw = JSON.parse(serializeModel(m));
  raw.diagrams[0].elements.find((e) => e.id === a.id).color = 'url(x)';
  assert.equal(loadModel(raw).diagrams[0].elements.find((e) => e.id === a.id).color, undefined);
  assert.equal(ungroupElements(m, d.id, [c.id]), 3);
  assert.equal(d.elements.filter((e) => e.groupId).length, 0);
});

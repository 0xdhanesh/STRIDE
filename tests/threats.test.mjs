import test from 'node:test';
import assert from 'node:assert/strict';
import { STATUSES, STATUS_LABELS, threatStatus, threatSeverity, updateThreat, matchesThreat } from '../js/threats.js';
import { syncThreats, threatList, threatStats, threatBadges, isOpen } from '../js/engine.js';
import { Store, store, normalizeModel, newModel } from '../js/store.js';
import { sampleModel } from '../js/sample.js';
import { STRIDE } from '../js/stencils.js';
import { serializeModel, readModelFile, buildReport } from '../js/io.js';
import { renderThreatSummary } from '../js/summary.js';
import { makeElement } from '../js/ops.js';
import { initPropsPanel, initThreatPanel } from '../js/panels.js';

function model() {
  const m = normalizeModel(sampleModel());
  syncThreats(m);
  return m;
}

test('properties View and canvas badges agree for an entity with a boundary-crossing flow', () => {
  const m = newModel(), diagram = m.diagrams[0];
  const entity = makeElement(m, 'external', { x: 0, y: 0 });
  const process = makeElement(m, 'process', { x: 400, y: 0 });
  const boundary = makeElement(m, 'boundary', { x: 250, y: -150 }, { w: 300, h: 300 });
  const flow = makeElement(m, 'flow', { x: 0, y: 0 });
  Object.assign(flow, { sourceId: entity.id, targetId: process.id, x2: 400 });
  diagram.elements.push(entity, process, boundary, flow); syncThreats(m);
  const spoofing = threatList(m).find((t) => t.ruleId === 'S01');
  assert.ok(spoofing); assert.equal(spoofing.elementId, entity.id); assert.equal(spoofing.flowId, flow.id);
  assert.ok(threatList(m).some((t) => t.ruleId === 'S02'), 'Fixture must cross a boundary');
  m.threats.orphan = { ...structuredClone(spoofing), key: 'orphan', id: m.nextThreatId++, orphan: true };

  // Exercise the real renderers and View handler; substitute only DOM nodes.
  const nodes = new Map(), oldDocument = globalThis.document, oldWidth = globalThis.innerWidth;
  const oldModel = store.model, oldUI = store.ui, listeners = new Set(store.listeners);
  globalThis.innerWidth = 1200;
  globalThis.document = { querySelector: (selector) => {
    if (!nodes.has(selector)) nodes.set(selector, {
      innerHTML: '', handlers: {}, querySelectorAll: () => [],
      addEventListener(name, handler) { this.handlers[name] = handler; }, showModal() {},
    });
    return nodes.get(selector);
  } };
  try {
    store.model = m;
    store.ui = { ...structuredClone(oldUI), diagramId: diagram.id, selection: new Set([entity.id]), analysis: false,
      filter: { text: '', status: '', severity: '', category: '', scope: 'all' }, activeThreat: spoofing.key };
    const props = initPropsPanel({}), threats = initThreatPanel({});
    for (const element of [entity, process, flow]) {
      store.ui.selection = new Set([element.id]); props.render();
      const count = Number(/class="threat-sum"><span>(\d+) threat/.exec(nodes.get('#props').innerHTML)?.[1]);
      assert.ok(count > 0, `${element.type} must have threats`);
      nodes.get('#props').handlers.click({ target: { closest: () => ({ dataset: { a: 'show-threats' } }) } });
      const list = nodes.get('#threat-list').innerHTML;
      assert.equal((list.match(/role="listitem"/g) || []).length, count, element.type);
      assert.ok(!list.includes('data-key="orphan"'));
      assert.equal(threatBadges(m, diagram.id).get(element.id).total, count, element.type);
    }
    store.ui.selection = new Set([entity.id, flow.id]); threats.render();
    const list = nodes.get('#threat-list').innerHTML;
    assert.equal(list.split(`data-key="${spoofing.key}"`).length - 1, 1, 'Selecting both endpoints must not duplicate a threat');
    assert.match(nodes.get('#threat-editor').innerHTML, new RegExp(`Threat #${spoofing.id}.*S01`));
    spoofing.ruleId = '<img src=x onerror=alert(1)>'; threats.render();
    assert.match(nodes.get('#threat-editor').innerHTML, /&lt;img src=x onerror=alert\(1\)&gt;/);
    assert.doesNotMatch(nodes.get('#threat-editor').innerHTML, /<img\b/);
  } finally {
    globalThis.document = oldDocument;
    if (oldWidth === undefined) delete globalThis.innerWidth; else globalThis.innerWidth = oldWidth;
    store.model = oldModel; store.ui = oldUI; store.listeners = listeners;
  }
});

test('badges count each threat once for every related element and contributing flow', () => {
  const base = { id: 1, key: 'related', diagramId: 'd', status: 'open', severity: 'Low', flowId: 'f1', elementId: 'entity',
    contributingFlows: [{ id: 'f1' }, { id: 'f2' }, { id: 'f2' }] };
  const m = { threats: {
    related: base,
    pending: { id: 2, key: 'pending', diagramId: 'd', status: 'mitigated', needsReview: true, severity: 'High', flowId: 'f2', elementId: 'entity' },
    closed: { id: 3, key: 'closed', diagramId: 'd', status: 'mitigated', severity: 'High', flowId: 'f1', elementId: 'f1' },
    orphan: { ...base, id: 4, key: 'orphan', orphan: true },
    hidden: { ...base, id: 5, key: 'hidden', suppressed: true },
    history: { ...base, id: 6, key: 'history', reviewMergedInto: 'related' },
    elsewhere: { ...base, id: 7, key: 'elsewhere', diagramId: 'other' },
  } };
  assert.deepEqual(threatBadges(m, 'd'), new Map([
    ['f1', { total: 2, open: 1, high: false }],
    ['entity', { total: 2, open: 2, high: true }],
    ['f2', { total: 2, open: 2, high: true }],
  ]));
});

test('new threats start open with review fields and rule-based severity', () => {
  const m = model();
  for (const t of Object.values(m.threats)) {
    assert.equal(t.status, 'open'); assert.equal(isOpen(t), true);
    assert.equal(t.severity, t.priority);
    for (const field of ['notes', 'owner', 'mitigation']) assert.equal(t[field], '');
  }
});

test('legacy states and priorities remain lossless and map to the four displayed statuses', async () => {
  const m = model();
  const states = ['Not Started', 'Needs Investigation', 'Mitigated', 'Not Applicable', 'Accepted'];
  const expected = ['open', 'open', 'mitigated', 'not-applicable', 'accepted'];
  Object.values(m.threats).forEach((t, i) => {
    delete t.status; delete t.severity; delete t.notes; delete t.owner;
    t.state = states[i % states.length]; t.justification = 'Original decision';
    assert.equal(threatStatus(t), expected[i % states.length]);
    assert.equal(threatSeverity(t), t.priority);
  });
  const saved = serializeModel(m);
  const loaded = await readModelFile({ name: 'old.stride.json', text: async () => saved });
  assert.deepEqual(loaded, m);
  const t = Object.values(loaded.threats)[1];
  updateThreat(t, 'status', 'accepted');
  assert.equal(t.legacyState, 'Needs Investigation');
  assert.equal(t.state, 'Accepted');
  assert.equal(t.justification, 'Original decision');
  updateThreat(t, 'status', 'open');
  assert.equal(t.legacyState, 'Needs Investigation');
});

test('all threats can be mitigated with notes, saved and reopened intact', async () => {
  const m = model();
  for (const t of Object.values(m.threats)) {
    for (const [field, value] of Object.entries({ status: 'mitigated', notes: 'Verified 2026-10-03\nEvidence: Bank-42', owner: 'Payments Security', mitigation: 'mTLS + input validation', severity: 'High' })) {
      updateThreat(t, field, value);
    }
  }
  syncThreats(m);
  const copy = await readModelFile({ name: 'bank.stride', text: async () => serializeModel(m) });
  assert.deepEqual(copy, m);
  assert.equal(threatStats(Object.values(copy.threats)).open, 0);
  assert.equal(threatStats(Object.values(copy.threats)).byStatus.mitigated, Object.keys(copy.threats).length);
  for (const badge of threatBadges(copy, copy.diagrams[0].id).values()) assert.equal(badge.open, 0);
});

test('all four statuses and review-only edits survive regeneration and removed interactions', () => {
  const m = model();
  const threats = Object.values(m.threats).filter((t) => t.flowId === 'f_1');
  const kept = [];
  for (const [i, t] of threats.slice(0, 4).entries()) {
    updateThreat(t, 'status', STATUSES[i]); kept.push(t);
  }
  // Notes/owner/severity alone also count as review work, even without a timestamp.
  const extra = threats.slice(4, 7);
  for (const [i, t] of extra.entries()) {
    if (i === 0) t.notes = 'Evidence';
    if (i === 1) t.owner = 'Reviewer';
    if (i === 2) t.severity = t.priority === 'Low' ? 'High' : 'Low';
    kept.push(t);
  }
  const before = new Map(kept.map((t) => [t.key, structuredClone(t)]));
  m.diagrams[0].elements = m.diagrams[0].elements.filter((e) => e.id !== 'f_1');
  syncThreats(m);
  for (const [key, t] of before) assert.deepEqual(m.threats[key], { ...t, orphan: true });
  for (const t of threats.slice(7)) assert.equal(m.threats[t.key], undefined);
  assert.ok(extra.length === 3, 'fixture must exercise all review-only fields');
});

test('dashboard counts every category/status across diagrams, including custom and orphaned threats', () => {
  const rows = STRIDE.flatMap((c, i) => STATUSES.map((status, j) => ({ category: c.key, status, severity: ['High', 'Medium', 'Low'][j % 3], diagramId: `d${i % 2}`, auto: j !== 0, orphan: j === 1 })));
  const stats = threatStats(rows);
  assert.equal(stats.total, 24); assert.equal(stats.open, 6); assert.equal(stats.orphaned, 6);
  for (const s of STATUSES) assert.equal(stats.byStatus[s], 6);
  for (const c of STRIDE) {
    assert.equal(stats.byCat[c.key], 4);
    for (const s of STATUSES) assert.equal(stats.byCatStatus[c.key][s], 1);
  }
  assert.equal(Object.values(stats.bySeverity).reduce((a, b) => a + b), 24);
  const html = renderThreatSummary(rows);
  for (const c of STRIDE) assert.ok(html.includes(c.name));
  for (const s of STATUSES) assert.ok(html.includes(STATUS_LABELS[s]));
  assert.match(html, /24 threats · 6 orphaned/);
  const empty = threatStats([]);
  for (const s of STATUSES) assert.equal(empty.byStatus[s], 0);
  assert.doesNotMatch(renderThreatSummary([]), /NaN|undefined/);
});

test('filters search review fields and use effective status and severity', () => {
  const t = { id: 42, category: 'T', state: 'Needs Investigation', priority: 'Low', notes: 'Evidence BANK-42', owner: 'Payments', mitigation: 'mTLS' };
  for (const text of ['bank-42', 'payments', 'MTLS', '#42']) assert.equal(matchesThreat(t, { text }), true);
  assert.equal(matchesThreat(t, { status: 'open', severity: 'Low', category: 'T' }), true);
  updateThreat(t, 'status', 'accepted'); updateThreat(t, 'severity', 'High');
  assert.equal(matchesThreat(t, { status: 'open' }), false);
  assert.equal(matchesThreat(t, { status: 'accepted', severity: 'High' }), true);
  assert.equal(t.priority, 'Low', 'original priority is retained separately');
});

test('review edits participate in store undo, redo and autosave', async () => {
  let snapshot;
  const autosave = { save: async (s) => { snapshot = s; } };
  const store = new Store({ autosave });
  store.replaceModel(model());
  const key = Object.keys(store.model.threats)[0];
  updateThreat(store.model.threats[key], 'status', 'accepted');
  updateThreat(store.model.threats[key], 'owner', 'Security');
  store.commit('threat-editor');
  assert.equal(JSON.parse(snapshot).threats[key].status, 'accepted');
  store.undo(); assert.equal(store.model.threats[key].status, 'open');
  store.redo(); assert.equal(store.model.threats[key].owner, 'Security');
  assert.equal(JSON.parse(snapshot).threats[key].status, 'accepted');
});

test('invalid review fields fail atomically and report fields are escaped', () => {
  const m = model(), t = Object.values(m.threats)[0];
  const before = structuredClone(t);
  for (const [field, value] of [['status', 'done'], ['severity', 'urgent'], ['owner', {}], ['category', 'X'], ['id', '2']]) {
    assert.throws(() => updateThreat(t, field, value)); assert.deepEqual(t, before);
  }
  updateThreat(t, 'owner', '<script>alert(1)</script>');
  updateThreat(t, 'notes', '<img src="https://example.test/">');
  updateThreat(t, 'status', 'accepted');
  const html = buildReport(m);
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(html.includes('&lt;img src=&quot;https://example.test/&quot;&gt;'));
  assert.doesNotMatch(html, /<script>|<img src="https/);
  assert.match(html, /Accepted/);
  const invalid = structuredClone(m); Object.values(invalid.threats)[0].status = 'done';
  assert.throws(() => normalizeModel(invalid), /status/);
});

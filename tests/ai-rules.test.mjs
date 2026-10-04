import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { DEFAULT_RULES, validateRules } from '../js/rules.js';
import { STENCILS, defaultProps } from '../js/stencils.js';
import { generateThreats, syncThreats, threatList, threatStats } from '../js/engine.js';
import { updateThreat, reviewNotice } from '../js/threats.js';
import { sampleModel } from '../js/sample.js';
import { createReport } from '../js/reports.js';

const AGENT = 'AI Agent / LLM App';
const rule = (id) => DEFAULT_RULES.find((r) => r.id === id);
const node = (id, type, subtype, x = 0, props = {}) => ({
  id, type, subtype, name: id, x, y: 0, w: 100, h: 100, style: {}, props: { ...defaultProps(type), ...props },
});
const flow = (id, sourceId, targetId, props = {}) => ({
  id, type: 'flow', subtype: 'Generic Data Flow', name: id, sourceId, targetId,
  x1: 0, y1: 0, x2: 400, y2: 0, bend: 0, style: {}, props: { ...defaultProps('flow'), ...props },
});
const modelFor = (elements) => ({
  diagrams: [{ id: 'diagram', name: 'AI fixture', elements }], threats: {}, nextThreatId: 1,
});
function pair(sourceType = 'external', sourceSubtype = 'Human User', targetType = 'process', targetSubtype = AGENT) {
  const source = node('source', sourceType, sourceSubtype), target = node('target', targetType, targetSubtype, 400);
  const request = flow('request', source.id, target.id);
  return { source, target, flow: request, model: modelFor([source, target, request]) };
}
function single(type, subtype, props = {}) {
  const element = node('element', type, subtype, 0, props);
  return { element, model: modelFor([element]) };
}
function boundary(f) {
  f.model.diagrams[0].elements.push({ id: 'zone', name: 'Agent zone', type: 'boundary', subtype: 'Internet Boundary', x: 350, y: -50, w: 200, h: 200, props: {}, style: {} });
}
const matches = (f, id) => generateThreats(f.model, [rule(id)]);
const fires = (f, id) => matches(f, id).length > 0;

// Rules without a control gate deliberately stay visible for review. Their
// negative fixture removes the architectural precondition, not a fictitious
// "safe" property such as input validation for prompt injection.
const cases = [
  ['A01', () => pair(), (f) => { Object.assign(f.source, node('source', 'process', 'Generic Process')); }],
  ['A02', () => pair('store', 'Vector Database'), (f) => { Object.assign(f.source, node('source', 'external', 'Human User')); }],
  ['A03', () => pair('process', AGENT, 'process', 'Generic Process'), (f) => { f.target.props.validatesInput = 'Yes'; }],
  ['A04', () => single('process', AGENT), (f) => { f.element.subtype = 'Generic Process'; }],
  ['A05', () => single('process', AGENT), (f) => { f.element.props.authorizesRequests = 'Yes'; }],
  ['A06', () => pair('process', AGENT, 'external', 'Human User'), (f) => { f.target.subtype = 'LLM Provider API'; }],
  ['A07', () => pair(), (f) => { f.flow.props.rateLimited = 'Yes'; }],
  ['A08', () => pair('store', 'Vector Database'), (f) => { f.source.props.accessControl = 'Fine-grained'; }],
  ['A09', () => pair('process', 'Background Worker', 'store', 'Vector Database'), (f) => { f.target.subtype = 'SQL Database'; }],
  ['A10', () => single('store', 'Vector Database', { storesPII: 'Yes' }), (f) => { f.element.props.storesPII = 'No'; }],
  ['A11', () => single('store', 'ML Model / Training Data'), (f) => { f.element.props.integrity = 'Yes'; }],
  ['A12', () => single('store', 'ML Model / Training Data'), (f) => { f.element.props.accessControl = 'Fine-grained'; }],
  ['A13', () => pair('store', 'ML Model / Training Data'), (f) => { f.flow.props.integrity = 'Yes'; }],
  ['A14', () => pair('external', 'Human User', 'process', 'ML Model Serving'), (f) => { f.flow.props.rateLimited = 'Yes'; f.target.props.authenticatesCallers = 'Yes'; }],
  ['A15', () => pair('external', 'MCP Client / AI Assistant', 'process', 'MCP Server'), (f) => { f.flow.props.authentication = 'Token (OAuth / JWT)'; }],
  ['A16', () => single('process', AGENT), (f) => { f.element.subtype = 'Generic Process'; }],
];

for (const [id, fixture, exclude] of cases) {
  test(`${id}: minimal matching DFD fires with interpolated text`, () => {
    const threats = matches(fixture(), id);
    assert.equal(threats.length, 1);
    const t = threats[0];
    for (const text of [t.title, t.description, t.mitigationHint]) {
      assert.ok(text.length > 0);
      assert.doesNotMatch(text, /\{(?:source|target|flow|element)\./);
      assert.doesNotMatch(text, /\n/);
    }
  });
  test(`${id}: safe control or excluded architecture does not fire`, () => {
    const f = fixture(); exclude(f);
    assert.equal(fires(f, id), false);
  });
}

test('AI template has the requested categories, severities, scopes and focus', () => {
  const expected = [
    ['A01', 'T', 'High', 'interaction', 'target', 'target'], ['A02', 'T', 'High', 'interaction', 'target', 'target'],
    ['A03', 'T', 'High', 'interaction', 'target'], ['A04', 'I', 'Medium', 'element', 'element'],
    ['A05', 'E', 'High', 'element', 'element'], ['A06', 'I', 'High', 'interaction', 'target'],
    ['A07', 'D', 'Medium', 'interaction', 'target', 'target'], ['A08', 'I', 'High', 'interaction', 'source', 'source'],
    ['A09', 'T', 'High', 'interaction', 'target', 'target'], ['A10', 'I', 'Medium', 'element', 'element'],
    ['A11', 'T', 'High', 'element', 'element'], ['A12', 'I', 'Medium', 'element', 'element'],
    ['A13', 'T', 'High', 'interaction', 'target'], ['A14', 'I', 'Medium', 'interaction', 'target', 'target'],
    ['A15', 'S', 'High', 'interaction', 'source'], ['A16', 'T', 'Low', 'element', 'element'],
  ];
  assert.deepEqual(DEFAULT_RULES.filter((r) => /^A\d+$/.test(r.id)).map((r) =>
    [r.id, r.category, r.priority, r.scope, r.focus, ...(r.dedupeKey ? [r.dedupeKey] : [])]), expected);
  assert.equal(DEFAULT_RULES.length, 97);
  assert.equal(validateRules(DEFAULT_RULES), DEFAULT_RULES);
});

function* clauses(condition) {
  if (Array.isArray(condition)) {
    if (typeof condition[0] === 'string') yield condition;
    else for (const child of condition) yield* clauses(child);
  } else if (condition && typeof condition === 'object') {
    for (const child of Object.values(condition)) yield* clauses(child);
  }
}
function assertKnownSubtypes(rules) {
  const known = new Set(Object.values(STENCILS).flatMap((s) => s.subtypes));
  let count = 0;
  for (const r of rules) for (const [path, op, value] of clauses(r.when)) {
    if (!path.endsWith('.subtype') || op === 'exists') continue;
    const values = ['in', 'nin'].includes(op) ? value : [value];
    for (const subtype of values) {
      assert.ok(known.has(subtype), `Rule ${r.id}: unknown stencil subtype ${JSON.stringify(subtype)} in ${path}`);
      count++;
    }
  }
  return count;
}
test('every subtype literal in every built-in rule exists in STENCILS', () => {
  assert.ok(assertKnownSubtypes(DEFAULT_RULES) > 0);
});
test('subtype guard catches typos inside AND/all/any/not and exclusion clauses', () => {
  for (const op of ['eq', 'ne', 'in', 'nin']) {
    const value = ['in', 'nin'].includes(op) ? ['MCP Sever'] : 'MCP Sever';
    const when = [{ all: [{ any: [{ not: ['source.subtype', op, value] }] }] }];
    assert.throws(() => assertKnownSubtypes([{ id: 'TYPO', when }]), /Rule TYPO: unknown stencil subtype "MCP Sever"/);
  }
});

test('A01 does not mistake input validation for a prompt-injection mitigation', () => {
  const f = pair(); f.target.props.validatesInput = 'Yes';
  assert.ok(fires(f, 'A01'));
  // Internal process inputs need a trust crossing; external inputs do not.
  Object.assign(f.source, node('source', 'process', 'Web Application'));
  assert.ok(!fires(f, 'A01')); boundary(f); assert.ok(fires(f, 'A01'));
});
test('A01 excludes provider and MCP responses even across a trust boundary', () => {
  for (const [type, subtype] of [['external', 'LLM Provider API'], ['process', 'MCP Server']]) {
    const f = pair(type, subtype); boundary(f);
    const all = generateThreats(f.model);
    assert.ok(!all.some((t) => t.ruleId === 'A01'));
    if (subtype === 'MCP Server') assert.ok(all.some((t) => t.ruleId === 'M01'));
  }
});
test('A02 covers stores and both third-party content sources without a boundary', () => {
  for (const [type, subtype] of [['store', 'File System'], ['external', 'Third-Party Service'], ['external', 'SaaS Application']]) {
    const f = pair(type, subtype); f.target.props.validatesInput = 'Yes';
    assert.ok(fires(f, 'A02'), subtype);
  }
  const f = pair('store', 'Vector Database'); f.target.subtype = 'Generic Process';
  assert.ok(!fires(f, 'A02'));
});
test('A03 checks both model producers and keeps browser sinks even with validation set', () => {
  for (const sourceSubtype of [AGENT, 'ML Model Serving']) {
    for (const [type, subtype] of [['external', 'Browser'], ['process', 'Browser Client (SPA)']]) {
      const f = pair('process', sourceSubtype, type, subtype); f.target.props.validatesInput = 'Yes';
      assert.ok(fires(f, 'A03'), `${sourceSubtype} -> ${subtype}`);
    }
  }
  assert.ok(!fires(pair('process', 'Generic Process', 'external', 'Browser'), 'A03'));
  assert.ok(!fires(pair('process', AGENT, 'external', 'Human User'), 'A03'));
});
test('A06 excludes provider-bound data while M04 still owns that interaction', () => {
  const f = pair('process', AGENT, 'external', 'LLM Provider API');
  const all = generateThreats(f.model);
  assert.ok(!all.some((t) => t.ruleId === 'A06'));
  assert.ok(all.some((t) => t.ruleId === 'M04'));
  f.target.type = 'process'; f.target.subtype = 'Generic Process';
  assert.ok(!fires(f, 'A06'));
});
test('A07 includes model serving and untrusted internal crossings but skips local internal calls', () => {
  for (const subtype of [AGENT, 'ML Model Serving']) {
    const f = pair('process', 'Generic Process', 'process', subtype);
    assert.ok(!fires(f, 'A07')); boundary(f); assert.ok(fires(f, 'A07'));
    f.flow.props.rateLimited = 'Yes'; assert.ok(!fires(f, 'A07'));
  }
});
test('A10 requires sensitive embeddings and is not suppressed by encryption at rest', () => {
  const f = single('store', 'Vector Database', { storesPII: 'Yes', encryptedAtRest: 'Yes' });
  assert.ok(fires(f, 'A10'));
  for (const value of ['No', 'Not Selected', undefined]) {
    f.element.props.storesPII = value; assert.ok(!fires(f, 'A10'));
  }
});
test('A13 covers both artefact sources and both model consumers', () => {
  for (const [type, subtype] of [['store', 'ML Model / Training Data'], ['external', 'Compromised Supply Chain']]) {
    for (const consumer of [AGENT, 'ML Model Serving']) {
      const f = pair(type, subtype, 'process', consumer);
      assert.ok(fires(f, 'A13')); f.flow.props.integrity = 'Yes'; assert.ok(!fires(f, 'A13'));
    }
  }
  assert.ok(!fires(pair('store', 'SQL Database'), 'A13'));
});
test('A14 requires both rate limits and caller authentication to suppress the prompt', () => {
  for (const rateLimited of ['No', 'Yes']) for (const authenticatesCallers of ['No', 'Yes']) {
    const f = pair('external', 'Human User', 'process', 'ML Model Serving');
    f.flow.props.rateLimited = rateLimited; f.target.props.authenticatesCallers = authenticatesCallers;
    assert.equal(fires(f, 'A14'), rateLimited !== 'Yes' || authenticatesCallers !== 'Yes');
  }
  assert.ok(!fires(pair('process', 'Generic Process', 'process', 'ML Model Serving'), 'A14'));
  assert.ok(!fires(pair(), 'A14'));
});
test('A15 covers absent/None authentication only for the specified MCP client/server pair', () => {
  const f = pair('external', 'MCP Client / AI Assistant', 'process', 'MCP Server');
  for (const value of ['Not Selected', 'None', undefined]) {
    f.flow.props.authentication = value; assert.ok(fires(f, 'A15'));
  }
  f.source.subtype = 'Human User'; assert.ok(!fires(f, 'A15'));
  f.source.subtype = 'MCP Client / AI Assistant'; f.target.subtype = AGENT; assert.ok(!fires(f, 'A15'));
});
test('A04, A09 and A16 remain review prompts when other controls are declared safe', () => {
  const f = single('process', AGENT, { validatesInput: 'Yes', authorizesRequests: 'Yes', handlesSecrets: 'No' });
  for (const id of ['A04', 'A16']) assert.ok(fires(f, id));
  const ingestion = pair('process', 'Background Worker', 'store', 'Vector Database');
  ingestion.target.props.integrity = 'Yes'; ingestion.target.props.accessControl = 'Fine-grained';
  ingestion.flow.props.integrity = 'Yes'; assert.ok(fires(ingestion, 'A09'));
});

for (const id of ['A01', 'A02', 'A07', 'A08', 'A09', 'A14']) test(`${id}: endpoint grouping retains all paths and reopens coverage for new flows`, () => {
  const f = cases.find(([key]) => key === id)[1]();
  f.model.diagrams[0].elements.push({ ...structuredClone(f.flow), id: 'second', name: 'second path' });
  const generated = matches(f, id);
  assert.equal(generated.length, 1); assert.equal(generated[0].contributingFlows.length, 2);
  assert.equal(generated[0].elementId, id === 'A08' ? f.source.id : f.target.id);
  f.model.template = [rule(id)]; syncThreats(f.model);
  const t = threatList(f.model)[0]; updateThreat(t, 'notes', 'Both paths reviewed'); updateThreat(t, 'status', 'mitigated');
  f.model.diagrams[0].elements.push({ ...structuredClone(f.flow), id: 'third', name: 'new path' }); syncThreats(f.model);
  assert.equal(threatList(f.model).length, 1); assert.equal(t.status, 'mitigated'); assert.equal(t.needsReview, true);
  assert.equal(threatStats([t]).open, 1); assert.match(reviewNotice(t), /new path/);
  updateThreat(t, 'status', 'mitigated'); assert.equal(t.needsReview, false); assert.equal(t.reviewedFlowIds.length, 3);
});

test('built-in example retains all 35 pre-AI findings, including text, keys and contributors', () => {
  // Captured from the 81-rule template before A01–A16 were introduced. Generated
  // findings have no timestamps, so this fingerprints the complete stable output.
  const preAIHash = 'a8d9ad9e1e41fac77a38820b55f675f0d4f261244016aa2fd87f97f57356b48e';
  const model = sampleModel(), threats = generateThreats(model);
  assert.equal(threats.length, 35);
  assert.equal(createHash('sha256').update(JSON.stringify(threats)).digest('hex'), preAIHash);
  assert.deepEqual(threats, generateThreats(model, DEFAULT_RULES.filter((r) => !/^A\d+$/.test(r.id))));
  syncThreats(model);
  assert.equal(threatList(model).length, 35);
  assert.ok(threatList(model).every((t) => !/^A\d+$/.test(t.ruleId)));
});

// This DFD mirrors GUIDE.md Exercise 5. It deliberately leaves controls unset
// except the sensitive-vector-store flag called out in the walkthrough.
function guideModel() {
  const elements = [
    node('analyst', 'external', 'Human User', -400), node('provider', 'external', 'LLM Provider API', -400),
    node('documents', 'external', 'Third-Party Service', -400), node('agent', 'process', AGENT),
    node('ingest', 'process', 'Background Worker'), node('mcp', 'process', 'MCP Server'),
    node('vector', 'store', 'Vector Database', 400, { storesPII: 'Yes' }), node('business', 'store', 'SQL Database', 400),
    { id: 'app-zone', name: 'Agent application zone', type: 'boundary', subtype: 'Process Boundary', x: -100, y: -50, w: 300, h: 250, props: {}, style: {} },
    { id: 'data-zone', name: 'Knowledge and business data zone', type: 'boundary', subtype: 'Corporate Network', x: 350, y: -50, w: 300, h: 250, props: {}, style: {} },
  ];
  for (const [id, source, target] of [
    ['question', 'analyst', 'agent'], ['documents-in', 'documents', 'ingest'], ['index', 'ingest', 'vector'],
    ['retrieval-query', 'agent', 'vector'], ['retrieved', 'vector', 'agent'], ['provider-request', 'agent', 'provider'], ['provider-output', 'provider', 'agent'],
    ['tool-call', 'agent', 'mcp'], ['business-query', 'mcp', 'business'], ['business-result', 'business', 'mcp'],
    ['tool-result', 'mcp', 'agent'], ['answer', 'agent', 'analyst'],
  ]) elements.push(flow(id, source, target));
  return modelFor(elements);
}
test('GUIDE Exercise 5: initial diagram has the stated rules, overlaps and exclusions', () => {
  const model = guideModel(), findings = generateThreats(model);
  const byRule = (id) => findings.filter((t) => t.ruleId === id);
  const paths = (id) => byRule(id).flatMap((t) => t.contributingFlows?.map((f) => f.id) || [t.flowId]);
  assert.deepEqual(new Set(paths('A01')), new Set(['question', 'retrieved']));
  assert.deepEqual(paths('A02'), ['retrieved']);
  assert.deepEqual(paths('A03'), ['tool-call']);
  for (const id of ['A04', 'A05', 'A16']) assert.deepEqual(byRule(id).map((t) => t.elementId), ['agent']);
  assert.deepEqual(paths('A06'), ['answer']);
  assert.deepEqual(new Set(paths('A07')), new Set(['question', 'retrieved', 'provider-output']));
  assert.deepEqual(paths('A08'), ['retrieved']); assert.deepEqual(new Set(paths('A09')), new Set(['index', 'retrieval-query']));
  assert.deepEqual(byRule('A10').map((t) => t.elementId), ['vector']);
  assert.deepEqual(new Set(paths('M01')), new Set(['business-query', 'tool-result'])); assert.deepEqual(paths('M04'), ['provider-request']);
  assert.equal(byRule('T03').filter((t) => t.elementId === 'vector').length, 0);
  for (const id of ['A11', 'A12', 'A13', 'A14', 'A15']) assert.equal(byRule(id).length, 0, id);
  syncThreats(model);
  const report = createReport(model).report;
  const reported = report.categories.flatMap((c) => c.interactions).flatMap((i) => i.threats);
  assert.deepEqual(new Set(reported.map((t) => t.key)), new Set(findings.map((t) => t.key)));
});
test('GUIDE Exercise 5: control changes suppress gated rules, not unconditional review prompts', () => {
  const model = guideModel(), elements = model.diagrams[0].elements;
  const agent = elements.find((e) => e.id === 'agent'), vector = elements.find((e) => e.id === 'vector');
  agent.props.validatesInput = 'Yes'; agent.props.authorizesRequests = 'Yes';
  vector.props.accessControl = 'Fine-grained'; vector.props.encryptedAtRest = 'Yes';
  elements.find((e) => e.id === 'mcp').props.validatesInput = 'Yes';
  for (const f of elements.filter((e) => e.type === 'flow' && e.targetId === 'agent')) f.props.rateLimited = 'Yes';
  const ids = new Set(generateThreats(model).map((t) => t.ruleId));
  for (const id of ['A03', 'A05', 'A07', 'A08']) assert.ok(!ids.has(id), id);
  for (const id of ['A01', 'A02', 'A04', 'A06', 'A09', 'A10', 'A16']) assert.ok(ids.has(id), id);
});
test('GUIDE Exercise 5: add model artefacts, a prediction API and an external MCP client', () => {
  const model = guideModel(), elements = model.diagrams[0].elements;
  elements.push(node('weights', 'store', 'ML Model / Training Data', 400), node('serving', 'process', 'ML Model Serving'));
  elements.push(node('client', 'external', 'MCP Client / AI Assistant', -400));
  elements.push(flow('load-agent', 'weights', 'agent'), flow('load-serving', 'weights', 'serving'));
  elements.push(flow('prediction', 'analyst', 'serving'), flow('client-tools', 'client', 'mcp'));
  const findings = generateThreats(model);
  for (const id of ['A11', 'A12', 'A13', 'A14', 'A15']) assert.ok(findings.some((t) => t.ruleId === id), id);
  const weights = elements.find((e) => e.id === 'weights');
  weights.props.integrity = 'Yes'; weights.props.accessControl = 'Fine-grained';
  for (const id of ['load-agent', 'load-serving']) elements.find((e) => e.id === id).props.integrity = 'Yes';
  elements.find((e) => e.id === 'prediction').props.rateLimited = 'Yes';
  elements.find((e) => e.id === 'serving').props.authenticatesCallers = 'Yes';
  elements.find((e) => e.id === 'client-tools').props.authentication = 'Token (OAuth / JWT)';
  const safe = new Set(generateThreats(model).map((t) => t.ruleId));
  for (const id of ['A11', 'A12', 'A13', 'A14', 'A15']) assert.ok(!safe.has(id), id);
});

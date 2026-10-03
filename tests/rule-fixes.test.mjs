import test from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_RULES } from '../js/rules.js';
import { generateThreats, syncThreats, threatList, threatBadges } from '../js/engine.js';
import { defaultProps, STENCILS } from '../js/stencils.js';
import { updateThreat, contributingFlowText } from '../js/threats.js';
import { createReport, buildMarkdown } from '../js/reports.js';
import { buildReport, serializeModel, readModelFile } from '../js/io.js';
import { normalizeModel } from '../js/store.js';

function fixture() {
  const node = (id, type, x) => ({ id, name: id, type, subtype: 'Generic Process', x, y: 0, w: 100, h: 100, props: defaultProps(type), style: {} });
  const source = node('source', 'external', 0), target = node('target', 'process', 400);
  const flow = { id: 'flow', name: 'request', type: 'flow', subtype: 'Generic Data Flow', sourceId: source.id, targetId: target.id, props: defaultProps('flow'), style: {} };
  const boundary = { id: 'boundary', name: 'Zone', type: 'boundary', x: 350, y: -50, w: 250, h: 250, props: {}, style: {} };
  const model = { diagrams: [{ id: 'diagram', name: 'Diagram', elements: [source, target, flow, boundary] }], threats: {}, nextThreatId: 1 };
  return { model, source, target, flow, boundary };
}
const rule = (id) => DEFAULT_RULES.find((r) => r.id === id);
const fires = (f, id) => generateThreats(f.model, [rule(id)]).some((t) => t.ruleId === id);
const noBoundary = (f) => { f.model.diagrams[0].elements = f.model.diagrams[0].elements.filter((e) => e !== f.boundary); };
const cases = [
  ['T01', () => {}, (f) => { f.target.props.validatesInput = 'Yes'; }],
  ['W03', (f) => { f.flow.subtype = 'WebSocket'; }, (f) => { f.flow.props.authentication = 'Token (OAuth / JWT)'; }],
  ['K01', (f) => { f.target.subtype = 'Kafka Broker'; }, (f) => { f.flow.props.authentication = 'mTLS / Certificate'; }],
  ['P13', (f) => { f.flow.subtype = 'Modbus'; }, (f) => { f.flow.props.authentication = 'mTLS / Certificate'; }],
  ['S02', () => {}, noBoundary],
  ['S04', (f) => { f.target.type = 'store'; }, noBoundary],
  ['S05', (f) => { f.source.type = 'store'; }, noBoundary],
  ['S06', (f) => { f.target.type = 'external'; }, noBoundary],
  ['E01', () => {}, noBoundary],
  ['E02', () => {}, (f) => { f.target.props.internetFacing = 'No'; f.target.props.validatesInput = 'Yes'; }],
  ['D01', () => {}, noBoundary],
  ['I05', () => {}, (f) => { f.target.props.internetFacing = 'No'; }],
  ['W02', (f) => { f.flow.subtype = 'WebSocket (ws://)'; }, (f) => { f.flow.subtype = 'WebSocket Secure (wss://)'; }],
  ['P01', (f) => { f.flow.subtype = 'Telnet'; }, (f) => { f.flow.subtype = 'NTLM'; }],
  ['E04', (f) => { f.target.subtype = 'Web Application'; f.flow.props.authentication = 'Cookie / Session'; }, (f) => { f.flow.props.authentication = 'Token (OAuth / JWT)'; }],
  ['W01', (f) => { f.flow.subtype = 'WebSocket'; f.flow.props.authentication = 'Cookie / Session'; }, (f) => { f.flow.props.authentication = 'Token (OAuth / JWT)'; }],
  ['D03', (f) => { f.target.type = 'store'; }, noBoundary],
  ['X04', (f) => { f.target.type = 'store'; }, (f) => { f.target.props.backedUp = 'Yes'; }],
  ['R01', () => {}, noBoundary],
  ['R02', (f) => { f.target.type = 'external'; f.source.type = 'process'; }, noBoundary],
  ['R03', (f) => { f.target.type = 'store'; }, noBoundary],
  ['T03', (f) => { f.target.type = 'store'; f.target.subtype = 'SQL Database'; }, (f) => { f.target.subtype = 'Vector Database'; }],
];
for (const [id, positive, negative] of cases) test(`${id}: matching minimal DFD fires; excluded DFD does not`, () => {
  const f = fixture(); positive(f);
  assert.ok(fires(f, id), `${id} positive fixture`);
  negative(f);
  assert.ok(!fires(f, id), `${id} negative fixture`);
});

test('cookie/session option exists and D03 interpolates both endpoint names', () => {
  assert.ok(STENCILS.flow.props.find((p) => p.key === 'authentication').options.includes('Cookie / Session'));
  const f = fixture(); f.target.type = 'store';
  assert.equal(generateThreats(f.model, [rule('D03')])[0].title, 'Data Store target Inaccessible from source');
});

test('W02 excludes wss with missing encryption and encrypted plain sockets', () => {
  const f = fixture(); f.flow.subtype = 'WebSocket Secure (wss://)'; delete f.flow.props.encrypted;
  assert.ok(!fires(f, 'W02'));
  f.flow.subtype = 'WebSocket'; assert.ok(fires(f, 'W02'));
  f.flow.props.encrypted = 'Yes'; assert.ok(!fires(f, 'W02'));
});

test('P01 excludes NTLM while P03 covers it; all cleartext protocols still match', () => {
  const f = fixture();
  for (const protocol of ['Telnet', 'FTP', 'TFTP', 'HTTP', 'LDAP', 'SNMP']) {
    f.flow.subtype = protocol; assert.ok(fires(f, 'P01'), protocol);
    f.flow.props.encrypted = 'Yes'; assert.ok(!fires(f, 'P01'), protocol);
    delete f.flow.props.encrypted;
  }
  f.flow.subtype = 'NTLM'; assert.ok(fires(f, 'P03')); assert.ok(!fires(f, 'P01'));
});

test('X04 considers explicit No and unset backups insecure', () => {
  const f = fixture(); f.target.type = 'store';
  for (const value of ['No', 'Not Selected', undefined]) {
    f.target.props.backedUp = value; assert.ok(fires(f, 'X04'));
  }
});

test('S04/S05 skip authenticated store flows, including across boundaries', () => {
  for (const id of ['S04', 'S05']) {
    const f = fixture(); f[id === 'S04' ? 'target' : 'source'].type = 'store';
    for (const auth of [undefined, 'Not Selected', 'None']) { f.flow.props.authentication = auth; assert.ok(fires(f, id)); }
    for (const auth of ['Password', 'Token (OAuth / JWT)', 'mTLS / Certificate']) { f.flow.props.authentication = auth; assert.ok(!fires(f, id)); }
  }
});

test('E02 requires a boundary and either internet exposure or missing input validation', () => {
  const f = fixture(); f.target.props.validatesInput = 'Yes'; f.target.props.internetFacing = 'Yes';
  assert.ok(fires(f, 'E02'));
  noBoundary(f); assert.ok(!fires(f, 'E02'));
  for (const key of ['internetFacing', 'validatesInput']) {
    const options = STENCILS.process.props.find((p) => p.key === key).options;
    for (const value of ['Yes', 'No', 'Not Selected']) assert.ok(options.includes(value));
  }
});

function fiveFlows() {
  const f = fixture();
  for (let i = 2; i <= 5; i++) f.model.diagrams[0].elements.push({ ...structuredClone(f.flow), id: `flow${i}`, name: `request ${i}` });
  return f;
}

test('endpoint rules each collapse five inbound flows, retain contributors and stable review identity', () => {
  const f = fiveFlows();
  for (const id of ['T01', 'R01', 'D01', 'E02', 'I05']) {
    const findings = generateThreats(f.model, [rule(id)]);
    assert.equal(findings.length, 1, id);
    assert.equal(findings[0].contributingFlows.length, 5, id);
    assert.equal(findings[0].elementId, f.target.id);
    assert.equal(findings[0].flowId, null);
    assert.match(contributingFlowText(findings[0]), /request 5/);
  }
  syncThreats(f.model);
  const t = threatList(f.model).find((t) => t.ruleId === 'T01'), key = t.key, id = t.id;
  updateThreat(t, 'status', 'mitigated'); updateThreat(t, 'notes', 'All five paths reviewed');
  f.model.diagrams[0].elements.reverse(); syncThreats(f.model);
  f.model.diagrams[0].elements = f.model.diagrams[0].elements.filter((e) => e.id !== f.flow.id);
  syncThreats(f.model);
  assert.equal(f.model.threats[key].id, id);
  assert.equal(f.model.threats[key].status, 'mitigated');
  assert.equal(f.model.threats[key].notes, 'All five paths reviewed');
  assert.equal(f.model.threats[key].contributingFlows.length, 4);
  assert.equal(threatList(f.model).filter((t) => t.ruleId === 'T01').length, 1);
});

test('source deduplication is optional; legacy custom templates retain per-flow keys', () => {
  const f = fiveFlows(), custom = { ...rule('T01'), id: 'Custom' }; delete custom.dedupeKey;
  const previous = generateThreats(f.model, [custom]);
  assert.equal(previous.length, 5);
  assert.ok(previous.every((t) => t.flowId && !t.contributingFlows && t.key === `diagram|${t.flowId}|Custom`));
  assert.deepEqual(generateThreats(f.model, [{ ...custom, dedupeKey: 'flow' }]), previous);
  const grouped = generateThreats(f.model, [{ ...custom, dedupeKey: 'source' }]);
  assert.equal(grouped.length, 1); assert.equal(grouped[0].elementId, 'source');
  // Grouping must not leak across diagrams or different target IDs.
  f.model.diagrams.push({ ...structuredClone(f.model.diagrams[0]), id: 'second' });
  assert.equal(generateThreats(f.model, [rule('T01')]).length, 2);
});

test('E03 is removed and its execution-flow and memory-safety guidance survives in T01', () => {
  assert.equal(DEFAULT_RULES.length, 81); assert.equal(rule('E03'), undefined);
  assert.match(rule('T01').description, /program execution/);
  assert.match(rule('T01').mitigation, /memory-safe.*ASLR, DEP, CFG/);
});

for (const [id, setup, hidden] of [
  ['P01', (f) => { f.flow.subtype = 'Telnet'; }, ['I01', 'T02']],
  ['W02', (f) => { f.flow.subtype = 'WebSocket (ws://)'; }, ['I01']],
  ['W03', (f) => { f.flow.subtype = 'WebSocket'; }, ['S03', 'S07']],
  ['K01', (f) => { f.target.subtype = 'Kafka Broker'; }, ['S03', 'S07']],
  ['P13', (f) => { f.flow.subtype = 'Modbus'; }, ['S07']],
]) test(`${id}: supersession hides only matching findings on that interaction`, () => {
  const f = fixture(); f.source.type = 'process'; setup(f);
  const selected = [rule(id), ...hidden.map(rule)];
  const other = { ...structuredClone(f.flow), id: 'other', subtype: 'Generic Data Flow', targetId: 'other-target' };
  f.model.diagrams[0].elements.push({ ...structuredClone(f.target), id: 'other-target', subtype: 'Generic Process' }, other);
  const generated = generateThreats(f.model, selected);
  assert.ok(generated.some((t) => t.ruleId === id && t.flowId === f.flow.id));
  for (const replaced of hidden) {
    assert.ok(!generated.some((t) => t.ruleId === replaced && t.flowId === f.flow.id));
    assert.ok(generated.some((t) => t.ruleId === replaced && t.flowId === 'other'));
  }
  assert.deepEqual(generateThreats(f.model, [...selected].reverse()).map((t) => t.key).sort(), generated.map((t) => t.key).sort());
});

test('saved superseded reviews are hidden from lists and badges, then restored when applicable', () => {
  const f = fixture(); f.model.template = [rule('I01'), rule('T02')]; syncThreats(f.model);
  const t = threatList(f.model).find((t) => t.ruleId === 'I01'); updateThreat(t, 'notes', 'Preserve this decision');
  const id = t.id;
  f.flow.subtype = 'Telnet'; f.model.template.push(rule('P01')); syncThreats(f.model);
  assert.deepEqual(threatList(f.model).map((t) => t.ruleId), ['P01']);
  assert.equal(f.model.threats[t.key].notes, 'Preserve this decision');
  assert.equal(threatBadges(f.model, 'diagram').get('flow').total, 1);
  f.flow.subtype = 'Generic Data Flow'; syncThreats(f.model);
  assert.equal(threatList(f.model).find((t) => t.ruleId === 'I01').id, id);
  assert.equal(t.suppressed, undefined);
});

test('legacy per-flow reviews migrate without losing conflicting notes or duplicating visible findings', () => {
  const f = fiveFlows(), legacy = { ...rule('T01') }; delete legacy.dedupeKey;
  f.model.template = [legacy]; syncThreats(f.model);
  const records = threatList(f.model);
  updateThreat(records[1], 'notes', 'Second flow reviewed'); updateThreat(records[2], 'notes', 'Third flow reviewed');
  const id = records[1].id;
  f.model.template = [rule('T01')]; syncThreats(f.model); syncThreats(f.model);
  assert.equal(threatList(f.model).length, 1);
  assert.equal(threatList(f.model)[0].id, id);
  assert.equal(threatList(f.model)[0].notes, 'Second flow reviewed');
  assert.ok(Object.values(f.model.threats).some((t) => t.notes === 'Third flow reviewed' && t.mergedInto));
});

test('supersession filters individual contributions before target grouping', () => {
  const f = fiveFlows();
  const generic = { ...rule('T01'), id: 'GENERIC' };
  const specific = { ...rule('P01'), id: 'SPECIFIC', supersedes: ['GENERIC'] };
  f.flow.subtype = 'Telnet';
  const out = generateThreats(f.model, [generic, specific]);
  const grouped = out.find((t) => t.ruleId === 'GENERIC');
  assert.equal(grouped.contributingFlows.length, 4);
  assert.ok(!grouped.contributingFlows.some((flow) => flow.id === f.flow.id));
  assert.equal(out.filter((t) => t.ruleId === 'SPECIFIC').length, 1);
  f.flow.outOfScope = true;
  assert.ok(!generateThreats(f.model, [generic, specific]).some((t) => t.ruleId === 'SPECIFIC'));
});

test('grouped findings list all flows in reports and survive local file round trips', async () => {
  const f = fiveFlows(); f.model = normalizeModel(f.model); syncThreats(f.model);
  const grouped = threatList(f.model).find((t) => t.ruleId === 'T01');
  updateThreat(grouped, 'notes', 'Grouped evidence');
  const bundle = createReport(f.model), md = buildMarkdown(bundle), html = buildReport(f.model);
  const exported = bundle.report.categories.flatMap((c) => c.interactions.flatMap((g) => g.threats)).find((t) => t.key === grouped.key);
  assert.deepEqual(exported.contributingFlows, grouped.contributingFlows);
  for (const flow of grouped.contributingFlows) {
    assert.ok(html.includes(flow.id)); assert.ok(md.includes(flow.id));
  }
  const loaded = await readModelFile({ name: 'grouped.stride', text: async () => serializeModel(f.model) });
  assert.deepEqual(loaded, f.model);
  syncThreats(loaded); assert.equal(loaded.threats[grouped.key].notes, 'Grouped evidence');
});

test('superseded reviewed records stay in JSON backups but not published threat registers', () => {
  const f = fixture(); f.model = normalizeModel(f.model); f.model.template = [rule('I01'), rule('T02')];
  syncThreats(f.model); const t = threatList(f.model)[0]; updateThreat(t, 'notes', 'Archived evidence');
  f.flow.subtype = 'Telnet'; f.model.template.push(rule('P01')); syncThreats(f.model);
  const bundle = createReport(f.model);
  assert.equal(bundle.model.threats[t.key].notes, 'Archived evidence');
  assert.equal(bundle.report.summary.total, 1);
  assert.deepEqual(bundle.report.categories.flatMap((c) => c.interactions.flatMap((g) => g.threats)).map((t) => t.ruleId), ['P01']);
});

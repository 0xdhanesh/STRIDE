import test from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_RULES } from '../js/rules.js';
import { generateThreats } from '../js/engine.js';
import { defaultProps, STENCILS } from '../js/stencils.js';

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

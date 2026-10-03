// Run with: node tests/engine.test.mjs
import assert from 'node:assert/strict';
import { sampleModel } from '../js/sample.js';
import { syncThreats, threatList, validate, generateThreats, evalCond } from '../js/engine.js';
import { DEFAULT_RULES, validateRules } from '../js/rules.js';
import { updateThreat } from '../js/threats.js';

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
updateThreat(t, 'status', 'mitigated'); t.justification = 'MFA enforced';
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

// WebSocket rules.
{
  const { defaultProps } = await import('../js/stencils.js');
  const { applySubtype } = await import('../js/ops.js');
  const node = (id, type, subtype, x) => ({ id, type, name: id, subtype, x, y: 0, w: 130, h: 130, props: defaultProps(type), style: {} });
  const flow = (subtype) => { const f = { id: 'ws', type: 'flow', name: 'socket', subtype: 'Generic Data Flow', sourceId: 'b', targetId: 's', bend: 0, props: defaultProps('flow'), style: {} }; applySubtype(f, subtype); return f; };
  const run = (f) => new Set(generateThreats({ diagrams: [{ id: 'd', elements: [node('b', 'external', 'Browser', 0), node('s', 'process', 'WebSocket Server / Gateway', 300), f] }], threats: {} }).map((g) => g.ruleId));
  const plain = run(flow('WebSocket (ws://)'));
  for (const r of ['W01', 'W02', 'W03', 'W04', 'W05', 'W06']) assert.ok(plain.has(r), `ws:// fires ${r}`);
  const secure = flow('WebSocket Secure (wss://)');
  secure.props.authentication = 'Token (OAuth / JWT)';
  secure.props.rateLimited = 'Yes';
  const sec = run(secure);
  assert.ok(!sec.has('W02') && !sec.has('W03') && !sec.has('W06'), 'wss:// with auth + rate limiting suppresses W02/W03/W06');
  assert.ok(sec.has('W01') && sec.has('W05'), 'CSWSH and message injection still apply');
  console.log('OK – WebSocket rules');
}

// Penetration-testing rules: each fires in a matching scenario.
{
  const { defaultProps } = await import('../js/stencils.js');
  const { applySubtype } = await import('../js/ops.js');
  let k = 0;
  const node = (type, subtype, props = {}, x = 0) => { const e = { id: `n${k++}`, type, name: subtype, subtype: 'x', x, y: 0, w: 130, h: 130, props: defaultProps(type), style: {} }; applySubtype(e, subtype); Object.assign(e.props, props); return e; };
  const fired = (els) => new Set(generateThreats({ diagrams: [{ id: 'd', elements: els }], threats: {} }).map((g) => g.ruleId));
  const pair = (a, b, subtype, flowProps = {}, boundary = false) => {
    const f = { id: `f${k++}`, type: 'flow', name: 'f', subtype: 'x', sourceId: a.id, targetId: b.id, bend: 0, props: defaultProps('flow'), style: {} };
    applySubtype(f, subtype); Object.assign(f.props, flowProps);
    b.x = 400;
    const els = [a, b, f];
    if (boundary) els.push({ id: `b${k++}`, type: 'boundary', name: 'Zone', subtype: 'DMZ', x: 350, y: -50, w: 300, h: 250, props: {}, style: {} });
    return fired(els);
  };
  const expect = (id, set) => assert.ok(set.has(id), `${id} should fire`);
  expect('P01', pair(node('external', 'Administrator'), node('process', 'Generic Process'), 'Telnet'));
  expect('P02', pair(node('external', 'Administrator'), node('process', 'Virtual Machine'), 'RDP', {}, true));
  expect('P03', pair(node('process', 'Generic Process'), node('process', 'File Transfer Server'), 'NTLM'));
  expect('P04', pair(node('process', 'Generic Process'), node('process', 'Active Directory Domain Controller'), 'Kerberos'));
  expect('P05', pair(node('external', 'OAuth / Social Login Provider'), node('process', 'Web Application'), 'SAML'));
  expect('P06', pair(node('process', 'Generic Process'), node('process', 'DNS Server'), 'DNS'));
  expect('P07', pair(node('external', 'Payment Gateway'), node('process', 'Web API / Service'), 'Webhook Callback'));
  expect('P08', pair(node('external', 'Browser'), node('process', 'GraphQL API'), 'GraphQL'));
  expect('P09', pair(node('process', 'Load Balancer'), node('process', 'Web Application'), 'HTTPS'));
  expect('P10', pair(node('process', 'Web API / Service'), node('store', 'Cloud Instance Metadata'), 'HTTP'));
  expect('P11', pair(node('store', 'Container Registry'), node('process', 'Kubernetes Pod'), 'HTTPS'));
  expect('P12', pair(node('process', 'Mail Server'), node('external', 'Email Recipient'), 'SMTP'));
  expect('P13', pair(node('process', 'SCADA / HMI'), node('process', 'PLC / Controller'), 'Modbus'));
  expect('P14', pair(node('external', 'IoT Device'), node('process', 'IoT Gateway'), 'Bluetooth / BLE'));
  expect('P15', pair(node('external', 'Privileged Insider'), node('process', 'Desktop / Thick Client'), 'USB / Physical Media'));
  expect('P16', pair(node('external', 'Malicious Insider'), node('process', 'Admin Console / Management Plane'), 'HTTPS'));
  expect('P17', pair(node('external', 'External Attacker (Internet)'), node('process', 'CDN / Edge'), 'HTTPS'));
  expect('P18', pair(node('process', 'Web API / Service'), node('process', 'SIEM / Log Collector'), 'Syslog'));
  expect('P19', fired([node('process', 'Web Application', { internetFacing: 'Yes' })]));
  expect('P20', fired([node('process', 'CI/CD Pipeline')]));
  expect('P21', fired([node('store', 'Source Code Repository')]));
  expect('P22', fired([node('process', 'Bastion / Jump Host')]));
  expect('P23', fired([node('store', 'Browser Storage', { storesCredentials: 'Yes' })]));
  expect('P24', fired([node('store', 'Mobile Device Storage')]));
  // Secure variants suppress protocol threats.
  assert.ok(!pair(node('external', 'Administrator'), node('process', 'Generic Process'), 'SSH').has('P01'), 'SSH is not a cleartext legacy protocol');
  assert.ok(!pair(node('process', 'Generic Process'), node('process', 'DNS Server'), 'DNS over HTTPS / TLS').has('P06'), 'DoH suppresses DNS spoofing');
  console.log('OK – penetration-testing rules (P01–P24)');
}

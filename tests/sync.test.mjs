import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { DEFAULT_TEMPLATE, addElement, createModel, crossedBoundaries, generateThreats, syncModel, updateThreat, validateModel } from '../src/core/index.js';
import { createMcpHandler } from '../src/cli/mcp.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function spec() {
  return {
    name: 'Acme Payments',
    zones: [
      { name: 'User device' },
      { name: 'Edge', type: 'SE.TB.B.TMCore.CorpNet' },
      { name: 'Cloud VPC', type: 'SE.TB.B.TMCore.CorpNet' },
    ],
    elements: [
      { name: 'Customer', type: 'SE.EI.TMCore.User' },
      { name: 'Billing SPA', type: 'SE.P.TMCore.BrowserClient', zone: 'User device', evidence: ['web/src/main.tsx:1'] },
      { name: 'API Gateway', type: 'SE.P.TMCore.WebServer', zone: 'Edge' },
      { name: 'Billing API', type: 'SE.P.TMCore.WebSvc', zone: 'Cloud VPC', props: { implementsCustomAuthorizationMechanism: 'Yes' }, evidence: ['api/app.py:12'] },
      { name: 'Invoices DB', type: 'SQL Database', zone: 'Cloud VPC' },
      { name: 'Session cache', type: 'SE.DS.TMCore.Cache', zone: 'Cloud VPC' },
      { name: 'Audit log', type: 'store', zone: 'Cloud VPC', props: { storesLogData: 'Yes' } },
      { name: 'Stripe', type: 'SE.EI.TMCore.WebSvc' },
      { name: 'Auth0', type: 'SE.EI.TMCore.AuthProvider' },
    ],
    flows: [
      { name: 'User actions', from: 'Customer', to: 'Billing SPA' },
      { name: 'API requests', from: 'Billing SPA', to: 'API Gateway', type: 'HTTPS', props: { JSON: 'Yes' } },
      { name: 'API responses', from: 'API Gateway', to: 'Billing SPA', type: 'HTTPS' },
      { name: 'Proxied requests', from: 'API Gateway', to: 'Billing API', type: 'HTTP' },
      { name: 'Token refresh', from: 'Billing SPA', to: 'Billing API', type: 'HTTPS' },
      { name: 'Invoice queries', from: 'Billing API', to: 'Invoices DB', evidence: ['api/db.py:30'] },
      { name: 'Invoice rows', from: 'Invoices DB', to: 'Billing API' },
      { name: 'Session reads', from: 'Session cache', to: 'Billing API' },
      { name: 'Audit events', from: 'Billing API', to: 'Audit log' },
      { name: 'Charge requests', from: 'Billing API', to: 'Stripe', type: 'HTTPS' },
      { name: 'Token validation', from: 'Billing API', to: 'Auth0', type: 'HTTPS' },
    ],
  };
}

const fresh = () => createModel({ template: DEFAULT_TEMPLATE });
const byName = (m, n) => m.diagrams[0].elements.find((e) => e.name === n);

test('sync builds zones, elements and flows with exact boundary crossings', () => {
  const m = fresh();
  const r = syncModel(m, spec());
  assert.equal(r.created.length, 3 + 9 + 11);
  assert.deepEqual(r.layoutWarnings, []);
  const d = m.diagrams[0];
  const crossed = (flow) => crossedBoundaries(m, d, byName(m, flow)).map((b) => b.name).sort();
  assert.deepEqual(crossed('Invoice queries'), [], 'same zone: no crossing');
  assert.deepEqual(crossed('API requests'), ['Edge', 'User device']);
  assert.deepEqual(crossed('Token refresh'), ['Cloud VPC', 'User device'], 'skips the Edge zone via an arc');
  assert.deepEqual(crossed('Charge requests'), ['Cloud VPC'], 'third party outside every zone');
  assert.deepEqual(crossed('User actions'), ['User device']);
  const g = generateThreats(m);
  assert.equal(g.errors.length, 0);
  assert.equal(validateModel(m).filter((x) => x.severity !== 'info').length, 0);
  assert.deepEqual(byName(m, 'Billing API').evidence, ['api/app.py:12']);
});

test('re-sync keeps triage, applies changes and prunes only spec-managed elements', () => {
  const m = fresh();
  syncModel(m, spec());
  generateThreats(m);
  const hand = addElement(m, null, { type: 'annotation', name: 'Hand-drawn note' });
  const t7 = m.threats.find((t) => t.typeId === 'T7');
  updateThreat(m, t7.key, { state: 'Mitigated', justification: 'Parameterized queries (api/db.py:30)' });

  const s2 = spec();
  s2.elements.push({ name: 'Jobs queue', type: 'store', zone: 'Cloud VPC' });
  s2.flows.push({ name: 'Enqueue jobs', from: 'Billing API', to: 'Jobs queue' });
  s2.flows = s2.flows.filter((f) => f.name !== 'Token refresh');
  s2.elements.find((e) => e.name === 'Billing API').props = {};
  const r = syncModel(m, s2);
  const g = generateThreats(m);
  assert.equal(r.created.length, 2);
  assert.equal(r.removed.length, 1);
  assert.equal(r.unmanaged, 1, 'hand-drawn note kept');
  assert.ok(m.diagrams[0].elements.includes(hand));
  const kept = m.threats.find((t) => t.key === t7.key);
  assert.equal(kept.state, 'Mitigated');
  assert.ok(!m.threats.some((t) => t.typeId === 'I2'), 'property removal drops Authorization bypass');
  assert.ok(g.added > 0 && g.removed > 0);
});

test('re-syncing an identical spec changes nothing', () => {
  const m = fresh();
  syncModel(m, spec());
  generateThreats(m);
  const before = JSON.stringify(m.diagrams);
  syncModel(m, spec());
  const g = generateThreats(m);
  assert.equal(JSON.stringify(m.diagrams), before);
  assert.equal(g.added + g.removed + g.updated, 0);
});

test('layout "keep" preserves hand-arranged positions and refits zones', () => {
  const m = fresh();
  syncModel(m, spec());
  const api = byName(m, 'Billing API');
  api.x += 400;
  syncModel(m, spec(), { layout: 'keep' });
  assert.equal(byName(m, 'Billing API').x, api.x);
  const vpc = byName(m, 'Cloud VPC');
  assert.ok(vpc.x + vpc.w >= api.x + api.w, 'zone grows to contain the moved element');
});

test('invalid specs report every problem at once', () => {
  assert.throws(
    () =>
      syncModel(fresh(), {
        zones: [{ name: 'Z', type: 'GE.P' }],
        elements: [{ name: 'A', type: 'nope' }, { name: 'B', type: 'process', zone: 'missing', props: { codeType: 'Bogus' } }, { name: 'F', type: 'flow' }],
        flows: [{ name: 'x', from: 'A', to: 'zzz' }],
      }),
    (e) => {
      for (const s of ['not a box trust boundary', "unknown type 'nope'", "unknown zone 'missing'", "invalid value 'Bogus'", 'must be a process', "unknown 'to' element 'zzz'"]) assert.ok(e.message.includes(s), s);
      return true;
    },
  );
});

test('MCP stride_sync_model accepts an inline spec or a spec file and creates the model', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'stride-sync-'));
  const handle = createMcpHandler({ root });
  const call = (args) => {
    const r = handle({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'stride_sync_model', arguments: args } }).result;
    return { isError: r.isError, data: r.isError ? r.content[0].text : JSON.parse(r.content[0].text) };
  };
  const a = call({ model: 'tm/acme.json', spec: spec() });
  assert.equal(a.isError, false, a.data);
  assert.equal(a.data.elements.created, 23);
  assert.equal(a.data.validation.errors, 0);
  assert.ok(a.data.threats.total > 50);
  fs.mkdirSync(path.join(root, 'threatmodel'));
  fs.writeFileSync(path.join(root, 'threatmodel', 'spec.json'), JSON.stringify(spec()));
  const b = call({ model: 'tm/acme.json', specFile: 'threatmodel/spec.json' });
  assert.equal(b.data.elements.created, 0);
  assert.equal(b.data.threats.added, 0);
  assert.match(call({ model: 'tm/acme.json' }).data, /Provide "spec"/);
  assert.match(call({ model: 'tm/acme.json', specFile: '../x.json' }).data, /outside the allowed root/);
});

test('CLI stride sync creates the model and reports results', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'stride-sync-cli-'));
  fs.writeFileSync(path.join(dir, 'spec.json'), JSON.stringify(spec()));
  const r = spawnSync(process.execPath, [path.join(ROOT, 'bin', 'stride.mjs'), 'sync', 'model.json', 'spec.json'], { cwd: dir, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /23 created/);
  assert.ok(fs.existsSync(path.join(dir, 'model.json')));
});

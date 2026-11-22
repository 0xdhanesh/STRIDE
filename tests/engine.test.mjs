import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  DEFAULT_TEMPLATE,
  addElement,
  addUserThreat,
  createModel,
  createSampleModel,
  crossedBoundaries,
  explainFlow,
  generateThreats,
  parseTb7,
  removeElements,
  updateElement,
  updateThreat,
} from '../src/core/index.js';

/** User → Web (HTTPS), Web → User (HTTPS), Web → DB (generic), arc Internet boundary between User and Web. */
export function webScenario(template = DEFAULT_TEMPLATE) {
  const m = createModel({ template });
  const user = addElement(m, null, { type: 'SE.EI.TMCore.User', name: 'User', x: 40, y: 200 });
  const web = addElement(m, null, { type: 'SE.P.TMCore.WebApp', name: 'Web App', x: 360, y: 190 });
  const db = addElement(m, null, { type: 'SE.DS.TMCore.SQL', name: 'Orders DB', x: 680, y: 200 });
  const req = addElement(m, null, { type: 'SE.DF.TMCore.HTTPS', name: 'Request', source: user.id, target: web.id });
  const resp = addElement(m, null, { type: 'SE.DF.TMCore.HTTPS', name: 'Response', source: web.id, target: user.id });
  const sql = addElement(m, null, { type: 'GE.DF', name: 'SQL query', source: web.id, target: db.id });
  const tb = addElement(m, null, { type: 'SE.TB.L.TMCore.Internet', name: 'Internet', x0: 260, y0: 100, x1: 260, y1: 400 });
  return { m, user, web, db, req, resp, sql, tb };
}

const ids = (m) => m.threats.map((t) => `${t.typeId}@${t.interaction}`).sort();

test('generates the expected threats for the web scenario', () => {
  const { m } = webScenario();
  const r = generateThreats(m);
  assert.equal(r.errors.length, 0);
  assert.deepEqual(ids(m), [
    'D2@From Web App to Orders DB via SQL query',
    'D3@From User to Web App via Request',
    'D4@From User to Web App via Request',
    'D4@From Web App to User via Response',
    'E5@From User to Web App via Request',
    'E6@From User to Web App via Request',
    'E7@From User to Web App via Request',
    'E8@From User to Web App via Request',
    'R6@From User to Web App via Request',
    'R7@From Web App to User via Response',
    'S3@From User to Web App via Request',
    'S7.1@From Web App to Orders DB via SQL query',
    'S8@From Web App to User via Response',
    'T13.1@From User to Web App via Request',
    'T7@From Web App to Orders DB via SQL query',
  ]);
  assert.equal(new Set(m.threats.map((t) => t.id)).size, m.threats.length, 'sequential unique ids');
});

test('threat text is expanded from element names', () => {
  const { m } = webScenario();
  generateThreats(m);
  const t = m.threats.find((x) => x.typeId === 'T7');
  assert.equal(t.title, 'Potential SQL injection vulnerability for Orders DB');
  assert.match(t.description, /Web App/);
});

test('crossing is geometric: moving the boundary changes the threats', () => {
  const { m, req, tb } = webScenario();
  assert.equal(crossedBoundaries(m, m.diagrams[0], req).length, 1);
  updateElement(m, tb.id, { x0: 1200, x1: 1200 });
  assert.equal(crossedBoundaries(m, m.diagrams[0], req).length, 0);
  generateThreats(m);
  assert.ok(!m.threats.some((t) => t.typeId === 'D3'));
});

test('box boundaries cross flows that cut their border, not ones fully inside', () => {
  const { m, sql } = webScenario();
  const box = addElement(m, null, { type: 'GE.TB.B', name: 'Backend', x: 330, y: 150, w: 600, h: 200 });
  assert.equal(crossedBoundaries(m, m.diagrams[0], sql).length, 0, 'web→db both inside the box');
  updateElement(m, box.id, { w: 250 });
  assert.equal(crossedBoundaries(m, m.diagrams[0], sql).length, 1, 'db now outside the box');
});

test('merge keeps triage, refreshes text, removes untouched and orphans triaged threats', () => {
  const { m, user, req, sql } = webScenario();
  generateThreats(m);
  const s3 = m.threats.find((t) => t.typeId === 'S3');
  updateThreat(m, s3.key, { state: 'Mitigated', justification: 'MFA' }, 'alice');
  // Rename refreshes generated text but keeps triage.
  updateElement(m, user.id, { name: 'Customer' });
  let r = generateThreats(m);
  const s3b = m.threats.find((t) => t.key === s3.key);
  assert.equal(s3b.state, 'Mitigated');
  assert.equal(s3b.title, 'Spoofing the Customer external entity');
  assert.ok(r.updated > 0);
  // A user-edited title is not overwritten.
  updateThreat(m, s3.key, { title: 'Custom title' });
  updateElement(m, user.id, { name: 'Buyer' });
  generateThreats(m);
  assert.equal(m.threats.find((t) => t.key === s3.key).title, 'Custom title');
  // Property change that excludes S3: the triaged threat becomes an orphan, untouched ones vanish.
  updateElement(m, req.id, { props: { authenticatesSource: 'Yes' } });
  r = generateThreats(m);
  assert.equal(m.threats.find((t) => t.key === s3.key).orphan, true);
  assert.equal(r.orphaned, 1);
  // Deleting a flow removes its untouched threats.
  const before = m.threats.filter((t) => t.flowId === sql.id).length;
  removeElements(m, [sql.id]);
  r = generateThreats(m);
  assert.equal(r.removed, before);
  // Restoring the property restores the orphan.
  updateElement(m, req.id, { props: { authenticatesSource: 'Not Selected' } });
  r = generateThreats(m);
  assert.equal(m.threats.find((t) => t.key === s3.key).orphan, false);
  assert.equal(r.restored, 1);
});

test('regeneration is idempotent', () => {
  const { m } = webScenario();
  generateThreats(m);
  const snapshot = JSON.stringify(m.threats);
  const r = generateThreats(m);
  assert.equal(r.added + r.removed + r.updated + r.orphaned, 0);
  assert.equal(JSON.stringify(m.threats), snapshot);
});

test('out of scope elements produce no threats', () => {
  const { m, db, sql } = webScenario();
  updateElement(m, db.id, { outOfScope: true });
  generateThreats(m);
  assert.ok(!m.threats.some((t) => t.flowId === sql.id));
});

test('user-defined threats survive regeneration and orphan when their flow is deleted', () => {
  const { m, sql } = webScenario();
  generateThreats(m);
  const t = addUserThreat(m, sql.id, { title: 'Backup exposure', category: 'I' });
  generateThreats(m);
  assert.ok(m.threats.includes(t));
  removeElements(m, [sql.id]);
  generateThreats(m);
  assert.equal(m.threats.find((x) => x.key === t.key).orphan, true);
});

test('disabled generation leaves threats alone', () => {
  const { m } = webScenario();
  m.settings.threatGeneration = false;
  const r = generateThreats(m);
  assert.equal(r.enabled, false);
  assert.equal(m.threats.length, 0);
});

test('explainFlow reports crossings and per-rule results', () => {
  const { m, req } = webScenario();
  const e = explainFlow(m, req.id);
  assert.equal(e.crosses[0].typeId, 'SE.TB.L.TMCore.Internet');
  assert.equal(e.results.find((r) => r.id === 'S3').applies, true);
  assert.equal(e.results.find((r) => r.id === 'S2').applies, false, 'HTTPS authenticates the destination');
});

test('sample model generates threats without rule errors', () => {
  const m = createSampleModel();
  const r = generateThreats(m);
  assert.equal(r.errors.length, 0);
  assert.ok(m.threats.length > 20);
});

// Optional parity check against Microsoft's own template.
const tb7 = process.env.MTMT_TB7;
test('parity with Microsoft Threat Modeling Tool Default.tb7 (set MTMT_TB7)', { skip: !tb7 && 'MTMT_TB7 not set' }, () => {
  const mtmt = parseTb7(fs.readFileSync(path.resolve(tb7), 'utf8'));
  const a = webScenario();
  const b = webScenario(mtmt);
  generateThreats(a.m);
  generateThreats(b.m);
  const norm = (m) => ids(m).map((x) => x.replace(/^8404dcf5-bdd8-4902-abc2-3b6c967b0261/, 'E8')).sort();
  assert.deepEqual(norm(b.m), norm(a.m));
});

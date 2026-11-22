// Acceptance checks: offline build, an end-to-end CLI modeling session, and the
// browser UI check (skipped when no Chrome is installed, unless --require-browser).

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildOffline } from './build-offline.mjs';
import { ROOT } from './static-server.mjs';

let failed = 0;
const step = (name, fn) => {
  try {
    const note = fn();
    console.log(`ok   ${name}${note ? ` — ${note}` : ''}`);
  } catch (e) {
    failed++;
    console.log(`FAIL ${name}\n     ${e.message}`);
  }
};
const assert = (cond, msg) => {
  if (!cond) throw new Error(msg);
};
const BIN = path.join(ROOT, 'bin', 'stride.mjs');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'stride-acceptance-'));
const cli = (...args) => {
  const r = spawnSync(process.execPath, [BIN, ...args], { cwd: dir, encoding: 'utf8' });
  if (r.status !== 0 && !args.includes('validate')) throw new Error(`stride ${args.join(' ')} → ${r.status}\n${r.stderr}`);
  return r;
};

step('offline single-file build', () => {
  const r = buildOffline();
  assert(r.bytes < 2_000_000, `build too large: ${r.bytes}`);
  return `${(r.bytes / 1024).toFixed(0)} KB, ${r.modules} modules`;
});

step('CLI: model a three-tier system and triage it', () => {
  cli('new', 'bank.json', '--name', 'Online banking');
  cli('add', 'bank.json', 'Human User', '--name', 'Customer');
  cli('add', 'bank.json', 'Browser Client', '--name', 'Banking SPA');
  cli('add', 'bank.json', 'Web Service', '--name', 'Accounts API', '--prop', 'implementsAuthenticationScheme=Yes', '--prop', 'implementsCustomAuthorizationMechanism=Yes');
  cli('add', 'bank.json', 'SQL Database', '--name', 'Ledger');
  cli('add', 'bank.json', 'store', '--name', 'Audit log', '--prop', 'storesLogData=Yes');
  cli('add', 'bank.json', 'Authorization Provider', '--name', 'Identity provider');
  cli('add', 'bank.json', 'flow', '--name', 'UI actions', '--from', 'Customer', '--to', 'Banking SPA');
  cli('add', 'bank.json', 'HTTPS', '--name', 'API calls', '--from', 'Banking SPA', '--to', 'Accounts API', '--prop', 'JSON=Yes');
  cli('add', 'bank.json', 'flow', '--name', 'Ledger queries', '--from', 'Accounts API', '--to', 'Ledger');
  cli('add', 'bank.json', 'flow', '--name', 'Audit events', '--from', 'Accounts API', '--to', 'Audit log');
  cli('add', 'bank.json', 'HTTPS', '--name', 'Token validation', '--from', 'Accounts API', '--to', 'Identity provider');
  cli('add', 'bank.json', 'SE.TB.B.TMCore.CorpNet', '--name', 'Bank datacenter', '--around', 'Accounts API,Ledger,Audit log');
  const v = JSON.parse(cli('validate', 'bank.json', '--json').stdout);
  assert(v.errors === 0, `validation errors: ${JSON.stringify(v.messages)}`);
  const t = JSON.parse(cli('threats', 'bank.json', '--json').stdout).threats;
  const types = new Set(t.map((x) => x.type));
  for (const id of ['T7', 'I2', 'R1', 'R3', 'E3', 'T12', 'T2', 'S1']) assert(types.has(id), `expected threat type ${id}; got ${[...types].join(',')}`);
  const sqli = t.find((x) => x.type === 'T7');
  cli('threat', 'bank.json', String(sqli.id), '--state', 'Mitigated', '--justification', 'Parameterized queries via ORM');
  cli('set', 'bank.json', 'Ledger', '--name', 'Core ledger');
  const after = JSON.parse(cli('threats', 'bank.json', '--state', 'Mitigated', '--json').stdout).threats;
  assert(after.length === 1 && /Core ledger/.test(after[0].title), 'triage kept and title refreshed after rename');
  cli('report', 'bank.json', '-o', 'bank.html');
  const html = fs.readFileSync(path.join(dir, 'bank.html'), 'utf8');
  assert(html.includes('Parameterized queries via ORM') && html.includes('<svg'), 'report contains triage and diagram');
  return `${t.length} threats across ${new Set(t.map((x) => x.category)).size} categories`;
});

step('MCP: source-code spec → threat model (examples/billing-service)', () => {
  const specFile = path.join(ROOT, 'examples', 'billing-service', 'threatmodel', 'spec.json');
  fs.copyFileSync(specFile, path.join(dir, 'spec.json'));
  const first = JSON.parse(cli('sync', 'billing.json', 'spec.json', '--json').stdout);
  assert(first.layoutWarnings.length === 0, `layout warnings: ${JSON.stringify(first.layoutWarnings)}`);
  assert(first.validation.errors === 0 && first.validation.warnings === 0, `validation: ${JSON.stringify(first.validation.messages)}`);
  const t = JSON.parse(cli('threats', 'billing.json', '--json').stdout).threats;
  assert(t.some((x) => x.type === 'I2' && x.interaction.includes('Billing API to Invoices DB')), 'authorization bypass on API → DB (the IDOR in api/app.py)');
  assert(t.some((x) => x.type === 'I6' && x.interaction.includes('Gateway to Billing API')), 'sniffing on the plain-HTTP proxy hop');
  const again = JSON.parse(cli('sync', 'billing.json', 'spec.json', '--json').stdout);
  assert(again.elements.created === 0 && again.threats.added === 0 && again.threats.removed === 0, 're-sync is idempotent');
  return `${first.elements.created} elements, ${first.threats.total} threats, 0 layout warnings`;
});

const ui = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'ui-check.mjs'), '--page', 'dist/STRIDE.html', '--file', ...process.argv.slice(2)], { cwd: ROOT, encoding: 'utf8' });
process.stdout.write(ui.stdout.split('\n').map((l) => (l ? `     ${l}` : l)).join('\n'));
if (ui.status !== 0) {
  failed++;
  console.log(`FAIL browser UI check\n${ui.stderr}`);
} else console.log('ok   browser UI check (offline build)');

fs.rmSync(dir, { recursive: true, force: true });
if (failed) {
  console.log(`\n${failed} acceptance check(s) failed`);
  process.exit(1);
}
console.log('\nAll acceptance checks passed');

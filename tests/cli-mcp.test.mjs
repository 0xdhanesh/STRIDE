import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createMcpHandler, TOOLS } from '../src/cli/mcp.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BIN = path.join(ROOT, 'bin', 'stride.mjs');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'stride-test-'));

function cli(cwd, ...args) {
  const r = spawnSync(process.execPath, [BIN, ...args], { cwd, encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

test('CLI builds a model end to end', () => {
  const dir = tmp();
  assert.equal(cli(dir, 'new', 'm.json', '--name', 'Shop').code, 0);
  assert.equal(cli(dir, 'new', 'm.json').code, 2, 'refuses to overwrite');
  cli(dir, 'add', 'm.json', 'Human User', '--name', 'Customer');
  cli(dir, 'add', 'm.json', 'SE.P.TMCore.WebApp', '--name', 'Web', '--prop', 'hasInputSanitizers=Yes');
  cli(dir, 'add', 'm.json', 'SE.DS.TMCore.SQL', '--name', 'DB');
  assert.equal(cli(dir, 'add', 'm.json', 'HTTPS', '--name', 'order', '--from', 'Customer', '--to', 'Web').code, 0);
  cli(dir, 'add', 'm.json', 'flow', '--name', 'query', '--from', 'Web', '--to', 'DB');
  const box = cli(dir, 'add', 'm.json', 'SE.TB.B.TMCore.CorpNet', '--name', 'Backend', '--around', 'Web,DB', '--json');
  assert.equal(JSON.parse(box.out).threats.errors.length, 0);
  const threats = JSON.parse(cli(dir, 'threats', 'm.json', '--json').out);
  assert.ok(threats.total >= 8);
  const s3 = threats.threats.find((t) => t.type === 'S3');
  assert.equal(cli(dir, 'threat', 'm.json', String(s3.id), '--state', 'mitigated', '--justification', 'MFA').code, 0);
  cli(dir, 'set', 'm.json', 'Customer', '--name', 'Buyer');
  const again = JSON.parse(cli(dir, 'threats', 'm.json', '--state', 'Mitigated', '--json').out);
  assert.equal(again.total, 1);
  assert.match(again.threats[0].title, /Buyer/);
  assert.equal(cli(dir, 'validate', 'm.json').code, 0);
  assert.equal(cli(dir, 'report', 'm.json', '-o', 'r.html').code, 0);
  assert.match(fs.readFileSync(path.join(dir, 'r.html'), 'utf8'), /<!doctype html>/);
  assert.match(cli(dir, 'report', 'm.json', '--format', 'csv').out, /^ID,Diagram/);
  assert.match(cli(dir, 'explain', 'm.json', 'order').out, /Crosses: Backend/);
  assert.equal(cli(dir, 'add', 'm.json', 'nope').code, 1);
  assert.equal(cli(dir, 'rule', 'check', "flow crosses 'GE.P'").code, 1);
  assert.equal(cli(dir, 'bogus').code, 2);
});

test('CLI validate exits 1 on errors', () => {
  const dir = tmp();
  cli(dir, 'new', 'm.json');
  cli(dir, 'add', 'm.json', 'process', '--name', 'A');
  const m = JSON.parse(fs.readFileSync(path.join(dir, 'm.json'), 'utf8'));
  m.diagrams[0].elements.push({ id: 'loose', typeId: 'GE.DF', name: 'x', x0: 0, y0: 0, x1: 10, y1: 0 });
  fs.writeFileSync(path.join(dir, 'm.json'), JSON.stringify(m));
  assert.equal(cli(dir, 'validate', 'm.json').code, 1);
});

function mcpCall(handle, name, args, id = 1) {
  const r = handle({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });
  const text = r.result.content[0].text;
  return { isError: r.result.isError, text, data: r.result.isError ? null : (() => { try { return JSON.parse(text); } catch { return text; } })() };
}

test('MCP handler: protocol basics', () => {
  const handle = createMcpHandler({ root: tmp() });
  const init = handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26' } });
  assert.equal(init.result.protocolVersion, '2025-03-26');
  assert.ok(init.result.capabilities.tools);
  assert.equal(handle({ jsonrpc: '2.0', method: 'notifications/initialized' }), null);
  const list = handle({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  assert.equal(list.result.tools.length, TOOLS.length);
  for (const t of list.result.tools) assert.equal(t.inputSchema.type, 'object', t.name);
  assert.equal(handle({ jsonrpc: '2.0', id: 3, method: 'nope' }).error.code, -32601);
  assert.equal(handle({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'nope' } }).error.code, -32602);
  assert.equal(handle({ jsonrpc: '2.0', id: 5, method: 'ping' }).result && true, true);
});

test('MCP tools model a system and stay inside the root', () => {
  const root = tmp();
  const handle = createMcpHandler({ root });
  handle({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} });
  assert.equal(mcpCall(handle, 'stride_create_model', { model: 'models/api.json', name: 'API' }).isError, false);
  mcpCall(handle, 'stride_add_element', { model: 'models/api.json', type: 'external', name: 'Client' });
  mcpCall(handle, 'stride_add_element', { model: 'models/api.json', type: 'Web Service', name: 'API' });
  const flow = mcpCall(handle, 'stride_add_element', { model: 'models/api.json', type: 'HTTP', name: 'call', from: 'Client', to: 'API' });
  assert.equal(flow.data.result.family, 'flow');
  const box = mcpCall(handle, 'stride_add_element', { model: 'models/api.json', type: 'box-boundary', name: 'DMZ', around: ['API'] });
  assert.ok(box.data.threats.total > 5);
  const v = mcpCall(handle, 'stride_validate_model', { model: 'models/api.json' });
  assert.equal(v.data.errors, 0);
  const list = mcpCall(handle, 'stride_list_threats', { model: 'models/api.json', category: 'Spoofing' });
  assert.ok(list.data.total >= 1);
  const upd = mcpCall(handle, 'stride_update_threat', { model: 'models/api.json', threat: list.data.threats[0].id, state: 'NotApplicable', justification: 'internal only' });
  assert.equal(upd.data.state, 'Not Applicable');
  assert.equal(mcpCall(handle, 'stride_update_threat', { model: 'models/api.json', threat: 1, state: 'weird' }).isError, true);
  const md = mcpCall(handle, 'stride_export_report', { model: 'models/api.json', format: 'md' });
  assert.match(md.text, /^# API/);
  mcpCall(handle, 'stride_export_report', { model: 'models/api.json', format: 'html', output: 'out/report.html' });
  assert.ok(fs.existsSync(path.join(root, 'out', 'report.html')));
  const explain = mcpCall(handle, 'stride_explain_flow', { model: 'models/api.json', flow: 'call' });
  assert.equal(explain.data.crosses[0].name, 'DMZ');

  // Sandbox
  assert.match(mcpCall(handle, 'stride_describe_model', { model: '../outside.json' }).text, /outside the allowed root/);
  assert.match(mcpCall(handle, 'stride_describe_model', { model: '/etc/passwd' }).text, /outside the allowed root|extension/);
  assert.match(mcpCall(handle, 'stride_export_report', { model: 'models/api.json', output: 'evil.sh' }).text, /extension not allowed/);
  fs.symlinkSync(os.tmpdir(), path.join(root, 'link'));
  assert.match(mcpCall(handle, 'stride_create_model', { model: 'link/x.json' }).text, /outside the allowed root/);
});

test('MCP server speaks newline-delimited JSON-RPC over stdio', async () => {
  const root = tmp();
  const proc = spawn(process.execPath, [BIN, 'mcp', '--root', root], { stdio: ['pipe', 'pipe', 'pipe'] });
  const lines = [];
  let buf = '';
  proc.stdout.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      lines.push(JSON.parse(buf.slice(0, i)));
      buf = buf.slice(i + 1);
    }
  });
  const send = (m) => proc.stdin.write(JSON.stringify(m) + '\n');
  send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } });
  send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'stride_create_model', arguments: { model: 'x.json' } } });
  proc.stdin.write('not json\n');
  proc.stdin.end();
  await new Promise((r) => proc.on('close', r));
  assert.equal(lines[0].result.serverInfo.name, 'stride-threat-modeler');
  assert.equal(lines[1].result.isError, false);
  assert.equal(lines[2].error.code, -32700);
  assert.ok(fs.existsSync(path.join(root, 'x.json')));
});

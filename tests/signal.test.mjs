import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_TEMPLATE,
  computeSignals,
  createModel,
  displayTitle,
  evidenceFile,
  generateThreats,
  loadModel,
  renderHtmlReport,
  renderMarkdownReport,
  serializeModel,
  stakeholderSummary,
  syncModel,
  updateThreat,
} from '../src/core/index.js';
import { opListThreats, opReport } from '../src/cli/ops.js';

function dvwa() {
  const m = createModel({ template: DEFAULT_TEMPLATE, name: 'DVWA' });
  syncModel(m, {
    name: 'DVWA',
    zones: [{ name: 'Web server', type: 'SE.TB.B.TMCore.CorpNet' }],
    elements: [
      { name: 'Browser', type: 'SE.EI.TMCore.Browser' },
      { name: 'PHP app', type: 'SE.P.TMCore.WebApp', zone: 'Web server' },
      { name: 'OS shell', type: 'SE.P.TMCore.OSProcess', zone: 'Web server' },
      { name: 'MySQL', type: 'SE.DS.TMCore.SQL', zone: 'Web server' },
      { name: 'Uploads', type: 'SE.DS.TMCore.FS', zone: 'Web server', custom: { path: 'hackable/uploads' } },
      { name: 'Config', type: 'SE.DS.TMCore.ConfigFile', zone: 'Web server', custom: { dbPassword: 'hardcoded' } },
    ],
    flows: [
      { name: 'Requests', from: 'Browser', to: 'PHP app', type: 'HTTP' },
      { name: 'shell_exec of user-controlled IP', from: 'PHP app', to: 'OS shell', evidence: ['vulnerabilities/exec/source/low.php:14'] },
      { name: 'Query', from: 'PHP app', to: 'MySQL', evidence: ["vulnerabilities/sqli/source/low.php:10 WHERE user_id = '$id'"] },
      { name: 'Upload', from: 'PHP app', to: 'Uploads', evidence: ['vulnerabilities/upload/source/low.php:12 move_uploaded_file'] },
      { name: 'Include', from: 'PHP app', to: 'Config', evidence: ["vulnerabilities/fi/source/low.php:4 include($_GET['page'])"] },
    ],
  });
  generateThreats(m);
  return m;
}

const onFlow = (m, name) => {
  const flow = m.diagrams[0].elements.find((e) => e.name === name);
  return m.threats.filter((t) => t.flowId === flow.id);
};

test('shell_exec flow surfaces as a specific command injection finding', () => {
  const m = dvwa();
  const titled = onFlow(m, 'shell_exec of user-controlled IP').filter((t) => t.signal.title);
  assert.equal(titled.length, 1, 'one finding per flow and sink');
  const t = titled[0];
  assert.equal(t.signal.title, 'Command injection via shell_exec of user-controlled IP');
  assert.equal(t.signal.level, 'high');
  assert.equal(t.signal.sink, 'command-injection');
  assert.deepEqual(t.signal.evidence, ['vulnerabilities/exec/source/low.php']);
  assert.match(m.threats.find((x) => x.key === t.key).title, /^(?!Command injection)/, 'rule title is untouched');
  assert.equal(displayTitle(t), t.signal.title);
});

test('every DVWA sink becomes exactly one titled finding', () => {
  const m = dvwa();
  const titles = m.threats.map((t) => t.signal.title).filter(Boolean).sort();
  assert.equal(titles.length, 4);
  assert.ok(titles.some((x) => x.startsWith('SQL injection via concatenated query')));
  assert.ok(titles.some((x) => x.startsWith('Unrestricted file upload to web root')));
  assert.ok(titles.some((x) => x.startsWith("Local file inclusion via 'page'")));
});

test('sink fix and title only go to the finding, not to sibling threats', () => {
  const m = dvwa();
  for (const t of onFlow(m, 'shell_exec of user-controlled IP')) {
    if (!t.signal.title) assert.equal(t.signal.fix, undefined);
  }
});

test('scoring weights: evidence, weak controls, sensitive targets, triage', () => {
  const m = dvwa();
  const generic = onFlow(m, 'Requests');
  assert.ok(generic.every((t) => t.signal.level !== 'high'), 'no evidence → not high');
  const cfg = onFlow(m, 'Include').find((t) => !t.signal.title);
  assert.ok(cfg.signal.reasons.includes('weak control in properties'));
  assert.ok(cfg.signal.reasons.includes('sensitive target type'));
  const before = cfg.signal.score;
  updateThreat(m, cfg.key, { state: 'NotApplicable' });
  const after = m.threats.find((t) => t.key === cfg.key).signal;
  assert.equal(after.score, before - 30 - (cfg.priority === 'High' ? 10 : 0));
});

test('signals do not change keys, ids or triage, and survive save/load', () => {
  const m = dvwa();
  const keys = m.threats.map((t) => `${t.id}|${t.key}|${t.state}|${t.title}`);
  computeSignals(m);
  generateThreats(m);
  assert.deepEqual(m.threats.map((t) => `${t.id}|${t.key}|${t.state}|${t.title}`), keys);
  const raw = JSON.parse(serializeModel(m));
  raw.threats[0].signal = { score: 999, level: 'high', title: '<script>' };
  const back = loadModel(raw);
  assert.notEqual(back.threats[0].signal.score, 999, 'stored signal is recomputed on load');
  assert.equal(back.threats.find((t) => t.signal.sink === 'command-injection' && t.signal.title)?.signal.title, 'Command injection via shell_exec of user-controlled IP');
});

test('user-edited titles are never overridden', () => {
  const m = dvwa();
  const t = m.threats.find((x) => x.signal.sink === 'command-injection' && x.signal.title);
  updateThreat(m, t.key, { title: 'My own title' });
  assert.equal(displayTitle(m.threats.find((x) => x.key === t.key)), 'My own title');
});

test('stakeholder summary: executive lines, ranked findings and top 3', () => {
  const m = dvwa();
  const sh = stakeholderSummary(m);
  assert.ok(sh.lines.length >= 5 && sh.lines.length <= 8, `${sh.lines.length} lines`);
  assert.match(sh.lines[0], /^DVWA models 6 elements and 5 data flows/);
  assert.equal(sh.topFindings.length, 3);
  assert.ok(sh.findings.every((f) => f.signal === 'high'));
  for (let i = 1; i < sh.findings.length; i++) assert.ok(sh.findings[i - 1].score >= sh.findings[i].score);
  assert.ok(stakeholderSummary(m, { signal: 'all' }).findings.length === m.threats.length);
});

test('HTML and Markdown put the stakeholder view first; --signal off keeps the classic layout', () => {
  const m = dvwa();
  const html = renderHtmlReport(m);
  assert.ok(html.indexOf('Executive summary') < html.indexOf('High-signal findings'));
  assert.ok(html.indexOf('High-signal findings') < html.indexOf('Diagram: '));
  assert.ok(html.includes('Command injection via shell_exec of user-controlled IP'));
  const md = renderMarkdownReport(m);
  assert.ok(md.indexOf('## Executive summary') < md.indexOf('## High-signal findings'));
  assert.ok(md.indexOf('## High-signal findings') < md.indexOf('## Full threat register'));
  assert.ok(!renderMarkdownReport(m, { signal: 'off' }).includes('Executive summary'));
  assert.ok(!renderHtmlReport(m, { signal: 'off' }).includes('Executive summary'));
});

test('report and threat listing accept --signal; unknown levels are rejected', () => {
  const m = dvwa();
  const json = JSON.parse(opReport(m, { format: 'json', signal: 'medium' }));
  assert.equal(json.stakeholder.level, 'medium');
  assert.ok(json.threats.every((t) => t.signal && typeof t.signal.score === 'number'));
  const list = opListThreats(m, { signal: 'high' });
  assert.ok(list.total > 0 && list.threats.every((t) => t.signal.level === 'high'));
  assert.throws(() => opReport(m, { format: 'md', signal: 'loud' }), /Invalid signal level/);
});

test('model text in findings is escaped in HTML', () => {
  const m = createModel({ template: DEFAULT_TEMPLATE });
  syncModel(m, {
    elements: [
      { name: 'U', type: 'SE.EI.TMCore.User' },
      { name: '<img src=x onerror=alert(1)>', type: 'SE.P.TMCore.WebApp' },
    ],
    flows: [{ name: 'system($_GET[<b>])', from: 'U', to: '<img src=x onerror=alert(1)>', evidence: ['a.php:1 <script>'] }],
  });
  generateThreats(m);
  const html = renderHtmlReport(m);
  assert.ok(!html.includes('<img src=x'));
  assert.ok(!html.includes('<script>x') && !/<b>\]/.test(html));
});

test('evidenceFile strips line numbers and snippets', () => {
  assert.equal(evidenceFile('src/a.php:12'), 'src/a.php');
  assert.equal(evidenceFile('src/a.php:12-20 — snippet'), 'src/a.php');
  assert.equal(evidenceFile('docker-compose.yml'), 'docker-compose.yml');
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_TEMPLATE,
  addElement,
  createModel,
  displayTitle,
  generateThreats,
  loadModel,
  parseEvidence,
  removeElements,
  renderHtmlReport,
  renderMarkdownReport,
  serializeModel,
  stableKey,
  stakeholderSummary,
  syncModel,
  updateThreat,
} from '../src/core/index.js';
import { opListThreats, opReport } from '../src/cli/ops.js';

const DVWA_SPEC = {
  name: 'DVWA',
  zones: [{ name: 'Web server', type: 'SE.TB.B.TMCore.CorpNet' }],
  elements: [
    { name: 'Browser', type: 'SE.EI.TMCore.Browser' },
    { name: 'PHP app', type: 'SE.P.TMCore.WebApp', zone: 'Web server' },
    { name: 'OS shell', type: 'SE.P.TMCore.OSProcess', zone: 'Web server' },
    { name: 'Uploads', type: 'SE.DS.TMCore.FS', zone: 'Web server', custom: { path: 'hackable/uploads' } },
  ],
  flows: [
    { name: 'Requests', from: 'Browser', to: 'PHP app', type: 'HTTP' },
    { name: 'shell_exec of user-controlled IP', from: 'PHP app', to: 'OS shell', evidence: ['vulnerabilities/exec/source/low.php:14'] },
    { name: 'shell_exec (medium filter)', from: 'PHP app', to: 'OS shell', evidence: ["vulnerabilities/exec/source/medium.php:21 shell_exec('ping -c 4 ' . $target)"] },
    { name: 'Upload', from: 'PHP app', to: 'Uploads', evidence: ['vulnerabilities/upload/source/low.php:12 move_uploaded_file'] },
  ],
};

const MATTERMOST_SPEC = {
  name: 'Mattermost',
  zones: [{ name: 'Server', type: 'SE.TB.B.TMCore.CorpNet' }],
  elements: [
    { name: 'Web client', type: 'SE.EI.TMCore.Browser' },
    { name: 'API server', type: 'SE.P.TMCore.WebSvc', zone: 'Server' },
    { name: 'Image proxy', type: 'SE.EI.TMCore.WebSvc' },
  ],
  flows: [
    {
      name: 'GET /api/v4/posts/{post_id}',
      from: 'Web client',
      to: 'API server',
      type: 'HTTPS',
      custom: { authz: 'missing' },
      evidence: ['channels/api4/post.go:74 c.App.GetSinglePost(c.Params.PostId) without channel membership check'],
    },
    {
      name: 'PATCH /api/v4/posts/{post_id}',
      from: 'Web client',
      to: 'API server',
      type: 'HTTPS',
      custom: { authz: 'missing' },
      evidence: ['channels/api4/post.go:520 patchPost uses c.Params.PostId without channel membership check'],
    },
    {
      name: 'DELETE /api/v4/posts/{post_id}',
      from: 'Web client',
      to: 'API server',
      type: 'HTTPS',
      custom: { authz: 'missing' },
      evidence: ['channels/api4/post.go:301 deletePost without team membership check'],
    },
    { name: 'WebSocket /api/v4/websocket', from: 'Web client', to: 'API server', evidence: ['channels/app/web_conn.go:120 authenticates with session token on first message only'] },
    { name: 'Fetch user-supplied image URL', from: 'API server', to: 'Image proxy', evidence: ['channels/app/proxy.go:88 http.Get(r.URL.Query().Get("url"))'] },
  ],
};

function build(spec) {
  const m = createModel({ template: DEFAULT_TEMPLATE, name: spec.name });
  syncModel(m, spec);
  generateThreats(m);
  return m;
}

const flowId = (m, name) => m.diagrams[0].elements.find((e) => e.name === name).id;
const classified = (m, cls) => m.threats.filter((t) => t.enriched?.class === cls);

test('parseEvidence splits file, line and snippet', () => {
  assert.deepEqual(parseEvidence('channels/api4/post.go:74 c.App.GetSinglePost'), { file: 'channels/api4/post.go', line: 74, snippet: 'c.App.GetSinglePost' });
  assert.deepEqual(parseEvidence('a/b.php:12-20 — snippet'), { file: 'a/b.php', line: 12, snippet: 'snippet' });
  assert.equal(parseEvidence('docker-compose.yml').line, undefined);
});

test('DVWA shell_exec → rce-sink with file + line evidence and an observed sink', () => {
  const m = build(DVWA_SPEC);
  const t = m.threats.find((x) => x.flowId === flowId(m, 'shell_exec of user-controlled IP') && x.enriched.class === 'rce-sink');
  assert.ok(t, 'classified');
  assert.equal(t.signal.level, 'high');
  assert.equal(t.enriched.specificTitle, 'Command / code injection sink (shell_exec) in vulnerabilities/exec/source/low.php');
  assert.deepEqual(t.enriched.evidence, [{ file: 'vulnerabilities/exec/source/low.php', line: 14, sink: 'command-exec' }]);
  assert.equal(t.enriched.confidence, 'observed-sink');
  assert.match(t.enriched.whyTest, /shell_exec at vulnerabilities\/exec\/source\/low\.php:14/);
  assert.equal(t.enriched.groupKey, 'rce-sink:os-shell');
  // Original rule text stays intact (MTMT compatibility).
  assert.doesNotMatch(t.title, /Command \/ code injection/);
  assert.equal(displayTitle(t), t.enriched.specificTitle);
  // Exactly one rce item per flow, not one per STRIDE category.
  assert.equal(m.threats.filter((x) => x.flowId === t.flowId && x.enriched.class === 'rce-sink').length, 1);
});

test('DVWA upload → unrestricted file upload; plain HTTP flow stays generic', () => {
  const m = build(DVWA_SPEC);
  const up = classified(m, 'upload');
  assert.equal(up.length, 1);
  assert.equal(up[0].enriched.evidence[0].line, 12);
  assert.equal(up[0].enriched.confidence, 'observed-sink');
  const plain = m.threats.filter((x) => x.flowId === flowId(m, 'Requests'));
  assert.ok(plain.every((x) => x.enriched.class === 'generic' && x.enriched.specificTitle === (x.signal.title || x.title)));
});

test('identical patterns collapse: two shell_exec flows into one OS shell are one item', () => {
  const m = build(DVWA_SPEC);
  const rce = classified(m, 'rce-sink');
  assert.equal(rce.length, 2);
  const [rep] = rce.filter((t) => t.enriched.duplicateOf === undefined);
  const dup = rce.find((t) => t !== rep);
  assert.equal(dup.enriched.duplicateOf, rep.id);
  assert.equal(rep.enriched.relatedFlows, 2);
  assert.deepEqual(rep.enriched.relatedThreats, [dup.id]);
  const sh = stakeholderSummary(m);
  assert.ok(sh.findings.some((f) => f.id === rep.id));
  assert.ok(!sh.findings.some((f) => f.id === dup.id), 'secondary is collapsed in the report');
  assert.ok(m.threats.includes(dup), 'secondary is kept in the model');
});

test('Mattermost IDOR: three post endpoints → one IDOR / BOLA item with 3 related flows', () => {
  const m = build(MATTERMOST_SPEC);
  const idor = classified(m, 'idor');
  assert.equal(idor.length, 3);
  assert.ok(idor.every((t) => t.enriched.groupKey === 'idor:posts' && t.enriched.confidence === 'hypothesized'));
  const rep = idor.find((t) => t.enriched.duplicateOf === undefined);
  assert.equal(rep.enriched.specificTitle, 'IDOR / BOLA on posts endpoints');
  assert.deepEqual(rep.enriched.evidence[0], { file: 'channels/api4/post.go', line: 74, sink: 'authorization-check' });
  assert.match(rep.enriched.whyTest, /without channel membership check/);
  assert.equal(rep.enriched.relatedFlows, 3);

  const md = renderMarkdownReport(m);
  const section = md.slice(md.indexOf('## High-signal findings'), md.indexOf('## Full threat register'));
  assert.equal(section.split('IDOR / BOLA on posts endpoints').length - 1, 1, 'collapsed to one block');
  assert.ok(section.includes('**Evidence:** channels/api4/post.go:74 (authorization-check)'));
  assert.ok(section.includes('**Confidence:** hypothesized'));
  assert.ok(section.includes('**Related flows:** 3'));
  assert.ok(section.includes('**Why test:**'));
  const html = renderHtmlReport(m);
  assert.ok(html.includes('<b>Related flows:</b> 3'));
  assert.ok(html.includes('channels/api4/post.go:74</code>'));
});

test('Mattermost WebSocket and SSRF classes', () => {
  const m = build(MATTERMOST_SPEC);
  const ws = classified(m, 'auth-bypass');
  assert.equal(ws.length, 1);
  assert.equal(ws[0].enriched.specificTitle, 'Inconsistent WebSocket authentication on API server');
  const ssrf = classified(m, 'ssrf');
  assert.equal(ssrf.length, 1);
  assert.equal(ssrf[0].enriched.specificTitle, 'SSRF in outbound request to Image proxy');
  assert.equal(ssrf[0].enriched.confidence, 'observed-sink');
  assert.equal(ssrf[0].signal.level, 'high', 'an evidence-backed class counts as a sink in the score');
  assert.ok(ssrf[0].signal.reasons.includes('specific class (ssrf)'));
});

test('a class hit without any file evidence is not promoted', () => {
  const m = build({
    elements: [
      { name: 'U', type: 'SE.EI.TMCore.User' },
      { name: 'App', type: 'SE.P.TMCore.WebApp' },
      { name: 'Remote', type: 'SE.EI.TMCore.WebSvc' },
    ],
    flows: [
      { name: 'Requests', from: 'U', to: 'App' },
      { name: 'fetch user-supplied webhook URL', from: 'App', to: 'Remote' },
    ],
  });
  assert.equal(classified(m, 'ssrf').length, 0);
});

test('CSRF only attaches to the CSRF rule on a cookie/session flow', () => {
  const m = build({
    zones: [{ name: 'DMZ', type: 'GE.TB.B' }],
    elements: [
      { name: 'Browser', type: 'SE.EI.TMCore.Browser' },
      { name: 'App', type: 'SE.P.TMCore.WebApp', zone: 'DMZ' },
    ],
    flows: [{ name: 'POST /account/email (session cookie)', from: 'Browser', to: 'App', evidence: ['app/routes/account.js:40 router.post("/account/email") uses session cookie'] }],
  });
  const csrf = classified(m, 'csrf');
  assert.equal(csrf.length, 1);
  assert.match(csrf[0].title, /Cross site request forgery/);
  assert.equal(csrf[0].enriched.specificTitle, 'CSRF on state-changing endpoint (account)');
});

test('user-edited titles still win over the specific title', () => {
  const m = build(MATTERMOST_SPEC);
  const rep = classified(m, 'idor').find((t) => t.enriched.duplicateOf === undefined);
  updateThreat(m, rep.key, { title: 'My IDOR' });
  assert.equal(displayTitle(m.threats.find((t) => t.key === rep.key)), 'My IDOR');
});

test('re-running generation and save/load keeps triage and only refreshes enriched', () => {
  const m = build(MATTERMOST_SPEC);
  const rep = classified(m, 'idor').find((t) => t.enriched.duplicateOf === undefined);
  updateThreat(m, rep.key, { state: 'NeedsInvestigation', justification: 'Repro on staging', custom: {} }, 'pentester');
  const before = m.threats.map((t) => `${t.id}|${t.key}|${t.state}|${t.justification}|${t.title}`);
  syncModel(m, MATTERMOST_SPEC);
  generateThreats(m);
  const back = loadModel(JSON.parse(serializeModel(m)));
  generateThreats(back);
  assert.deepEqual(back.threats.map((t) => `${t.id}|${t.key}|${t.state}|${t.justification}|${t.title}`), before);
  const again = back.threats.find((t) => t.key === rep.key);
  assert.equal(again.enriched.class, 'idor');
  assert.equal(again.changedBy, 'pentester');
});

test('triaging a classified threat does not move its class or finding to a sibling', () => {
  const m = build(DVWA_SPEC);
  const fid = flowId(m, 'shell_exec of user-controlled IP');
  const t = m.threats.find((x) => x.flowId === fid && x.enriched.class === 'rce-sink');
  for (const state of ['NeedsInvestigation', 'Mitigated', 'NotStarted']) {
    updateThreat(m, t.key, { state });
    const now = m.threats.find((x) => x.flowId === fid && x.enriched.class === 'rce-sink');
    assert.equal(now.key, t.key, state);
    assert.ok(now.signal.title, `signal finding stays put (${state})`);
  }
});

test('stable triage: elements re-created with new ids keep their threat triage', () => {
  const m = build(MATTERMOST_SPEC);
  const rep = classified(m, 'idor').find((t) => t.enriched.duplicateOf === undefined);
  const sk = stableKey(rep);
  assert.equal(rep.enriched.stableKey, sk);
  updateThreat(m, rep.key, { state: 'Mitigated', justification: 'Fixed in 9.1', custom: { ticket: 'SEC-42' } }, 'dev');
  const oldKey = rep.key;
  const oldId = rep.id;
  // Same architecture, but the agent now gives explicit ids → every element gets a new id.
  const withIds = structuredClone(MATTERMOST_SPEC);
  withIds.elements.forEach((e, i) => (e.id = `e${i}`));
  withIds.flows.forEach((f, i) => (f.id = `f${i}`));
  syncModel(m, withIds);
  const summary = generateThreats(m);
  assert.ok(summary.rematched > 0, 'threats were re-attached by stable key');
  assert.equal(summary.orphaned, 0);
  const t = m.threats.find((x) => x.id === oldId);
  assert.notEqual(t.key, oldKey, 'key follows the new element ids');
  assert.equal(t.state, 'Mitigated');
  assert.equal(t.justification, 'Fixed in 9.1');
  assert.equal(t.custom.ticket, 'SEC-42');
  assert.equal(t.enriched.class, 'idor');
  assert.ok(!t.orphan);
  assert.ok(!m.threats.some((x) => x.id !== oldId && stableKey(x) === sk), 'no duplicate NotStarted copy');
});

test('stable triage: a hand-drawn flow that is deleted and redrawn keeps its triage', () => {
  const m = createModel({ template: DEFAULT_TEMPLATE });
  const d = m.diagrams[0].id;
  const a = addElement(m, d, { type: 'SE.EI.TMCore.User', name: 'User', x: 0, y: 0 });
  const b = addElement(m, d, { type: 'SE.P.TMCore.WebApp', name: 'App', x: 400, y: 0 });
  const f = addElement(m, d, { type: 'GE.DF', name: 'Login', source: a.id, target: b.id });
  generateThreats(m);
  const t0 = m.threats[0];
  updateThreat(m, t0.key, { state: 'NotApplicable', justification: 'SSO only' });
  removeElements(m, [f.id]);
  addElement(m, d, { type: 'GE.DF', name: 'Login', source: a.id, target: b.id });
  generateThreats(m);
  const t = m.threats.find((x) => x.id === t0.id);
  assert.equal(t.state, 'NotApplicable');
  assert.equal(t.justification, 'SSO only');
  assert.ok(!t.orphan);
});

test('enriched fields reach JSON report and threat listing', () => {
  const m = build(MATTERMOST_SPEC);
  const json = JSON.parse(opReport(m, { format: 'json' }));
  const f = json.stakeholder.findings.find((x) => x.class === 'idor');
  assert.equal(f.relatedFlows, 3);
  assert.ok(json.stakeholder.collapsed >= 2);
  const list = opListThreats(m, { signal: 'high' });
  const v = list.threats.find((x) => x.enriched?.class === 'idor' && x.enriched.duplicateOf === undefined);
  assert.equal(v.displayTitle, 'IDOR / BOLA on posts endpoints');
  assert.equal(v.enriched.evidence[0].line, 74);
});

test('enriched text is escaped in HTML', () => {
  const m = build({
    elements: [
      { name: 'U', type: 'SE.EI.TMCore.User' },
      { name: '<img src=x onerror=alert(1)>', type: 'SE.P.TMCore.OSProcess' },
    ],
    flows: [{ name: 'system($_GET[<b>])', from: 'U', to: '<img src=x onerror=alert(1)>', evidence: ['a.php:1 <script>x</script>'] }],
  });
  assert.ok(classified(m, 'rce-sink').length);
  const html = renderHtmlReport(m);
  assert.ok(!html.includes('<img src=x'));
  assert.ok(!html.includes('<script>x'));
});

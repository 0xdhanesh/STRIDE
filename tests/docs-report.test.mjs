import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { ROOT, startServer } from '../scripts/static-server.mjs';
import { buildDocs } from '../scripts/build-docs.mjs';
import { opReport } from '../src/cli/ops.js';
import { DEFAULT_TEMPLATE, createModel, createSampleModel, executiveSummary, generateThreats, renderExecutiveReport, renderHtmlReport, resolveFont, syncModel, validateModel } from '../src/core/index.js';

test('executive report is plain language and carries no technical detail', () => {
  const m = createSampleModel();
  const html = renderExecutiveReport(m);
  assert.match(html, /Security risk summary for leadership/);
  assert.match(html, /Recommended action/);
  assert.doesNotMatch(html, /Related flows|Why test|Confidence|evidence:|\.php|\.py:\d/);
  assert.ok(html.includes('<svg'), 'shows the system picture');
  const s = executiveSummary(m);
  assert.ok(s.posture.label && s.top.length <= 5);
  for (const r of s.top) assert.ok(r.plain);
});

test('executive report escapes model text', () => {
  const m = createSampleModel();
  m.meta.name = '<img src=x onerror=alert(1)>';
  m.meta.description = '<script>alert(1)</script>';
  const html = renderExecutiveReport(m);
  assert.ok(!html.includes('<img src=x') && !html.includes('<script>alert'));
});

test('font choice applies to technical and executive reports; bad fonts are rejected', () => {
  const m = createSampleModel();
  for (const render of [renderExecutiveReport, renderHtmlReport]) {
    assert.ok(render(m, { font: 'verdana' }).includes('Verdana,Tahoma'));
    assert.ok(render(m, { font: 'Segoe UI' }).includes('"Segoe UI"'));
  }
  assert.ok(!renderHtmlReport(m).includes('font-family:Verdana'), 'default report is unchanged');
  assert.throws(() => resolveFont('x;}body{background:url(//evil)'), /Unknown font/);
  assert.throws(() => opReport(m, { format: 'exec', font: '</style><script>' }), /Unknown font/);
  assert.ok(opReport(m, { format: 'exec', font: 'georgia' }).includes('Georgia'));
});

test('documentation pages are current and every worked-example spec builds cleanly', () => {
  assert.deepEqual(buildDocs({ check: true }), []);
  const dir = path.join(ROOT, 'how-to-max/specs');
  const specs = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
  assert.ok(specs.length >= 4);
  for (const f of specs) {
    const m = createModel({ template: DEFAULT_TEMPLATE, name: f });
    const report = syncModel(m, JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')));
    generateThreats(m);
    assert.deepEqual(report.layoutWarnings, [], `${f} layout`);
    assert.deepEqual(validateModel(m).filter((x) => x.severity !== 'info'), [], `${f} validation`);
    assert.ok(m.threats.length > 20, `${f} produces threats`);
  }
});

test('/how-to, /what-is and /how-to-max are served', async () => {
  const { server, port } = await startServer(0);
  try {
    for (const p of ['how-to', 'what-is', 'how-to-max']) {
      const r = await fetch(`http://127.0.0.1:${port}/${p}`, { redirect: 'manual' });
      assert.equal(r.status, 301);
      const page = await fetch(`http://127.0.0.1:${port}/${p}/`);
      assert.equal(page.status, 200);
      assert.match(await page.text(), /<h1>/);
    }
  } finally {
    server.close();
  }
});

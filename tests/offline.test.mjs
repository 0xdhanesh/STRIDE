import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { diagramToSVG } from '../js/render.js';
import { buildReport } from '../js/io.js';
import { sampleModel } from '../js/sample.js';

test('runtime sources and exported reports have no external resources or network APIs', async () => {
  // Vendored libraries have optional networking APIs. Export tests separately
  // deny every network API and verify that the actual PDF path never calls one.
  const files = ['index.html', 'css/app.css', ...(await readdir('js')).filter((f) => f.endsWith('.js')).map((f) => `js/${f}`)];
  for (const path of files) {
    const source = await readFile(path, 'utf8');
    assert.doesNotMatch(source, /\b(?:fetch|sendBeacon)\s*\(|\bnew\s+(?:XMLHttpRequest|WebSocket|EventSource)\s*\(/, path);
    assert.doesNotMatch(source, /(?:src|href)=["']https?:|@import\s|url\(["']?https?:/, path);
  }
  const model = sampleModel();
  for (const output of [diagramToSVG(model.diagrams[0]), buildReport(model)]) {
    assert.doesNotMatch(output, /(?:src|href)=["']https?:|@import\s|url\(["']?https?:/);
  }
  assert.match(await readFile('index.html', 'utf8'), /connect-src 'none'/);
});

test('offline bundle contains all modules and assets, valid JavaScript, and matching CSP hash', async () => {
  execFileSync(process.execPath, ['scripts/build-offline.mjs']);
  const html = await readFile('dist/STRIDE.html', 'utf8');
  assert.doesNotMatch(html, /<script[^>]*\bsrc=|<link[^>]*href="(?:css\/|favicon\.svg)/);
  const script = /<script type="module">([\s\S]*)<\/script>/.exec(html)?.[1];
  assert.ok(script);
  assert.doesNotMatch(script, /^\s*(?:import|export)\s/gm);
  assert.ok(html.includes(`script-src 'sha256-${createHash('sha256').update(script).digest('base64')}'`));
  assert.match(html, /img-src data: blob:/);
  const syntax = spawnSync(process.execPath, ['--input-type=module', '--check'], { input: script, encoding: 'utf8' });
  assert.equal(syntax.status, 0, syntax.stderr);
  // Execute every bundled dependency before the DOM bootstrap to catch missing
  // exports and incorrect module ordering, without pretending to test a browser.
  const dependencies = script.slice(0, script.indexOf('// js/main.js\n'));
  const run = spawnSync(process.execPath, ['--input-type=module'], { input: dependencies, encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
});

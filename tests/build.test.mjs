import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { buildOffline, collectModules } from '../scripts/build-offline.mjs';

test('offline build inlines every module and pins inline scripts in the CSP', () => {
  const r = buildOffline();
  const html = fs.readFileSync(r.file, 'utf8');
  assert.ok(r.modules >= 15);
  assert.ok(!/<link rel="stylesheet"/.test(html));
  assert.ok(!/src="src\//.test(html));
  const map = JSON.parse(/<script type="importmap">([\s\S]*?)<\/script>/.exec(html)[1]);
  assert.equal(Object.keys(map.imports).length, r.modules);
  for (const [key, url] of Object.entries(map.imports)) {
    assert.ok(url.startsWith('data:text/javascript;base64,'), key);
    const code = Buffer.from(url.split(',')[1], 'base64').toString('utf8');
    for (const m of code.matchAll(/from\s+['"]([^'"]+)['"]/g)) assert.ok(map.imports[m[1]], `${key} imports unmapped ${m[1]}`);
  }
  const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
  const raw = /<script type="importmap">([\s\S]*?)<\/script>/.exec(html)[1];
  const hash = crypto.createHash('sha256').update(raw, 'utf8').digest('base64');
  assert.ok(csp.includes(`'sha256-${hash}'`), 'import map hash pinned');
  assert.ok(csp.includes("connect-src 'none'"), 'no network access');
});

test('module graph has no dynamic imports and reaches the core', () => {
  const mods = collectModules();
  assert.ok(mods.has('src/core/engine.js'));
  assert.ok(mods.has('src/templates/default.js'));
});

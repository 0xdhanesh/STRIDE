// Build dist/STRIDE.html: a single self-contained file that works offline from file://.
// ES modules are inlined as data: URLs behind an import map, CSS is inlined, and the
// Content-Security-Policy pins the two inline scripts by hash.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { ROOT } from './static-server.mjs';

const ENTRY = 'src/web/main.js';
const OUT = path.join(ROOT, 'dist', 'STRIDE.html');
const IMPORT_RE = /(\bimport\s+(?:[\s\S]*?\s+from\s+)?|\bexport\s+(?:\*(?:\s+as\s+\w+)?|\{[\s\S]*?\})\s+from\s+)(['"])(\.{1,2}\/[^'"]+)\2/g;

const toKey = (rel) => `stride/${rel.split(path.sep).join('/')}`;

export function collectModules(entry = ENTRY) {
  const modules = new Map();
  const visit = (rel) => {
    if (modules.has(rel)) return;
    const abs = path.join(ROOT, rel);
    let code = fs.readFileSync(abs, 'utf8');
    modules.set(rel, null);
    code = code.replace(IMPORT_RE, (m, head, q, spec) => {
      const dep = path.relative(ROOT, path.resolve(path.dirname(abs), spec));
      visit(dep);
      return `${head}${q}${toKey(dep)}${q}`;
    });
    if (/\bimport\s*\(/.test(code)) throw new Error(`Dynamic import() is not supported by the offline build: ${rel}`);
    modules.set(rel, code);
  };
  visit(entry);
  return modules;
}

const sha = (s) => `'sha256-${crypto.createHash('sha256').update(s, 'utf8').digest('base64')}'`;

export function buildOffline() {
  // Inline every referenced asset (assets/*.png|svg) as a data: URI so the file is self-contained.
  const dataUri = (rel) => {
    const ext = path.extname(rel).slice(1).toLowerCase();
    const mime = { png: 'image/png', svg: 'image/svg+xml', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp' }[ext];
    if (!mime) throw new Error(`Unsupported asset type: ${rel}`);
    return `data:${mime};base64,${fs.readFileSync(path.join(ROOT, rel)).toString('base64')}`;
  };
  const inlineAssets = (text) => text.replace(/assets\/[A-Za-z0-9._-]+\.(?:png|svg|jpe?g|webp)/g, (rel) => dataUri(rel));
  const modules = collectModules();
  const imports = {};
  for (const [rel, code0] of modules) {
    const code = inlineAssets(code0);
    imports[toKey(rel)] = `data:text/javascript;base64,${Buffer.from(code, 'utf8').toString('base64')}`;
  }
  const importMap = JSON.stringify({ imports });
  const boot = `import ${JSON.stringify(toKey(ENTRY))};`;
  const css = fs.readFileSync(path.join(ROOT, 'src/web/styles.css'), 'utf8');
  const csp = `default-src 'none'; script-src ${sha(importMap)} ${sha(boot)} data:; style-src 'unsafe-inline'; img-src data: blob:; connect-src 'none'; font-src data:; object-src 'none'; base-uri 'none'; form-action 'none'`;
  let html = inlineAssets(fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8'));
  html = html
    .replace(/<meta http-equiv="Content-Security-Policy"[^>]*>/, `<meta http-equiv="Content-Security-Policy" content="${csp}" />`)
    .replace(/<link rel="stylesheet"[^>]*>/, () => `<style>\n${css}\n</style>`)
    .replace(/<script type="module" src="[^"]*"><\/script>/, () => `<script type="importmap">${importMap}</script>\n    <script type="module">${boot}</script>`);
  if (!html.includes('type="importmap"')) throw new Error('index.html is missing the module script tag');
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, html);
  return { file: OUT, bytes: Buffer.byteLength(html), modules: modules.size };
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('build-offline.mjs')) {
  const r = buildOffline();
  console.log(`Built ${path.relative(ROOT, r.file)} (${(r.bytes / 1024).toFixed(0)} KB, ${r.modules} modules)`);
}

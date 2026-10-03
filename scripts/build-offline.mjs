// Dependency-free packaging for the project's named ES-module imports/exports.
// Produces one file that can be opened from disk, with no runtime asset loads.
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const modules = new Map();
const chunks = [];
async function bundle(path) {
  if (modules.has(path)) return modules.get(path);
  const name = `module_${modules.size}`;
  modules.set(path, name);
  let source = await readFile(path, 'utf8');
  for (const match of [...source.matchAll(/^import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"];?/gm)]) {
    if (!match[2].startsWith('./')) throw new Error(`Nonlocal import: ${match[2]}`);
    const dependency = await bundle(resolve(dirname(path), match[2]));
    source = source.replace(match[0], `const {${match[1].replace(/\bas\b/g, ':')}} = ${dependency};`);
  }
  const exports = [...source.matchAll(/^export\s+(?:async\s+)?(?:function|class|const|let)\s+(\w+)/gm)].map((m) => m[1]);
  source = source.replace(/^export\s+/gm, '');
  if (/^import\s/m.test(source)) throw new Error(`Unsupported import in ${path}`);
  chunks.push(`// ${relative(root, path)}\nconst ${name} = await (async () => {\n${source}\nreturn { ${exports.join(', ')} };\n})();`);
  return name;
}
await bundle(resolve(root, 'js/main.js'));
const script = chunks.join('\n').replace(/<\/script/gi, '<\\/script');
const hash = createHash('sha256').update(script).digest('base64');
let html = await readFile(resolve(root, 'index.html'), 'utf8');
html = html.replace("script-src 'self'", `script-src 'sha256-${hash}'`)
  .replace("style-src 'self' 'unsafe-inline'", "style-src 'unsafe-inline'")
  .replace("img-src 'self' data: blob:", 'img-src data: blob:');
const css = await readFile(resolve(root, 'css/app.css'), 'utf8');
html = html.replace('<link rel="stylesheet" href="css/app.css">', () => `<style>${css}</style>`);
const favicon = await readFile(resolve(root, 'favicon.svg'));
html = html.replace('href="favicon.svg"', `href="data:image/svg+xml;base64,${favicon.toString('base64')}"`)
  .replace('<script type="module" src="js/main.js"></script>', () => `<script type="module">${script}</script>`);
await mkdir(resolve(root, 'dist'), { recursive: true });
await writeFile(resolve(root, 'dist/STRIDE.html'), html);
console.log(`Built dist/STRIDE.html (${Math.round(Buffer.byteLength(html) / 1024)} KB). Open directly in a modern browser.`);

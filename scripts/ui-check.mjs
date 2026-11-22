// End-to-end UI check driven over the Chrome DevTools Protocol (no dependencies).
// Draws a diagram with real pointer/keyboard input and asserts on the app state.
//
//   node scripts/ui-check.mjs [--page index.html|dist/STRIDE.html] [--file] [--screenshot out.png]
//
// Set CHROME_PATH to choose the browser. Exits 0 with a notice when no Chrome is found
// (unless --require-browser is given).

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startServer } from './static-server.mjs';

const args = process.argv.slice(2);
const opt = (name, def) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : def;
};
const PAGE = opt('page', 'index.html');
const SHOT = opt('screenshot');
const REQUIRE = args.includes('--require-browser');
const FILE_URL = args.includes('--file');

function findChrome() {
  const candidates = [
    process.env.CHROME_PATH,
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  ].filter(Boolean);
  return candidates.find((p) => fs.existsSync(p));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function launch(chrome) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'stride-ui-'));
  const proc = spawn(chrome, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${dir}`, '--no-first-run', '--no-default-browser-check', '--window-size=1440,900', ...(process.env.CI ? ['--no-sandbox'] : []), 'about:blank'], { stdio: 'ignore' });
  const portFile = path.join(dir, 'DevToolsActivePort');
  for (let i = 0; i < 100 && !fs.existsSync(portFile); i++) await sleep(100);
  if (!fs.existsSync(portFile)) throw new Error('Chrome did not start');
  const port = fs.readFileSync(portFile, 'utf8').split('\n')[0].trim();
  return { proc, dir, port };
}

/** Terminate Chrome and wait for it to exit (SIGKILL after a grace period). */
async function stopChrome(proc) {
  if (proc.exitCode !== null || proc.signalCode !== null) return;
  const exited = new Promise((r) => proc.once('exit', r));
  proc.kill('SIGTERM');
  const timer = setTimeout(() => proc.kill('SIGKILL'), 3000);
  await exited;
  clearTimeout(timer);
  await sleep(300);
}

class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.listeners = [];
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
      } else if (msg.method) for (const l of this.listeners) l(msg);
    });
  }
  send(method, params = {}) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
  }
  on(fn) {
    this.listeners.push(fn);
  }
}

async function main() {
  const chrome = findChrome();
  if (typeof globalThis.WebSocket !== 'function') {
    // Global WebSocket is built in from Node 22 (needed to talk to Chrome over CDP).
    console.log(`ui-check: this Node.js (${process.version}) has no global WebSocket; use Node 22+ to run the browser check. Skipping.`);
    process.exit(REQUIRE ? 1 : 0);
  }
  if (!chrome) {
    console.log('ui-check: no Chrome/Chromium found (set CHROME_PATH); skipping.');
    process.exit(REQUIRE ? 1 : 0);
  }
  const { server, port } = await startServer(0);
  const { proc, dir, port: dport } = await launch(chrome);
  let failures = 0;
  const check = (cond, msg) => {
    console.log(`${cond ? 'ok  ' : 'FAIL'} ${msg}`);
    if (!cond) failures++;
  };
  try {
    const target = await (await fetch(`http://127.0.0.1:${dport}/json/new?about:blank`, { method: 'PUT' })).json();
    const ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((r, j) => {
      ws.addEventListener('open', r);
      ws.addEventListener('error', j);
    });
    const cdp = new Cdp(ws);
    const errors = [];
    cdp.on((m) => {
      if (m.method === 'Runtime.exceptionThrown') errors.push(m.params.exceptionDetails?.exception?.description || m.params.exceptionDetails?.text);
      if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') errors.push(m.params.args.map((a) => a.value ?? a.description).join(' '));
    });
    await cdp.send('Runtime.enable');
    await cdp.send('Page.enable');
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
    const url = FILE_URL ? `file://${path.resolve(PAGE)}` : `http://127.0.0.1:${port}/${PAGE}`;
    await cdp.send('Page.navigate', { url });

    const evaluate = async (expr) => {
      const r = await cdp.send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(`eval failed: ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}`);
      return r.result.value;
    };
    for (let i = 0; i < 100; i++) {
      if (await evaluate('!!window.__stride').catch(() => false)) break;
      await sleep(100);
    }
    check(await evaluate('!!window.__stride'), `app booted (${url})`);
    check((await evaluate('__stride.store.model.threats.length')) > 0, 'example model loaded with threats on first run');

    const mouse = (type, x, y, extra = {}) => cdp.send('Input.dispatchMouseEvent', { type, x, y, button: 'left', buttons: type === 'mouseReleased' ? 0 : 1, clickCount: 1, ...extra });
    const click = async (x, y) => {
      await mouse('mousePressed', x, y);
      await mouse('mouseReleased', x, y);
      await sleep(80);
    };
    const drag = async (x0, y0, x1, y1) => {
      await mouse('mousePressed', x0, y0);
      for (let i = 1; i <= 8; i++) await mouse('mouseMoved', x0 + ((x1 - x0) * i) / 8, y0 + ((y1 - y0) * i) / 8);
      await mouse('mouseReleased', x1, y1);
      await sleep(120);
    };
    const key = async (k, modifiers = 0) => {
      const code = k.length === 1 ? (/\d/.test(k) ? `Digit${k}` : `Key${k.toUpperCase()}`) : k;
      await cdp.send('Input.dispatchKeyEvent', { type: 'keyDown', key: k, code, modifiers, text: k.length === 1 && !modifiers ? k : undefined });
      await cdp.send('Input.dispatchKeyEvent', { type: 'keyUp', key: k, code, modifiers });
      await sleep(60);
    };
    const type = async (text) => {
      await cdp.send('Input.insertText', { text });
      await key('Enter');
    };

    // Fresh model with a fixed camera so screen coordinates are predictable.
    await evaluate(`(() => { const s = __stride.store; s.setModel(__stride.core.createModel({ template: __stride.core.DEFAULT_TEMPLATE, name: 'UI check' })); const c = __stride.ui.canvas.cam; c.x = 0; c.y = 0; c.z = 1; c.fresh = false; __stride.ui.canvas.render(); })()`);
    const stage = await evaluate(`(() => { const r = document.getElementById('canvas').getBoundingClientRect(); return { x: r.left, y: r.top }; })()`);
    const S = (x, y) => [stage.x + x, stage.y + y];
    const count = () => evaluate('__stride.store.diagram.elements.length');

    await key('2');
    await click(...S(200, 250));
    await type('Web App');
    await key('3');
    await click(...S(560, 250));
    await type('Customer');
    check((await count()) === 2, 'placed a process and an external interactor with keyboard tools');
    check((await evaluate('__stride.store.diagram.elements.map(e => e.name).join(",")')) === 'Web App,Customer', 'inline rename after placing shapes');

    await key('5');
    await drag(...S(560, 250), ...S(200, 250));
    await type('Login');
    const flow = await evaluate(`(() => { const d = __stride.store.diagram; const f = d.elements.find(e => e.generic === 'GE.DF'); const by = id => d.elements.find(e => e.id === id)?.name; return f && { name: f.name, s: by(f.source), t: by(f.target) }; })()`);
    check(flow && flow.s === 'Customer' && flow.t === 'Web App' && flow.name === 'Login', `drew a bound data flow by dragging (${JSON.stringify(flow)})`);

    await key('7');
    await drag(...S(100, 160), ...S(330, 360));
    await key('Escape');
    await sleep(400);
    const titles = await evaluate('__stride.store.model.threats.map(t => t.typeId + ":" + t.title)');
    check(titles.some((t) => t.startsWith('S3:') && t.includes('Customer')), 'threats generated for the interaction (S3 spoofing Customer)');
    check(titles.some((t) => t.startsWith('D3:')), 'boundary-dependent threat (D3) appears after drawing a box boundary across the flow');
    const crossBefore = titles.length;

    // Undo the boundary: boundary-dependent threats disappear.
    await key('z', process.platform === 'darwin' ? 4 : 2);
    await sleep(400);
    const afterUndo = await evaluate('__stride.store.model.threats.map(t => t.typeId)');
    check(afterUndo.length < crossBefore && !afterUndo.includes('D3'), `undo removes the boundary and its threats (${crossBefore} → ${afterUndo.length})`);
    await key('z', (process.platform === 'darwin' ? 4 : 2) | 8);
    await sleep(400);
    check((await evaluate('__stride.store.model.threats.length')) === crossBefore, 'redo restores them');

    // Triage survives moving and renaming.
    await evaluate(`(() => { const s = __stride.store; const t = s.model.threats.find(x => x.typeId === 'S3'); s.commit(m => __stride.core.updateThreat(m, t.key, { state: 'Mitigated', justification: 'MFA' }, 'ui')); })()`);
    await key('Escape');
    await drag(...S(200, 250), ...S(200, 420));
    const moved = await evaluate(`__stride.store.diagram.elements.find(e => e.name === 'Web App').y`);
    check(moved > 300, `drag-moved the process (y=${moved})`);
    await sleep(400);
    const s3 = await evaluate(`__stride.store.model.threats.find(t => t.typeId === 'S3')`);
    check(s3 && s3.state === 'Mitigated' && s3.justification === 'MFA', 'triage preserved after moving elements');

    // Delete the external interactor: flow detaches, validation reports it.
    await click(...S(560, 250));
    await key('Delete');
    await sleep(400);
    const msgs = await evaluate('__stride.store.messages.map(m => m.issue)');
    check(msgs.includes('flow.unconnected'), 'deleting a shape leaves a loose flow that validation reports');

    // Panels respond.
    check((await evaluate(`document.querySelectorAll('.stencil').length`)) > 40, 'stencil palette lists template element types');
    await evaluate(`document.querySelector('.seg button:nth-child(2)').click()`);
    await sleep(200);
    check((await evaluate('document.getElementById("app").dataset.view')) === 'analyze', 'Analyze view toggles');

    // High-signal view: an evidence-backed shell_exec flow ranks first with a specific title.
    await evaluate(`(() => {
      const c = __stride.core; const m = c.createModel({ template: c.DEFAULT_TEMPLATE, name: 'Signal check' });
      c.syncModel(m, { elements: [{ name: 'User', type: 'SE.EI.TMCore.User' }, { name: 'App', type: 'SE.P.TMCore.WebApp' }, { name: 'Shell', type: 'SE.P.TMCore.OSProcess' }],
        flows: [{ name: 'Ping', from: 'User', to: 'App' }, { name: 'shell_exec of user-controlled IP', from: 'App', to: 'Shell', evidence: ['exec/low.php:14'] }] });
      __stride.store.setModel(m); __stride.store.processNow(); __stride.ui.drawer.filters.scope = 'all'; __stride.ui.drawer.show('threats');
    })()`);
    await sleep(300);
    const allRows = await evaluate(`document.querySelectorAll('.table-wrap tbody tr').length`);
    await evaluate(`document.getElementById('hsview').click()`);
    await sleep(200);
    const hs = await evaluate(`(() => ({ rows: document.querySelectorAll('.table-wrap tbody tr').length, high: __stride.store.model.threats.filter(t => t.signal?.level === 'high').length, first: document.querySelector('.table-wrap tbody tr td.title')?.textContent || '' }))()`);
    check(hs.rows === hs.high && hs.rows > 0 && hs.rows < allRows && hs.first.startsWith('Command injection via shell_exec'), `high-signal view filters and ranks threats (${allRows} → ${hs.rows}, first: ${hs.first.slice(0, 60)})`);

    if (SHOT) {
      await evaluate(`(() => { __stride.store.setModel(__stride.core.createSampleModel()); __stride.ui.canvas.zoomToFit(); })()`);
      await sleep(500);
      const { data } = await cdp.send('Page.captureScreenshot', { format: 'png' });
      fs.writeFileSync(SHOT, Buffer.from(data, 'base64'));
      console.log(`screenshot: ${SHOT}`);
    }
    check(errors.length === 0, `no page errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
    ws.close();
  } finally {
    server.close();
    await stopChrome(proc);
    // Best effort: Chrome helpers can still be flushing the profile; never fail the run over cleanup.
    try {
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
    } catch (e) {
      console.log(`note: could not remove temporary profile ${dir} (${e.code || e.message})`);
    }
  }
  if (failures) {
    console.log(`\n${failures} UI check(s) failed`);
    process.exit(1);
  }
  console.log('\nUI checks passed');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

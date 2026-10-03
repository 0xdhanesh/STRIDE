import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createReport, buildMarkdown } from '../js/reports.js';
import { buildPDF } from '../js/pdf-report.js';
import { readModelFile, exportReport, buildReport } from '../js/io.js';
import { normalizeModel, newDiagram } from '../js/store.js';
import { sampleModel } from '../js/sample.js';
import { syncThreats } from '../js/engine.js';
import { updateThreat } from '../js/threats.js';

function fixture() {
  const m = normalizeModel(sampleModel()); syncThreats(m);
  m.diagrams.push(newDiagram('Empty second diagram'));
  for (const t of Object.values(m.threats)) {
    updateThreat(t, 'status', 'mitigated');
    updateThreat(t, 'notes', 'Verified\nEvidence BANK-042');
    updateThreat(t, 'owner', 'Payments Security');
    updateThreat(t, 'mitigation', 'Mutual TLS and least privilege');
  }
  const id = m.nextThreatId++;
  m.threats.orphan = { ...structuredClone(Object.values(m.threats)[0]), id, key: 'orphan', auto: false, diagramId: 'deleted-diagram', flowId: 'deleted-flow', orphan: true, title: 'Retained finding after diagram deletion' };
  m.auditExtension = { unicode: 'نموذج', nested: [1, false, { unchanged: true }] };
  return m;
}

test('report JSON restores the full model losslessly, without trusting derived report content', async () => {
  const m = fixture(), before = structuredClone(m);
  const bundle = createReport(m, { generatedAt: '2026-10-03T12:00:00Z' });
  assert.deepEqual(m, before);
  assert.equal(bundle.report.rules.length, 81);
  assert.equal(bundle.report.diagrams.length, 2);
  for (const d of bundle.report.diagrams) {
    assert.match(d.image.svg, /<svg/);
    assert.equal(d.elements.length, m.diagrams.find((x) => x.id === d.id).elements.length);
  }
  const loaded = await readModelFile({ name: 'report.json', text: async () => JSON.stringify(bundle) });
  assert.deepEqual(loaded, m);
  assert.deepEqual(createReport(loaded, { generatedAt: bundle.report.generatedAt }), bundle);
  bundle.report = { image: 'https://example.test/untrusted' };
  assert.deepEqual(await readModelFile({ name: 'report.json', text: async () => JSON.stringify(bundle) }), m);
  bundle.version = 999;
  await assert.rejects(readModelFile({ name: 'report.json', text: async () => JSON.stringify(bundle) }), /Unsupported report version/);
});

test('all threats occur exactly once in category/interaction groups, including orphaned diagrams', () => {
  const m = fixture();
  for (const t of Object.values(m.threats)) if (t.flowId === 'f_1' || t.flowId === 'f_2') t.interaction = 'Identical interaction label';
  const b = createReport(m), grouped = b.report.categories.flatMap((c) => c.interactions.flatMap((g) => g.threats));
  assert.equal(grouped.length, Object.keys(m.threats).length);
  assert.equal(new Set(grouped.map((t) => t.key)).size, grouped.length);
  const groups = b.report.categories[0].interactions;
  assert.ok(groups.some((g) => g.interactionId === 'f_1'));
  assert.ok(groups.some((g) => g.interactionId === 'f_2'));
  assert.ok(groups.some((g) => g.diagramName === 'No current diagram'));
  assert.equal(b.report.summary.open, 0);
});

test('Markdown embeds every image and escapes untrusted Markdown, HTML and tables', () => {
  const m = fixture();
  m.meta.title = '<img src="https://example.test/leak">';
  Object.values(m.threats)[0].notes = '![leak](https://example.test) | col\n# heading';
  const b = createReport(m), md = buildMarkdown(b);
  assert.equal((md.match(/!\[Diagram\]\(data:image\/svg\+xml/g) || []).length, 2);
  assert.equal((md.match(/^##### Threat /gm) || []).length, Object.keys(m.threats).length);
  assert.ok(md.includes('Trust Boundary'));
  assert.ok(md.includes('Retained finding after diagram deletion'));
  assert.ok(md.includes('\\!\\[leak\\]\\('));
  assert.doesNotMatch(md, /<img|!\[leak\]|^# heading/m);
  const svgURI = /!\[Diagram\]\((data:[^)]+)\)/.exec(md)[1];
  assert.equal(decodeURIComponent(svgURI.split(',').slice(1).join(',')), b.report.diagrams[0].image.svg);
  assert.ok(buildReport(m).includes('Retained finding after diagram deletion'));
});

test('real PDF generation works with every network API denied and rejects URL resources', () => {
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', `
    let calls = 0;
    const denied = () => { calls++; throw new Error('Network forbidden'); };
    globalThis.fetch = denied; globalThis.XMLHttpRequest = denied; globalThis.WebSocket = denied;
    globalThis.EventSource = denied;
    const { createReport } = await import('./js/reports.js');
    const { buildPDF } = await import('./js/pdf-report.js');
    const { pdfMake } = await import('./js/vendor/pdfmake.js');
    const { sampleModel } = await import('./js/sample.js');
    const bytes = await buildPDF(createReport(sampleModel()));
    if (new TextDecoder().decode(bytes.slice(0,5)) !== '%PDF-') throw new Error('Invalid PDF');
    try { await pdfMake.createPdf({content:[{image:'blocked'}],images:{blocked:'https://example.test/leak.png'}}).getBuffer(); throw new Error('URL was allowed'); }
    catch (e) { if (e.message === 'URL was allowed') throw e; }
    if (calls) throw new Error('Network attempted');
    console.log('PDF generated offline; URL blocked before network');
  `], { encoding: 'utf8', timeout: 20000 });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /PDF generated offline/);
});

test('PDF supports multi-page notes and rejects unsupported glyphs instead of losing text', async () => {
  const b = createReport(fixture());
  b.report.categories[0].interactions[0].threats[0].notes = 'Long evidence paragraph with a traceable reference. '.repeat(450);
  const pdf = await buildPDF(b);
  assert.ok(pdf.length > 30000);
  assert.match(new TextDecoder().decode(pdf.slice(0, 8)), /^%PDF-/);
  b.model.meta.title = 'Unsupported character: 漢';
  await assert.rejects(buildPDF(b), /PDF font does not support U\+6F22/);
});

test('export actions download local PDF, Markdown and JSON with the correct extensions', async () => {
  const saved = [], originalDocument = globalThis.document, originalURL = URL.createObjectURL;
  let currentBlob;
  try {
    URL.createObjectURL = (blob) => { currentBlob = blob; return 'blob:local'; };
    globalThis.document = { body: { appendChild() {} }, createElement: () => ({ click() { saved.push({ name: this.download, blob: currentBlob }); }, remove() {} }) };
    for (const format of ['pdf', 'markdown', 'json']) await exportReport(fixture(), format);
    assert.deepEqual(saved.map((x) => x.name.split('.').pop()), ['pdf', 'md', 'json']);
    assert.equal(saved[0].blob.type, 'application/pdf');
    assert.equal(JSON.parse(await saved[2].blob.text()).format, 'stride-report');
  } finally { globalThis.document = originalDocument; URL.createObjectURL = originalURL; }
});

test('vendored PDF assets match their recorded integrity hashes', async () => {
  const manifest = JSON.parse(await readFile('js/vendor/manifest.json', 'utf8'));
  for (const [file, hash] of Object.entries(manifest.sha256)) {
    assert.equal(createHash('sha256').update(await readFile(`js/vendor/${file}`)).digest('hex'), hash, file);
  }
});

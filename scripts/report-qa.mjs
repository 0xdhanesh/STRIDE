// Development-only fixtures; no dependencies or network access required.
import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { sampleModel } from '../js/sample.js';
import { normalizeModel } from '../js/store.js';
import { syncThreats, threatList } from '../js/engine.js';
import { updateThreat } from '../js/threats.js';
import { createReport, buildMarkdown } from '../js/reports.js';
import { buildPDF } from '../js/pdf-report.js';
import { readModelFile, serializeModel } from '../js/io.js';

// This exercises app logic and actual file bytes, not browser UI or native
// IndexedDB. Those checks are documented separately in REVIEW.md.
let networkCalls = 0;
const denyNetwork = () => { networkCalls++; throw new Error('Network forbidden during acceptance checks'); };
for (const api of ['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource']) globalThis[api] = denyNetwork;

await mkdir('tmp/pdfs', { recursive: true });
await mkdir('output/pdf', { recursive: true });
const model = normalizeModel(sampleModel());
syncThreats(model);
const threats = threatList(model);
assert.ok(threats.length > 0, 'Fixture must generate threats');
for (const threat of threats) {
  updateThreat(threat, 'status', 'mitigated');
  updateThreat(threat, 'owner', 'Payments Security');
  updateThreat(threat, 'notes', 'Verified in security review. Evidence BANK-042.');
  updateThreat(threat, 'mitigation', 'Mutual TLS, least privilege and monitored audit logs.');
}
const reviewSnapshot = (m) => threatList(m).map((t) => Object.fromEntries(
  ['id', 'key', 'status', 'severity', 'notes', 'owner', 'mitigation', 'justification', 'created', 'modified'].map((key) => [key, t[key]])
));
const before = reviewSnapshot(model);
syncThreats(model);
assert.deepEqual(reviewSnapshot(model), before, 'Regeneration changed review decisions or identity');
const modelPath = 'output/pdf/stride-example-model.stride';
await writeFile(modelPath, serializeModel(model));
const reopened = await readModelFile({ name: modelPath, text: () => readFile(modelPath, 'utf8') });
assert.deepEqual(reopened, model, 'Local save/reopen changed the model');
const bundle = createReport(reopened);
assert.equal(bundle.report.summary.open, 0);
assert.equal(bundle.report.summary.byStatus.mitigated, threats.length);
const grouped = bundle.report.categories.flatMap((c) => c.interactions.flatMap((g) => g.threats));
assert.deepEqual(grouped.map((t) => t.key).sort(), threats.map((t) => t.key).sort(), 'Report lost or duplicated threats');
await writeFile('tmp/pdfs/example-report.json', JSON.stringify(bundle, null, 2));
const restoredReport = await readModelFile({ name: 'example-report.json', text: () => readFile('tmp/pdfs/example-report.json', 'utf8') });
assert.deepEqual(restoredReport, model, 'Report JSON changed the editable model');
const markdown = buildMarkdown(bundle);
assert.equal((markdown.match(/^##### Threat /gm) || []).length, threats.length);
await writeFile('tmp/pdfs/example.md', markdown);
await writeFile('output/pdf/stride-example-report.pdf', await buildPDF(bundle));
assert.deepEqual(reopened, model, 'Export mutated the model');
const stress = structuredClone(model);
Object.values(stress.threats)[0].notes = Array.from({ length: 450 }, (_, i) => `Evidence-${String(i + 1).padStart(4, '0')}: Long evidence paragraph with a traceable reference.`).join('\n') + '\nEND-OF-LONG-NOTES';
await writeFile('tmp/pdfs/long-notes.pdf', await buildPDF(createReport(stress)));
assert.equal(networkCalls, 0, 'App attempted a network request');
console.log(`PASS: ${threats.length} reviewed threats survived regeneration, local .stride save/reopen, and report JSON restoration; Markdown and PDF generated with zero network API calls.`);
console.log('Generated sample and 450-paragraph stress PDFs. Run scripts/verify-report-pdf.py with PyMuPDF for content/layout checks.');

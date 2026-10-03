// Development-only fixtures; no dependencies or network access required.
import { mkdir, writeFile } from 'node:fs/promises';
import { sampleModel } from '../js/sample.js';
import { normalizeModel } from '../js/store.js';
import { syncThreats } from '../js/engine.js';
import { updateThreat } from '../js/threats.js';
import { createReport, buildMarkdown } from '../js/reports.js';
import { buildPDF } from '../js/pdf-report.js';

await mkdir('tmp/pdfs', { recursive: true });
await mkdir('output/pdf', { recursive: true });
const model = normalizeModel(sampleModel());
syncThreats(model);
for (const threat of Object.values(model.threats)) {
  updateThreat(threat, 'status', 'mitigated');
  updateThreat(threat, 'owner', 'Payments Security');
  updateThreat(threat, 'notes', 'Verified in security review. Evidence BANK-042.');
  updateThreat(threat, 'mitigation', 'Mutual TLS, least privilege and monitored audit logs.');
}
const bundle = createReport(model, { generatedAt: '2026-10-03T12:00:00Z' });
await writeFile('tmp/pdfs/example-report.json', JSON.stringify(bundle, null, 2));
await writeFile('tmp/pdfs/example.md', buildMarkdown(bundle));
await writeFile('output/pdf/stride-example-report.pdf', await buildPDF(bundle));
const stress = structuredClone(model);
Object.values(stress.threats)[0].notes = Array.from({ length: 450 }, (_, i) => `Evidence-${String(i + 1).padStart(4, '0')}: Long evidence paragraph with a traceable reference.`).join('\n') + '\nEND-OF-LONG-NOTES';
await writeFile('tmp/pdfs/long-notes.pdf', await buildPDF(createReport(stress)));
console.log('Generated sample and 450-paragraph stress PDFs. Run scripts/verify-report-pdf.py with PyMuPDF for content/layout checks.');

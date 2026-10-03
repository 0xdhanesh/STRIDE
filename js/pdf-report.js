import { pdfMake } from './vendor/pdfmake.js';
import { pdfFonts } from './vendor/fonts.js';
import { STRIDE } from './stencils.js';
import { STATUSES, STATUS_LABELS } from './threats.js';
import { elementDetails, threatDetails } from './reports.js';
import { fontCoverage } from './vendor/font-coverage.js';

pdfMake.addVirtualFileSystem(pdfFonts);
// Defense in depth: the library must reject URL resources even outside our CSP.
pdfMake.setUrlAccessPolicy(() => false);

const text = (value) => (String(value ?? '').replace(/→/g, '->').replace(/[–—]/g, '-') || '-');
const heading = (value, level = 1) => ({ text: value, style: `h${level}`, headlineLevel: level });
const table = (body, widths, options = {}) => ({
  table: { headerRows: 1, widths, body, ...options },
  layout: {
    fillColor: (row) => row === 0 ? '#edf0f8' : null,
    hLineWidth: () => 0.5, vLineWidth: () => 0,
    hLineColor: () => '#dce0e8', paddingLeft: () => 7, paddingRight: () => 7,
    paddingTop: () => 6, paddingBottom: () => 6,
  }, margin: [0, 4, 0, 12],
});

export function pdfDefinition(bundle) {
  const { model, report } = bundle;
  let interactionIndex = 0;
  const content = [
    { text: 'STRIDE / THREAT MODEL REPORT', fontSize: 10, color: '#5753a8', bold: true, margin: [0, 8, 0, 14] },
    { text: text(model.meta.title), fontSize: 25, bold: true, margin: [0, 0, 0, 10] },
    { text: `Generated ${report.generatedAt}\n${report.summary.total} threats / ${report.diagrams.length} diagrams / ${report.rules.length} rules`, color: '#596273', margin: [0, 0, 0, 18] },
    ...Object.entries(model.meta).filter(([key]) => key !== 'title').map(([key, value]) => ({ text: [{ text: `${key.charAt(0).toUpperCase() + key.slice(1)}: `, bold: true }, text(value)], margin: [0, 0, 0, 6] })),
    heading('Review summary'),
    table([
      ['STRIDE category', ...STATUSES.map((s) => STATUS_LABELS[s]), 'Total'].map((t) => ({ text: t, bold: true })),
      ...STRIDE.map((c) => [c.name, ...STATUSES.map((s) => String(report.summary.byCatStatus[c.key][s])), String(report.summary.byCat[c.key])]),
      ['Total', ...STATUSES.map((s) => String(report.summary.byStatus[s])), String(report.summary.total)],
    ], ['*', 43, 49, 46, 65, 28]),
    { text: `Includes ${report.summary.orphaned} orphaned records. Accepted and not applicable threats remain distinct from mitigated threats.`, color: '#596273', margin: [0, 0, 0, 10] },
  ];
  if (report.validation.length) content.push(heading('Validation observations', 2), ...report.validation.map((v) => ({ text: `• ${v.text}`, margin: [0, 0, 0, 4] })));
  for (const d of report.diagrams) {
    content.push({ ...heading(`Diagram: ${d.name}`), pageBreak: 'before' },
      { text: `Diagram ID: ${d.id}`, style: 'small' },
      { svg: d.image.svg.replace(/font-family="[^"]*"/g, 'font-family="Roboto"').replace(/→/g, '-&gt;').replace(/[–—]/g, '-'), fit: [499, 420], margin: [0, 10, 0, 12] },
      heading('Elements and security properties', 2),
      table([
        ['Element / ID', 'Type / stencil', 'Properties, scope and notes'].map((t) => ({ text: t, bold: true })),
        ...d.elements.map((e) => [text(e.name) + '\n' + e.id, e.typeLabel + '\n' + text(e.subtype), elementDetails(e)]),
        ...(!d.elements.length ? [['No elements', '', '']] : []),
      ], [110, 85, '*']),
    );
  }
  for (const c of report.categories) {
    content.push({ ...heading(`${c.key} / ${c.name}`), pageBreak: 'before' });
    if (!c.interactions.length) content.push({ text: 'No recorded threats in this category.', color: '#596273' });
    for (const group of c.interactions) {
      const groupId = `interaction-${interactionIndex++}`;
      content.push({ ...heading('', 2), id: groupId, text: [
        { text: text(`${group.diagramName} / ${group.label}`) },
        { text: `\nInteraction ID: ${group.interactionId || 'General'}`, fontSize: 8, bold: false, color: '#596273' },
      ] });
      for (const t of group.threats) {
        const fields = threatDetails(t);
        const summary = fields.slice(0, 4).map(([label, value]) => `${label}: ${text(value)}`).join('  |  ');
        const body = [
          { text: summary, fontSize: 8, color: '#596273', margin: [0, 0, 0, 7], ...(t === group.threats[0] ? { id: `${groupId}-first-threat` } : {}) },
          ...fields.slice(4, 9).filter(([, value]) => value).map(([label, value]) => ({ text: [{ text: `${label}: `, bold: true }, text(value)], margin: [0, 0, 0, 5] })),
          { text: fields.slice(9).map(([label, value]) => `${label}: ${text(value)}`).join('\n'), fontSize: 7, color: '#596273' },
        ];
        const estimatedHeight = 65 + fields.reduce((n, [, v]) => n + String(v || '').split('\n').reduce((a, line) => a + Math.max(1, Math.ceil(line.length / 75)) * 12, 0), 0);
        content.push(table([
          [{ text: text(`Threat ${t.id}: ${t.title}`), bold: true }],
          [{ stack: body }],
        ], ['*'], { dontBreakRows: estimatedHeight < 620, keepWithHeaderRows: estimatedHeight < 620 ? 1 : 0 }));
      }
    }
  }
  return {
    info: { title: text(model.meta.title), author: text(model.meta.owner), subject: 'STRIDE threat model audit report', creator: 'STRIDE Threat Modeler (local export)' },
    pageSize: 'A4', pageMargins: [40, 48, 40, 45],
    defaultStyle: { font: 'Roboto', fontSize: 9, lineHeight: 1.15, color: '#222b3a' },
    styles: { h1: { fontSize: 18, bold: true, margin: [0, 15, 0, 10], color: '#343164' }, h2: { fontSize: 11, bold: true, margin: [0, 10, 0, 6] }, small: { fontSize: 8, color: '#596273', margin: [0, 0, 0, 5] } },
    header: { id: 'running-header', text: 'STRIDE / THREAT MODEL REPORT', fontSize: 8, color: '#687085', margin: [40, 22, 40, 0] },
    footer: (page, pages) => ({ id: 'running-footer', columns: [{ id: 'running-footer-label', text: 'Local export · Review snapshot' }, { id: 'running-footer-page', text: `Page ${page} of ${pages}`, alignment: 'right' }], fontSize: 8, color: '#687085', margin: [40, 12, 40, 0] }),
    pageBreakBefore: (node, container) => {
      if (!node.headlineLevel) return false;
      const following = container.getFollowingNodesOnPage();
      // Running headers/footers are appended to the layout node list. They
      // cannot count as content following a heading at the end of a page.
      // Use the first body paragraph: repeated table titles retain positions
      // from the final continuation page, not necessarily the starting page.
      if (node.id?.startsWith('interaction-')) return !following.some((n) => n.id === `${node.id}-first-threat`);
      return !following.some((n) => !n.id?.startsWith('running-'));
    },
    content,
  };
}

export async function buildPDF(bundle) {
  const definition = pdfDefinition(bundle);
  // Never silently emit missing-glyph boxes in an audit report. The printable
  // HTML export uses system fonts for scripts outside the bundled font coverage.
  const check = (value) => {
    for (const char of text(value)) {
      const cp = char.codePointAt(0);
      if (/\s/u.test(char) || fontCoverage.some(([a, b]) => cp >= a && cp <= b)) continue;
      throw new Error(`PDF font does not support U+${cp.toString(16).toUpperCase()}. Use Printable HTML report and Save as PDF for system-font rendering.`);
    }
  };
  const walk = (node) => {
    if (typeof node === 'string') { check(node); return text(node); }
    if (Array.isArray(node)) return node.map(walk);
    if (!node || typeof node !== 'object') return node;
    if (node.text != null) node.text = walk(node.text);
    if (node.stack) node.stack = walk(node.stack);
    if (node.table) node.table.body = walk(node.table.body);
    return node;
  };
  definition.content = walk(definition.content);
  for (const d of bundle.report.diagrams) for (const e of d.elements) check(e.name);
  return new Uint8Array(await pdfMake.createPdf(definition).getBuffer());
}

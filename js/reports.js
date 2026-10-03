// A single immutable report snapshot shared by every export format.
import { normalizeModel } from './store.js';
import { activeRules, threatList, threatStats, validate } from './engine.js';
import { STRIDE, STENCILS } from './stencils.js';
import { STATUSES, STATUS_LABELS, threatStatus, threatSeverity, contributingFlowText } from './threats.js';
import { diagramToSVG } from './render.js';
import { esc } from './util.js';

export function createReport(model, { sketchy = false, generatedAt = new Date().toISOString() } = {}) {
  const snapshot = normalizeModel(structuredClone(model));
  const threats = threatList(snapshot);
  const diagrams = snapshot.diagrams.map((d) => ({
    id: d.id, name: d.name, image: { mediaType: 'image/svg+xml', svg: diagramToSVG(d, { sketchy }) },
    elements: d.elements.map((e) => ({ ...structuredClone(e), typeLabel: STENCILS[e.type].label })),
  }));
  const categories = STRIDE.map((category) => {
    const groups = new Map();
    for (const t of threats.filter((t) => t.category === category.key)) {
      const key = JSON.stringify([t.diagramId ?? null, t.flowId || t.elementId || null]);
      if (!groups.has(key)) groups.set(key, {
        diagramId: t.diagramId ?? null,
        diagramName: snapshot.diagrams.find((d) => d.id === t.diagramId)?.name || 'No current diagram',
        interactionId: t.flowId || t.elementId || null, label: t.interaction || 'General', threats: [],
      });
      groups.get(key).threats.push(t);
    }
    return { key: category.key, name: category.name, color: category.color, interactions: [...groups.values()] };
  });
  return {
    format: 'stride-report', version: 1, model: snapshot,
    report: { generatedAt, summary: threatStats(threats), diagrams, categories, rules: structuredClone(activeRules(snapshot)), validation: validate(snapshot) },
  };
}

export function elementDetails(e) {
  const lines = Object.entries(e.props || {}).map(([key, value]) => {
    const label = STENCILS[e.type]?.props?.find((p) => p.key === key)?.label || key;
    return `${label}: ${value}`;
  });
  if (e.sourceId || e.targetId) lines.unshift(`Source: ${e.sourceId || '(unconnected)'}; target: ${e.targetId || '(unconnected)'}`);
  lines.push(`Out of scope: ${e.outOfScope ? 'Yes' : 'No'}${e.outOfScopeReason ? ` - ${e.outOfScopeReason}` : ''}`);
  if (e.notes) lines.push(`Notes: ${e.notes}`);
  if (e.tm7) {
    lines.push(`TMT original type: ${e.tm7.header || e.tm7.typeId || e.tm7.genericTypeId || '(unknown)'}`);
    lines.push(...(e.tm7.properties || []).map((p) => `TMT ${p.name}: ${p.value}`));
  }
  return lines.join('\n');
}

export function threatDetails(t) {
  return [
    ['Status', STATUS_LABELS[threatStatus(t)]], ['Severity', threatSeverity(t)], ['Owner', t.owner || 'Unassigned'],
    ['Record', `${t.auto ? `Rule ${t.ruleId}` : 'Custom threat'}${t.orphan ? ' - orphaned (retained review)' : ''}`],
    ['Description', t.description], ['Mitigation', t.mitigation], ['Notes', t.notes], ['Justification', t.justification],
    ['Suggested mitigation', t.mitigationHint], ['Created', t.created], ['Last reviewed', t.modified],
    ['Stable key', t.key], ...(t.contributingFlows?.length ? [['Contributing flows', contributingFlowText(t)]] : []),
  ];
}

// Escape user content so Markdown cannot turn model text into remote images,
// links, HTML, or table/heading syntax. Explicit newlines remain visible.
export function markdownText(value) {
  return esc(value ?? '').replace(/([\\`*_{}\[\]()#+.!|~>\-])/g, '\\$1').replace(/\r?\n/g, '<br>');
}

export function buildMarkdown(bundle) {
  const { model, report } = bundle;
  const md = markdownText;
  const lines = [`# ${md(model.meta.title)}`, '', 'STRIDE threat model report', '', `Generated: ${md(report.generatedAt)}`, ''];
  for (const [key, value] of Object.entries(model.meta)) lines.push(`**${md(key)}:** ${md(value) || '—'}`, '');
  lines.push('## Summary', '', `${report.summary.total} threats; ${report.summary.orphaned} orphaned; ${report.rules.length} rules.`, '',
    `| Category | ${STATUSES.map((s) => STATUS_LABELS[s]).join(' | ')} | Total |`, '| --- | ---: | ---: | ---: | ---: | ---: |');
  for (const c of STRIDE) lines.push(`| ${c.name} | ${STATUSES.map((s) => report.summary.byCatStatus[c.key][s]).join(' | ')} | ${report.summary.byCat[c.key]} |`);
  lines.push(`| Total | ${STATUSES.map((s) => report.summary.byStatus[s]).join(' | ')} | ${report.summary.total} |`, '');
  if (report.validation.length) {
    lines.push('### Validation observations', '');
    for (const v of report.validation) lines.push(`- ${md(v.text)}`);
    lines.push('');
  }
  for (const d of report.diagrams) {
    // A self-contained image, with no external asset path or companion file.
    const data = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(d.image.svg).replace(/[()']/g, (c) => '%' + c.charCodeAt(0).toString(16));
    lines.push(`## Diagram: ${md(d.name)}`, '', `![Diagram](${data})`, '', '### Elements', '', '| Element / ID | Type / stencil | Security properties, scope and notes |', '| --- | --- | --- |');
    for (const e of d.elements) lines.push(`| ${md(e.name)}<br>${md(e.id)} | ${md(e.typeLabel)}<br>${md(e.subtype)} | ${md(elementDetails(e))} |`);
    if (!d.elements.length) lines.push('| No elements | | |');
    lines.push('');
  }
  lines.push('## Threat register', '');
  for (const c of report.categories) {
    lines.push(`### ${c.name}`, '');
    if (!c.interactions.length) lines.push('No recorded threats.', '');
    for (const group of c.interactions) {
      lines.push(`#### ${md(group.diagramName)} / ${md(group.label)}`, '', `Interaction ID: ${md(group.interactionId || 'General')}`, '');
      for (const t of group.threats) {
        lines.push(`##### Threat ${t.id}: ${md(t.title)}`, '');
        for (const [label, value] of threatDetails(t)) lines.push(`**${label}:** ${md(value) || '—'}`, '');
      }
    }
  }
  return lines.join('\n');
}

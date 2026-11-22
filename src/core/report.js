// Reports: HTML "Full Report" (MTMT parity), CSV threat export, Markdown and JSON summaries.
// All model/template text is untrusted and is escaped on output.

import { THREAT_STATES, THREAT_STATE_LABELS, elementIndex, kbOf } from './model.js';
import { renderDiagramSvg } from './svg.js';
import { validateModel } from './validate.js';
import { csvCell, escapeHtml } from './util.js';

export function filterThreats(model, { states, categories, priorities, diagramId, text, includeOrphans = true } = {}) {
  const q = text ? String(text).toLowerCase() : '';
  return model.threats.filter((t) => {
    if (states?.length && !states.includes(t.state)) return false;
    if (categories?.length && !categories.includes(t.category)) return false;
    if (priorities?.length && !priorities.includes(t.priority)) return false;
    if (diagramId && t.diagramId !== diagramId) return false;
    if (!includeOrphans && t.orphan) return false;
    if (q && !`${t.id} ${t.title} ${t.description} ${t.interaction} ${t.typeId}`.toLowerCase().includes(q)) return false;
    return true;
  });
}

export function summarize(model) {
  const kb = kbOf(model);
  const byState = Object.fromEntries(THREAT_STATES.map((s) => [s, 0]));
  const byCategory = Object.fromEntries(kb.categories.map((c) => [c.id, 0]));
  const byPriority = Object.fromEntries(kb.priorities().map((p) => [p, 0]));
  for (const t of model.threats) {
    byState[t.state] = (byState[t.state] || 0) + 1;
    byCategory[t.category] = (byCategory[t.category] || 0) + 1;
    byPriority[t.priority] = (byPriority[t.priority] || 0) + 1;
  }
  const elements = model.diagrams.reduce((n, d) => n + d.elements.length, 0);
  return {
    name: model.meta.name,
    template: `${kb.manifest.name} ${kb.manifest.version}`,
    diagrams: model.diagrams.length,
    elements,
    threats: model.threats.length,
    orphaned: model.threats.filter((t) => t.orphan).length,
    userDefined: model.threats.filter((t) => t.userDefined).length,
    open: byState.NotStarted + byState.NeedsInvestigation,
    byState,
    byCategory,
    byPriority,
  };
}

const COLUMNS = ['ID', 'Diagram', 'Changed By', 'Last Modified', 'State', 'Title', 'Category', 'Description', 'Justification', 'Interaction', 'Priority', 'Mitigation', 'References', 'Type'];

/** CSV export of threats (MTMT "Export to CSV"), with formula-injection protection. */
export function threatsToCsv(model, threats = model.threats) {
  const kb = kbOf(model);
  const diagrams = new Map(model.diagrams.map((d) => [d.id, d.name]));
  const custom = kb.customThreatProperties().map((p) => p.name);
  const rows = [[...COLUMNS, ...custom].map(csvCell).join(',')];
  for (const t of threats) {
    rows.push(
      [
        t.id,
        diagrams.get(t.diagramId) || '',
        t.changedBy,
        t.modifiedAt,
        THREAT_STATE_LABELS[t.state] || t.state,
        t.title,
        kb.category(t.category)?.name || t.category,
        t.description,
        t.justification,
        t.orphan ? `${t.interaction} (no longer present)` : t.interaction,
        t.priority,
        t.mitigation,
        (t.references || []).join(' '),
        t.userDefined ? 'User-defined' : t.typeId,
        ...custom.map((c) => t.custom?.[c] ?? ''),
      ]
        .map(csvCell)
        .join(','),
    );
  }
  return rows.join('\r\n') + '\r\n';
}

const REPORT_CSS = `
:root{--ink:#1e1e1e;--muted:#6c757d;--paper:#fff;--line:#dee2e6;--accent:#4c6ef5}
*{box-sizing:border-box}body{font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--ink);background:#f8f9fa;margin:0}
main{max-width:1100px;margin:0 auto;padding:32px 20px 80px}
h1{font-size:28px;margin:0 0 4px}h2{font-size:21px;margin:40px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--line)}h3{font-size:17px;margin:28px 0 8px}
.meta{display:grid;grid-template-columns:max-content 1fr;gap:4px 18px;background:#fff;border:1px solid var(--line);border-radius:10px;padding:16px 20px}
.meta dt{color:var(--muted)}.meta dd{margin:0;white-space:pre-wrap}
.cards{display:flex;flex-wrap:wrap;gap:10px}.card{background:#fff;border:1px solid var(--line);border-radius:10px;padding:10px 16px;min-width:130px}
.card b{display:block;font-size:24px}.card span{color:var(--muted);font-size:13px}
figure{margin:12px 0;background:#fff;border:1px solid var(--line);border-radius:10px;padding:10px;overflow:auto}figure svg{max-width:100%;height:auto}
table{border-collapse:collapse;width:100%;background:#fff;border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{background:#f1f3f5;font-weight:600}
.threat{background:#fff;border:1px solid var(--line);border-radius:10px;padding:14px 18px;margin:10px 0}
.threat h4{margin:0 0 6px;font-size:16px}.threat p{margin:6px 0}.threat .k{color:var(--muted);font-size:13px}
.pill{display:inline-block;border-radius:99px;padding:1px 9px;font-size:12px;font-weight:600;margin-right:6px;background:#e9ecef}
.s-NotStarted{background:#ffe3e3;color:#c92a2a}.s-NeedsInvestigation{background:#fff3bf;color:#a76b00}.s-NotApplicable{background:#e9ecef;color:#495057}.s-Mitigated{background:#d3f9d8;color:#2b8a3e}
.p-High{background:#ffe8cc;color:#d9480f}.p-Medium{background:#e7f5ff;color:#1971c2}.p-Low{background:#f1f3f5;color:#495057}
.msg-error{color:#c92a2a}.msg-warning{color:#a76b00}.msg-info{color:var(--muted)}
footer{margin-top:60px;color:var(--muted);font-size:13px}
@media print{body{background:#fff}.threat,figure,table,.meta,.card{break-inside:avoid}}
`;

function threatHtml(model, kb, t) {
  const cat = kb.category(t.category)?.name || t.category;
  const refs = (t.references || []).length ? `<p class="k">References: ${t.references.map(escapeHtml).join(', ')}</p>` : '';
  return `<div class="threat" id="threat-${t.id}">
<h4>${t.id}. ${escapeHtml(t.title)}</h4>
<p><span class="pill s-${escapeHtml(t.state)}">${escapeHtml(THREAT_STATE_LABELS[t.state] || t.state)}</span><span class="pill p-${escapeHtml(t.priority)}">${escapeHtml(t.priority)}</span><span class="pill">${escapeHtml(cat)}</span>${t.userDefined ? '<span class="pill">User-defined</span>' : ''}</p>
<p class="k">${escapeHtml(t.interaction)}</p>
<p>${escapeHtml(t.description)}</p>
${t.mitigation ? `<p><b>Mitigation:</b> ${escapeHtml(t.mitigation)}</p>` : ''}
<p><b>Justification:</b> ${t.justification ? escapeHtml(t.justification) : '<i>&lt;no mitigation provided&gt;</i>'}</p>
${refs}${t.changedBy ? `<p class="k">Last changed by ${escapeHtml(t.changedBy)}${t.modifiedAt ? ` on ${escapeHtml(t.modifiedAt)}` : ''}</p>` : ''}
</div>`;
}

/**
 * Full HTML report: metadata, summary, notes, per-diagram image, validation messages,
 * threats grouped by interaction, and threats no longer associated with an interaction.
 */
export function renderHtmlReport(model, { states, includeMessages = true } = {}) {
  const kb = kbOf(model);
  const m = model.meta;
  const s = summarize(model);
  const threats = filterThreats(model, { states });
  const idx = elementIndex(model);
  const messages = includeMessages ? validateModel(model).filter((x) => !x.suppressed) : [];
  const metaRows = [
    ['Owner', m.owner],
    ['Reviewer', m.reviewer],
    ['Contributors', m.contributors],
    ['Description', m.description],
    ['Assumptions', m.assumptions],
    ['External dependencies', m.externalDependencies],
    ['Template', s.template],
    ['Last updated', m.updatedAt],
  ].filter(([, v]) => v);

  let html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(m.name)} — Threat Model Report</title><style>${REPORT_CSS}</style></head><body><main>
<h1>${escapeHtml(m.name)}</h1><p class="k" style="color:var(--muted)">Threat model report · generated ${escapeHtml(new Date().toISOString())}</p>
<dl class="meta">${metaRows.map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v)}</dd>`).join('')}</dl>
<h2>Summary</h2><div class="cards">
<div class="card"><b>${s.threats}</b><span>Total threats</span></div>
${THREAT_STATES.map((st) => `<div class="card"><b>${s.byState[st] || 0}</b><span>${escapeHtml(THREAT_STATE_LABELS[st])}</span></div>`).join('')}
${kb.priorities().map((p) => `<div class="card"><b>${s.byPriority[p] || 0}</b><span>${escapeHtml(p)} priority</span></div>`).join('')}
</div>`;

  if (model.notes.length) {
    html += `<h2>Notes</h2><table><tr><th>Date</th><th>Author</th><th>Note</th></tr>${model.notes
      .map((n) => `<tr><td>${escapeHtml(n.date)}</td><td>${escapeHtml(n.author)}</td><td style="white-space:pre-wrap">${escapeHtml(n.text)}</td></tr>`)
      .join('')}</table>`;
  }

  for (const d of model.diagrams) {
    const dThreats = threats.filter((t) => t.diagramId === d.id && !t.orphan);
    html += `<h2>Diagram: ${escapeHtml(d.name)}</h2><figure>${renderDiagramSvg(model, d, { sketch: true })}</figure>`;
    const dMsgs = messages.filter((x) => x.diagramId === d.id);
    if (dMsgs.length) {
      html += `<h3>Validation messages</h3><ul>${dMsgs.map((x) => `<li class="msg-${x.severity}">${escapeHtml(x.message)}</li>`).join('')}</ul>`;
    }
    if (!dThreats.length) {
      html += `<p class="k">No threats present for this diagram.</p>`;
      continue;
    }
    const byFlow = new Map();
    for (const t of dThreats) byFlow.set(t.flowId, [...(byFlow.get(t.flowId) || []), t]);
    for (const [flowId, list] of byFlow) {
      const flow = idx.get(flowId)?.element;
      html += `<h3>Interaction: ${escapeHtml(flow?.name || list[0].interaction)}</h3><p class="k">${escapeHtml(list[0].interaction)}</p>`;
      html += list.map((t) => threatHtml(model, kb, t)).join('');
    }
  }
  const orphans = threats.filter((t) => t.orphan);
  if (orphans.length) {
    html += `<h2>Threats not associated with an interaction</h2><p class="k">These threats were triaged before the diagram changed and no longer match a data flow.</p>`;
    html += orphans.map((t) => threatHtml(model, kb, t)).join('');
  }
  html += `<footer>Generated by STRIDE Threat Modeler. Threats are produced from template “${escapeHtml(kb.manifest.name)}” rules and require expert review.</footer></main></body></html>`;
  return html;
}

/** Markdown report, convenient for pull requests, chat and agents. */
export function renderMarkdownReport(model, { states } = {}) {
  const kb = kbOf(model);
  const s = summarize(model);
  const md = (v) => String(v ?? '').replace(/([\\`*_{}[\]<>|#])/g, '\\$1').replace(/\r?\n/g, ' ');
  let out = `# ${md(model.meta.name)}\n\n`;
  out += `Template: ${md(s.template)} · Diagrams: ${s.diagrams} · Elements: ${s.elements} · Threats: ${s.threats}\n\n`;
  out += `| State | Count |\n|---|---:|\n${THREAT_STATES.map((st) => `| ${THREAT_STATE_LABELS[st]} | ${s.byState[st] || 0} |`).join('\n')}\n\n`;
  const threats = filterThreats(model, { states });
  out += `| ID | Category | Priority | State | Title | Interaction |\n|---:|---|---|---|---|---|\n`;
  for (const t of threats) {
    out += `| ${t.id} | ${md(kb.category(t.category)?.name || t.category)} | ${md(t.priority)} | ${md(THREAT_STATE_LABELS[t.state])} | ${md(t.title)} | ${md(t.interaction)}${t.orphan ? ' (no longer present)' : ''} |\n`;
  }
  return out;
}

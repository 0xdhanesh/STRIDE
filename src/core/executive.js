// Executive report: a short, large-print summary for senior management.
// Plain language, no rule ids, file paths or per-flow detail; the technical report is the other mode.

import { GENERIC } from './kb.js';
import { THREAT_STATE_LABELS, kbOf } from './model.js';
import { renderDiagramSvg } from './svg.js';
import { escapeHtml } from './util.js';
import { annotateThreats, } from './enrich/enrichThreat.js';
import { displayTitle, oneLine } from './signal.js';
import { fontCss } from './fonts.js';

const OPEN = new Set(['NotStarted', 'NeedsInvestigation']);
const PRIORITY_RANK = { High: 0, Medium: 1, Low: 2 };

/** STRIDE categories in the words a non-specialist uses. */
const PLAIN = [
  [/spoof/i, 'Someone could pretend to be a trusted person or system'],
  [/tamper/i, 'Data or software could be changed without permission'],
  [/repudiat/i, 'An action could be denied because there is no reliable record of it'],
  [/disclos/i, 'Confidential information could be exposed'],
  [/denial|dos/i, 'The service could be knocked offline or slowed down'],
  [/elevat|privilege/i, 'Someone could gain more access than they should have'],
];
const plainCategory = (name) => PLAIN.find(([re]) => re.test(name))?.[1] || name;

const trim = (s, n) => {
  const t = oneLine(s || '');
  return t.length > n ? `${t.slice(0, n - 1).trimEnd()}…` : t;
};

const EXEC_CSS = `
:root{--ink:#111;--muted:#444;--line:#c9ced4;--accent:#0b3d91;--paper:#fff}
*{box-sizing:border-box}
body{margin:0;background:#fff;color:var(--ink);font:19px/1.65 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}
main{max-width:920px;margin:0 auto;padding:48px 28px 90px}
h1{font-size:38px;line-height:1.2;margin:0 0 6px}
h2{font-size:27px;margin:54px 0 14px}
.sub{color:var(--muted);font-size:17px;margin:0}
.status{margin:30px 0 0;padding:22px 26px;border:3px solid var(--ink);border-radius:14px}
.status b{display:block;font-size:30px;line-height:1.25;margin-bottom:6px}
.status p{margin:0;font-size:20px}
.figures{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:16px;margin-top:26px}
.figure{border:2px solid var(--line);border-radius:12px;padding:16px 18px}
.figure b{display:block;font-size:44px;line-height:1.1}
.figure span{font-size:17px;color:var(--muted)}
figure{margin:14px 0 0;border:2px solid var(--line);border-radius:12px;padding:12px;overflow:auto}
figure svg{max-width:100%;height:auto}figcaption{font-size:16px;color:var(--muted);margin-top:8px}
.risk{border:2px solid var(--line);border-left:8px solid var(--ink);border-radius:12px;padding:18px 22px;margin:16px 0;break-inside:avoid}
.risk h3{margin:0 0 4px;font-size:23px;line-height:1.3}
.risk .what{margin:0 0 10px;color:var(--muted)}
.risk dl{margin:0;display:grid;grid-template-columns:max-content 1fr;gap:6px 18px}
.risk dt{font-weight:700}.risk dd{margin:0}
.tag{display:inline-block;border:2px solid var(--ink);border-radius:99px;padding:0 12px;font-size:16px;font-weight:700;margin-right:8px}
.tag.high{background:var(--ink);color:#fff}
ul.next{padding-left:26px}ul.next li{margin:8px 0}
.legend{font-size:17px;color:var(--muted)}
footer{margin-top:60px;font-size:15px;color:var(--muted);border-top:1px solid var(--line);padding-top:14px}
@media print{body{font-size:15px}main{padding:0}h2{margin-top:30px}.figure,.risk,figure,.status{break-inside:avoid}}
@media (max-width:560px){body{font-size:17px}h1{font-size:30px}.risk dl{grid-template-columns:1fr}}
`;

/** Group threats into distinct risks (same title = same risk) with the worst priority and the best example. */
function distinctRisks(model, kb) {
  const idx = new Map();
  for (const d of model.diagrams) for (const e of d.elements) idx.set(e.id, e);
  const groups = new Map();
  for (const t of model.threats) {
    if (t.orphan) continue;
    const key = displayTitle(t);
    const g = groups.get(key) || { title: key, threats: [] };
    g.threats.push(t);
    groups.set(key, g);
  }
  return [...groups.values()].map((g) => {
    const open = g.threats.filter((t) => OPEN.has(t.state));
    const pool = open.length ? open : g.threats;
    const best = [...pool].sort((a, b) => (PRIORITY_RANK[a.priority] ?? 3) - (PRIORITY_RANK[b.priority] ?? 3) || (b.signal?.score ?? 0) - (a.signal?.score ?? 0) || a.id - b.id)[0];
    const priority = [...g.threats].map((t) => t.priority).sort((a, b) => (PRIORITY_RANK[a] ?? 3) - (PRIORITY_RANK[b] ?? 3))[0];
    return {
      title: g.title,
      isOpen: open.length > 0,
      inProgress: open.some((t) => t.state === 'NeedsInvestigation'),
      priority,
      high: best.signal?.level === 'high',
      score: best.signal?.score ?? 0,
      category: kb.category(best.category)?.name || best.category,
      state: THREAT_STATE_LABELS[best.state] || best.state,
      source: idx.get(best.sourceId)?.name || '',
      target: idx.get(best.targetId)?.name || '',
      fix: best.enriched?.fix || best.signal?.fix || best.mitigation,
      count: g.threats.length,
    };
  });
}

/** Plain data for the executive report (also useful for tests and JSON consumers). */
export function executiveSummary(model, { top = 5 } = {}) {
  annotateThreats(model);
  const kb = kbOf(model);
  const risks = distinctRisks(model, kb);
  const open = risks.filter((r) => r.isOpen);
  const needDecision = open.filter((r) => r.priority === 'High' || r.high);
  const resolved = risks.filter((r) => !r.isOpen);
  const ranked = [...open].sort((a, b) => Number(b.high) - Number(a.high) || (PRIORITY_RANK[a.priority] ?? 3) - (PRIORITY_RANK[b.priority] ?? 3) || b.score - a.score || a.title.localeCompare(b.title));
  const systems = model.diagrams.reduce((n, d) => n + d.elements.filter((e) => [GENERIC.PROCESS, GENERIC.EXTERNAL, GENERIC.STORE].includes(e.generic)).length, 0);
  let posture;
  if (!risks.length) posture = { label: 'No risks recorded yet', text: 'The model has no generated threats yet. Add data flows and trust boundaries to the diagram, then review again.' };
  else if (needDecision.length) posture = { label: 'Action needed', text: `${needDecision.length} high-priority ${needDecision.length === 1 ? 'risk needs' : 'risks need'} an owner and a decision before the design is considered safe to release.` };
  else if (open.length) posture = { label: 'Under control, work remaining', text: `No high-priority risks are open. ${open.length} lower-priority ${open.length === 1 ? 'risk is' : 'risks are'} still being worked.` };
  else posture = { label: 'Well managed', text: 'Every identified risk has been addressed or marked as not applicable.' };
  return { posture, systems, totals: { risks: risks.length, open: open.length, needDecision: needDecision.length, inProgress: open.filter((r) => r.inProgress).length, resolved: resolved.length }, top: ranked.slice(0, top).map((r) => ({ ...r, plain: plainCategory(r.category) })), more: Math.max(0, ranked.length - top) };
}

/** Executive HTML report. `font` is a preset id or the name of an installed font (see fonts.js). */
export function renderExecutiveReport(model, { font, top = 5 } = {}) {
  const s = executiveSummary(model, { top });
  const m = model.meta;
  const people = [m.owner && `Owner: ${m.owner}`, m.reviewer && `Reviewer: ${m.reviewer}`].filter(Boolean).join(' · ');
  const fig = (n, label) => `<div class="figure"><b>${n}</b><span>${escapeHtml(label)}</span></div>`;
  const risk = (r) =>
    `<div class="risk"><h3>${escapeHtml(r.title)}</h3><p class="what">${escapeHtml(r.plain)}</p>
<p><span class="tag${r.priority === 'High' ? ' high' : ''}">${escapeHtml(r.priority)} priority</span><span class="tag">${escapeHtml(r.state)}</span></p>
<dl>${r.source || r.target ? `<dt>Where</dt><dd>${escapeHtml(r.source || 'Outside the system')} → ${escapeHtml(r.target || 'Outside the system')}</dd>` : ''}${r.fix ? `<dt>Recommended action</dt><dd>${escapeHtml(trim(r.fix, 260))}</dd>` : ''}</dl></div>`;
  const next = [];
  if (s.totals.needDecision) next.push(`Name an owner and a target date for each of the ${s.totals.needDecision} high-priority ${s.totals.needDecision === 1 ? 'risk' : 'risks'}.`);
  if (s.totals.open - s.totals.needDecision > 0) next.push('Let the team schedule the remaining lower-priority risks into normal planning.');
  next.push('Re-run this review whenever the architecture changes, a new integration is added, or a new kind of data is stored.');
  const diagrams = model.diagrams.filter((d) => d.elements.length);
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(m.name)} — Executive security summary</title><style>${EXEC_CSS}${fontCss(font)}</style></head><body><main>
<h1>${escapeHtml(m.name)}</h1>
<p class="sub">Security risk summary for leadership${people ? ` · ${escapeHtml(people)}` : ''} · ${escapeHtml(new Date().toISOString().slice(0, 10))}</p>
<div class="status"><b>${escapeHtml(s.posture.label)}</b><p>${escapeHtml(s.posture.text)}</p></div>
<div class="figures">${fig(s.totals.needDecision, 'High-priority risks needing a decision')}${fig(s.totals.open - s.totals.needDecision, 'Lower-priority items still open')}${fig(s.totals.resolved, 'Risks resolved')}${fig(s.systems, 'Systems and data stores reviewed')}</div>
${m.description ? `<h2>What was reviewed</h2><p>${escapeHtml(m.description)}</p>` : ''}
${diagrams.length ? `<h2>How the system fits together</h2>${diagrams.map((d) => `<figure>${renderDiagramSvg(model, d, { sketch: false })}<figcaption>${escapeHtml(d.name)}. Each arrow is information moving between two parts; dashed red lines are trust boundaries.</figcaption></figure>`).join('')}` : ''}
<h2>${s.top.length ? `The ${s.top.length === 1 ? 'risk' : `${s.top.length} risks`} that matter most` : 'Risks'}</h2>
${s.top.length ? s.top.map(risk).join('') : '<p>No open risks.</p>'}
${s.more ? `<p class="legend">${s.more} further lower-priority ${s.more === 1 ? 'risk is' : 'risks are'} tracked in the technical report.</p>` : ''}
<h2>What we suggest next</h2><ul class="next">${next.map((n) => `<li>${escapeHtml(n)}</li>`).join('')}</ul>
<p class="legend"><b>High</b> priority: address before release. <b>Medium</b>: schedule soon. <b>Low</b>: handle in normal maintenance.</p>
<footer>Generated automatically from the threat model using the STRIDE method. Findings are prompts for expert review, not a guarantee of security. The technical report lists every threat with its evidence.</footer>
</main></body></html>`;
}

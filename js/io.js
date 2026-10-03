// File I/O: save/open models, image export, CSV, share links, HTML report
// and a best-effort importer for Microsoft Threat Modeling Tool (.tm7) files.

import { esc, slug, download } from './util.js';
import { diagramToSVG } from './render.js';
import { threatList, threatStats, validate, threatBadges, activeRules, isOpen } from './engine.js';
import { STATUS_LABELS, threatStatus, threatSeverity, contributingFlowText } from './threats.js';
import { STRIDE, STRIDE_BY_KEY, STATES, PRIORITIES, STENCILS, defaultProps } from './stencils.js';
import { newModel, normalizeModel } from './store.js';
import { createReport, buildMarkdown } from './reports.js';
import { buildPDF } from './pdf-report.js';

/* --------------------------------------------------------------- model files */

export function saveModelFile(model) {
  download(`${slug(model.meta.title)}.stride`, serializeModel(model), 'application/json');
}

export function serializeModel(model) {
  return JSON.stringify(normalizeModel(structuredClone(model)), null, 2);
}

export async function readModelFile(file) {
  const text = await file.text();
  if (/\.tm7$/i.test(file.name) || /^\s*<\??(xml|ThreatModel)/.test(text)) return importTM7(text);
  let data;
  try { data = JSON.parse(text); } catch { throw new Error('File is not valid JSON.'); }
  if (data?.format === 'stride-report') {
    if (data.version !== 1) throw new Error(`Unsupported report version: ${data.version}.`);
    data = data.model;
  }
  if (!data || !Array.isArray(data.diagrams)) throw new Error('This JSON file is not a threat model.');
  return normalizeModel(data);
}

export async function exportReport(model, format, options = {}) {
  const bundle = createReport(model, options);
  const name = `${slug(bundle.model.meta.title)}-report`;
  if (format === 'json') download(`${name}.json`, JSON.stringify(bundle, null, 2), 'application/json');
  else if (format === 'markdown') download(`${name}.md`, buildMarkdown(bundle), 'text/markdown;charset=utf-8');
  else if (format === 'pdf') download(`${name}.pdf`, await buildPDF(bundle), 'application/pdf');
  else throw new Error('Unsupported report format.');
}

/* -------------------------------------------------------------- share links */

const fromB64url = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

async function pipe(bytes, stream) {
  return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(stream)).arrayBuffer());
}

export async function shareLink(model) {
  const bytes = await pipe(new TextEncoder().encode(JSON.stringify(model)), new CompressionStream('deflate-raw'));
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  const data = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${location.origin}${location.pathname}#model=${data}`;
}

export async function modelFromHash(hash) {
  const m = /model=([A-Za-z0-9_-]+)/.exec(hash || '');
  if (!m) return null;
  const bytes = await pipe(fromB64url(m[1]), new DecompressionStream('deflate-raw'));
  return JSON.parse(new TextDecoder().decode(bytes));
}

/* ------------------------------------------------------------------ images */

export async function exportSVG(model, diagram, sketchy) {
  const svg = diagramToSVG(diagram, { sketchy });
  download(`${slug(model.meta.title)}-${slug(diagram.name)}.svg`, svg, 'image/svg+xml');
}

export async function diagramPNG(diagram, sketchy, scale = 2) {
  const svg = diagramToSVG(diagram, { sketchy });
  const w = +/width="(\d+)"/.exec(svg)[1], h = +/height="(\d+)"/.exec(svg)[1];
  const img = new Image();
  img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
  await img.decode();
  const canvas = document.createElement('canvas');
  const k = Math.min(scale, 16000 / Math.max(w, h));
  canvas.width = Math.round(w * k);
  canvas.height = Math.round(h * k);
  const ctx = canvas.getContext('2d');
  ctx.scale(k, k);
  ctx.drawImage(img, 0, 0, w, h);
  return new Promise((res) => canvas.toBlob(res, 'image/png'));
}

export async function exportPNG(model, diagram, sketchy) {
  const blob = await diagramPNG(diagram, sketchy);
  download(`${slug(model.meta.title)}-${slug(diagram.name)}.png`, blob);
}

/* --------------------------------------------------------------------- CSV */

export function exportCSV(model) {
  const dName = Object.fromEntries(model.diagrams.map((d) => [d.id, d.name]));
  const cols = ['ID', 'Diagram', 'Interaction', 'Category', 'Title', 'Severity', 'Status', 'Description', 'Justification', 'Mitigation', 'Suggested mitigation', 'Source', 'Owner', 'Notes', 'Contributing flows'];
  // Quoting alone does not stop spreadsheet formula execution on open.
  const cell = (v) => {
    const value = String(v ?? '');
    return `"${(/^[\s]*[=+@-]|^[\t\r\n]/.test(value) ? "'" : '') + value.replace(/"/g, '""')}"`;
  };
  const rows = threatList(model).map((t) => [
    t.id, dName[t.diagramId] || '', t.interaction, STRIDE_BY_KEY[t.category]?.name, t.title, threatSeverity(t), STATUS_LABELS[threatStatus(t)],
    t.description, t.justification, t.mitigation, t.mitigationHint, t.auto ? `Rule ${t.ruleId}` : 'Custom', t.owner, t.notes, contributingFlowText(t),
  ].map(cell).join(','));
  download(`${slug(model.meta.title)}-threats.csv`, '﻿' + [cols.map(cell).join(','), ...rows].join('\r\n'), 'text/csv');
}

/* ------------------------------------------------------------------ report */

const para = (s) => esc(s).replace(/\n/g, '<br>');

export function buildReport(model, { sketchy = true } = {}) {
  const bundle = createReport(model, { sketchy });
  model = bundle.model;
  const threats = threatList(model);
  const stats = threatStats(threats);
  const msgs = validate(model);
  const date = new Date().toLocaleString();
  const m = model.meta;
  const bar = (n) => `<span class="bar"><span style="width:${stats.total ? Math.round((n / stats.total) * 100) : 0}%"></span></span>`;

  const catRows = STRIDE.map((c) => {
    const ts = threats.filter((t) => t.category === c.key);
    const open = ts.filter(isOpen).length;
    return `<tr><td><span class="cat" style="background:${c.color}">${c.key}</span> ${c.name}</td><td>${ts.length}</td><td>${open}</td><td>${ts.filter((t) => threatStatus(t) === 'mitigated').length}</td><td>${bar(ts.length)}</td></tr>`;
  }).join('');

  const threatBlock = (t) => `
    <article class="threat">
      <header><span class="cat" style="background:${STRIDE_BY_KEY[t.category]?.color}">${t.category}</span>
        <h4>#${t.id} ${esc(t.title)}</h4>
        <span class="state s-${slug(STATUS_LABELS[threatStatus(t)])}">${STATUS_LABELS[threatStatus(t)]}</span><span class="prio p-${slug(threatSeverity(t))}">${threatSeverity(t)}</span></header>
      <dl>
        <dt>Category</dt><dd>${esc(STRIDE_BY_KEY[t.category]?.name)}</dd>
        <dt>Interaction</dt><dd>${esc(t.interaction || '—')}</dd>
        ${t.contributingFlows?.length ? `<dt>Contributing flows</dt><dd>${para(contributingFlowText(t))}</dd>` : ''}
        <dt>Description</dt><dd>${para(t.description)}</dd>
        <dt>Owner</dt><dd>${para(t.owner) || '—'}</dd>
        <dt>Notes</dt><dd>${para(t.notes) || '—'}</dd>
        <dt>Record</dt><dd>${t.auto ? `Rule ${esc(t.ruleId)}` : 'Custom threat'}${t.orphan ? ' - orphaned (retained review)' : ''}</dd>
        ${t.justification ? `<dt>Justification</dt><dd>${para(t.justification)}</dd>` : ''}
        ${t.mitigation ? `<dt>Mitigation</dt><dd>${para(t.mitigation)}</dd>` : ''}
        ${t.mitigationHint && !t.mitigation ? `<dt>Suggested mitigation</dt><dd class="muted">${para(t.mitigationHint)}</dd>` : ''}
      </dl>
    </article>`;

  const diagrams = model.diagrams.map((d) => {
    const ts = threats.filter((t) => t.diagramId === d.id);
    const nodes = d.elements;
    const elRows = nodes.map((e) => {
      const props = Object.entries(e.props || {}).filter(([, v]) => v && v !== 'Not Selected')
        .map(([k, v]) => `${esc(STENCILS[e.type].props.find((p) => p.key === k)?.label || k)}: <b>${esc(v)}</b>`).join('<br>');
      return `<tr><td>${esc(e.name)}</td><td>${esc(STENCILS[e.type].label)}</td><td>${esc(e.subtype)}</td><td>${props || '<span class="muted">—</span>'}</td><td>${e.outOfScope ? `Yes${e.outOfScopeReason ? ': ' + esc(e.outOfScopeReason) : ''}` : 'No'}</td></tr>`;
    }).join('');
    return `
      <section class="diagram">
        <h2>Diagram: ${esc(d.name)}</h2>
        <figure>${diagramToSVG(d, { sketchy, badges: threatBadges(model, d.id) })}</figure>
        <p class="muted">${ts.length} threat(s) on this diagram · badges show open threats per element/flow.</p>
        <details open><summary><h3 style="display:inline">Elements &amp; properties</h3></summary>
        <table class="grid"><thead><tr><th>Name</th><th>Type</th><th>Subtype</th><th>Security properties</th><th>Out of scope</th></tr></thead><tbody>${elRows || '<tr><td colspan="5">No elements</td></tr>'}</tbody></table></details>
      </section>`;
  }).join('');
  const register = bundle.report.categories.map((c) => `<section><h2>${esc(c.name)}</h2>${c.interactions.map((g) => `<h3>${esc(g.diagramName)} / ${esc(g.label)}</h3><p class="muted">Interaction ID: ${esc(g.interactionId || 'General')}</p>${g.threats.map(threatBlock).join('')}`).join('') || '<p>No recorded threats.</p>'}</section>`).join('');

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(m.title)} – Threat Model Report</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data: blob:; style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<style>
body{font:14px/1.55 Inter,'Segoe UI',system-ui,sans-serif;color:#1b1b1f;max-width:1000px;margin:0 auto;padding:32px 24px 80px;background:#fff}
h1{font-size:28px;margin:0 0 4px}h2{margin-top:40px;padding-bottom:6px;border-bottom:2px solid #6965db}h3{margin:28px 0 8px;font-size:15px}
.muted{color:#6b6b76}.meta{display:grid;grid-template-columns:160px 1fr;gap:4px 16px;margin:16px 0}.meta dt{color:#6b6b76}.meta dd{margin:0}
table{border-collapse:collapse;width:100%;margin:8px 0}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #e7e7ee;vertical-align:top}th{font-size:12px;color:#6b6b76;font-weight:600}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:16px 0}.card{border:1px solid #e7e7ee;border-radius:10px;padding:12px}.card b{display:block;font-size:26px}
.cat{display:inline-grid;place-items:center;width:22px;height:22px;border-radius:50%;color:#fff;font-weight:800;font-size:12px;flex:none}
.bar{display:inline-block;width:120px;height:8px;background:#f1f1f5;border-radius:4px;overflow:hidden;vertical-align:middle}.bar span{display:block;height:100%;background:#6965db}
figure{margin:12px 0;border:1px solid #e7e7ee;border-radius:10px;padding:8px;overflow:auto}figure svg{max-width:100%;height:auto;display:block;margin:auto}
.threat{border:1px solid #e7e7ee;border-radius:10px;padding:10px 14px;margin:10px 0;break-inside:avoid}
.threat header{display:flex;align-items:center;gap:8px}.threat h4{margin:0;flex:1;font-size:14px}.threat dl{display:grid;grid-template-columns:150px 1fr;gap:4px 12px;margin:8px 0 0}.threat dt{color:#6b6b76;font-size:12.5px}.threat dd{margin:0}
.state{font-size:11px;font-weight:600;padding:1px 8px;border-radius:999px}.s-open,.s-not-started{background:#ffe3e3;color:#c92a2a}.s-accepted,.s-needs-investigation{background:#fff3bf;color:#a35d00}.s-not-applicable{background:#e9ecef;color:#495057}.s-mitigated{background:#d3f9d8;color:#2b8a3e}
.prio{font-size:11px;font-weight:700}.p-high{color:#e03131}.p-medium{color:#f08c00}.p-low{color:#6b6b76}
.toolbar{position:fixed;top:12px;right:12px}.toolbar button{font:inherit;padding:8px 14px;border:0;border-radius:8px;background:#6965db;color:#fff;cursor:pointer}
summary{cursor:pointer}
body{overflow-wrap:anywhere}@page{size:A4;margin:16mm}
@media print{.toolbar{display:none}body{padding:0}h2{break-before:page}h3,h4{break-after:avoid}thead{display:table-header-group}.threat{break-inside:auto}.diagram:first-of-type h2{break-before:auto}}
</style></head><body>
<div class="toolbar">Print / Save as PDF: Ctrl+P / ⌘P</div>
<h1>${esc(m.title)}</h1>
<div class="muted">Threat model report · generated ${esc(date)} · STRIDE Threat Modeler</div>
<dl class="meta">
<dt>Owner</dt><dd>${esc(m.owner) || '—'}</dd><dt>Reviewer</dt><dd>${esc(m.reviewer) || '—'}</dd><dt>Contributors</dt><dd>${esc(m.contributors) || '—'}</dd>
<dt>Description</dt><dd>${para(m.description) || '—'}</dd><dt>Assumptions</dt><dd>${para(m.assumptions) || '—'}</dd><dt>External dependencies</dt><dd>${para(m.dependencies) || '—'}</dd>
<dt>Threat template</dt><dd>${model.template ? `Custom (${activeRules(model).length} rules)` : `Built-in STRIDE (${activeRules(model).length} rules)`}</dd>
</dl>
<h2>Summary</h2>
<div class="cards">
<div class="card"><b>${stats.total}</b>Threats</div><div class="card"><b style="color:#e03131">${stats.open}</b>Open</div>
<div class="card"><b style="color:#2f9e44">${stats.byState['Mitigated'] || 0}</b>Mitigated</div><div class="card"><b>${stats.byState['Accepted'] || 0}</b>Accepted</div><div class="card"><b>${stats.byState['Not Applicable'] || 0}</b>Not applicable</div>
</div>
<table><thead><tr><th>STRIDE category</th><th>Total</th><th>Open</th><th>Mitigated</th><th></th></tr></thead><tbody>${catRows}</tbody></table>
<table><thead><tr>${STATES.map((s) => `<th>${s}</th>`).join('')}${PRIORITIES.map((p) => `<th>${p} severity</th>`).join('')}</tr></thead>
<tbody><tr>${STATES.map((s) => `<td>${stats.byState[s] || 0}</td>`).join('')}${PRIORITIES.map((p) => `<td>${stats.bySeverity[p] || 0}</td>`).join('')}</tr></tbody></table>
${msgs.length ? `<h3>Validation notes</h3><ul>${msgs.map((x) => `<li>${esc(x.text)}</li>`).join('')}</ul>` : ''}
${diagrams}
${register}
</body></html>`;
}

export function openReport(model, sketchy) {
  const html = buildReport(model, { sketchy });
  const url = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
  const win = window.open(url, '_blank');
  if (!win) download(`${slug(model.meta.title)}-report.html`, html, 'text/html');
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

export function downloadReport(model, sketchy) {
  download(`${slug(model.meta.title)}-report.html`, buildReport(model, { sketchy }), 'text/html');
}

/* -------------------------------------------------------------- TM7 import */

const kids = (el, name) => [...(el?.children || [])].filter((c) => c.localName === name);
const kid = (el, name) => kids(el, name)[0] || null;
const txt = (el, name) => kid(el, name)?.textContent?.trim() ?? '';
const NIL = '00000000-0000-0000-0000-000000000000';

// Read TMT's property list into { displayName: value }.
function tmProps(valueEl) {
  const out = {};
  let header = '';
  for (const a of kid(valueEl, 'Properties')?.children || []) {
    const name = txt(a, 'DisplayName');
    const type = a.getAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'type') || '';
    if (/HeaderDisplayAttribute/.test(type)) { header ||= name; continue; }
    const v = kid(a, 'Value');
    const sel = kid(a, 'SelectedIndex');
    if (sel && v) {
      const opts = [...v.children].map((c) => c.textContent.trim());
      out[name] = opts[+sel.textContent] ?? '';
    } else out[name] = v?.textContent?.trim() ?? '';
  }
  return { props: out, header };
}

const matchSubtype = (type, header) =>
  STENCILS[type].subtypes.find((s) => s.toLowerCase() === header.toLowerCase()) ||
  STENCILS[type].subtypes.find((s) => header && s.toLowerCase().includes(header.toLowerCase().split(' ')[0])) ||
  STENCILS[type].subtypes[0];

const STATE_MAP = { NotStarted: 'Not Started', AutoGenerated: 'Not Started', NeedsInvestigation: 'Needs Investigation', NotApplicable: 'Not Applicable', Mitigated: 'Mitigated' };

export function importTM7(xmlText) {
  const doc = new DOMParser().parseFromString(xmlText, 'application/xml');
  if (doc.querySelector('parsererror')) throw new Error('Could not parse the .tm7 file (invalid XML).');
  const root = doc.documentElement;
  const model = newModel();
  model.diagrams = [];
  const meta = kid(root, 'MetaInformation');
  if (meta) {
    Object.assign(model.meta, {
      title: txt(meta, 'ThreatModelName') || 'Imported TMT model', owner: txt(meta, 'Owner'), reviewer: txt(meta, 'Reviewer'),
      contributors: txt(meta, 'Contributors'), description: txt(meta, 'HighLevelSystemDescription'),
      assumptions: txt(meta, 'Assumptions'), dependencies: txt(meta, 'ExternalDependencies'),
    });
  }
  const typeMap = { 'GE.P': 'process', 'GE.EI': 'external', 'GE.DS': 'store', 'GE.TB.B': 'boundary', 'GE.A': 'note', 'GE.DF': 'flow', 'GE.TB.L': 'boundaryLine' };

  for (const surface of doc.getElementsByTagNameNS('*', 'DrawingSurfaceModel')) {
    const sp = tmProps(surface);
    const d = { id: txt(surface, 'Guid') || `d_${model.diagrams.length + 1}`, name: txt(surface, 'Header') || sp.props.Name || `Diagram ${model.diagrams.length + 1}`, elements: [] };
    const toEl = (v) => {
      const generic = txt(v, 'GenericTypeId');
      const type = typeMap[generic] || (generic.startsWith('GE.P') ? 'process' : generic.startsWith('GE.EI') ? 'external' : generic.startsWith('GE.DS') ? 'store' : null);
      if (!type) return null;
      const { props, header: h } = tmProps(v);
      // Fall back to the last segment of TMT's TypeId (e.g. SE.DF.TMCore.HTTPS -> HTTPS).
      const header = h || (txt(v, 'TypeId').split('.').pop() || '').replace(/([a-z])([A-Z])/g, '$1 $2');
      const el = {
        id: txt(v, 'Guid'), type, name: props.Name || header || STENCILS[type].label, subtype: STENCILS[type].subtypes.length ? matchSubtype(type, header) : '',
        props: defaultProps(type), style: {}, outOfScope: /true/i.test(props['Out Of Scope'] || ''), outOfScopeReason: props['Reason For Out Of Scope'] || '',
        notes: header ? `Imported from TMT as "${header}".` : '',
      };
      if (type === 'flow' || type === 'boundaryLine') {
        const src = txt(v, 'SourceGuid'), tgt = txt(v, 'TargetGuid');
        Object.assign(el, {
          sourceId: src && src !== NIL ? src : null, targetId: tgt && tgt !== NIL ? tgt : null,
          x1: +txt(v, 'SourceX') || 0, y1: +txt(v, 'SourceY') || 0, x2: +txt(v, 'TargetX') || 0, y2: +txt(v, 'TargetY') || 0,
          hx: +txt(v, 'HandleX') || 0, hy: +txt(v, 'HandleY') || 0, bend: 0,
        });
      } else {
        Object.assign(el, { x: +txt(v, 'Left') || 0, y: +txt(v, 'Top') || 0, w: +txt(v, 'Width') || 100, h: +txt(v, 'Height') || 100 });
        if (type === 'note') el.name = props.Name || props.Annotation || header || 'Note';
      }
      return el;
    };
    for (const kv of kids(kid(surface, 'Borders'), 'KeyValueOfguidanyType')) { const el = toEl(kid(kv, 'Value')); if (el) d.elements.push(el); }
    for (const kv of kids(kid(surface, 'Lines'), 'KeyValueOfguidanyType')) { const el = toEl(kid(kv, 'Value')); if (el) d.elements.push(el); }
    // Convert TMT's bezier handle into our perpendicular bend value.
    for (const el of d.elements) {
      if (el.hx === undefined) continue;
      const mx = (el.x1 + el.x2) / 2, my = (el.y1 + el.y2) / 2;
      const dx = el.x2 - el.x1, dy = el.y2 - el.y1, len = Math.hypot(dx, dy) || 1;
      el.bend = Math.round((((el.hx - mx) * -dy) / len + ((el.hy - my) * dx) / len) / 2);
      if (Math.abs(el.bend) < 8) el.bend = 0;
      delete el.hx; delete el.hy;
      const ids = new Set(d.elements.map((e) => e.id));
      if (el.sourceId && !ids.has(el.sourceId)) el.sourceId = null;
      if (el.targetId && !ids.has(el.targetId)) el.targetId = null;
    }
    model.diagrams.push(d);
  }
  if (!model.diagrams.length) throw new Error('No diagrams found in the .tm7 file.');

  // Threats from TMT become custom threats so their state and justification are preserved.
  const catOf = (s) => {
    const k = (s || '').toLowerCase();
    return STRIDE.find((c) => k.startsWith(c.name.toLowerCase().slice(0, 6)))?.key || (k[0] || 'S').toUpperCase();
  };
  let n = 0;
  for (const inst of doc.getElementsByTagNameNS('*', 'ThreatInstances')) {
    for (const kv of inst.children) {
      const v = kid(kv, 'Value');
      if (!v) continue;
      const p = {};
      for (const pair of kid(v, 'Properties')?.children || []) p[txt(pair, 'Key')] = txt(pair, 'Value');
      const id = model.nextThreatId++;
      const cat = catOf(p.UserThreatCategory || txt(v, 'UserThreatCategory'));
      model.threats[`tm7:${id}`] = {
        id, key: `tm7:${id}`, auto: false, ruleId: txt(v, 'TypeId'),
        diagramId: txt(v, 'DrawingSurfaceGuid'), flowId: txt(v, 'FlowGuid') || null, elementId: txt(v, 'TargetGuid') || null,
        category: 'STRIDE'.includes(cat) ? cat : 'S', priority: PRIORITIES.includes(txt(v, 'Priority')) ? txt(v, 'Priority') : (PRIORITIES.includes(p.Priority) ? p.Priority : 'Medium'),
        state: STATE_MAP[txt(v, 'State')] || 'Not Started',
        title: p.Title || txt(v, 'Title') || 'Imported threat', description: p.UserThreatDescription || p.UserThreatShortDescription || '',
        justification: p.StateInformation || txt(v, 'StateInformation') || '', mitigation: '', mitigationHint: '',
        interaction: p.InteractionString || '', created: new Date().toISOString(), modified: txt(v, 'ModifiedAt') || null, customText: true,
      };
      n++;
    }
  }
  model.importNote = `Imported ${model.diagrams.length} diagram(s) and ${n} threat(s) from TMT.`;
  return model;
}

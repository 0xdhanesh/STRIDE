// SVG rendering of a diagram. Shared by the web canvas, HTML reports and the CLI.

import { GENERIC } from './kb.js';
import { center, quadPoint } from './geometry.js';
import { diagramBounds, kbOf, lineGeometry } from './model.js';
import { arrowHead, ellipsePath, quadPath, roughEllipse, roughLine, roughQuad, roughRect } from './sketch.js';
import { escapeHtml } from './util.js';

const FONT = 16;
const SMALL = 11;

/** Embedded stylesheet so standalone SVGs (reports) look right without the app CSS. */
export const SVG_STYLE = `
.dg text{font-family:"Virgil","Excalifont","Segoe Print","Bradley Hand","Comic Sans MS","Chalkboard SE",cursive;fill:var(--ink,#1e1e1e)}
.dg .stroke{fill:none;stroke:var(--ink,#1e1e1e);stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
.dg .fill-P{fill:var(--fill-process,#d0ebff)}.dg .fill-EI{fill:var(--fill-external,#fff3bf)}.dg .fill-DS{fill:var(--fill-store,#d3f9d8)}
.dg .fill-A{fill:var(--fill-annotation,#f8f9fa)}
.dg .boundary{fill:none;stroke:var(--boundary,#e03131);stroke-width:1.8;stroke-dasharray:8 7;stroke-linecap:round}
.dg .box-fill{fill:var(--boundary-fill,rgba(224,49,49,.035))}
.dg .flow{fill:none;stroke:var(--flow,#1e1e1e);stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
.dg .label-bg{fill:var(--paper,#fff);opacity:.92}
.dg .caption{font-size:${SMALL}px;fill:var(--muted,#868e96);font-style:italic}
.dg .blabel{fill:var(--boundary,#e03131);font-size:13px}
.dg .oos .stroke,.dg .oos .flow,.dg .oos .boundary{stroke:var(--muted,#adb5bd);stroke-dasharray:4 5}
.dg .oos text{fill:var(--muted,#adb5bd)}
.dg .badge circle{fill:var(--badge,#e8590c)}.dg .badge text{fill:#fff;font-family:system-ui,sans-serif;font-size:11px;font-weight:700}
.dg .sel .stroke,.dg .sel .flow,.dg .sel .boundary{stroke:var(--accent,#4c6ef5)}
.dg .hl .stroke,.dg .hl .flow{stroke:var(--highlight,#f08c00);stroke-width:2.6}
.dg .hit{fill:none;stroke:transparent;stroke-width:16;pointer-events:stroke}
.dg .loose .flow{stroke:var(--error,#e03131)}
`;

/** Greedy word wrap using an average glyph width estimate. */
export function wrapText(text, maxWidth, fontSize = FONT) {
  const avg = fontSize * 0.56;
  const maxChars = Math.max(4, Math.floor(maxWidth / avg));
  const words = String(text || '').split(/\s+/).filter(Boolean);
  const lines = [];
  let cur = '';
  for (const w of words) {
    if (!cur) cur = w;
    else if ((cur + ' ' + w).length <= maxChars) cur += ' ' + w;
    else {
      lines.push(cur);
      cur = w;
    }
    while (cur.length > maxChars) {
      lines.push(cur.slice(0, maxChars - 1) + '-');
      cur = cur.slice(maxChars - 1);
    }
  }
  if (cur) lines.push(cur);
  return lines.slice(0, 5);
}

function textBlock(lines, cx, cy, fontSize = FONT, cls = '') {
  const lh = fontSize * 1.2;
  const start = cy - ((lines.length - 1) * lh) / 2;
  return lines
    .map((l, i) => `<text x="${cx.toFixed(1)}" y="${(start + i * lh).toFixed(1)}" font-size="${fontSize}" text-anchor="middle" dominant-baseline="central"${cls ? ` class="${cls}"` : ''}>${escapeHtml(l)}</text>`)
    .join('');
}

function badge(x, y, count) {
  if (!count) return '';
  const label = count > 99 ? '99+' : String(count);
  const r = label.length > 2 ? 11 : 9;
  return `<g class="badge"><circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r}"/><text x="${x.toFixed(1)}" y="${(y + 0.5).toFixed(1)}" text-anchor="middle" dominant-baseline="central">${label}</text></g>`;
}

function typeCaption(kb, el) {
  const def = kb.element(el.typeId);
  if (!def || el.typeId === el.generic) return '';
  return def.name;
}

export function renderElement(model, diagram, el, opts = {}) {
  const kb = kbOf(model);
  const sketch = opts.sketch !== false;
  const classes = ['el'];
  if (el.outOfScope) classes.push('oos');
  if (opts.selected?.has(el.id)) classes.push('sel');
  if (opts.highlighted?.has(el.id)) classes.push('hl');
  const g = el.generic;
  let body = '';
  const seed = el.id;
  const count = opts.badges?.get(el.id) || 0;

  if (g === GENERIC.PROCESS || g === GENERIC.EXTERNAL || g === GENERIC.STORE || g === GENERIC.ANNOTATION) {
    const { x, y, w, h } = el;
    const c = center(el);
    if (g === GENERIC.PROCESS) {
      body += `<path class="fill-P" d="${ellipsePath(c.x, c.y, w / 2, h / 2)}"/>`;
      body += `<path class="stroke" d="${sketch ? roughEllipse(c.x, c.y, w / 2, h / 2, seed) : ellipsePath(c.x, c.y, w / 2, h / 2)}"/>`;
    } else if (g === GENERIC.EXTERNAL) {
      body += `<rect class="fill-EI" x="${x}" y="${y}" width="${w}" height="${h}" rx="3"/>`;
      body += `<path class="stroke" d="${sketch ? roughRect(x, y, w, h, seed) : `M${x} ${y}h${w}v${h}h${-w}Z`}"/>`;
    } else if (g === GENERIC.STORE) {
      body += `<rect class="fill-DS" x="${x}" y="${y}" width="${w}" height="${h}"/>`;
      const top = sketch ? roughLine({ x, y }, { x: x + w, y }, `${seed}:t`) : `M${x} ${y}h${w}`;
      const bot = sketch ? roughLine({ x, y: y + h }, { x: x + w, y: y + h }, `${seed}:b`) : `M${x} ${y + h}h${w}`;
      body += `<path class="stroke" d="${top}${bot}"/>`;
    } else {
      body += `<rect class="fill-A" x="${x}" y="${y}" width="${w}" height="${h}" rx="4" opacity=".7"/>`;
    }
    const caption = g === GENERIC.ANNOTATION ? '' : typeCaption(kb, el);
    const inner = g === GENERIC.PROCESS ? w * 0.74 : w - 14;
    const lines = wrapText(el.name, inner, g === GENERIC.ANNOTATION ? 14 : FONT);
    body += textBlock(lines, c.x, caption ? c.y - 6 : c.y, g === GENERIC.ANNOTATION ? 14 : FONT);
    if (caption) body += textBlock([caption], c.x, c.y + (lines.length * FONT * 1.2) / 2 + 4, SMALL, 'caption');
    if (count) body += badge(x + w - 4, y + 4, count);
    // Invisible hit area covering the shape.
    body = `<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="transparent"/>` + body;
  } else if (g === GENERIC.BOX_BOUNDARY) {
    const { x, y, w, h } = el;
    body += `<rect class="box-fill" x="${x}" y="${y}" width="${w}" height="${h}"/>`;
    body += `<path class="boundary" d="${sketch ? roughRect(x, y, w, h, seed, 0.6) : `M${x} ${y}h${w}v${h}h${-w}Z`}"/>`;
    body += `<path class="hit" d="M${x} ${y}h${w}v${h}h${-w}Z"/>`;
    body += `<text class="blabel" x="${x + 8}" y="${y + 16}">${escapeHtml(el.name)}</text>`;
  } else if (g === GENERIC.LINE_BOUNDARY || g === GENERIC.FLOW) {
    const geo = lineGeometry(model, diagram, el);
    const isFlow = g === GENERIC.FLOW;
    if (isFlow && (!el.source || !el.target)) classes.push('loose');
    const d = sketch ? roughQuad(geo.p0, geo.c, geo.p1, seed, isFlow ? 0.8 : 0.6) : quadPath(geo.p0, geo.c, geo.p1);
    body += `<path class="hit" d="${quadPath(geo.p0, geo.c, geo.p1)}"/>`;
    body += `<path class="${isFlow ? 'flow' : 'boundary'}" d="${d}"/>`;
    if (isFlow) body += `<path class="flow" d="${arrowHead(geo.c, geo.p1)}"/>`;
    // Flow labels sit mid-curve; arc boundary labels near the start so they do not collide with flow labels.
    const mid = quadPoint(geo.p0, geo.c, geo.p1, isFlow ? 0.5 : 0.1);
    if (el.name) {
      const fs = isFlow ? 14 : 13;
      const lines = wrapText(el.name, 160, fs);
      const tw = Math.max(...lines.map((l) => l.length)) * fs * 0.56 + 10;
      const th = lines.length * fs * 1.2 + 4;
      body += `<rect class="label-bg" x="${(mid.x - tw / 2).toFixed(1)}" y="${(mid.y - th / 2).toFixed(1)}" width="${tw.toFixed(1)}" height="${th.toFixed(1)}" rx="4"/>`;
      body += textBlock(lines, mid.x, mid.y, fs, isFlow ? '' : 'blabel');
    }
    if (count) body += badge(mid.x + 14, mid.y - 16, count);
  }
  return `<g class="${classes.join(' ')}" data-id="${escapeHtml(el.id)}">${body}</g>`;
}

const LAYER = {
  'GE.TB.B': 0,
  'GE.A': 1,
  'GE.DF': 2,
  'GE.P': 3,
  'GE.EI': 3,
  'GE.DS': 3,
  'GE.TB.L': 4,
};

/** Elements in paint order: box boundaries, annotations, flows, nodes, arc boundaries. */
export function paintOrder(diagram) {
  return [...diagram.elements].sort((a, b) => (LAYER[a.generic] ?? 5) - (LAYER[b.generic] ?? 5));
}

/** Inner SVG markup for all elements (no <svg> wrapper). */
export function renderDiagramContent(model, diagram, opts = {}) {
  return paintOrder(diagram)
    .map((el) => renderElement(model, diagram, el, opts))
    .join('');
}

/** Standalone SVG document for a diagram. */
export function renderDiagramSvg(model, diagram, opts = {}) {
  const b = diagramBounds(model, diagram, 30);
  const w = Math.max(200, Math.ceil(b.w));
  const h = Math.max(120, Math.ceil(b.h));
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" class="dg" viewBox="${b.x.toFixed(0)} ${b.y.toFixed(0)} ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="${escapeHtml(diagram.name)}">` +
    `<style>${SVG_STYLE}</style><rect x="${b.x}" y="${b.y}" width="${w}" height="${h}" fill="var(--paper,#fff)"/>` +
    renderDiagramContent(model, diagram, opts) +
    `</svg>`
  );
}

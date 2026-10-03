// Pure SVG-markup renderer for diagrams. Used by the live canvas, image export
// and the HTML report so they always look identical.

import {
  esc, hashStr, lineGeom, wrapText, roughEllipse, roughRect, roughLine, roughQuad,
  cleanEllipse, cleanQuad, unionBounds, elementBounds,
} from './util.js';
import { BOUNDARY_COLOR, SUBTYPE_GLYPH, SUBTYPE_SHAPE } from './stencils.js';
import { glyphSVG } from './glyphs.js';

export const FONTS = {
  sketchy: "'Comic Sans MS', 'Segoe Print', cursive",
  clean: "Inter, 'Segoe UI', system-ui, -apple-system, sans-serif",
};

export const LAYER_ORDER = { boundary: 0, process: 1, external: 1, store: 1, flow: 2, boundaryLine: 3, note: 4 };

export function orderedElements(diagram) {
  return diagram.elements
    .map((el, i) => ({ el, i }))
    .sort((a, b) => LAYER_ORDER[a.el.type] - LAYER_ORDER[b.el.type] || a.i - b.i)
    .map((x) => x.el);
}

function textBlock(lines, x, y, { size, font, fill, anchor = 'middle', halo = null, weight = 400 }) {
  const lh = size * 1.25;
  const haloAttr = halo ? ` paint-order="stroke" stroke="${halo}" stroke-width="${size * 0.35}" stroke-linejoin="round"` : '';
  const spans = lines.map((l, i) => `<tspan x="${x}" dy="${i === 0 ? 0 : lh}">${esc(l) || ' '}</tspan>`).join('');
  return `<text x="${x}" y="${y}" font-family="${esc(font)}" font-size="${size}" font-weight="${weight}" fill="${fill}" text-anchor="${anchor}"${haloAttr}>${spans}</text>`;
}

function centeredText(label, cx, cy, width, o, color) {
  const size = 16;
  const lines = wrapText(label, width, size);
  const y = cy - ((lines.length - 1) * size * 1.25) / 2 + size * 0.35;
  return textBlock(lines, cx, y, { size, font: o.font, fill: color });
}

function badge(x, y, info) {
  if (!info || !info.total) return '';
  const color = info.open === 0 ? '#2f9e44' : info.high ? '#e03131' : '#f08c00';
  const label = info.open === 0 ? '✓' : String(info.open);
  const w = Math.max(20, 9 + label.length * 8);
  return `<g class="badge" pointer-events="none"><rect x="${x - w / 2}" y="${y - 10}" width="${w}" height="20" rx="10" fill="${color}"/>` +
    `<text x="${x}" y="${y + 4.5}" font-family="system-ui,sans-serif" font-size="12" font-weight="700" fill="#fff" text-anchor="middle">${label}</text></g>`;
}

function renderNode(el, o) {
  const seed = hashStr(el.id);
  const stroke = el.type === 'boundary' ? (el.style.stroke || BOUNDARY_COLOR) : (el.style.stroke || o.ink);
  const fill = el.style.fill || 'none';
  const sw = 1.8;
  const dash = el.type === 'boundary' ? ' stroke-dasharray="10 7"' : el.outOfScope ? ' stroke-dasharray="6 5"' : '';
  const { x, y, w, h } = el;
  const cx = x + w / 2, cy = y + h / 2;
  const strokeAttrs = `fill="none" stroke="${stroke}" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round"${dash}`;
  let body = '';

  const glyph = SUBTYPE_GLYPH[el.subtype];
  const shape = el.type === 'store' ? SUBTYPE_SHAPE[el.subtype] : null;
  // Symbol on the left of a label that is centred in the remaining space.
  const sideGlyph = (left, right) => {
    const gs = Math.min(24, h * 0.42, (right - left) * 0.25);
    if (!glyph || gs < 12) return centeredText(el.name, (left + right) / 2, cy, right - left - 12, o, stroke);
    const gx = left + 8;
    return glyphSVG(glyph, gx, cy - gs / 2, gs, stroke) + centeredText(el.name, (gx + gs + 4 + right) / 2, cy, right - gx - gs - 12, o, stroke);
  };

  if (el.type === 'process') {
    const rx = w / 2, ry = h / 2;
    if (fill !== 'none') body += `<path d="${cleanEllipse(cx, cy, rx, ry)}" fill="${fill}" stroke="none"/>`;
    body += `<path d="${o.sketchy ? roughEllipse(seed, cx, cy, rx, ry) : cleanEllipse(cx, cy, rx, ry)}" ${strokeAttrs}/>`;
    if (el.subtype === 'Multiple Processes') {
      const k = 8;
      body += `<path d="${o.sketchy ? roughEllipse(seed + 7, cx, cy, rx - k, ry - k) : cleanEllipse(cx, cy, rx - k, ry - k)}" ${strokeAttrs}/>`;
    }
    const gs = Math.min(28, h * 0.22, w * 0.22);
    if (glyph && gs >= 12) {
      const gy = cy - h * 0.1 - gs;
      const n = wrapText(el.name, w * 0.76, 16).length;
      // Keep multi-line labels clear of the symbol above them.
      const ly = Math.max(cy + h * 0.12, gy + gs + 6 + (n * 20) / 2);
      body += glyphSVG(glyph, cx - gs / 2, gy - Math.max(0, ly + (n * 20) / 2 - (y + h * 0.9)), gs, stroke);
      body += centeredText(el.name, cx, Math.min(ly, y + h * 0.9 - (n * 20) / 2), w * 0.76, o, stroke);
    } else body += centeredText(el.name, cx, cy, w * 0.72, o, stroke);
  } else if (el.type === 'external') {
    if (fill !== 'none') body += `<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="${fill}"/>`;
    body += o.sketchy ? `<path d="${roughRect(seed, x, y, w, h)}" ${strokeAttrs}/>` : `<rect x="${x}" y="${y}" width="${w}" height="${h}" ${strokeAttrs}/>`;
    body += sideGlyph(x, x + w);
  } else if (el.type === 'store' && shape === 'cylinder') {
    const ry = Math.min(14, h * 0.16), rx = w / 2;
    const side = `M${x} ${y + ry}V${y + h - ry}A${rx} ${ry} 0 0 0 ${x + w} ${y + h - ry}V${y + ry}`;
    if (fill !== 'none') body += `<path d="${side}A${rx} ${ry} 0 0 0 ${x} ${y + ry}Z" fill="${fill}"/>`;
    body += `<path d="${o.sketchy ? roughEllipse(seed, cx, y + ry, rx, ry, 0.6) : cleanEllipse(cx, y + ry, rx, ry)}" ${strokeAttrs}/>`;
    body += `<path d="${o.sketchy ? roughLine(seed + 1, x, y + ry, x, y + h - ry) + ' ' + roughLine(seed + 2, x + w, y + ry, x + w, y + h - ry) + ` M${x} ${y + h - ry}A${rx} ${ry} 0 0 0 ${x + w} ${y + h - ry}` : side}" ${strokeAttrs}/>`;
    body += centeredText(el.name, cx, cy + ry / 2, w - 12, o, stroke);
  } else if (el.type === 'store' && shape === 'log') {
    const seg = Math.min(16, w * 0.09);
    if (fill !== 'none') body += `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="3" fill="${fill}"/>`;
    body += o.sketchy ? `<path d="${roughRect(seed, x, y, w, h)}" ${strokeAttrs}/>` : `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="3" ${strokeAttrs}/>`;
    let segs = '';
    for (let k = 1; k <= 4; k++) segs += o.sketchy ? roughLine(seed + 10 + k, x + w - k * seg, y, x + w - k * seg, y + h, 0.5) + ' ' : `M${x + w - k * seg} ${y}V${y + h}`;
    body += `<path d="${segs}" ${strokeAttrs}/>`;
    body += sideGlyph(x, x + w - 4 * seg);
  } else if (el.type === 'store') {
    if (fill !== 'none') body += `<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="${fill}"/>`;
    const lines = o.sketchy
      ? roughLine(seed, x, y, x + w, y) + ' ' + roughLine(seed + 1, x, y + h, x + w, y + h)
      : `M${x} ${y}H${x + w}M${x} ${y + h}H${x + w}`;
    body += `<path d="${lines}" ${strokeAttrs}/>`;
    body += sideGlyph(x, x + w);
  } else if (el.type === 'boundary') {
    if (fill !== 'none') body += `<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="${fill}" fill-opacity="0.35"/>`;
    body += o.sketchy ? `<path d="${roughRect(seed, x, y, w, h, 0.6)}" ${strokeAttrs}/>` : `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="6" ${strokeAttrs}/>`;
    const off = glyph ? 26 : 0;
    if (glyph) body += glyphSVG(glyph, x + 9, y + 8, 18, stroke);
    body += textBlock(wrapText(el.name, w - 16 - off, 15), x + 10 + off, y + 22, { size: 15, font: o.font, fill: stroke, anchor: 'start', weight: 600 });
  } else if (el.type === 'note') {
    const lines = String(el.name || '').split('\n');
    body += textBlock(lines, x, y + 18 * 0.95, { size: 18, font: o.font, fill: el.style.stroke || o.ink, anchor: 'start' });
  }
  if (o.badges && el.type !== 'boundary' && el.type !== 'note') body += badge(x + w - 4, y + 4, o.badges.get(el.id));
  const op = el.outOfScope ? ' opacity="0.55"' : '';
  return `<g class="el" data-id="${esc(el.id)}"${op}>${body}</g>`;
}

function arrowHead(g, seed, o) {
  let dx = g.t.x - g.c.x, dy = g.t.y - g.c.y;
  if (Math.hypot(dx, dy) < 1) { dx = g.t.x - g.s.x; dy = g.t.y - g.s.y; }
  const len = Math.hypot(dx, dy) || 1;
  const ux = dx / len, uy = dy / len;
  const L = 14, a = 0.45;
  const w1 = { x: g.t.x - L * (ux * Math.cos(a) - uy * Math.sin(a)), y: g.t.y - L * (uy * Math.cos(a) + ux * Math.sin(a)) };
  const w2 = { x: g.t.x - L * (ux * Math.cos(-a) - uy * Math.sin(-a)), y: g.t.y - L * (uy * Math.cos(-a) + ux * Math.sin(-a)) };
  if (o.sketchy) return roughLine(seed + 3, w1.x, w1.y, g.t.x, g.t.y, 0.5) + ' ' + roughLine(seed + 4, w2.x, w2.y, g.t.x, g.t.y, 0.5);
  return `M${w1.x} ${w1.y}L${g.t.x} ${g.t.y}L${w2.x} ${w2.y}`;
}

function renderLine(el, byId, o) {
  const seed = hashStr(el.id);
  const g = lineGeom(el, byId);
  const isFlow = el.type === 'flow';
  const stroke = el.style.stroke || (isFlow ? o.ink : BOUNDARY_COLOR);
  const dash = isFlow ? (el.outOfScope ? ' stroke-dasharray="6 5"' : '') : ' stroke-dasharray="10 7"';
  const d = o.sketchy ? roughQuad(seed, g.s, g.c, g.t, isFlow ? 1 : 0.7) : cleanQuad(g.s, g.c, g.t);
  let body = `<path d="${d}" fill="none" stroke="${stroke}" stroke-width="${isFlow ? 1.8 : 2}" stroke-linecap="round"${dash}/>`;
  if (isFlow) body += `<path d="${arrowHead(g, seed, o)}" fill="none" stroke="${stroke}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>`;
  // Wide invisible stroke makes thin lines easy to hit in the browser's own hit-testing (used for cursors).
  body += `<path d="${cleanQuad(g.s, g.c, g.t)}" fill="none" stroke="transparent" stroke-width="14"/>`;
  const size = isFlow ? 14 : 15;
  const lines = wrapText(el.name, 180, size);
  if (el.name) {
    const y = g.mid.y - ((lines.length - 1) * size * 1.25) / 2 + size * 0.35;
    const lw = Math.max(...lines.map((l) => l.length)) * size * 0.52 + 10, lh = lines.length * size * 1.25 + 4;
    body += `<rect x="${g.mid.x - lw / 2}" y="${g.mid.y - lh / 2}" width="${lw}" height="${lh}" rx="4" fill="${o.bg}"/>`;
    body += textBlock(lines, g.mid.x, y, { size, font: o.font, fill: stroke, weight: isFlow ? 400 : 600 });
  }
  if (o.badges && isFlow) {
    const half = Math.min(90, Math.max(...lines.map((l) => l.length)) * size * 0.28);
    body += badge(g.mid.x + half + 16, g.mid.y - 12, o.badges.get(el.id));
  }
  const op = el.outOfScope ? ' opacity="0.55"' : '';
  return `<g class="el" data-id="${esc(el.id)}"${op}>${body}</g>`;
}

export function renderElements(diagram, o) {
  const byId = new Map(diagram.elements.map((e) => [e.id, e]));
  return orderedElements(diagram)
    .map((el) => {
      if (o.hidden && o.hidden === el.id) return '';
      return el.type === 'flow' || el.type === 'boundaryLine' ? renderLine(el, byId, o) : renderNode(el, o);
    })
    .join('');
}

export function diagramBounds(diagram) {
  const byId = new Map(diagram.elements.map((e) => [e.id, e]));
  return unionBounds(diagram.elements.map((e) => {
    const b = elementBounds(e, byId);
    if (e.type === 'flow' || e.type === 'boundaryLine') { b.x -= 60; b.w += 120; b.y -= 20; b.h += 40; }
    return b;
  }));
}

// Standalone SVG document for export / reports.
export function diagramToSVG(diagram, { sketchy = true, pad = 30, background = '#ffffff', badges = null } = {}) {
  const b = diagramBounds(diagram) || { x: 0, y: 0, w: 400, h: 300 };
  const x = Math.floor(b.x - pad), y = Math.floor(b.y - pad), w = Math.ceil(b.w + pad * 2), h = Math.ceil(b.h + pad * 2);
  const font = sketchy ? FONTS.sketchy : FONTS.clean;
  const content = renderElements(diagram, { sketchy, ink: '#1e1e1e', bg: background, font, badges });
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${x} ${y} ${w} ${h}" width="${w}" height="${h}">` +
    `<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="${background}"/>${content}</svg>`;
}

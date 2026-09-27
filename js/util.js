// Generic helpers, geometry and the hand-drawn ("sketchy") path generator.
// This module is DOM-free except for `download`, so it can be unit-tested in Node.

export const uid = (prefix = '') =>
  prefix + Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4);

export const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

export const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

export function slug(s) {
  return String(s || 'threat-model').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'threat-model';
}

export function download(filename, data, type = 'application/octet-stream') {
  const blob = data instanceof Blob ? data : new Blob([data], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function hashStr(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}

// Deterministic PRNG so a shape's sketchy wobble is stable between renders.
export function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const f = (n) => Math.round(n * 10) / 10;

/* ------------------------------------------------------------------ geometry */

export const NODE_TYPES = ['process', 'external', 'store', 'boundary', 'note'];
export const LINE_TYPES = ['flow', 'boundaryLine'];
export const isNode = (el) => NODE_TYPES.includes(el.type);
export const isLine = (el) => LINE_TYPES.includes(el.type);

export const center = (el) => ({ x: el.x + el.w / 2, y: el.y + el.h / 2 });

export function pointInRect(p, r) {
  return p.x >= r.x && p.x <= r.x + r.w && p.y >= r.y && p.y <= r.y + r.h;
}

export function rectContainsRect(outer, inner) {
  return inner.x >= outer.x && inner.y >= outer.y &&
    inner.x + inner.w <= outer.x + outer.w && inner.y + inner.h <= outer.y + outer.h;
}

export function distToSeg(p, a, b) {
  const dx = b.x - a.x, dy = b.y - a.y;
  const len2 = dx * dx + dy * dy;
  let t = len2 ? ((p.x - a.x) * dx + (p.y - a.y) * dy) / len2 : 0;
  t = clamp(t, 0, 1);
  return Math.hypot(p.x - (a.x + t * dx), p.y - (a.y + t * dy));
}

export function segIntersect(p1, p2, p3, p4) {
  const d = (p2.x - p1.x) * (p4.y - p3.y) - (p2.y - p1.y) * (p4.x - p3.x);
  if (Math.abs(d) < 1e-9) return false;
  const u = ((p3.x - p1.x) * (p4.y - p3.y) - (p3.y - p1.y) * (p4.x - p3.x)) / d;
  const v = ((p3.x - p1.x) * (p2.y - p1.y) - (p3.y - p1.y) * (p2.x - p1.x)) / d;
  return u >= 0 && u <= 1 && v >= 0 && v <= 1;
}

export function quadPoint(p0, c, p2, t) {
  const m = 1 - t;
  return { x: m * m * p0.x + 2 * m * t * c.x + t * t * p2.x, y: m * m * p0.y + 2 * m * t * c.y + t * t * p2.y };
}

export function quadPolyline(p0, c, p2, n = 20) {
  const pts = [];
  for (let i = 0; i <= n; i++) pts.push(quadPoint(p0, c, p2, i / n));
  return pts;
}

export function polylinesIntersect(a, b) {
  for (let i = 0; i < a.length - 1; i++)
    for (let j = 0; j < b.length - 1; j++)
      if (segIntersect(a[i], a[i + 1], b[j], b[j + 1])) return true;
  return false;
}

// Point where the ray from the element's centre towards `toward` leaves its outline.
export function clipToShape(el, toward, gap = 3) {
  const c = center(el);
  const dx = toward.x - c.x, dy = toward.y - c.y;
  if (!dx && !dy) return c;
  let t;
  if (el.type === 'process') {
    const rx = el.w / 2, ry = el.h / 2;
    t = 1 / Math.sqrt((dx * dx) / (rx * rx) + (dy * dy) / (ry * ry));
  } else {
    const hw = el.w / 2, hh = el.h / 2;
    t = Math.min(Math.abs(dx) > 1e-9 ? hw / Math.abs(dx) : Infinity, Math.abs(dy) > 1e-9 ? hh / Math.abs(dy) : Infinity);
  }
  const len = Math.hypot(dx, dy);
  return { x: c.x + dx * t + (dx / len) * gap, y: c.y + dy * t + (dy / len) * gap };
}

// Geometry of a (possibly bent) flow or boundary line.
// s/t = visible endpoints, c = quadratic control point, mid = point on the curve at t=0.5.
export function lineGeom(el, byId) {
  const a = el.sourceId ? byId.get(el.sourceId) : null;
  const b = el.targetId ? byId.get(el.targetId) : null;
  const p0 = a ? center(a) : { x: el.x1, y: el.y1 };
  const p2 = b ? center(b) : { x: el.x2, y: el.y2 };
  const bend = el.bend || 0;
  const dx = p2.x - p0.x, dy = p2.y - p0.y;
  const len = Math.hypot(dx, dy) || 1;
  const n = { x: -dy / len, y: dx / len };
  const roughCtrl = { x: (p0.x + p2.x) / 2 + n.x * bend * 2, y: (p0.y + p2.y) / 2 + n.y * bend * 2 };
  const ortho = !bend && a && b ? orthogonalEnds(a, b) : null;
  const s = ortho ? ortho.s : a ? clipToShape(a, roughCtrl) : p0;
  const t = ortho ? ortho.t : b ? clipToShape(b, roughCtrl, 4) : p2;
  const mx = (s.x + t.x) / 2, my = (s.y + t.y) / 2;
  const mid = { x: mx + n.x * bend, y: my + n.y * bend };
  const c = { x: mx + n.x * bend * 2, y: my + n.y * bend * 2 };
  return { s, t, c, mid, n, p0, p2 };
}

// Point on the outline of `el` at a given y (side = +1 right, -1 left) or x (side = +1 bottom, -1 top).
function outlineAt(el, axis, v, side, gap) {
  const c = center(el);
  if (el.type === 'process') {
    const rx = el.w / 2, ry = el.h / 2;
    if (axis === 'y') { const k = Math.sqrt(Math.max(0, 1 - ((v - c.y) / ry) ** 2)); return { x: c.x + side * (rx * k + gap), y: v }; }
    const k = Math.sqrt(Math.max(0, 1 - ((v - c.x) / rx) ** 2));
    return { x: v, y: c.y + side * (ry * k + gap) };
  }
  return axis === 'y' ? { x: side > 0 ? el.x + el.w + gap : el.x - gap, y: v } : { x: v, y: side > 0 ? el.y + el.h + gap : el.y - gap };
}

// When two shapes overlap enough on one axis, connect them with a straight
// horizontal / vertical segment through the middle of the overlap.
function orthogonalEnds(a, b) {
  const ov = (a0, a1, b0, b1) => [Math.max(a0, b0), Math.min(a1, b1)];
  const [y0, y1] = ov(a.y, a.y + a.h, b.y, b.y + b.h);
  const [x0, x1] = ov(a.x, a.x + a.w, b.x, b.x + b.w);
  const inset = (el, axis) => (el.type === 'process' ? (axis === 'y' ? el.h : el.w) * 0.2 : 0);
  if (y1 - y0 >= 0.3 * Math.min(a.h, b.h) && (a.x + a.w < b.x || b.x + b.w < a.x)) {
    const lo = Math.max(y0, a.y + inset(a, 'y'), b.y + inset(b, 'y')), hi = Math.min(y1, a.y + a.h - inset(a, 'y'), b.y + b.h - inset(b, 'y'));
    if (hi >= lo) {
      const y = (lo + hi) / 2, dir = a.x < b.x ? 1 : -1;
      return { s: outlineAt(a, 'y', y, dir, 3), t: outlineAt(b, 'y', y, -dir, 4) };
    }
  }
  if (x1 - x0 >= 0.3 * Math.min(a.w, b.w) && (a.y + a.h < b.y || b.y + b.h < a.y)) {
    const lo = Math.max(x0, a.x + inset(a, 'x'), b.x + inset(b, 'x')), hi = Math.min(x1, a.x + a.w - inset(a, 'x'), b.x + b.w - inset(b, 'x'));
    if (hi >= lo) {
      const x = (lo + hi) / 2, dir = a.y < b.y ? 1 : -1;
      return { s: outlineAt(a, 'x', x, dir, 3), t: outlineAt(b, 'x', x, -dir, 4) };
    }
  }
  return null;
}

// Approximate distance from p to the outline of a node (0 when inside).
export function distToShape(el, p) {
  if (el.type === 'process') {
    const c = center(el);
    const dx = p.x - c.x, dy = p.y - c.y;
    const r = Math.sqrt((dx / (el.w / 2)) ** 2 + (dy / (el.h / 2)) ** 2);
    return r <= 1 ? 0 : (Math.hypot(dx, dy) * (r - 1)) / r;
  }
  const dx = Math.max(el.x - p.x, 0, p.x - (el.x + el.w));
  const dy = Math.max(el.y - p.y, 0, p.y - (el.y + el.h));
  return Math.hypot(dx, dy);
}

export function nodeBounds(el) {
  return { x: el.x, y: el.y, w: el.w, h: el.h };
}

export function unionBounds(rects) {
  if (!rects.length) return null;
  let x1 = Infinity, y1 = Infinity, x2 = -Infinity, y2 = -Infinity;
  for (const r of rects) {
    x1 = Math.min(x1, r.x); y1 = Math.min(y1, r.y);
    x2 = Math.max(x2, r.x + r.w); y2 = Math.max(y2, r.y + r.h);
  }
  return { x: x1, y: y1, w: x2 - x1, h: y2 - y1 };
}

export function elementBounds(el, byId) {
  if (isNode(el)) return nodeBounds(el);
  const g = lineGeom(el, byId);
  const pts = quadPolyline(g.s, g.c, g.t, 8);
  const xs = pts.map((p) => p.x), ys = pts.map((p) => p.y);
  const x = Math.min(...xs), y = Math.min(...ys);
  return { x, y, w: Math.max(...xs) - x, h: Math.max(...ys) - y };
}

/* ------------------------------------------------------- sketchy path builder */

function smoothPath(pts, closed = false) {
  let d = `M${f(pts[0].x)} ${f(pts[0].y)}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] || (closed ? pts[pts.length - 2] : pts[i]);
    const p1 = pts[i], p2 = pts[i + 1];
    const p3 = pts[i + 2] || (closed ? pts[1] : p2);
    const c1 = { x: p1.x + (p2.x - p0.x) / 6, y: p1.y + (p2.y - p0.y) / 6 };
    const c2 = { x: p2.x - (p3.x - p1.x) / 6, y: p2.y - (p3.y - p1.y) / 6 };
    d += ` C${f(c1.x)} ${f(c1.y)} ${f(c2.x)} ${f(c2.y)} ${f(p2.x)} ${f(p2.y)}`;
  }
  return d;
}

function roughSeg(r, x1, y1, x2, y2, rough) {
  const len = Math.hypot(x2 - x1, y2 - y1) || 1;
  const off = Math.min(len * 0.015 + 0.8, 2.6) * rough;
  const j = () => (r() * 2 - 1) * off;
  const bow = (r() * 2 - 1) * Math.min(len * 0.012, 3.5) * rough;
  const nx = -(y2 - y1) / len, ny = (x2 - x1) / len;
  const mx = (x1 + x2) / 2 + nx * bow, my = (y1 + y2) / 2 + ny * bow;
  return `M${f(x1 + j())} ${f(y1 + j())} Q${f(mx + j() * 0.4)} ${f(my + j() * 0.4)} ${f(x2 + j())} ${f(y2 + j())}`;
}

export function roughLine(seed, x1, y1, x2, y2, rough = 1) {
  const r = rng(seed);
  return roughSeg(r, x1, y1, x2, y2, rough) + ' ' + roughSeg(r, x1, y1, x2, y2, rough * 0.8);
}

export function roughRect(seed, x, y, w, h, rough = 1) {
  const r = rng(seed);
  const segs = [[x, y, x + w, y], [x + w, y, x + w, y + h], [x + w, y + h, x, y + h], [x, y + h, x, y]];
  return segs.map((s) => roughSeg(r, ...s, rough) + ' ' + roughSeg(r, ...s, rough * 0.7)).join(' ');
}

export function roughEllipse(seed, cx, cy, rx, ry, rough = 1) {
  const r = rng(seed);
  const pass = (k) => {
    const n = 14;
    const start = r() * Math.PI * 2;
    const overshoot = 0.25 + r() * 0.3;
    const pts = [];
    for (let i = 0; i <= n; i++) {
      const a = start + ((Math.PI * 2 + overshoot) * i) / n;
      const jr = 1 + (r() * 2 - 1) * 0.022 * rough * k;
      pts.push({ x: cx + Math.cos(a) * rx * jr, y: cy + Math.sin(a) * ry * jr });
    }
    return smoothPath(pts);
  };
  return pass(1) + ' ' + pass(0.7);
}

export function roughQuad(seed, p0, c, p2, rough = 1) {
  const r = rng(seed);
  const pass = (k) => {
    const pts = quadPolyline(p0, c, p2, 8).map((p, i, a) => {
      const edge = i === 0 || i === a.length - 1;
      const m = (edge ? 1.2 : 1.6) * rough * k;
      return { x: p.x + (r() * 2 - 1) * m, y: p.y + (r() * 2 - 1) * m };
    });
    return smoothPath(pts);
  };
  return pass(1) + ' ' + pass(0.7);
}

export const cleanEllipse = (cx, cy, rx, ry) =>
  `M${f(cx - rx)} ${f(cy)} a${f(rx)} ${f(ry)} 0 1 0 ${f(rx * 2)} 0 a${f(rx)} ${f(ry)} 0 1 0 ${f(-rx * 2)} 0Z`;

export const cleanQuad = (p0, c, p2) => `M${f(p0.x)} ${f(p0.y)} Q${f(c.x)} ${f(c.y)} ${f(p2.x)} ${f(p2.y)}`;

// Very small word-wrapper used for SVG labels (SVG has no native wrapping).
export function wrapText(text, maxWidth, fontSize) {
  const charW = fontSize * 0.56;
  const maxChars = Math.max(4, Math.floor(maxWidth / charW));
  const out = [];
  for (const para of String(text ?? '').split('\n')) {
    let line = '';
    for (const word of para.split(/\s+/)) {
      if (!word) continue;
      if (!line) line = word;
      else if ((line + ' ' + word).length <= maxChars) line += ' ' + word;
      else { out.push(line); line = word; }
      // Only break a single long word when it clearly doesn't fit.
      const hard = Math.ceil(maxChars * 1.4);
      while (line.length > hard) { out.push(line.slice(0, hard)); line = line.slice(hard); }
    }
    out.push(line);
  }
  return out;
}

export function measureText(text, fontSize) {
  const lines = String(text ?? '').split('\n');
  const w = Math.max(...lines.map((l) => l.length)) * fontSize * 0.56;
  return { w: Math.max(20, w), h: lines.length * fontSize * 1.3 };
}

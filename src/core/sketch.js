// Deterministic "hand-drawn" path generators (Excalidraw-like look) with no dependencies.
// Every shape is seeded by its element id, so strokes do not flicker while dragging.

import { seededRandom } from './util.js';

const f = (n) => (Math.round(n * 100) / 100).toString();

function jitter(rng, amount) {
  return (rng() - 0.5) * 2 * amount;
}

/** Slightly bowed double-stroke line. */
export function roughLine(p0, p1, seed, roughness = 1) {
  const rng = seededRandom(seed);
  const len = Math.hypot(p1.x - p0.x, p1.y - p0.y);
  const amt = Math.min(2.2, 0.6 + len / 200) * roughness;
  let d = '';
  for (let pass = 0; pass < 2; pass++) {
    const a = { x: p0.x + jitter(rng, amt), y: p0.y + jitter(rng, amt) };
    const b = { x: p1.x + jitter(rng, amt), y: p1.y + jitter(rng, amt) };
    const nx = -(p1.y - p0.y) / (len || 1);
    const ny = (p1.x - p0.x) / (len || 1);
    const bow = jitter(rng, Math.min(4, len / 60) * roughness);
    const t = 0.4 + rng() * 0.2;
    const m = { x: p0.x + (p1.x - p0.x) * t + nx * bow, y: p0.y + (p1.y - p0.y) * t + ny * bow };
    d += `M${f(a.x)} ${f(a.y)}Q${f(m.x)} ${f(m.y)} ${f(b.x)} ${f(b.y)}`;
  }
  return d;
}

export function roughRect(x, y, w, h, seed, roughness = 1) {
  const p = [
    { x, y },
    { x: x + w, y },
    { x: x + w, y: y + h },
    { x, y: y + h },
  ];
  return [0, 1, 2, 3].map((i) => roughLine(p[i], p[(i + 1) % 4], `${seed}:${i}`, roughness)).join('');
}

/** Closed smooth curve through points (Catmull-Rom → cubic Bézier). */
function closedCurve(pts) {
  const n = pts.length;
  let d = `M${f(pts[0].x)} ${f(pts[0].y)}`;
  for (let i = 0; i < n; i++) {
    const p0 = pts[(i - 1 + n) % n];
    const p1 = pts[i];
    const p2 = pts[(i + 1) % n];
    const p3 = pts[(i + 2) % n];
    const c1 = { x: p1.x + (p2.x - p0.x) / 6, y: p1.y + (p2.y - p0.y) / 6 };
    const c2 = { x: p2.x - (p3.x - p1.x) / 6, y: p2.y - (p3.y - p1.y) / 6 };
    d += `C${f(c1.x)} ${f(c1.y)} ${f(c2.x)} ${f(c2.y)} ${f(p2.x)} ${f(p2.y)}`;
  }
  return d;
}

export function roughEllipse(cx, cy, rx, ry, seed, roughness = 1) {
  const rng = seededRandom(seed);
  let d = '';
  for (let pass = 0; pass < 2; pass++) {
    const steps = 9;
    const rot = rng() * Math.PI * 2;
    const pts = [];
    for (let i = 0; i < steps; i++) {
      const a = rot + (i / steps) * Math.PI * 2;
      const k = 1 + jitter(rng, 0.035 * roughness);
      pts.push({ x: cx + Math.cos(a) * rx * k, y: cy + Math.sin(a) * ry * k });
    }
    d += closedCurve(pts);
  }
  return d;
}

/** Smooth ellipse path (non-sketch mode / fills). */
export function ellipsePath(cx, cy, rx, ry) {
  return `M${f(cx - rx)} ${f(cy)}a${f(rx)} ${f(ry)} 0 1 0 ${f(rx * 2)} 0a${f(rx)} ${f(ry)} 0 1 0 ${f(-rx * 2)} 0Z`;
}

export function roughQuad(p0, c, p1, seed, roughness = 1) {
  const rng = seededRandom(seed);
  const len = Math.hypot(p1.x - p0.x, p1.y - p0.y);
  const amt = Math.min(2, 0.5 + len / 260) * roughness;
  let d = '';
  for (let pass = 0; pass < 2; pass++) {
    d += `M${f(p0.x + jitter(rng, amt))} ${f(p0.y + jitter(rng, amt))}Q${f(c.x + jitter(rng, amt * 2))} ${f(c.y + jitter(rng, amt * 2))} ${f(p1.x + jitter(rng, amt))} ${f(p1.y + jitter(rng, amt))}`;
  }
  return d;
}

export function quadPath(p0, c, p1) {
  return `M${f(p0.x)} ${f(p0.y)}Q${f(c.x)} ${f(c.y)} ${f(p1.x)} ${f(p1.y)}`;
}

/** Open arrowhead at p1 pointing along direction (from → p1). */
export function arrowHead(from, p1, size = 12) {
  const a = Math.atan2(p1.y - from.y, p1.x - from.x);
  const spread = 0.42;
  const l = { x: p1.x - Math.cos(a - spread) * size, y: p1.y - Math.sin(a - spread) * size };
  const r = { x: p1.x - Math.cos(a + spread) * size, y: p1.y - Math.sin(a + spread) * size };
  return `M${f(l.x)} ${f(l.y)}L${f(p1.x)} ${f(p1.y)}L${f(r.x)} ${f(r.y)}`;
}

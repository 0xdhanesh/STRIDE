// Geometry for diagrams: shapes, bound flow endpoints, quadratic Bézier
// curves and the intersection tests that implement MTMT's geometric
// "flow crosses boundary" semantics.

export const CURVE_SEGMENTS = 32;

export function rectOf(el) {
  return { x: el.x, y: el.y, w: el.w, h: el.h };
}

export function center(r) {
  return { x: r.x + r.w / 2, y: r.y + r.h / 2 };
}

export function rectContains(r, p, pad = 0) {
  return p.x >= r.x - pad && p.x <= r.x + r.w + pad && p.y >= r.y - pad && p.y <= r.y + r.h + pad;
}

export function rectsOverlap(a, b) {
  return a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
}

export function rectInside(inner, outer) {
  return inner.x >= outer.x && inner.y >= outer.y && inner.x + inner.w <= outer.x + outer.w && inner.y + inner.h <= outer.y + outer.h;
}

export function unionRect(rects) {
  if (!rects.length) return null;
  let x0 = Infinity,
    y0 = Infinity,
    x1 = -Infinity,
    y1 = -Infinity;
  for (const r of rects) {
    x0 = Math.min(x0, r.x);
    y0 = Math.min(y0, r.y);
    x1 = Math.max(x1, r.x + r.w);
    y1 = Math.max(y1, r.y + r.h);
  }
  return { x: x0, y: y0, w: x1 - x0, h: y1 - y0 };
}

/**
 * Point where a ray from the shape centre toward `toward` leaves the shape.
 * Ellipses (processes) use the analytic ellipse; everything else its rectangle.
 */
export function perimeterPoint(shape, kind, toward, gap = 2) {
  const c = center(shape);
  let dx = toward.x - c.x;
  let dy = toward.y - c.y;
  if (Math.abs(dx) < 1e-9 && Math.abs(dy) < 1e-9) dx = 1;
  const len = Math.hypot(dx, dy);
  const ux = dx / len;
  const uy = dy / len;
  const a = shape.w / 2;
  const b = shape.h / 2;
  let t;
  if (kind === 'ellipse') {
    t = 1 / Math.sqrt((ux * ux) / (a * a || 1) + (uy * uy) / (b * b || 1));
  } else {
    const tx = Math.abs(ux) > 1e-9 ? a / Math.abs(ux) : Infinity;
    const ty = Math.abs(uy) > 1e-9 ? b / Math.abs(uy) : Infinity;
    t = Math.min(tx, ty);
  }
  t += gap;
  return { x: c.x + ux * t, y: c.y + uy * t };
}

/** Point on a quadratic Bézier at t. */
export function quadPoint(p0, c, p1, t) {
  const mt = 1 - t;
  return {
    x: mt * mt * p0.x + 2 * mt * t * c.x + t * t * p1.x,
    y: mt * mt * p0.y + 2 * mt * t * c.y + t * t * p1.y,
  };
}

/**
 * Control point from endpoints and a signed perpendicular "bend":
 * the curve's midpoint (t=0.5) sits `bend` units from the chord midpoint.
 */
export function controlFromBend(p0, p1, bend) {
  const mx = (p0.x + p1.x) / 2;
  const my = (p0.y + p1.y) / 2;
  const dx = p1.x - p0.x;
  const dy = p1.y - p0.y;
  const len = Math.hypot(dx, dy) || 1;
  const nx = -dy / len;
  const ny = dx / len;
  return { x: mx + nx * bend * 2, y: my + ny * bend * 2 };
}

/** Inverse of controlFromBend for a desired curve midpoint `m`. */
export function bendFromMidpoint(p0, p1, m) {
  const dx = p1.x - p0.x;
  const dy = p1.y - p0.y;
  const len = Math.hypot(dx, dy) || 1;
  const nx = -dy / len;
  const ny = dx / len;
  return (m.x - (p0.x + p1.x) / 2) * nx + (m.y - (p0.y + p1.y) / 2) * ny;
}

export function flatten(p0, c, p1, n = CURVE_SEGMENTS) {
  const pts = [];
  for (let i = 0; i <= n; i++) pts.push(quadPoint(p0, c, p1, i / n));
  return pts;
}

function orient(a, b, c) {
  return (b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x);
}

function onSegment(a, b, p) {
  return Math.min(a.x, b.x) - 1e-9 <= p.x && p.x <= Math.max(a.x, b.x) + 1e-9 && Math.min(a.y, b.y) - 1e-9 <= p.y && p.y <= Math.max(a.y, b.y) + 1e-9;
}

/** Segment intersection including touching/collinear overlap. */
export function segmentsIntersect(a, b, c, d) {
  const o1 = orient(a, b, c);
  const o2 = orient(a, b, d);
  const o3 = orient(c, d, a);
  const o4 = orient(c, d, b);
  if (((o1 > 0 && o2 < 0) || (o1 < 0 && o2 > 0)) && ((o3 > 0 && o4 < 0) || (o3 < 0 && o4 > 0))) return true;
  if (Math.abs(o1) < 1e-9 && onSegment(a, b, c)) return true;
  if (Math.abs(o2) < 1e-9 && onSegment(a, b, d)) return true;
  if (Math.abs(o3) < 1e-9 && onSegment(c, d, a)) return true;
  if (Math.abs(o4) < 1e-9 && onSegment(c, d, b)) return true;
  return false;
}

export function polylinesIntersect(pa, pb) {
  for (let i = 0; i < pa.length - 1; i++) {
    for (let j = 0; j < pb.length - 1; j++) {
      if (segmentsIntersect(pa[i], pa[i + 1], pb[j], pb[j + 1])) return true;
    }
  }
  return false;
}

export function rectEdges(r) {
  const tl = { x: r.x, y: r.y };
  const tr = { x: r.x + r.w, y: r.y };
  const br = { x: r.x + r.w, y: r.y + r.h };
  const bl = { x: r.x, y: r.y + r.h };
  return [
    [tl, tr],
    [tr, br],
    [br, bl],
    [bl, tl],
  ];
}

/** Does a polyline cut through the border of rectangle r? */
export function polylineCrossesRect(pts, r) {
  for (let i = 0; i < pts.length - 1; i++) {
    for (const [e0, e1] of rectEdges(r)) if (segmentsIntersect(pts[i], pts[i + 1], e0, e1)) return true;
  }
  return false;
}

export function distanceToSegment(p, a, b) {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const l2 = dx * dx + dy * dy;
  let t = l2 ? ((p.x - a.x) * dx + (p.y - a.y) * dy) / l2 : 0;
  t = Math.max(0, Math.min(1, t));
  return Math.hypot(p.x - (a.x + t * dx), p.y - (a.y + t * dy));
}

export function distanceToPolyline(p, pts) {
  let best = Infinity;
  for (let i = 0; i < pts.length - 1; i++) best = Math.min(best, distanceToSegment(p, pts[i], pts[i + 1]));
  return best;
}

/** Distance from p to the border of rect r (0 when on the border). */
export function distanceToRectBorder(p, r) {
  let best = Infinity;
  for (const [a, b] of rectEdges(r)) best = Math.min(best, distanceToSegment(p, a, b));
  return best;
}

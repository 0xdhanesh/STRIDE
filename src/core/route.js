// Flow routing: where each data flow attaches to its entities, how it bends
// around other entities, where its label sits, and which colour it is drawn in.
//
// Rules (all computed, nothing is stored unless the user overrides it):
//  - Egress is bundled: every flow leaving an entity through the same side shares
//    one exit port, so a fan-out reads as one trunk that splits towards its targets.
//  - Ingress is separate: every flow entering an entity gets its own port along the
//    side that faces its source, ordered to avoid crossings.
//  - Flows from different entities never run on top of each other: a flow with no
//    manual bend picks the least-bent curve that clears other entities and other
//    entities' flows.
//  - Colour follows the entity: all egress of an entity shares its colour, so the
//    flows entering an entity are told apart by where they come from.

import { GENERIC } from './kb.js';
import { center, controlFromBend, distanceToPolyline, flatten, polylineCrossesRect, rectContains, rectOf, rectsOverlap } from './geometry.js';

const OBSTACLE = new Set([GENERIC.PROCESS, GENERIC.EXTERNAL, GENERIC.STORE]);
const BEND_CANDIDATES = [0, 36, -36, 72, -72, 110, -110, 150, -150, 200, -200, 260, -260];
const LABEL_T = [0.5, 0.42, 0.58, 0.34, 0.66, 0.26, 0.74];
const SIDE_SPAN = 0.8; // share of a side that ports may use
const SOURCE_GAP = 2;
const TARGET_GAP = 4;

/** Colours for entities, chosen to stay apart from each other and from the red boundary colour. */
export const FLOW_PALETTE = Object.freeze(['#1c7ed6', '#e8590c', '#2f9e44', '#c2255c', '#7048e8', '#0c8599', '#f08c00', '#5c940d', '#9c36b5', '#495057']);

export function normalizeColor(v) {
  const s = String(v ?? '').trim();
  return /^#[0-9a-f]{6}$/i.test(s) ? s.toLowerCase() : undefined;
}

function hslHex(h, s, l) {
  const a = s * Math.min(l, 1 - l);
  const f = (n) => {
    const k = (n + h / 30) % 12;
    return Math.round(255 * (l - a * Math.max(-1, Math.min(k - 3, 9 - k, 1))))
      .toString(16)
      .padStart(2, '0');
  };
  return `#${f(0)}${f(8)}${f(4)}`;
}

/** Colour of an entity's egress traffic: its own colour if set, else a stable palette pick. */
export function entityColor(diagram, node) {
  const own = normalizeColor(node?.color);
  if (own) return own;
  const nodes = diagram.elements.filter((e) => OBSTACLE.has(e.generic));
  const i = Math.max(0, nodes.findIndex((e) => e.id === node?.id));
  return i < FLOW_PALETTE.length ? FLOW_PALETTE[i] : hslHex((i * 137.508) % 360, 0.62, 0.42);
}

/** Colour a flow is drawn in: its own override, else its source entity's colour. */
export function flowColor(diagram, flow) {
  const own = normalizeColor(flow?.color);
  if (own) return own;
  const src = flow?.source ? diagram.elements.find((e) => e.id === flow.source) : null;
  return src ? entityColor(diagram, src) : undefined;
}

function sideToward(r, q) {
  const c = center(r);
  const dx = (q.x - c.x) / (r.w / 2 || 1);
  const dy = (q.y - c.y) / (r.h / 2 || 1);
  if (Math.abs(dx) >= Math.abs(dy)) return dx >= 0 ? 'E' : 'W';
  return dy >= 0 ? 'S' : 'N';
}

/** Point on the border of a node on `side`, `u` units along the side from its middle. */
function portPoint(r, ellipse, side, u, gap) {
  const c = center(r);
  const a = r.w / 2;
  const b = r.h / 2;
  const vertical = side === 'N' || side === 'S';
  const sign = side === 'S' || side === 'E' ? 1 : -1;
  if (vertical) {
    const k = ellipse ? Math.sqrt(Math.max(0, 1 - (u / a) ** 2)) : 1;
    return { x: c.x + u, y: c.y + sign * (b * k + gap) };
  }
  const k = ellipse ? Math.sqrt(Math.max(0, 1 - (u / b) ** 2)) : 1;
  return { x: c.x + sign * (a * k + gap), y: c.y + u };
}

function labelBox(name, p, fs = 14) {
  const len = String(name || '').length;
  const lines = Math.max(1, Math.min(5, Math.ceil((len * fs * 0.56) / 160)));
  const w = Math.min(len, Math.floor(160 / (fs * 0.56))) * fs * 0.56 + 10;
  const h = lines * fs * 1.2 + 4;
  return { x: p.x - w / 2, y: p.y - h / 2, w, h };
}

function quadAt(p0, c, p1, t) {
  const mt = 1 - t;
  return { x: mt * mt * p0.x + 2 * mt * t * c.x + t * t * p1.x, y: mt * mt * p0.y + 2 * mt * t * c.y + t * t * p1.y };
}

/**
 * Compute routes for every flow that is bound at both ends.
 * Returns Map flowId → { p0, p1, bend, labelT }.
 */
export function computeRoutes(diagram) {
  const nodes = new Map(diagram.elements.filter((e) => OBSTACLE.has(e.generic)).map((e) => [e.id, e]));
  const flows = diagram.elements.filter((e) => e.generic === GENERIC.FLOW && e.source && e.target && e.source !== e.target && nodes.has(e.source) && nodes.has(e.target));
  const routes = new Map();
  if (!flows.length) return routes;

  // 1. Group flow ends by (node, side).
  const slots = new Map(); // "node|side" -> [{ key, flow, role, other }]
  const sideKey = (id, side) => `${id}|${side}`;
  const ends = new Map(); // flowId -> { out: key, in: key }
  for (const f of flows) {
    const s = nodes.get(f.source);
    const t = nodes.get(f.target);
    const sc = center(rectOf(s));
    const tc = center(rectOf(t));
    const outSide = sideToward(rectOf(s), tc);
    const inSide = sideToward(rectOf(t), sc);
    const outK = sideKey(s.id, outSide);
    const inK = sideKey(t.id, inSide);
    if (!slots.has(outK)) slots.set(outK, []);
    if (!slots.has(inK)) slots.set(inK, []);
    slots.get(outK).push({ flow: f, role: 'out', other: tc });
    slots.get(inK).push({ flow: f, role: 'in', other: sc });
    ends.set(f.id, { outSide, inSide });
  }

  // 2. Lay out ports on each side: one shared slot for all egress, one slot per ingress.
  //    Entries are ordered by where their other end currently is, then re-ordered twice
  //    against the new port positions so opposite/parallel flows stay side by side
  //    instead of crossing.
  let portOf = new Map(); // `${flowId}|out` / `${flowId}|in` -> point
  for (let pass = 0; pass < 3; pass++) {
    const next = new Map();
    for (const [key, list] of slots) {
      const [nodeId, side] = key.split('|');
      const node = nodes.get(nodeId);
      const r = rectOf(node);
      const ellipse = node.generic === GENERIC.PROCESS;
      const vertical = side === 'N' || side === 'S';
      const axis = (p) => (vertical ? p.x : p.y);
      const otherPos = (e) => {
        const role = e.role === 'out' ? 'in' : 'out'; // the far end's port
        const pt = pass ? portOf.get(`${e.flow.id}|${role}`) : null;
        return axis(pt || e.other);
      };
      const entries = [];
      const outs = list.filter((e) => e.role === 'out');
      if (outs.length) {
        const others = new Set(outs.map((e) => e.flow.target));
        entries.push({ role: 'out', flows: outs.map((e) => e.flow), pos: outs.reduce((acc, e) => acc + otherPos(e), 0) / outs.length, otherId: others.size === 1 ? [...others][0] : null });
      }
      for (const e of list.filter((x) => x.role === 'in')) entries.push({ role: 'in', flows: [e.flow], pos: otherPos(e), otherId: e.flow.source });
      entries.sort((x, y) => {
        if (Math.abs(x.pos - y.pos) > 1) return x.pos - y.pos;
        // Tie between the two directions of one pair: a fixed rule per pair keeps both ends in the same order.
        if (x.otherId && x.otherId === y.otherId && x.role !== y.role) return (x.role === 'out') === (nodeId < x.otherId) ? -1 : 1;
        return x.role === y.role ? 0 : x.role === 'out' ? -1 : 1;
      });
      const len = vertical ? r.w : r.h;
      const n = entries.length;
      entries.forEach((en, i) => {
        const u = n === 1 ? 0 : ((i + 1) / (n + 1) - 0.5) * len * SIDE_SPAN * (n === 2 ? 1.1 : 1.25);
        const pt = portPoint(r, ellipse, side, Math.max(-len * 0.42, Math.min(len * 0.42, u)), en.role === 'out' ? SOURCE_GAP : TARGET_GAP);
        for (const f of en.flows) next.set(`${f.id}|${en.role}`, pt);
      });
    }
    portOf = next;
  }

  // 3. Pick a bend for flows without a manual one.
  const obstacles = [...nodes.values()].map((n) => ({ id: n.id, r: rectOf(n) }));
  const placed = []; // { source, pts }
  for (const f of flows) {
    const p0 = portOf.get(`${f.id}|out`);
    const p1 = portOf.get(`${f.id}|in`);
    const manual = Math.abs(f.bend || 0) > 1;
    let best = { bend: manual ? f.bend : 0, cost: Infinity };
    for (const cand of manual ? [f.bend] : BEND_CANDIDATES) {
      const pts = flatten(p0, controlFromBend(p0, p1, cand), p1, 20);
      let cost = Math.abs(cand) * 0.05;
      for (const o of obstacles) {
        if (o.id === f.source || o.id === f.target) continue;
        const pad = { x: o.r.x - 10, y: o.r.y - 10, w: o.r.w + 20, h: o.r.h + 20 };
        if (polylineCrossesRect(pts, pad) || rectContains(pad, pts[10])) cost += 1000;
      }
      for (const other of placed) {
        if (other.source === f.source) continue; // egress of one entity may share its trunk
        let close = 0;
        for (let i = 2; i < pts.length - 2; i++) if (distanceToPolyline(pts[i], other.pts) < 8) close++;
        if (close > 3) cost += close * 12; // running alongside counts; a plain crossing does not
      }
      if (cost < best.cost) best = { bend: cand, cost };
      if (cost <= 0.05 * Math.abs(cand) + 0.001) break; // clear path found
    }
    const c = controlFromBend(p0, p1, best.bend);
    placed.push({ source: f.source, pts: flatten(p0, c, p1, 20) });
    routes.set(f.id, { p0, p1, bend: best.bend, labelT: 0.5 });
  }

  // 4. Labels: first position that clears entities, other labels and other flows.
  const labels = [];
  for (const f of flows) {
    const rt = routes.get(f.id);
    if (!f.name) {
      labels.push(null);
      continue;
    }
    const c = controlFromBend(rt.p0, rt.p1, rt.bend);
    let best = { t: 0.5, cost: Infinity, box: null };
    for (const t of LABEL_T) {
      const box = labelBox(f.name, quadAt(rt.p0, c, rt.p1, t));
      let cost = Math.abs(t - 0.5) * 4;
      for (const o of obstacles) if (rectsOverlap(box, o.r)) cost += 100;
      for (const l of labels) if (l && rectsOverlap(box, l)) cost += 100;
      const mid = { x: box.x + box.w / 2, y: box.y + box.h / 2 };
      for (const other of placed) {
        if (other.pts === placed[flows.indexOf(f)].pts) continue;
        if (distanceToPolyline(mid, other.pts) < Math.max(box.h / 2, 10)) cost += 15;
      }
      if (cost < best.cost) best = { t, cost, box };
      if (cost < 1) break;
    }
    rt.labelT = best.t;
    labels.push(best.box);
  }
  return routes;
}

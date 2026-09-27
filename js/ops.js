// Operations that mutate diagram elements. Callers are responsible for store.commit().

import { uid, isNode, isLine, lineGeom, rectContainsRect, measureText } from './util.js';
import { STENCILS, DEFAULT_NAMES, defaultProps } from './stencils.js';

function nextName(model, type) {
  if (type === 'note') return '';
  const base = DEFAULT_NAMES[type];
  const used = new Set(model.diagrams.flatMap((d) => d.elements.map((e) => e.name)));
  for (let n = 1; ; n++) if (!used.has(`${base} ${n}`)) return `${base} ${n}`;
}

export function makeElement(model, type, at, size = null) {
  const st = STENCILS[type];
  const el = {
    id: uid('e_'), type, name: nextName(model, type), subtype: st.subtypes[0] || '',
    props: defaultProps(type), style: {}, outOfScope: false, outOfScopeReason: '', notes: '',
  };
  if (isLine(el)) {
    Object.assign(el, { x1: at.x, y1: at.y, x2: at.x, y2: at.y, bend: 0, sourceId: null, targetId: null });
  } else if (type === 'note') {
    Object.assign(el, { x: at.x, y: at.y - 12, w: 40, h: 24 });
  } else {
    const w = size?.w ?? st.size.w, h = size?.h ?? st.size.h;
    Object.assign(el, { x: size ? at.x : at.x - w / 2, y: size ? at.y : at.y - h / 2, w, h });
  }
  return el;
}

const PRESET_SIZE = {
  'Kafka Topic / Event Log': { w: 190, h: 70 }, Database: { w: 140, h: 100 }, 'SQL Database': { w: 140, h: 100 },
  'NoSQL Database': { w: 140, h: 100 }, 'Vector Database': { w: 140, h: 100 },
};

// Create an element from a library preset (type + subtype), named after the subtype.
export function makeFromLibrary(model, type, subtype, at) {
  const size = PRESET_SIZE[subtype];
  const el = makeElement(model, type, size ? { x: at.x - size.w / 2, y: at.y - size.h / 2 } : at, size || null);
  applySubtype(el, subtype);
  const base = subtype.replace(/\s*\(.*\)$/, '').split(' / ')[0];
  const used = new Set(model.diagrams.flatMap((d) => d.elements.map((e) => e.name)));
  el.name = used.has(base) ? Array.from({ length: 999 }, (_, i) => `${base} ${i + 2}`).find((n) => !used.has(n)) : base;
  return el;
}

export function fitNote(el) {
  const m = measureText(el.name || ' ', 18);
  el.w = m.w;
  el.h = m.h;
}

export function applySubtype(el, subtype) {
  el.subtype = subtype;
  const defaults = STENCILS[el.type].subtypeDefaults?.[subtype];
  if (defaults) for (const [k, v] of Object.entries(defaults)) if (!el.props[k] || el.props[k] === 'Not Selected') el.props[k] = v;
}

// Remove elements; flows attached to removed nodes keep a free end where the node was.
export function deleteElements(diagram, ids) {
  const byId = new Map(diagram.elements.map((e) => [e.id, e]));
  for (const f of diagram.elements) {
    if (!isLine(f) || ids.has(f.id)) continue;
    const g = lineGeom(f, byId);
    if (f.sourceId && ids.has(f.sourceId)) { f.x1 = g.s.x; f.y1 = g.s.y; f.sourceId = null; }
    if (f.targetId && ids.has(f.targetId)) { f.x2 = g.t.x; f.y2 = g.t.y; f.targetId = null; }
  }
  diagram.elements = diagram.elements.filter((e) => !ids.has(e.id));
}

// Clipboard payload: selected elements + flows fully between selected nodes.
export function copyPayload(diagram, ids) {
  const byId = new Map(diagram.elements.map((e) => [e.id, e]));
  const set = new Set(ids);
  for (const e of diagram.elements) if (e.type === 'flow' && set.has(e.sourceId) && set.has(e.targetId)) set.add(e.id);
  const els = diagram.elements.filter((e) => set.has(e.id)).map((e) => {
    const c = structuredClone(e);
    if (isLine(c)) {
      const g = lineGeom(e, byId);
      if (c.sourceId && !set.has(c.sourceId)) { c.x1 = g.s.x; c.y1 = g.s.y; c.sourceId = null; }
      if (c.targetId && !set.has(c.targetId)) { c.x2 = g.t.x; c.y2 = g.t.y; c.targetId = null; }
    }
    return c;
  });
  return { app: 'stride-threat-modeler', kind: 'clipboard', elements: els };
}

export function pastePayload(diagram, payload, dx = 24, dy = 24) {
  const map = new Map();
  const out = payload.elements.map((e) => {
    const c = structuredClone(e);
    map.set(e.id, (c.id = uid('e_')));
    return c;
  });
  for (const c of out) {
    if (isNode(c)) { c.x += dx; c.y += dy; }
    if (isLine(c)) {
      c.sourceId = c.sourceId ? map.get(c.sourceId) ?? null : null;
      c.targetId = c.targetId ? map.get(c.targetId) ?? null : null;
      c.x1 += dx; c.y1 += dy; c.x2 += dx; c.y2 += dy;
    }
  }
  diagram.elements.push(...out);
  return out.map((c) => c.id);
}

export function duplicateElements(diagram, ids) {
  return pastePayload(diagram, copyPayload(diagram, ids));
}

export function reverseFlow(el) {
  [el.sourceId, el.targetId] = [el.targetId, el.sourceId];
  [el.x1, el.y1, el.x2, el.y2] = [el.x2, el.y2, el.x1, el.y1];
}

// Keep request/response pairs and parallel flows from drawing on top of each other.
// Bends are relative to each flow's own direction, so a reverse flow with bend b sits at -b.
export function autoBend(diagram, flow) {
  if (!flow.sourceId || !flow.targetId) return;
  const siblings = diagram.elements.filter((e) => e !== flow && e.type === 'flow' &&
    ((e.sourceId === flow.sourceId && e.targetId === flow.targetId) || (e.sourceId === flow.targetId && e.targetId === flow.sourceId)));
  if (!siblings.length) return;
  for (const s of siblings) if (!s.bend && s.sourceId !== flow.sourceId) s.bend = 30;
  const taken = siblings.map((s) => (s.sourceId === flow.sourceId ? 1 : -1) * (s.bend || 0));
  flow.bend = [30, -30, 65, -65, 100, -100, 135, -135].find((b) => taken.every((t) => Math.abs(t - b) >= 20)) ?? 170;
}

export function reorder(diagram, ids, toFront) {
  const sel = diagram.elements.filter((e) => ids.has(e.id));
  const rest = diagram.elements.filter((e) => !ids.has(e.id));
  diagram.elements = toFront ? [...rest, ...sel] : [...sel, ...rest];
}

// Elements that move together with a trust-boundary box (like Excalidraw frames).
export function containedIn(diagram, box) {
  const byId = new Map(diagram.elements.map((e) => [e.id, e]));
  return diagram.elements.filter((e) => {
    if (e === box) return false;
    if (isNode(e)) return rectContainsRect(box, e);
    const g = lineGeom(e, byId);
    const inside = (p) => p.x >= box.x && p.x <= box.x + box.w && p.y >= box.y && p.y <= box.y + box.h;
    return inside(g.s) && inside(g.t);
  });
}

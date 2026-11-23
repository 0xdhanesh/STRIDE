// Threat model document: diagrams of elements, flows and boundaries, plus
// threats, notes and metadata. Mirrors MTMT's ModelData (.tm7) concepts in JSON.

import { GENERIC, GENERIC_IDS, REPRESENTATION, kbFor, normalizeTemplate } from './kb.js';
import { center, controlFromBend, flatten, perimeterPoint, rectOf, rectsOverlap } from './geometry.js';
import { clone, isSafeKey, nowIso, safeStringMap, uid } from './util.js';
import { annotateThreats } from './enrich/enrichThreat.js';
import { computeRoutes, normalizeColor } from './route.js';

export const MODEL_FORMAT = 'stride-model';
export const MODEL_VERSION = 1;

export const THREAT_STATES = Object.freeze(['NotStarted', 'NeedsInvestigation', 'NotApplicable', 'Mitigated']);
export const THREAT_STATE_LABELS = Object.freeze({
  NotStarted: 'Not Started',
  NeedsInvestigation: 'Needs Investigation',
  NotApplicable: 'Not Applicable',
  Mitigated: 'Mitigation Implemented',
});

export const GENERIC_ALIASES = Object.freeze({
  process: GENERIC.PROCESS,
  external: GENERIC.EXTERNAL,
  interactor: GENERIC.EXTERNAL,
  store: GENERIC.STORE,
  datastore: GENERIC.STORE,
  flow: GENERIC.FLOW,
  dataflow: GENERIC.FLOW,
  'line-boundary': GENERIC.LINE_BOUNDARY,
  'boundary-line': GENERIC.LINE_BOUNDARY,
  'box-boundary': GENERIC.BOX_BOUNDARY,
  'boundary-box': GENERIC.BOX_BOUNDARY,
  boundary: GENERIC.BOX_BOUNDARY,
  annotation: GENERIC.ANNOTATION,
  note: GENERIC.ANNOTATION,
});

export const DEFAULT_SIZE = Object.freeze({
  'GE.P': { w: 130, h: 90 },
  'GE.EI': { w: 140, h: 70 },
  'GE.DS': { w: 150, h: 64 },
  'GE.A': { w: 180, h: 54 },
  'GE.TB.B': { w: 340, h: 240 },
});

export class ModelError extends Error {}

export function isShapeGeneric(g) {
  return g === GENERIC.PROCESS || g === GENERIC.EXTERNAL || g === GENERIC.STORE || g === GENERIC.ANNOTATION || g === GENERIC.BOX_BOUNDARY;
}
export function isLineGeneric(g) {
  return g === GENERIC.FLOW || g === GENERIC.LINE_BOUNDARY;
}
/** Elements that data flows can connect to. */
export function isNodeGeneric(g) {
  return g === GENERIC.PROCESS || g === GENERIC.EXTERNAL || g === GENERIC.STORE;
}

export function createModel({ template, name = 'Untitled threat model', owner = '' } = {}) {
  if (!template) throw new ModelError('A template is required to create a model');
  const now = nowIso();
  return {
    format: MODEL_FORMAT,
    version: MODEL_VERSION,
    id: uid('tm'),
    meta: {
      name,
      owner,
      reviewer: '',
      contributors: '',
      description: '',
      assumptions: '',
      externalDependencies: '',
      createdAt: now,
      updatedAt: now,
    },
    template: normalizeTemplate(clone(template)),
    settings: { threatGeneration: true },
    diagrams: [{ id: uid('dg'), name: 'Diagram 1', elements: [] }],
    threats: [],
    nextThreatId: 1,
    notes: [],
    suppressedMessages: [],
  };
}

export function kbOf(model) {
  return kbFor(model.template);
}

export function touch(model) {
  model.meta.updatedAt = nowIso();
}

// ---------------------------------------------------------------- lookup

export function findDiagram(model, ref) {
  if (!ref) return model.diagrams[0];
  return model.diagrams.find((d) => d.id === ref) || model.diagrams.find((d) => d.name === ref);
}

export function requireDiagram(model, ref) {
  const d = findDiagram(model, ref);
  if (!d) throw new ModelError(`Diagram not found: ${ref}`);
  return d;
}

/** Map of element id → { element, diagram }. */
export function elementIndex(model) {
  const map = new Map();
  for (const d of model.diagrams) for (const e of d.elements) map.set(e.id, { element: e, diagram: d });
  return map;
}

export function findElement(model, ref, diagramRef) {
  if (!ref) return undefined;
  const diagrams = diagramRef ? [requireDiagram(model, diagramRef)] : model.diagrams;
  for (const d of diagrams) {
    const e = d.elements.find((x) => x.id === ref);
    if (e) return { element: e, diagram: d };
  }
  const byName = [];
  for (const d of diagrams) for (const e of d.elements) if (e.name === ref) byName.push({ element: e, diagram: d });
  if (byName.length > 1) throw new ModelError(`Element name '${ref}' is ambiguous (${byName.length} matches); use the element id`);
  return byName[0];
}

export function requireElement(model, ref, diagramRef) {
  const hit = findElement(model, ref, diagramRef);
  if (!hit) throw new ModelError(`Element not found: ${ref}`);
  return hit;
}

export function genericOfElement(model, el) {
  return kbOf(model).genericOf(el.typeId) || el.generic;
}

export function representationOf(model, el) {
  return REPRESENTATION[genericOfElement(model, el)] || 'rectangle';
}

/** Resolve a type reference: exact id, generic alias, or element type name. */
export function resolveTypeId(kb, ref) {
  if (!ref) return undefined;
  if (kb.element(ref)) return ref;
  const alias = GENERIC_ALIASES[String(ref).toLowerCase()];
  if (alias) return alias;
  const lower = String(ref).toLowerCase();
  const byName = kb.template.elements.filter((e) => e.name.toLowerCase() === lower);
  if (byName.length === 1) return byName[0].id;
  return undefined;
}

// ---------------------------------------------------------------- properties

/** Effective value of a template attribute on an element (list default = first value). */
export function attributeValue(kb, el, attr) {
  if (attr.mode === 'static') return attr.values[0] ?? '';
  const v = el.props?.[attr.name];
  if (v !== undefined && (attr.values.length === 0 || attr.values.includes(v))) return v;
  return attr.values[0] ?? '';
}

/** All effective properties (name → value) used by the rule engine and UI. */
export function effectiveProperties(kb, el) {
  const out = new Map();
  out.set('Name', el.name || '');
  out.set('Dataflow Order', String(el.order ?? 0));
  out.set('Out Of Scope', el.outOfScope ? 'True' : 'False');
  out.set('Reason For Out Of Scope', el.outOfScopeReason || '');
  for (const a of kb.attributes(el.typeId)) out.set(a.name, attributeValue(kb, el, a));
  for (const [k, v] of Object.entries(el.custom || {})) if (!out.has(k)) out.set(k, v);
  return out;
}

// ---------------------------------------------------------------- geometry

function shapeById(diagram, id) {
  return id ? diagram.elements.find((e) => e.id === id && e.w !== undefined) : undefined;
}

const ROUTE_CACHE = new WeakMap();

/** Routes for all bound flows of a diagram, recomputed only when geometry changes. */
function routesFor(diagram) {
  const sig = diagram.elements
    .map((e) => (e.w !== undefined ? `${e.id}${e.generic}${e.x},${e.y},${e.w},${e.h}` : e.generic === GENERIC.FLOW ? `${e.id}${e.source}>${e.target}${e.bend}${(e.name || '').length}` : ''))
    .join('|');
  const hit = ROUTE_CACHE.get(diagram);
  if (hit && hit.sig === sig) return hit.routes;
  const routes = computeRoutes(diagram);
  ROUTE_CACHE.set(diagram, { sig, routes });
  return routes;
}

/**
 * Resolve the drawn curve for a flow or line boundary.
 * Bound flow endpoints sit on the perimeter of their shapes, aimed at the curve's control point.
 */
export function lineGeometry(model, diagram, el) {
  if (el.generic === GENERIC.FLOW && el.source && el.target) {
    const r = routesFor(diagram).get(el.id);
    if (r) {
      const bend = Math.abs(el.bend || 0) > 1 ? el.bend : r.bend;
      const c = controlFromBend(r.p0, r.p1, bend);
      return { p0: r.p0, c, p1: r.p1, points: flatten(r.p0, c, r.p1), labelT: r.labelT };
    }
  }
  const src = shapeById(diagram, el.source);
  const tgt = shapeById(diagram, el.target);
  let a = src ? center(rectOf(src)) : { x: el.x0, y: el.y0 };
  let b = tgt ? center(rectOf(tgt)) : { x: el.x1, y: el.y1 };
  let c = controlFromBend(a, b, el.bend || 0);
  if (src) a = perimeterPoint(rectOf(src), representationOf(model, src), Math.abs(el.bend || 0) > 1 ? c : b);
  if (tgt) b = perimeterPoint(rectOf(tgt), representationOf(model, tgt), Math.abs(el.bend || 0) > 1 ? c : a, 4);
  c = controlFromBend(a, b, el.bend || 0);
  return { p0: a, c, p1: b, points: flatten(a, c, b) };
}

export function elementBounds(model, diagram, el) {
  if (el.w !== undefined) return rectOf(el);
  const g = lineGeometry(model, diagram, el);
  let x0 = Infinity,
    y0 = Infinity,
    x1 = -Infinity,
    y1 = -Infinity;
  for (const p of g.points) {
    x0 = Math.min(x0, p.x);
    y0 = Math.min(y0, p.y);
    x1 = Math.max(x1, p.x);
    y1 = Math.max(y1, p.y);
  }
  return { x: x0, y: y0, w: x1 - x0, h: y1 - y0 };
}

export function diagramBounds(model, diagram, pad = 40) {
  if (!diagram.elements.length) return { x: 0, y: 0, w: 800, h: 500 };
  let x0 = Infinity,
    y0 = Infinity,
    x1 = -Infinity,
    y1 = -Infinity;
  for (const e of diagram.elements) {
    const b = elementBounds(model, diagram, e);
    x0 = Math.min(x0, b.x);
    y0 = Math.min(y0, b.y);
    x1 = Math.max(x1, b.x + b.w);
    y1 = Math.max(y1, b.y + b.h);
  }
  return { x: x0 - pad, y: y0 - pad, w: x1 - x0 + pad * 2, h: y1 - y0 + pad * 2 };
}

/** Find a free grid slot so CLI/MCP-created shapes do not overlap. */
export function findFreeSpot(model, diagram, w, h) {
  const shapes = diagram.elements.filter((e) => e.w !== undefined && genericOfElement(model, e) !== GENERIC.BOX_BOUNDARY);
  for (let row = 0; row < 200; row++) {
    for (let col = 0; col < 5; col++) {
      const r = { x: 80 + col * 320, y: 80 + row * 230, w, h };
      const padded = { x: r.x - 50, y: r.y - 50, w: r.w + 100, h: r.h + 100 };
      if (!shapes.some((s) => rectsOverlap(padded, rectOf(s)))) return { x: r.x, y: r.y };
    }
  }
  return { x: 80, y: 80 };
}

// ---------------------------------------------------------------- mutation

/** Normalize source-code evidence references (e.g. "src/api/routes.ts:42"). */
export function normalizeEvidence(list) {
  if (!Array.isArray(list)) list = list === undefined || list === null || list === '' ? [] : [list];
  return [...new Set(list.map((x) => String(x).trim().slice(0, 500)).filter(Boolean))].slice(0, 25);
}

function num(v, fallback) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

export function addDiagram(model, name) {
  const d = { id: uid('dg'), name: name || `Diagram ${model.diagrams.length + 1}`, elements: [] };
  model.diagrams.push(d);
  touch(model);
  return d;
}

export function renameDiagram(model, ref, name) {
  const d = requireDiagram(model, ref);
  d.name = String(name || d.name).slice(0, 256);
  touch(model);
  return d;
}

export function removeDiagram(model, ref) {
  if (model.diagrams.length <= 1) throw new ModelError('A model must keep at least one diagram');
  const d = requireDiagram(model, ref);
  model.diagrams = model.diagrams.filter((x) => x !== d);
  touch(model);
  return d;
}

/**
 * Add an element. spec: { type, name, x, y, w, h, props, custom, source, target,
 * x0, y0, x1, y1, bend, outOfScope, outOfScopeReason, id }
 */
export function addElement(model, diagramRef, spec = {}) {
  const kb = kbOf(model);
  const diagram = requireDiagram(model, diagramRef);
  const typeId = resolveTypeId(kb, spec.type || spec.typeId);
  if (!typeId) throw new ModelError(`Unknown element type: ${spec.type || spec.typeId}`);
  const generic = kb.genericOf(typeId);
  if (!GENERIC_IDS.includes(generic)) throw new ModelError(`Type ${typeId} has no known generic family`);
  const typeDef = kb.element(typeId);
  const el = {
    id: spec.id && isSafeKey(spec.id) && !elementIndex(model).has(spec.id) ? spec.id : uid('el'),
    typeId,
    generic,
    name: String(spec.name ?? typeDef.name).slice(0, 500),
    props: {},
    custom: {},
    outOfScope: !!spec.outOfScope,
    outOfScopeReason: String(spec.outOfScopeReason || ''),
    order: num(spec.order, 0),
  };
  const evidence = normalizeEvidence(spec.evidence);
  if (evidence.length) el.evidence = evidence;
  if (normalizeColor(spec.color)) el.color = normalizeColor(spec.color);
  if (spec.groupId && isSafeKey(spec.groupId)) el.groupId = spec.groupId;
  if (isShapeGeneric(generic)) {
    const size = DEFAULT_SIZE[generic];
    el.w = Math.max(20, num(spec.w, size.w));
    el.h = Math.max(20, num(spec.h, size.h));
    if (spec.x === undefined || spec.y === undefined) Object.assign(el, findFreeSpot(model, diagram, el.w, el.h));
    else {
      el.x = num(spec.x, 0);
      el.y = num(spec.y, 0);
    }
  } else {
    if (generic === GENERIC.FLOW) {
      for (const end of ['source', 'target']) {
        if (!spec[end]) continue;
        const hit = requireElement(model, spec[end], diagram.id);
        if (hit.diagram !== diagram) throw new ModelError(`Flow ${end} must be on the same diagram`);
        if (!isNodeGeneric(genericOfElement(model, hit.element))) throw new ModelError(`Flow ${end} must be a process, external interactor or data store`);
        el[end] = hit.element.id;
      }
    }
    el.x0 = num(spec.x0, 100);
    el.y0 = num(spec.y0, 100);
    el.x1 = num(spec.x1, 300);
    el.y1 = num(spec.y1, 100);
    el.bend = num(spec.bend, 0);
    // Parallel and reverse flows are separated automatically by per-flow ports (see route.js).
  }
  diagram.elements.push(el);
  if (spec.props) setProperties(model, el, spec.props);
  if (spec.custom) el.custom = safeStringMap(spec.custom);
  touch(model);
  return el;
}

/** Set template attribute values with validation. Unknown names become custom properties when allowCustom. */
export function setProperties(model, el, props, { allowCustom = false } = {}) {
  const kb = kbOf(model);
  for (const [name, raw] of Object.entries(props || {})) {
    if (!isSafeKey(name)) throw new ModelError(`Invalid property name: ${name}`);
    const value = String(raw);
    const attr = kb.attribute(el.typeId, name) || kb.attributes(el.typeId).find((a) => a.label.toLowerCase() === name.toLowerCase());
    if (!attr) {
      if (allowCustom) {
        el.custom = { ...(el.custom || {}), [name]: value };
        continue;
      }
      throw new ModelError(`Property '${name}' is not defined for ${el.typeId}`);
    }
    if (attr.mode === 'static') throw new ModelError(`Property '${attr.name}' is fixed by type ${attr.definedBy}`);
    if (attr.values.length && !attr.values.includes(value)) {
      throw new ModelError(`Invalid value '${value}' for '${attr.name}'. Allowed: ${attr.values.join(', ')}`);
    }
    el.props = { ...(el.props || {}), [attr.name]: value };
  }
  touch(model);
}

/** Patch common fields of an element. */
export function updateElement(model, ref, patch = {}) {
  const { element: el, diagram } = requireElement(model, ref);
  if (patch.name !== undefined) el.name = String(patch.name).slice(0, 500);
  if (patch.outOfScope !== undefined) el.outOfScope = !!patch.outOfScope;
  if (patch.outOfScopeReason !== undefined) el.outOfScopeReason = String(patch.outOfScopeReason);
  if (patch.order !== undefined) el.order = num(patch.order, el.order);
  if (patch.color !== undefined) {
    const c = normalizeColor(patch.color);
    if (c) el.color = c;
    else if (patch.color === '' || patch.color === null) delete el.color;
    else throw new ModelError(`Invalid color '${patch.color}'. Use a hex value like #1c7ed6, or '' to reset`);
  }
  if (patch.evidence !== undefined) {
    const ev = normalizeEvidence(patch.evidence);
    if (ev.length) el.evidence = ev;
    else delete el.evidence;
  }
  if (patch.type !== undefined || patch.typeId !== undefined) changeType(model, el, patch.type ?? patch.typeId);
  for (const k of ['x', 'y', 'w', 'h']) if (patch[k] !== undefined && el.w !== undefined) el[k] = num(patch[k], el[k]);
  for (const k of ['x0', 'y0', 'x1', 'y1', 'bend']) if (patch[k] !== undefined && el.w === undefined) el[k] = num(patch[k], el[k]);
  if (el.generic === GENERIC.FLOW) {
    for (const end of ['source', 'target']) {
      if (patch[end] === undefined) continue;
      if (patch[end] === null || patch[end] === '') {
        el[end] = undefined;
        continue;
      }
      const hit = requireElement(model, patch[end], diagram.id);
      if (!isNodeGeneric(genericOfElement(model, hit.element))) throw new ModelError(`Flow ${end} must be a process, external interactor or data store`);
      el[end] = hit.element.id;
    }
  }
  if (patch.props) setProperties(model, el, patch.props);
  if (patch.custom) {
    const next = { ...(el.custom || {}) };
    for (const [k, v] of Object.entries(patch.custom)) {
      if (!isSafeKey(k)) continue;
      if (v === null) delete next[k];
      else next[k] = String(v);
    }
    el.custom = next;
  }
  touch(model);
  return el;
}

/** Change an element's type within its generic family (MTMT ChangeElementType). */
export function changeType(model, el, typeRef) {
  const kb = kbOf(model);
  const typeId = resolveTypeId(kb, typeRef);
  if (!typeId) throw new ModelError(`Unknown element type: ${typeRef}`);
  const g = kb.genericOf(typeId);
  if (g !== genericOfElement(model, el)) throw new ModelError(`Cannot change ${el.typeId} to ${typeId}: different element family`);
  el.typeId = typeId;
  el.generic = g;
  // Drop values that the new type does not accept.
  const next = {};
  for (const [k, v] of Object.entries(el.props || {})) {
    const a = kb.attribute(typeId, k);
    if (a && a.mode !== 'static' && (a.values.length === 0 || a.values.includes(v))) next[k] = v;
  }
  el.props = next;
  touch(model);
}

/**
 * Remove elements. Flows attached to a removed shape are detached (left as
 * loose connectors, like MTMT) unless `cascade` is set.
 */
export function removeElements(model, refs, { cascade = false } = {}) {
  const removed = [];
  for (const ref of refs) {
    const hit = findElement(model, ref);
    if (!hit) continue;
    const { element: el, diagram } = hit;
    for (const f of diagram.elements) {
      if (f.generic !== GENERIC.FLOW || (f.source !== el.id && f.target !== el.id)) continue;
      if (cascade) {
        removed.push(f.id);
        continue;
      }
      const g = lineGeometry(model, diagram, f);
      if (f.source === el.id) {
        f.source = undefined;
        f.x0 = g.p0.x;
        f.y0 = g.p0.y;
      }
      if (f.target === el.id) {
        f.target = undefined;
        f.x1 = g.p1.x;
        f.y1 = g.p1.y;
      }
    }
    removed.push(el.id);
    const ids = new Set(removed);
    diagram.elements = diagram.elements.filter((e) => !ids.has(e.id));
  }
  touch(model);
  return removed;
}

/** Move shapes (and free flow endpoints/line boundaries) by dx, dy. */
export function moveElements(model, ids, dx, dy) {
  const idx = elementIndex(model);
  for (const id of ids) {
    const hit = idx.get(id);
    if (!hit) continue;
    const el = hit.element;
    if (el.w !== undefined) {
      el.x += dx;
      el.y += dy;
    } else {
      // Bound endpoints follow their shapes; free endpoints move with the selection.
      if (!el.source) {
        el.x0 += dx;
        el.y0 += dy;
      }
      if (!el.target) {
        el.x1 += dx;
        el.y1 += dy;
      }
    }
  }
  touch(model);
}

// ---------------------------------------------------------------- groups

/** Ids of the given elements plus every other member of their groups. */
export function expandGroups(diagram, ids) {
  const out = new Set(ids);
  const groups = new Set();
  for (const e of diagram.elements) if (out.has(e.id) && e.groupId) groups.add(e.groupId);
  if (groups.size) for (const e of diagram.elements) if (e.groupId && groups.has(e.groupId)) out.add(e.id);
  return out;
}

/** Group elements (Ctrl+G). Members of groups touched by the selection join the new group. Returns the group id. */
export function groupElements(model, diagramRef, ids) {
  const diagram = requireDiagram(model, diagramRef);
  const members = expandGroups(diagram, ids);
  if (members.size < 2) throw new ModelError('Select at least two elements to group');
  const groupId = uid('grp');
  for (const e of diagram.elements) if (members.has(e.id)) e.groupId = groupId;
  touch(model);
  return groupId;
}

/** Ungroup (Ctrl+Shift+G): dissolve every group that the given elements belong to. */
export function ungroupElements(model, diagramRef, ids) {
  const diagram = requireDiagram(model, diagramRef);
  const members = expandGroups(diagram, ids);
  let n = 0;
  for (const e of diagram.elements) {
    if (members.has(e.id) && e.groupId) {
      delete e.groupId;
      n++;
    }
  }
  if (n) touch(model);
  return n;
}

// ---------------------------------------------------------------- threats & notes

export function findThreat(model, ref) {
  const n = Number(ref);
  return model.threats.find((t) => t.key === ref || (Number.isFinite(n) && t.id === n));
}

/** Update triage fields of a threat; marks it as user-touched. */
export function updateThreat(model, ref, patch = {}, user = 'user') {
  const t = findThreat(model, ref);
  if (!t) throw new ModelError(`Threat not found: ${ref}`);
  const kb = kbOf(model);
  if (patch.state !== undefined) {
    const state = normalizeState(patch.state);
    if (!state) throw new ModelError(`Invalid state '${patch.state}'. Use one of: ${THREAT_STATES.join(', ')}`);
    t.state = state;
  }
  if (patch.priority !== undefined) {
    const p = kb.priorities().find((x) => x.toLowerCase() === String(patch.priority).toLowerCase());
    if (!p) throw new ModelError(`Invalid priority '${patch.priority}'. Use one of: ${kb.priorities().join(', ')}`);
    t.priority = p;
  }
  if (patch.justification !== undefined) t.justification = String(patch.justification);
  for (const f of ['title', 'description', 'mitigation']) {
    if (patch[f] !== undefined) {
      t[f] = String(patch[f]);
      if (!t.edited.includes(f)) t.edited.push(f);
    }
  }
  if (patch.category !== undefined && kb.category(patch.category)) t.category = patch.category;
  if (patch.custom) {
    for (const [k, v] of Object.entries(patch.custom)) if (isSafeKey(k)) t.custom[k] = String(v);
  }
  t.changedBy = String(user || 'user');
  t.modifiedAt = nowIso();
  annotateThreats(model);
  touch(model);
  return t;
}

export function normalizeState(s) {
  if (!s) return undefined;
  const v = String(s).replace(/[\s_-]/g, '').toLowerCase();
  const map = {
    notstarted: 'NotStarted',
    autogenerated: 'NotStarted',
    new: 'NotStarted',
    needsinvestigation: 'NeedsInvestigation',
    investigate: 'NeedsInvestigation',
    needsmitigation: 'NeedsInvestigation',
    notapplicable: 'NotApplicable',
    na: 'NotApplicable',
    mitigated: 'Mitigated',
    mitigationimplemented: 'Mitigated',
  };
  return map[v];
}

/** Add a user-defined threat on a flow (MTMT AddUserDefinedThreat). */
export function addUserThreat(model, flowRef, fields = {}, user = 'user') {
  const kb = kbOf(model);
  const { element: flow, diagram } = requireElement(model, flowRef);
  if (flow.generic !== GENERIC.FLOW) throw new ModelError('User-defined threats must be attached to a data flow');
  const idx = elementIndex(model);
  const s = idx.get(flow.source)?.element;
  const t = idx.get(flow.target)?.element;
  const category = kb.category(fields.category) ? fields.category : kb.categories[0]?.id || '';
  const threat = {
    key: `user:${uid('th')}`,
    id: model.nextThreatId++,
    typeId: 'USER',
    category,
    title: String(fields.title || 'User-defined threat'),
    description: String(fields.description || ''),
    mitigation: String(fields.mitigation || ''),
    interaction: interactionString(s, flow, t),
    diagramId: diagram.id,
    sourceId: flow.source || '',
    flowId: flow.id,
    targetId: flow.target || '',
    state: normalizeState(fields.state) || 'NotStarted',
    priority: kb.priorities().find((p) => p.toLowerCase() === String(fields.priority || '').toLowerCase()) || kb.priorities()[0],
    justification: String(fields.justification || ''),
    custom: {},
    references: [],
    userDefined: true,
    orphan: false,
    changedBy: String(user),
    modifiedAt: nowIso(),
    edited: ['title', 'description', 'mitigation'],
  };
  model.threats.push(threat);
  annotateThreats(model);
  touch(model);
  return threat;
}

export function deleteThreat(model, ref) {
  const t = findThreat(model, ref);
  if (!t) throw new ModelError(`Threat not found: ${ref}`);
  if (!t.userDefined && !t.orphan) throw new ModelError('Generated threats cannot be deleted; mark them Not Applicable instead');
  model.threats = model.threats.filter((x) => x !== t);
  annotateThreats(model);
  touch(model);
  return t;
}

export function interactionString(source, flow, target) {
  const s = source?.name || '<unconnected>';
  const t = target?.name || '<unconnected>';
  return `From ${s} to ${t} via ${flow?.name || 'unnamed'}`;
}

export function addNote(model, text, author = '') {
  const note = { id: uid('nt'), text: String(text).slice(0, 20000), author: String(author), date: nowIso() };
  model.notes.push(note);
  touch(model);
  return note;
}

// ---------------------------------------------------------------- load / save

function sanitizeElement(raw, kb) {
  if (!raw || typeof raw !== 'object' || !isSafeKey(raw.id)) return null;
  const typeId = typeof raw.typeId === 'string' ? raw.typeId : '';
  const generic = kb.genericOf(typeId) || (GENERIC_IDS.includes(raw.generic) ? raw.generic : undefined);
  if (!generic) return null;
  const el = {
    id: raw.id,
    typeId: kb.element(typeId) ? typeId : generic,
    generic,
    name: String(raw.name ?? '').slice(0, 500),
    props: safeStringMap(raw.props),
    custom: safeStringMap(raw.custom),
    outOfScope: !!raw.outOfScope,
    outOfScopeReason: String(raw.outOfScopeReason || ''),
    order: num(raw.order, 0),
  };
  const evidence = normalizeEvidence(raw.evidence);
  if (evidence.length) el.evidence = evidence;
  if (normalizeColor(raw.color)) el.color = normalizeColor(raw.color);
  if (isSafeKey(raw.groupId)) el.groupId = raw.groupId;
  if (isShapeGeneric(generic)) {
    const size = DEFAULT_SIZE[generic];
    el.x = num(raw.x, 0);
    el.y = num(raw.y, 0);
    el.w = Math.max(10, num(raw.w, size.w));
    el.h = Math.max(10, num(raw.h, size.h));
  } else {
    el.x0 = num(raw.x0, 0);
    el.y0 = num(raw.y0, 0);
    el.x1 = num(raw.x1, 100);
    el.y1 = num(raw.y1, 0);
    el.bend = num(raw.bend, 0);
    if (generic === GENERIC.FLOW) {
      if (isSafeKey(raw.source)) el.source = raw.source;
      if (isSafeKey(raw.target)) el.target = raw.target;
    }
  }
  return el;
}

function sanitizeThreat(raw) {
  if (!raw || typeof raw !== 'object' || typeof raw.key !== 'string') return null;
  const s = (v) => String(v ?? '');
  return {
    key: raw.key.slice(0, 1000),
    id: num(raw.id, 0),
    typeId: s(raw.typeId),
    category: s(raw.category),
    title: s(raw.title),
    description: s(raw.description),
    mitigation: s(raw.mitigation),
    interaction: s(raw.interaction),
    diagramId: s(raw.diagramId),
    sourceId: s(raw.sourceId),
    flowId: s(raw.flowId),
    targetId: s(raw.targetId),
    state: normalizeState(raw.state) || 'NotStarted',
    priority: s(raw.priority),
    justification: s(raw.justification),
    custom: safeStringMap(raw.custom),
    references: Array.isArray(raw.references) ? raw.references.map(s).slice(0, 32) : [],
    userDefined: !!raw.userDefined,
    orphan: !!raw.orphan,
    changedBy: s(raw.changedBy),
    modifiedAt: s(raw.modifiedAt),
    edited: Array.isArray(raw.edited) ? raw.edited.filter((f) => ['title', 'description', 'mitigation'].includes(f)) : [],
  };
}

/**
 * Load a model from untrusted JSON (string or object). Unknown fields are
 * dropped and every value is re-validated.
 */
export function loadModel(input) {
  const raw = typeof input === 'string' ? JSON.parse(input) : input;
  if (!raw || typeof raw !== 'object' || raw.format !== MODEL_FORMAT) throw new ModelError('Not a STRIDE model file (format must be "stride-model")');
  if (num(raw.version, 0) > MODEL_VERSION) throw new ModelError(`Model version ${raw.version} is newer than this tool supports`);
  const template = normalizeTemplate(raw.template);
  const kb = kbFor(template);
  const metaIn = raw.meta && typeof raw.meta === 'object' ? raw.meta : {};
  const meta = {};
  for (const k of ['name', 'owner', 'reviewer', 'contributors', 'description', 'assumptions', 'externalDependencies', 'createdAt', 'updatedAt']) {
    meta[k] = String(metaIn[k] ?? '');
  }
  if (!meta.name) meta.name = 'Untitled threat model';
  const diagrams = [];
  const seen = new Set();
  for (const d of Array.isArray(raw.diagrams) ? raw.diagrams : []) {
    if (!d || !isSafeKey(d.id)) continue;
    const elements = [];
    for (const e of Array.isArray(d.elements) ? d.elements : []) {
      const el = sanitizeElement(e, kb);
      if (el && !seen.has(el.id)) {
        seen.add(el.id);
        elements.push(el);
      }
    }
    diagrams.push({ id: d.id, name: String(d.name || 'Diagram').slice(0, 256), elements });
  }
  if (!diagrams.length) diagrams.push({ id: uid('dg'), name: 'Diagram 1', elements: [] });
  // Drop flow bindings that point at missing shapes.
  for (const d of diagrams) {
    const shapeIds = new Set(d.elements.filter((e) => isNodeGeneric(e.generic)).map((e) => e.id));
    for (const e of d.elements) {
      if (e.generic !== GENERIC.FLOW) continue;
      if (e.source && !shapeIds.has(e.source)) e.source = undefined;
      if (e.target && !shapeIds.has(e.target)) e.target = undefined;
    }
  }
  const threats = [];
  const keys = new Set();
  for (const t of Array.isArray(raw.threats) ? raw.threats : []) {
    const th = sanitizeThreat(t);
    if (th && !keys.has(th.key)) {
      keys.add(th.key);
      threats.push(th);
    }
  }
  const maxId = threats.reduce((m, t) => Math.max(m, t.id), 0);
  // threat.signal and threat.enriched are derived data: any stored copy is dropped and recomputed below.
  return annotateThreats({
    format: MODEL_FORMAT,
    version: MODEL_VERSION,
    id: isSafeKey(raw.id) ? raw.id : uid('tm'),
    meta,
    template,
    settings: { threatGeneration: raw.settings?.threatGeneration !== false },
    diagrams,
    threats,
    nextThreatId: Math.max(num(raw.nextThreatId, 1), maxId + 1),
    notes: (Array.isArray(raw.notes) ? raw.notes : [])
      .filter((n) => n && typeof n === 'object')
      .map((n) => ({ id: isSafeKey(n.id) ? n.id : uid('nt'), text: String(n.text ?? ''), author: String(n.author ?? ''), date: String(n.date ?? '') })),
    suppressedMessages: (Array.isArray(raw.suppressedMessages) ? raw.suppressedMessages : []).filter((x) => typeof x === 'string').slice(0, 10000),
  });
}

export function serializeModel(model) {
  return JSON.stringify(model, null, 2);
}

/** Replace the model's embedded template (MTMT "Apply Template"). Elements with unknown types fall back to their generic. */
export function applyTemplate(model, template) {
  model.template = normalizeTemplate(clone(template));
  const kb = kbOf(model);
  for (const d of model.diagrams) {
    for (const e of d.elements) {
      if (!kb.element(e.typeId)) e.typeId = e.generic;
      const next = {};
      for (const [k, v] of Object.entries(e.props || {})) {
        const a = kb.attribute(e.typeId, k);
        if (a && (a.values.length === 0 || a.values.includes(v))) next[k] = v;
      }
      e.props = next;
    }
  }
  touch(model);
}

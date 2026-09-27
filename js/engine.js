// STRIDE analysis engine: evaluates the threat template against every
// interaction (data flow) and element, keeps user edits across regenerations,
// and produces validation messages. DOM-free.

import { DEFAULT_RULES } from './rules.js';
import { OPEN_STATES } from './stencils.js';
import { center, lineGeom, pointInRect, quadPolyline, polylinesIntersect } from './util.js';

const ENDPOINT_TYPES = ['process', 'external', 'store'];

export const activeRules = (model) => (Array.isArray(model.template) && model.template.length ? model.template : DEFAULT_RULES);

/* ---------------------------------------------------------- conditions */

function resolve(ctx, path) {
  let v = ctx;
  for (const part of String(path).split('.')) {
    if (v == null) return undefined;
    v = v[part];
  }
  return v;
}

function evalClause([path, op, value], ctx) {
  const v = resolve(ctx, path);
  switch (op) {
    case 'eq': return v === value;
    case 'ne': return v !== value;
    case 'in': return Array.isArray(value) && value.includes(v ?? 'Not Selected');
    case 'nin': return Array.isArray(value) && !value.includes(v ?? 'Not Selected');
    case 'exists': return (v != null && v !== '') === (value !== false);
    default: return false;
  }
}

export function evalCond(cond, ctx) {
  if (cond == null) return true;
  if (Array.isArray(cond)) {
    if (typeof cond[0] === 'string') return evalClause(cond, ctx);
    return cond.every((c) => evalCond(c, ctx));
  }
  if (cond.any) return cond.any.some((c) => evalCond(c, ctx));
  if (cond.all) return cond.all.every((c) => evalCond(c, ctx));
  if (cond.not) return !evalCond(cond.not, ctx);
  return false;
}

export function interpolate(text, ctx) {
  return String(text ?? '').replace(/\{([a-zA-Z0-9_.]+)\}/g, (m, path) => {
    const v = resolve(ctx, path);
    return v == null ? m : String(v);
  });
}

/* ------------------------------------------------------- trust boundaries */

export function flowCrossings(flow, diagram, byId) {
  const a = byId.get(flow.sourceId), b = byId.get(flow.targetId);
  const g = lineGeom(flow, byId);
  const pa = a ? center(a) : g.s;
  const pb = b ? center(b) : g.t;
  let poly = null;
  const out = [];
  for (const el of diagram.elements) {
    if (el.type === 'boundary') {
      if (pointInRect(pa, el) !== pointInRect(pb, el)) out.push(el.name || 'Trust Boundary');
    } else if (el.type === 'boundaryLine') {
      poly ||= quadPolyline(g.s, g.c, g.t, 16);
      const bg = lineGeom(el, byId);
      if (polylinesIntersect(poly, quadPolyline(bg.s, bg.c, bg.t, 16))) out.push(el.name || 'Trust Boundary');
    }
  }
  return out;
}

const elCtx = (el) => ({
  id: el.id, name: el.name || '(unnamed)', type: el.type, subtype: el.subtype || '',
  props: el.props || {}, outOfScope: !!el.outOfScope,
});

/* ------------------------------------------------------------- generation */

export function generateThreats(model, rules = activeRules(model)) {
  const out = [];
  const interactionRules = rules.filter((r) => (r.scope || 'interaction') === 'interaction');
  const elementRules = rules.filter((r) => r.scope === 'element');

  for (const d of model.diagrams) {
    const byId = new Map(d.elements.map((e) => [e.id, e]));
    for (const flow of d.elements) {
      if (flow.type !== 'flow') continue;
      const a = byId.get(flow.sourceId), b = byId.get(flow.targetId);
      if (!a || !b || !ENDPOINT_TYPES.includes(a.type) || !ENDPOINT_TYPES.includes(b.type)) continue;
      const crossing = flowCrossings(flow, d, byId);
      const ctx = {
        source: elCtx(a), target: elCtx(b),
        flow: { ...elCtx(flow), crossesBoundary: crossing.length > 0, boundaries: crossing.join(', ') || 'none' },
      };
      for (const rule of interactionRules) {
        const focusEl = rule.focus === 'source' ? a : rule.focus === 'target' ? b : flow;
        if (flow.outOfScope || focusEl.outOfScope) continue;
        if (!evalCond(rule.when, ctx)) continue;
        out.push({
          key: `${d.id}|${flow.id}|${rule.id}`, ruleId: rule.id, diagramId: d.id, flowId: flow.id, elementId: focusEl.id,
          category: rule.category, priority: rule.priority || 'Medium',
          title: interpolate(rule.title, ctx), description: interpolate(rule.description, ctx),
          mitigationHint: interpolate(rule.mitigation || '', ctx),
          interaction: `${ctx.source.name} → ${ctx.target.name}${flow.name ? ` (${flow.name})` : ''}`,
        });
      }
    }
    for (const el of d.elements) {
      if (!ENDPOINT_TYPES.includes(el.type) || el.outOfScope) continue;
      const ctx = { element: elCtx(el) };
      for (const rule of elementRules) {
        if (!evalCond(rule.when, ctx)) continue;
        out.push({
          key: `${d.id}|${el.id}|${rule.id}`, ruleId: rule.id, diagramId: d.id, flowId: null, elementId: el.id,
          category: rule.category, priority: rule.priority || 'Medium',
          title: interpolate(rule.title, ctx), description: interpolate(rule.description, ctx),
          mitigationHint: interpolate(rule.mitigation || '', ctx),
          interaction: ctx.element.name,
        });
      }
    }
  }
  return out;
}

const untouched = (t) => t.state === 'Not Started' && !t.justification && !t.mitigation && !t.customText && !t.modified;

// Merge freshly generated threats into model.threats, keeping IDs and user edits.
export function syncThreats(model) {
  model.threats ||= {};
  model.nextThreatId ||= 1;
  const seen = new Set();
  for (const g of generateThreats(model)) {
    seen.add(g.key);
    const t = model.threats[g.key];
    if (!t) {
      model.threats[g.key] = {
        id: model.nextThreatId++, key: g.key, auto: true, ruleId: g.ruleId,
        diagramId: g.diagramId, flowId: g.flowId, elementId: g.elementId,
        category: g.category, priority: g.priority, state: 'Not Started',
        title: g.title, description: g.description, mitigationHint: g.mitigationHint,
        mitigation: '', justification: '', interaction: g.interaction,
        created: new Date().toISOString(), modified: null,
      };
    } else {
      t.orphan = false;
      t.interaction = g.interaction;
      t.mitigationHint = g.mitigationHint;
      if (!t.customText) { t.title = g.title; t.description = g.description; }
    }
  }
  for (const [key, t] of Object.entries(model.threats)) {
    if (!t.auto || seen.has(key)) continue;
    if (untouched(t)) delete model.threats[key];
    else t.orphan = true;
  }
  // Manual threats whose element was deleted become orphans too.
  const ids = new Set(model.diagrams.flatMap((d) => d.elements.map((e) => e.id)));
  for (const t of Object.values(model.threats)) {
    if (!t.auto) t.orphan = !!(t.flowId || t.elementId) && !ids.has(t.flowId || t.elementId);
  }
}

export const threatList = (model) => Object.values(model.threats || {}).sort((a, b) => a.id - b.id);
export const isOpen = (t) => OPEN_STATES.includes(t.state);

export function threatStats(threats) {
  const s = { total: threats.length, open: 0, byCat: {}, byState: {}, byPriority: {} };
  for (const t of threats) {
    if (isOpen(t)) s.open++;
    s.byCat[t.category] = (s.byCat[t.category] || 0) + 1;
    s.byState[t.state] = (s.byState[t.state] || 0) + 1;
    s.byPriority[t.priority] = (s.byPriority[t.priority] || 0) + 1;
  }
  return s;
}

/* ------------------------------------------------------------- validation */

export function validate(model) {
  const msgs = [];
  const warn = (text, d, el) => msgs.push({ level: 'warning', text, diagramId: d.id, elementId: el?.id });
  const info = (text, d, el) => msgs.push({ level: 'info', text, diagramId: d.id, elementId: el?.id });

  for (const d of model.diagrams) {
    const byId = new Map(d.elements.map((e) => [e.id, e]));
    const flows = d.elements.filter((e) => e.type === 'flow');
    const nodes = d.elements.filter((e) => ENDPOINT_TYPES.includes(e.type));
    const names = new Map();

    for (const f of flows) {
      const a = byId.get(f.sourceId), b = byId.get(f.targetId);
      if (!a || !b) { warn(`Data flow "${f.name}" is not connected at both ends; no threats are generated for it.`, d, f); continue; }
      if (a.type !== 'process' && b.type !== 'process')
        warn(`"${a.name}" → "${b.name}": in a DFD, data between ${a.type === 'store' ? 'data stores' : 'external entities'} and ${b.type === 'store' ? 'data stores' : 'external entities'} should pass through a process.`, d, f);
    }
    for (const n of nodes) {
      const key = (n.name || '').trim().toLowerCase();
      names.set(key, (names.get(key) || 0) + 1);
      if (!flows.some((f) => f.sourceId === n.id || f.targetId === n.id)) info(`"${n.name}" has no data flows.`, d, n);
    }
    for (const n of nodes) {
      if (names.get((n.name || '').trim().toLowerCase()) > 1) warn(`Duplicate element name "${n.name}" makes threats ambiguous.`, d, n);
    }
    for (const el of d.elements) {
      if (el.outOfScope && !(el.outOfScopeReason || '').trim()) info(`"${el.name}" is out of scope but has no justification.`, d, el);
    }
    if (flows.length && !d.elements.some((e) => e.type === 'boundary' || e.type === 'boundaryLine'))
      info(`Diagram "${d.name}" has no trust boundaries; boundary-crossing threats will not be generated.`, d);
  }
  const orphans = Object.values(model.threats || {}).filter((t) => t.orphan);
  if (orphans.length) msgs.push({ level: 'info', text: `${orphans.length} threat(s) no longer match the diagram but were kept because you edited them.`, threatIds: orphans.map((t) => t.id) });
  return msgs;
}

// Per-element counts used for the badges drawn on the canvas in Analysis view.
export function threatBadges(model, diagramId) {
  const map = new Map();
  for (const t of Object.values(model.threats || {})) {
    if (t.diagramId !== diagramId || t.orphan) continue;
    const id = t.flowId || t.elementId;
    if (!id) continue;
    const b = map.get(id) || { total: 0, open: 0, high: false };
    b.total++;
    if (isOpen(t)) { b.open++; if (t.priority === 'High') b.high = true; }
    map.set(id, b);
  }
  return map;
}

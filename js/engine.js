// STRIDE analysis engine: evaluates the threat template against every
// interaction (data flow) and element, keeps user edits across regenerations,
// and produces validation messages. DOM-free.

import { DEFAULT_RULES } from './rules.js';
import { STRIDE, PRIORITIES } from './stencils.js';
import { STATUSES, STATUS_LABELS, threatStatus, effectiveThreatStatus, threatSeverity } from './threats.js';
import { center, lineGeom, pointInRect, quadPolyline, polylinesIntersect } from './util.js';

const ENDPOINT_TYPES = ['process', 'external', 'store'];

export const activeRules = (model) => (Array.isArray(model.template) && model.template.length ? model.template : DEFAULT_RULES);

/* ---------------------------------------------------------- conditions */

function resolve(ctx, path) {
  let v = ctx;
  for (const part of String(path).split('.')) {
    if (['__proto__', 'prototype', 'constructor'].includes(part)) return undefined;
    if (v == null || !Object.hasOwn(v, part)) return undefined;
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

export function generateThreats(model, rules = activeRules(model), { includeSuppressed = false } = {}) {
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
      const matching = [];
      for (const rule of interactionRules) {
        const focusEl = rule.focus === 'source' ? a : rule.focus === 'target' ? b : flow;
        if (flow.outOfScope || focusEl.outOfScope) continue;
        if (!evalCond(rule.when, ctx)) continue;
        matching.push({ rule, threat: {
          key: `${d.id}|${flow.id}|${rule.id}`, ruleId: rule.id, diagramId: d.id, flowId: flow.id, elementId: focusEl.id,
          category: rule.category, priority: rule.priority || 'Medium',
          title: interpolate(rule.title, ctx), description: interpolate(rule.description, ctx),
          mitigationHint: interpolate(rule.mitigation || '', ctx),
          interaction: `${ctx.source.name} → ${ctx.target.name}${flow.name ? ` (${flow.name})` : ''}`,
        } });
      }
      // Evaluate supersession before grouping so it cannot hide findings on
      // other flows into the same endpoint. Rule order does not affect this.
      for (const { rule, threat } of matching) {
        const supersededBy = matching.filter((m) => m.rule !== rule && m.rule.supersedes?.includes(rule.id)).map((m) => m.rule.id);
        if (supersededBy.length) { threat.suppressed = true; threat.supersededBy = supersededBy; }
        if (rule.dedupeKey === 'target' || rule.dedupeKey === 'source') {
          const endpoint = rule.dedupeKey === 'target' ? b : a;
          threat.key = `${d.id}|${rule.dedupeKey}:${endpoint.id}|${rule.id}`;
          threat.elementId = endpoint.id;
          threat.flowId = null;
          threat.dedupeKey = rule.dedupeKey;
          threat.contributingFlows = [{ id: flow.id, sourceId: a.id, targetId: b.id, name: flow.name || '', interaction: threat.interaction }];
          threat.interaction = endpoint.name || '(unnamed)';
        }
        out.push(threat);
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
  const groups = new Map();
  for (const threat of out) {
    if (!groups.has(threat.key)) groups.set(threat.key, []);
    groups.get(threat.key).push(threat);
  }
  return [...groups.values()].flatMap((matches) => {
    const visible = matches.filter((t) => !t.suppressed);
    if (!visible.length && !includeSuppressed) return [];
    const contributors = visible.length ? visible : matches;
    if (contributors[0].dedupeKey) contributors.sort((a, b) => a.contributingFlows[0].id.localeCompare(b.contributingFlows[0].id));
    const result = { ...contributors[0] };
    if (result.dedupeKey) {
      result.contributingFlows = contributors.flatMap((t) => t.contributingFlows).sort((a, b) => a.id.localeCompare(b.id));
      // Text comes from the first contributor; the flow list describes all paths.
    }
    return [result];
  });
}

const untouched = (t) => !t.needsReview && threatStatus(t) === 'open' && (!t.state || t.state === 'Not Started' || t.state === 'Open') &&
  !t.justification && !t.mitigation && !t.notes && !t.owner && !t.customText && !t.modified &&
  (t.severity == null || t.severity === t.priority);

// Merge freshly generated threats into model.threats, keeping IDs and user edits.
export function syncThreats(model) {
  model.threats ||= {};
  model.nextThreatId ||= 1;
  const seen = new Set();
  for (const g of generateThreats(model, activeRules(model), { includeSuppressed: true })) {
    seen.add(g.key);
    let t = model.threats[g.key];
    // Folded per-flow records are permanent audit history, even if a later
    // template generates their old key again.
    if (t?.reviewMergedInto) continue;
    // Migrate older grouped decisions using their saved contributors, before
    // replacing them with the current flows. Newly added flows are not covered.
    if (t?.dedupeKey && t.reviewedFlowIds == null && threatStatus(t) !== 'open') {
      t.reviewedFlowIds = (t.contributingFlows || []).map((f) => f.id);
    }
    if (g.dedupeKey && !g.suppressed) {
      const flowIds = new Set(g.contributingFlows.map((f) => f.id));
      const previous = Object.values(model.threats).filter((old) => old !== t && old.auto && old.ruleId === g.ruleId && old.diagramId === g.diagramId && flowIds.has(old.flowId) && !old.reviewMergedInto);
      if (previous.length) {
        const rank = { open: 0, accepted: 1, mitigated: 2, 'not-applicable': 2 };
        const records = [...(t ? [t] : []), ...previous].sort((a, b) =>
          rank[threatStatus(a)] - rank[threatStatus(b)] || Number(untouched(a)) - Number(untouched(b)) || a.id - b.id);
        const adopted = records[0];
        const conflict = new Set(records.map(threatStatus)).size > 1 || records.some((r) => r.needsReview);
        const reviewedFlowIds = [...new Set(records.flatMap((r) => r.reviewedFlowIds ||
          (threatStatus(r) !== 'open' && !r.needsReview && r.flowId ? [r.flowId] : [])))];
        const label = (r) => g.contributingFlows.find((f) => f.id === r.flowId)?.name || r.interaction || r.flowId;
        const combined = Object.fromEntries(['notes', 'mitigation'].map((field) => [field,
          records.filter((r) => r[field]?.trim()).map((r) => r === t ? r[field] : `${label(r)}: ${r[field]}`).join('\n\n')]));
        if (!t) {
          t = adopted; delete model.threats[t.key];
          t.key = g.key; model.threats[g.key] = t;
        }
        t.status = threatStatus(adopted); t.state = adopted.state || STATUS_LABELS[t.status];
        Object.assign(t, combined);
        if (reviewedFlowIds.length || conflict) t.reviewedFlowIds = reviewedFlowIds;
        t.needsReview = conflict;
        // Keep original records for audit history, but merge their decisions
        // only once so regeneration cannot restore an obsolete open status.
        for (const old of previous) if (old !== t) { old.mergedInto = g.key; old.reviewMergedInto = g.key; old.suppressed = true; old.orphan = false; }
      }
    }
    if (g.suppressed && !t) continue;
    if (!t) {
      t = model.threats[g.key] = {
        id: model.nextThreatId++, key: g.key, auto: true, ruleId: g.ruleId,
        diagramId: g.diagramId, flowId: g.flowId, elementId: g.elementId,
        category: g.category, priority: g.priority, state: 'Not Started',
        status: 'open', severity: threatSeverity(g), notes: '', owner: '',
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
    t.flowId = g.flowId; t.elementId = g.elementId;
    delete t.mergedInto;
    for (const field of ['dedupeKey', 'contributingFlows', 'suppressed', 'supersededBy']) {
      if (g[field] !== undefined) t[field] = g[field]; else delete t[field];
    }
    if (t.dedupeKey && t.reviewedFlowIds && t.contributingFlows.some((f) => !t.reviewedFlowIds.includes(f.id))) t.needsReview = true;
  }
  for (const [key, t] of Object.entries(model.threats)) {
    if (t.reviewMergedInto) { t.suppressed = true; t.orphan = false; continue; }
    if (!t.auto || seen.has(key)) continue;
    if (t.mergedInto && seen.has(t.mergedInto)) continue;
    delete t.suppressed; delete t.supersededBy; delete t.mergedInto;
    // Preserve grouped identity and review coverage across rule toggles. Only
    // edited unmatched groups appear as orphans; untouched ones stay hidden.
    if (t.dedupeKey && untouched(t)) { t.suppressed = true; t.orphan = false; }
    else if (untouched(t)) delete model.threats[key];
    else t.orphan = true;
  }
  // Manual threats whose element was deleted become orphans too.
  const ids = new Set(model.diagrams.flatMap((d) => d.elements.map((e) => e.id)));
  for (const t of Object.values(model.threats)) {
    if (!t.auto && !t.reviewMergedInto) t.orphan = !!(t.flowId || t.elementId) && !ids.has(t.flowId || t.elementId);
  }
}

export const threatList = (model) => Object.values(model.threats || {}).filter((t) => !t.suppressed && !t.reviewMergedInto).sort((a, b) => a.id - b.id);
export const isOpen = (t) => effectiveThreatStatus(t) === 'open';

export function threatStats(threats) {
  const counts = (keys) => Object.fromEntries(keys.map((k) => [k, 0]));
  const s = {
    total: threats.length, open: 0, orphaned: 0,
    byCat: counts(STRIDE.map((c) => c.key)), byState: counts(Object.values(STATUS_LABELS)), byPriority: {},
    byStatus: counts(STATUSES), bySeverity: counts(PRIORITIES),
    byCatStatus: Object.fromEntries(STRIDE.map((c) => [c.key, counts(STATUSES)])),
  };
  for (const t of threats) {
    const status = effectiveThreatStatus(t), severity = threatSeverity(t);
    if (isOpen(t)) s.open++;
    if (t.orphan) s.orphaned++;
    s.byCat[t.category] = (s.byCat[t.category] || 0) + 1;
    s.byState[STATUS_LABELS[status]]++;
    s.byPriority[t.priority] = (s.byPriority[t.priority] || 0) + 1;
    s.byStatus[status]++;
    s.bySeverity[severity]++;
    if (s.byCatStatus[t.category]) s.byCatStatus[t.category][status]++;
  }
  return s;
}

/* ------------------------------------------------------------- validation */

export function validate(model) {
  const msgs = (model.importWarnings || []).map((w) => ({ ...w, level: 'warning' }));
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
  const orphans = threatList(model).filter((t) => t.orphan);
  if (orphans.length) msgs.push({ level: 'info', text: `${orphans.length} threat(s) no longer match the diagram but were kept because you edited them.`, threatIds: orphans.map((t) => t.id) });
  return msgs;
}

// Per-element counts used for the badges drawn on the canvas in Analysis view.
export function threatBadges(model, diagramId) {
  const map = new Map();
  for (const t of threatList(model)) {
    if (t.diagramId !== diagramId || t.orphan) continue;
    const id = t.flowId || t.elementId;
    if (!id) continue;
    const b = map.get(id) || { total: 0, open: 0, high: false };
    b.total++;
    if (isOpen(t)) { b.open++; if (threatSeverity(t) === 'High') b.high = true; }
    map.set(id, b);
  }
  return map;
}

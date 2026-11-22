// Threat generation — the MTMT pipeline (§8 of the MTMT report):
//   for every in-scope data flow (source, flow, target)
//     for every threat type: applicable = Include ∧ ¬Exclude
// followed by a key-based merge that preserves user triage.

import { GENERIC } from './kb.js';
import { polylineCrossesRect, polylinesIntersect, rectOf } from './geometry.js';
import { effectiveProperties, elementIndex, interactionString, kbOf, lineGeometry, touch } from './model.js';
import { compileRule, evaluate, expandTemplate } from './rules.js';
import { annotateThreats } from './enrich/enrichThreat.js';
import { adoptCandidate, matchByStableKey } from './enrich/triage.js';

export function threatKey(typeId, sourceId, flowId, targetId) {
  return `${typeId}:${sourceId}:${flowId}:${targetId}`;
}

/** Rule-engine view of an element: type chain + upper-cased property map. */
export function subjectContext(kb, el) {
  const props = new Map();
  for (const [k, v] of effectiveProperties(kb, el)) props.set(k.toUpperCase(), v);
  return { chain: kb.chain(el.typeId), props, element: el };
}

/** Boundaries (elements) whose drawn shape the flow's curve cuts through. */
export function crossedBoundaries(model, diagram, flow) {
  const pts = lineGeometry(model, diagram, flow).points;
  const out = [];
  for (const b of diagram.elements) {
    if (b.outOfScope) continue;
    if (b.generic === GENERIC.LINE_BOUNDARY) {
      if (polylinesIntersect(pts, lineGeometry(model, diagram, b).points)) out.push(b);
    } else if (b.generic === GENERIC.BOX_BOUNDARY) {
      if (polylineCrossesRect(pts, rectOf(b))) out.push(b);
    }
  }
  return out;
}

/** Build the evaluation context for one interaction. */
export function interactionContext(model, diagram, flow, source, target) {
  const kb = kbOf(model);
  const crossed = crossedBoundaries(model, diagram, flow);
  const boundaryIds = new Set(kb.boundaryTypeIds());
  return {
    subjects: {
      source: subjectContext(kb, source),
      flow: subjectContext(kb, flow),
      target: subjectContext(kb, target),
    },
    crossed,
    crosses: (typeId) => crossed.some((b) => kb.isDerived(b.typeId, typeId)),
    isBoundaryType: (typeId) => boundaryIds.has(typeId),
  };
}

/** Interactions (flows with both ends attached) on the given diagrams. */
export function interactions(model, { diagramId } = {}) {
  const idx = elementIndex(model);
  const out = [];
  for (const diagram of model.diagrams) {
    if (diagramId && diagram.id !== diagramId) continue;
    for (const flow of diagram.elements) {
      if (flow.generic !== GENERIC.FLOW) continue;
      const source = flow.source ? idx.get(flow.source)?.element : undefined;
      const target = flow.target ? idx.get(flow.target)?.element : undefined;
      out.push({ diagram, flow, source, target });
    }
  }
  return out;
}

/** Evaluate one threat type against one interaction context. Throws on rule errors. */
export function isApplicable(threatType, ctx) {
  const inc = compileRule(threatType.include);
  if (inc.error) throw inc.error;
  if (!inc.ast) return false;
  if (!evaluate(inc.ast, ctx)) return false;
  const exc = compileRule(threatType.exclude);
  if (exc.error) throw exc.error;
  return !(exc.ast && evaluate(exc.ast, ctx));
}

/**
 * Compute the threats the template produces for the model right now.
 * Returns { candidates: Map<key, threat>, errors: [{threatTypeId, flowId, message}] }.
 */
export function computeThreats(model, { diagramId } = {}) {
  const kb = kbOf(model);
  const candidates = new Map();
  const errors = [];
  const errorKeys = new Set();
  const pushError = (threatTypeId, flowId, message) => {
    const k = `${threatTypeId}|${message}`;
    if (errorKeys.has(k)) return;
    errorKeys.add(k);
    errors.push({ threatTypeId, flowId, message });
  };
  const types = kb.threatTypes.filter((t) => !t.legacy);

  for (const { diagram, flow, source, target } of interactions(model, { diagramId })) {
    if (!source || !target) continue; // loose connector: reported by validation
    if (flow.outOfScope || source.outOfScope || target.outOfScope) continue;
    const ctx = interactionContext(model, diagram, flow, source, target);
    for (const tt of types) {
      let applies;
      try {
        applies = isApplicable(tt, ctx);
      } catch (e) {
        pushError(tt.id, flow.id, e.message);
        continue;
      }
      if (!applies) continue;
      const key = threatKey(tt.id, source.id, flow.id, target.id);
      const custom = {};
      for (const p of kb.customThreatProperties()) {
        const v = tt.properties?.[p.name];
        if (v !== undefined) custom[p.name] = expandTemplate(v, ctx.subjects);
      }
      candidates.set(key, {
        key,
        typeId: tt.id,
        category: tt.category,
        title: expandTemplate(tt.title, ctx.subjects),
        description: expandTemplate(tt.description, ctx.subjects),
        mitigation: expandTemplate(tt.mitigation, ctx.subjects),
        interaction: interactionString(source, flow, target),
        diagramId: diagram.id,
        sourceId: source.id,
        flowId: flow.id,
        targetId: target.id,
        priority: tt.priority || tt.properties?.Priority || kb.priorities()[0],
        custom,
        references: tt.references || [],
      });
    }
  }
  return { candidates, errors };
}

function isUntouched(t) {
  return t.state === 'NotStarted' && !t.changedBy && !t.justification;
}

/**
 * Generate threats and merge them into model.threats (MTMT GenerateThreatsInternal):
 *  - new keys are added with the next sequential id;
 *  - existing keys keep their triage and get refreshed text (unless the user edited it);
 *  - a threat whose key vanished is re-attached to a new candidate with the same stable key
 *    (type + source/target/flow names), keeping its triage;
 *  - threats that are no longer produced are removed if untouched, otherwise kept as orphans;
 *  - user-defined threats are never removed.
 */
export function generateThreats(model, { diagramId } = {}) {
  const summary = { enabled: model.settings.threatGeneration !== false, added: 0, updated: 0, removed: 0, orphaned: 0, restored: 0, rematched: 0, total: 0, errors: [] };
  if (!summary.enabled) {
    annotateThreats(model);
    summary.total = model.threats.length;
    return summary;
  }
  const { candidates, errors } = computeThreats(model, { diagramId });
  summary.errors = errors;
  const diagramIds = new Set(model.diagrams.map((d) => d.id));
  const idx = elementIndex(model);
  const inScope = (t) => (diagramId ? t.diagramId === diagramId : true);
  const kept = [];
  const unmatched = [];

  for (const t of model.threats) {
    if (t.userDefined) {
      const flow = idx.get(t.flowId)?.element;
      if (flow) {
        t.interaction = interactionString(idx.get(flow.source)?.element, flow, idx.get(flow.target)?.element);
        t.sourceId = flow.source || '';
        t.targetId = flow.target || '';
        t.orphan = false;
      } else t.orphan = true;
      kept.push(t);
      continue;
    }
    if (!inScope(t) && diagramIds.has(t.diagramId)) {
      kept.push(t);
      continue;
    }
    const c = candidates.get(t.key);
    if (c) {
      candidates.delete(t.key);
      let changed = false;
      for (const f of ['title', 'description', 'mitigation']) {
        if (!t.edited.includes(f) && t[f] !== c[f]) {
          t[f] = c[f];
          changed = true;
        }
      }
      if (t.interaction !== c.interaction) {
        t.interaction = c.interaction;
        changed = true;
      }
      t.references = c.references;
      if (t.orphan) {
        t.orphan = false;
        summary.restored++;
      }
      if (changed) summary.updated++;
      kept.push(t);
    } else {
      unmatched.push(t);
    }
  }
  // Stable triage: a threat whose key vanished but whose type + source/target/flow names
  // reappear under a new key (elements got new ids) keeps its triage under the new key.
  const adopted = new Set();
  for (const [t, c] of matchByStableKey(unmatched, [...candidates.values()])) {
    candidates.delete(c.key);
    if (t.orphan) summary.restored++;
    adoptCandidate(t, c);
    adopted.add(t);
    summary.rematched++;
    kept.push(t);
  }
  for (const t of unmatched) {
    if (adopted.has(t)) continue;
    if (isUntouched(t)) {
      summary.removed++;
    } else {
      if (!t.orphan) summary.orphaned++;
      t.orphan = true;
      kept.push(t);
    }
  }
  for (const c of candidates.values()) {
    kept.push({
      ...c,
      id: model.nextThreatId++,
      state: 'NotStarted',
      justification: '',
      userDefined: false,
      orphan: false,
      changedBy: '',
      modifiedAt: '',
      edited: [],
    });
    summary.added++;
  }
  kept.sort((a, b) => a.id - b.id);
  const changed = summary.added || summary.removed || summary.orphaned || summary.updated || summary.restored || summary.rematched;
  model.threats = kept;
  annotateThreats(model); // post-processing only: never feeds back into rule matching or merge
  if (changed) touch(model);
  summary.total = kept.length;
  return summary;
}

/** Threats attached to an element (as source, flow or target). */
export function threatsForElement(model, elementId) {
  return model.threats.filter((t) => t.flowId === elementId || t.sourceId === elementId || t.targetId === elementId);
}

/** Explain why each threat type does or does not apply to a flow (rule debugging aid). */
export function explainFlow(model, flowRef) {
  const idx = elementIndex(model);
  const hit = idx.get(flowRef) || [...idx.values()].find((h) => h.element.name === flowRef);
  if (!hit || hit.element.generic !== GENERIC.FLOW) throw new Error(`Data flow not found: ${flowRef}`);
  const { element: flow, diagram } = hit;
  const source = idx.get(flow.source)?.element;
  const target = idx.get(flow.target)?.element;
  if (!source || !target) return { flow: flow.id, connected: false, results: [] };
  const kb = kbOf(model);
  const ctx = interactionContext(model, diagram, flow, source, target);
  const results = kb.threatTypes
    .filter((t) => !t.legacy)
    .map((tt) => {
      const title = expandTemplate(tt.title, ctx.subjects);
      try {
        return { id: tt.id, title, applies: isApplicable(tt, ctx) };
      } catch (e) {
        return { id: tt.id, title, applies: false, error: e.message };
      }
    });
  return {
    flow: flow.id,
    connected: true,
    crosses: ctx.crossed.map((b) => ({ id: b.id, name: b.name, typeId: b.typeId })),
    results,
  };
}

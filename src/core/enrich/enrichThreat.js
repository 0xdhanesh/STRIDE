// Enrichment orchestrator: a thin post-processing pass over generated threats.
//
//   annotateSignals (score)  →  classify (specific class, evidence, why-test)  →  dedupe
//
// The result lives in `threat.enriched`; original `title` and `description` stay intact so the
// model remains MTMT-compatible. Like `threat.signal`, it is derived data: recomputed after
// generation, triage and load, and never fed back into rule matching or the merge.

import { kbFor } from '../kb.js';
import { SIGNAL_THRESHOLDS, SIGNAL_WEIGHTS, annotateSignals } from '../signal.js';
import { classCategories, classFix, classifyInteraction } from './classify.js';
import { dedupeThreats } from './dedupe.js';
import { stableKey } from './triage.js';

function genericEnrichment(t) {
  const evidence = (t.signal?.evidence || []).map((f) => ({ file: f }));
  return {
    specificTitle: t.signal?.title || t.title,
    class: 'generic',
    evidence,
    whyTest: '',
    confidence: 'needs-verification',
    // The same rule between the same two components on parallel flows is one pattern.
    groupKey: t.userDefined || t.orphan ? '' : `generic:${t.typeId}:${t.sourceId}>${t.targetId}`,
    stableKey: stableKey(t),
  };
}

/**
 * Score without the triage-dependent bonus, so triaging a threat (e.g. NotStarted →
 * NeedsInvestigation) does not move its class to a sibling threat on the same flow.
 */
function baseScore(t) {
  const s = t.signal?.score ?? 0;
  return t.signal?.reasons?.includes('high priority, not started') ? s - SIGNAL_WEIGHTS.highUntriaged : s;
}

/** Prefer the threat that already carries the sink finding, then base score, then id. */
function pickBest(pool) {
  let best = null;
  for (const t of pool) {
    if (!best) best = t;
    else {
      const a = t.signal?.title ? 1 : 0;
      const b = best.signal?.title ? 1 : 0;
      const as = baseScore(t);
      const bs = baseScore(best);
      if (a > b || (a === b && (as > bs || (as === bs && t.id < best.id)))) best = t;
    }
  }
  return best;
}

/**
 * Compute `threat.enriched` for every threat in the model. Each (flow, class) becomes one item on
 * the best threat in a category the class explains, so one flow does not repeat the same finding
 * across its STRIDE categories. Only high-signal threats get a class: a class hit backed by file
 * evidence counts as a dangerous sink in the score (the signal layer only knows its own sinks),
 * so e.g. an SSRF with a code reference is high signal; a hit without evidence is not promoted.
 */
export function enrichThreats(model) {
  const kb = kbFor(model.template);
  const idx = new Map();
  for (const d of model.diagrams) for (const e of d.elements) idx.set(e.id, e);
  for (const t of model.threats) t.enriched = genericEnrichment(t);

  const byFlow = new Map();
  for (const t of model.threats) {
    if (t.orphan || t.state === 'NotApplicable') continue;
    if (!byFlow.has(t.flowId)) byFlow.set(t.flowId, []);
    byFlow.get(t.flowId).push(t);
  }
  const catName = (id) => String(kb.category(id)?.name || id || '').toLowerCase();

  for (const [flowId, list] of byFlow) {
    const flow = idx.get(flowId);
    if (!flow) continue;
    const taken = new Set();
    // A flow has one source and one target, so the first threat's ends are the interaction's.
    const source = idx.get(list[0].sourceId);
    const target = idx.get(list[0].targetId);
    for (const hit of classifyInteraction(kb, flow, source, target)) {
      let pool = list.filter((t) => !taken.has(t) && (t.signal?.level === 'high' || hit.evidence.length));
      if (hit.ruleMatch) {
        const rule = pool.filter(hit.ruleMatch);
        if (rule.length) pool = rule;
        else if (hit.ruleOnly) continue;
      }
      const cats = classCategories(hit.class);
      const relevant = pool.filter((t) => cats.some((c) => catName(t.category).startsWith(c)));
      const best = pickBest(relevant.length ? relevant : pool);
      if (!best) continue;
      if (best.signal && best.signal.level !== 'high') {
        best.signal.score += SIGNAL_WEIGHTS.sink;
        best.signal.reasons.push(`specific class (${hit.class})`);
        best.signal.level = best.signal.score >= SIGNAL_THRESHOLDS.high ? 'high' : best.signal.score >= SIGNAL_THRESHOLDS.medium ? 'medium' : 'generic';
        if (best.signal.level !== 'high') continue;
      }
      taken.add(best);
      best.enriched = {
        specificTitle: hit.title,
        class: hit.class,
        evidence: hit.evidence.length ? hit.evidence : best.enriched.evidence,
        whyTest: hit.whyTest,
        confidence: hit.confidence,
        groupKey: hit.groupKey,
        stableKey: best.enriched.stableKey,
        fix: classFix(hit.class),
      };
    }
  }
  dedupeThreats(model.threats);
  return model;
}

/** Score then enrich: the single post-generation pass used by generation, triage, load and reports. */
export function annotateThreats(model) {
  annotateSignals(model);
  return enrichThreats(model);
}

/** Evidence as "file:line" strings for display. */
export function enrichedEvidence(t) {
  return (t.enriched?.evidence || []).map((e) => `${e.file}${e.line ? `:${e.line}` : ''}`);
}


// De-duplication: collapse threats that describe the same pattern (same class and same
// target component / endpoint pattern; for unclassified threats, the same rule between the
// same two components) into one representative. All threats stay in the
// model; secondaries are marked with `enriched.duplicateOf` (the representative's id).

const OPEN = new Set(['NotStarted', 'NeedsInvestigation']);

/** Representative order: open first, then highest signal score, then lowest id (stable). */
function better(a, b) {
  const ao = OPEN.has(a.state) ? 1 : 0;
  const bo = OPEN.has(b.state) ? 1 : 0;
  if (ao !== bo) return ao > bo;
  const as = a.signal?.score ?? 0;
  const bs = b.signal?.score ?? 0;
  if (as !== bs) return as > bs;
  return a.id < b.id;
}

/**
 * Group enriched threats by `enriched.groupKey` (threats without one are never grouped).
 * Sets `relatedFlows` / `relatedThreats` on each representative and `duplicateOf` on the rest.
 * Returns Map<groupKey, { representative, members }>.
 */
export function dedupeThreats(threats) {
  const groups = new Map();
  for (const t of threats) {
    const e = t.enriched;
    if (!e) continue;
    delete e.duplicateOf;
    delete e.relatedFlows;
    delete e.relatedThreats;
    if (!e.groupKey) continue;
    if (!groups.has(e.groupKey)) groups.set(e.groupKey, []);
    groups.get(e.groupKey).push(t);
  }
  const out = new Map();
  for (const [key, members] of groups) {
    let rep = members[0];
    for (const t of members) if (better(t, rep)) rep = t;
    rep.enriched.relatedFlows = new Set(members.map((t) => t.flowId)).size;
    if (members.length > 1) rep.enriched.relatedThreats = members.filter((t) => t !== rep).map((t) => t.id).sort((a, b) => a - b);
    for (const t of members) if (t !== rep) t.enriched.duplicateOf = rep.id;
    out.set(key, { representative: rep, members });
  }
  return out;
}

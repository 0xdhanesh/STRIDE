// Stable triage across re-generation.
//
// Generated threats are merged by key (typeId:sourceId:flowId:targetId). When elements get new
// ids — a flow is redrawn, a spec gains explicit ids, a diagram is rebuilt — the key changes and
// triage would be lost. The stable key is a hash of the threat type and the *names* of source,
// target and flow (via the persisted interaction string), so a threat that disappeared under one
// key and reappears under another is re-attached with its state, justification and notes intact.

/** FNV-1a 32-bit, hex. Deterministic and isomorphic. */
function fnv1a(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

const norm = (s) => String(s ?? '').toLowerCase().replace(/\s+/g, ' ').trim();

/** Stable key of a threat: typeId + source/target/flow names (the interaction string). */
export function stableKey(t) {
  return `sk_${fnv1a(`${norm(t.typeId)}|${norm(t.interaction)}`)}`;
}

function uniqueBy(list, keyOf) {
  const m = new Map();
  for (const x of list) {
    const k = keyOf(x);
    m.set(k, m.has(k) ? null : x);
  }
  return m;
}

/**
 * Pair threats that lost their key match (`unmatched`) with new candidates by stable key.
 * Only unambiguous pairs (one threat and one candidate per stable key) are matched.
 * Returns [[threat, candidate], …].
 */
export function matchByStableKey(unmatched, candidates) {
  const olds = uniqueBy(unmatched.filter((t) => !t.userDefined), stableKey);
  const news = uniqueBy(candidates, stableKey);
  const pairs = [];
  for (const [k, c] of news) {
    const t = olds.get(k);
    if (c && t) pairs.push([t, c]);
  }
  return pairs;
}

/**
 * Re-attach an existing threat to a candidate's new key. Triage (state, justification,
 * changedBy, modifiedAt, custom notes, edited text) is kept; only identity and un-edited
 * rule text are refreshed.
 */
export function adoptCandidate(t, c) {
  for (const f of ['key', 'diagramId', 'sourceId', 'flowId', 'targetId', 'interaction', 'category']) t[f] = c[f];
  for (const f of ['title', 'description', 'mitigation']) if (!t.edited.includes(f)) t[f] = c[f];
  t.references = c.references;
  t.custom = { ...c.custom, ...t.custom };
  t.orphan = false;
  return t;
}

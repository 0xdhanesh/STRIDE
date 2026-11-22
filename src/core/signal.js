// High-signal narrative layer: a post-generation pass that scores every threat by how
// much concrete evidence backs it, and derives a specific, evidence-aware display title.
//
// This never touches rule matching, threat keys, ids or triage state. The result lives in
// `threat.signal` ({ score, level, reasons, title?, sink?, fix? }) and is recomputed
// whenever threats are generated, triaged or loaded.

import { kbFor } from './kb.js';

export const SIGNAL_LEVELS = Object.freeze(['high', 'medium', 'generic']);
export const SIGNAL_LABELS = Object.freeze({ high: 'High Signal', medium: 'Medium Signal', generic: 'Generic' });
export const SIGNAL_THRESHOLDS = Object.freeze({ high: 50, medium: 25 });

export const SIGNAL_WEIGHTS = Object.freeze({
  evidence: 40,
  sink: 30,
  weakControl: 20,
  sensitiveTarget: 15,
  highUntriaged: 10,
  notApplicable: -30,
});

/**
 * Dangerous sinks. `categories` are the STRIDE category names a sink plausibly explains;
 * the sink bonus and title rewrite only apply to threats in those categories, so a
 * shell_exec flow does not turn its Spoofing or DoS threats into "command injection".
 */
export const DANGEROUS_SINKS = Object.freeze([
  {
    id: 'command-injection',
    pattern: /\b(shell_exec|passthru|proc_open|popen|execSync|execFile|child_process|os\.system|subprocess\.\w+|Runtime\.getRuntime\(\)\.exec)\b|\b(system|exec)\s*\(/i,
    categories: ['elevation of privilege', 'tampering'],
    title: 'Command injection',
    fix: 'Do not pass user input to a shell: call the program directly with an argument list, and allow-list the input (e.g. validate an IP with filter_var).',
  },
  {
    id: 'code-injection',
    pattern: /\beval\s*\(|\bassert\s*\(\s*\$|\bcreate_function\b|\bnew\s+Function\s*\(/i,
    categories: ['elevation of privilege', 'tampering'],
    title: 'Code injection',
    fix: 'Remove dynamic code evaluation; map user choices to fixed code paths.',
  },
  {
    id: 'file-inclusion',
    pattern: /\b(include|require)(_once)?\s*\(?\s*\$/i,
    categories: ['information disclosure', 'elevation of privilege'],
    title: 'Local file inclusion',
    fix: 'Include only files from a fixed allow-list; never build include paths from request parameters.',
  },
  {
    id: 'sql-injection',
    pattern:
      /'\$\w+'|"\$\w+"|\b(select|insert|update|delete)\b[^;\n]*?(\$\w+|"\s*\.\s*|\.\s*"|\+\s*req\.|\$\{)|concatenat\w*\s+(sql|query)|\b(raw|dynamic)\s+sql\b|\bsql\s+concat|\bmysqli?_query\s*\(/i,
    categories: ['tampering', 'information disclosure'],
    title: 'SQL injection',
    fix: 'Use parameterized queries / prepared statements; never concatenate request data into SQL.',
  },
  {
    id: 'file-upload',
    pattern: /\bmove_uploaded_file\b|\bunrestricted\s+(file\s+)?upload/i,
    categories: ['tampering', 'elevation of privilege'],
    title: 'Unrestricted file upload to web root',
    fix: 'Validate type and content server-side, store uploads outside the web root with random names, and never execute them.',
  },
  {
    id: 'weak-token',
    pattern: /\bmd5\s*\(\s*uniqid|\buniqid\s*\(|\b(mt_)?rand\s*\(\s*\)\s*[^;\n]*token/i,
    categories: ['spoofing', 'tampering'],
    title: 'Weak CSRF token',
    fix: 'Generate tokens with a CSPRNG (random_bytes / crypto.randomBytes) and compare them in constant time.',
  },
  {
    id: 'hardcoded-secret',
    pattern: /\bhard-?coded\s+(key|secret|password|token|credential)s?\b|\b(api_?key|secret|passw(or)?d|token)\s*[:=]\s*['"][^'"\s]{4,}['"]/i,
    categories: ['information disclosure', 'spoofing'],
    title: 'Hardcoded secret',
    fix: 'Move the secret to a secrets manager or environment configuration and rotate it.',
  },
  {
    id: 'deserialization',
    pattern: /\bunserialize\s*\(|\bpickle\.loads?\b|\byaml\.load\s*\((?![^)]*SafeLoader)|\bObjectInputStream\b|\bBinaryFormatter\b/i,
    categories: ['elevation of privilege', 'tampering'],
    title: 'Insecure deserialization',
    fix: 'Do not deserialize untrusted data with native formats; use a data-only format such as JSON with schema validation.',
  },
]);

/** Custom property keys/values that indicate weak or missing controls. */
const WEAK_VALUE = /hard-?coded|\bmd5\b|\bsha-?1\b|unvalidated|unsalted|unsani[tz]i[sz]ed|unescaped|unauthenticated|plain-?text|clear-?text|\bweak\b|\binsecure\b|\bdisabled\b|\bdes\b|\becb\b|\brc4\b/i;
const CONTROL_KEY = /valid|saniti|escap|auth|encrypt|csrf|tls|ssl|hash|salt|sign/i;
const NEGATIVE = /^(no|false|none|off|missing|disabled)$/i;
const WEB_SERVED = /web|www|public|upload|htdocs|webroot|static|hackable|served/i;

/** Plain-text haystack used for sink matching on an element. */
function elementText(el) {
  if (!el) return [];
  return [...(el.evidence || []), ...Object.values(el.custom || {})];
}

/** File part of an evidence reference ("a/b.php:12 — snippet" → "a/b.php"). */
export function evidenceFile(ref) {
  const s = String(ref || '').trim();
  const m = /^([^\s:]+?\.[A-Za-z0-9]+)(?::\d+(?:-\d+)?)?(?:\s|$)/.exec(s);
  return m ? m[1] : s.split(/\s/)[0];
}

function categoryName(kb, id) {
  return String(kb.category(id)?.name || id || '').toLowerCase();
}

function typeNames(kb, typeId) {
  return kb.chain(typeId).map((c) => `${c} ${kb.element(c)?.name || ''}`.toLowerCase());
}

function hasWeakControl(el) {
  for (const [k, v] of Object.entries(el?.custom || {})) {
    if (WEAK_VALUE.test(k) || WEAK_VALUE.test(v)) return true;
    if (CONTROL_KEY.test(k) && NEGATIVE.test(String(v).trim())) return true;
  }
  return false;
}

function isSensitiveTarget(kb, el) {
  if (!el) return false;
  const names = typeNames(kb, el.typeId);
  if (names.some((n) => n.includes('osprocess') || n.includes('os process'))) return true;
  if (names.some((n) => n.includes('configfile') || n.includes('configuration file'))) return true;
  const isFs = names.some((n) => n.includes('tmcore.fs ') || n.includes('file system'));
  if (!isFs) return false;
  return [el.name, ...Object.keys(el.custom || {}), ...Object.values(el.custom || {}), ...(el.evidence || [])].some((x) => WEB_SERVED.test(String(x)));
}

/** First sink that matches the flow name, evidence or custom values of the interaction. */
function findSink(flow, source, target) {
  const sources = [
    { text: flow?.name || '', where: 'flow' },
    ...elementText(flow).map((text) => ({ text, where: 'flow' })),
    ...elementText(target).map((text) => ({ text, where: 'target' })),
    ...elementText(source).map((text) => ({ text, where: 'source' })),
  ];
  for (const sink of DANGEROUS_SINKS) {
    for (const s of sources) {
      const m = sink.pattern.exec(String(s.text));
      if (m) return { sink, match: m[0], text: String(s.text), where: s.where };
    }
  }
  return null;
}

function cleanToken(match) {
  return match.replace(/\s*\(\s*$/, '').replace(/\s+/g, ' ').trim();
}

/** Evidence-aware title for a sink hit, e.g. "Command injection via shell_exec in exec/low.php". */
function sinkTitle(hit, flow, files) {
  const { sink, match, text } = hit;
  const token = cleanToken(match);
  const file = files[0];
  const flowName = String(flow?.name || '').trim();
  switch (sink.id) {
    case 'file-inclusion': {
      const p = /\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*['"]?(\w+)/i.exec(text) || /\$(\w+)/.exec(text);
      const param = p ? p[2] || p[1] : '';
      return `Local file inclusion via ${param ? `'${param}'` : 'user-controlled path'}${file ? ` in ${file}` : ''}`;
    }
    case 'sql-injection':
      return `SQL injection via concatenated query${file ? ` in ${file}` : ''}`;
    case 'file-upload':
      return `Unrestricted file upload to web root${file ? ` via ${file}` : ''}`;
    case 'weak-token':
      return `Weak CSRF token (${/md5/i.test(token) ? 'md5(uniqid())' : token})${file ? ` in ${file}` : ''}`;
    case 'hardcoded-secret':
      return `Hardcoded secret${file ? ` in ${file}` : ''}`;
    default:
      if (flowName && flowName.toLowerCase().includes(token.toLowerCase())) return `${sink.title} via ${flowName}`;
      return `${sink.title} via ${token}${file ? ` in ${file}` : ''}`;
  }
}

function levelOf(score) {
  return score >= SIGNAL_THRESHOLDS.high ? 'high' : score >= SIGNAL_THRESHOLDS.medium ? 'medium' : 'generic';
}

/**
 * Score one threat. `idx` is a Map of element id → element.
 * Returns { signal, hit } where hit is the sink match for the interaction (if any)
 * and whether it is relevant to this threat's category.
 */
export function scoreThreat(kb, idx, t) {
  const source = idx.get(t.sourceId);
  const flow = idx.get(t.flowId);
  const target = idx.get(t.targetId);
  const W = SIGNAL_WEIGHTS;
  let score = 0;
  const reasons = [];
  const evidence = [flow, source, target].flatMap((e) => e?.evidence || []);
  if (evidence.length) {
    score += W.evidence;
    reasons.push('source-code evidence');
  }
  const hit = t.orphan ? null : findSink(flow, source, target);
  const relevant = !!hit && hit.sink.categories.some((c) => categoryName(kb, t.category).startsWith(c));
  if (relevant) {
    score += W.sink;
    reasons.push(`dangerous sink (${cleanToken(hit.match)})`);
  }
  if ([source, flow, target].some(hasWeakControl)) {
    score += W.weakControl;
    reasons.push('weak control in properties');
  }
  if (isSensitiveTarget(kb, target)) {
    score += W.sensitiveTarget;
    reasons.push('sensitive target type');
  }
  if (String(t.priority).toLowerCase() === 'high' && t.state === 'NotStarted') {
    score += W.highUntriaged;
    reasons.push('high priority, not started');
  }
  if (t.state === 'NotApplicable') {
    score += W.notApplicable;
    reasons.push('marked not applicable');
  }
  const hitEl = hit ? { flow, target, source }[hit.where] : null;
  const files = [...new Set((hitEl?.evidence || []).map(evidenceFile))];
  if (!files.length) files.push(...new Set(evidence.map(evidenceFile)));
  const signal = { score, level: levelOf(score), reasons };
  if (files.length) signal.evidence = files.slice(0, 3);
  return { signal, hit: hit ? { ...hit, relevant, title: sinkTitle(hit, flow, files) } : null };
}

/**
 * Compute signals for every threat without mutating the model. Returns Map<threatKey, signal>.
 *
 * Each (flow, sink) pair becomes one finding: the highest scoring threat in a category the sink
 * explains gets the evidence-aware title and the sink's fix. When the template produced no threat
 * in such a category on that flow (e.g. only Spoofing/DoS on an upload flow), the best threat on the
 * flow carries the finding instead, so a dangerous sink is never lost. Other threats keep their
 * rule title, so reports do not repeat the same finding.
 */
export function computeSignals(model) {
  const kb = kbFor(model.template);
  const idx = new Map();
  for (const d of model.diagrams) for (const e of d.elements) idx.set(e.id, e);
  const out = new Map();
  const groups = new Map();
  for (const t of model.threats) {
    const { signal, hit } = scoreThreat(kb, idx, t);
    out.set(t.key, signal);
    if (!hit) continue;
    const k = `${t.flowId}|${hit.sink.id}`;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push({ t, signal, hit });
  }
  // Rank without the triage-dependent bonus so triaging the finding never moves it to a sibling.
  const base = (x) => x.signal.score - (x.signal.reasons.includes('high priority, not started') ? SIGNAL_WEIGHTS.highUntriaged : 0);
  const better = (a, b) => (base(a) !== base(b) ? base(a) > base(b) : a.t.id < b.t.id);
  for (const list of groups.values()) {
    const eligible = list.filter((x) => x.t.state !== 'NotApplicable');
    const relevant = eligible.filter((x) => x.hit.relevant);
    const pool = relevant.length ? relevant : eligible;
    let best = null;
    for (const x of pool) if (!best || better(x, best)) best = x;
    if (!best) continue;
    const s = best.signal;
    if (!best.hit.relevant) {
      s.score += SIGNAL_WEIGHTS.sink;
      s.level = levelOf(s.score);
      s.reasons.push(`dangerous sink (${cleanToken(best.hit.match)})`);
    }
    s.sink = best.hit.sink.id;
    s.fix = best.hit.sink.fix;
    if (s.level === 'high' && !best.t.edited?.includes('title')) s.title = best.hit.title;
  }
  return out;
}

/** Store the signal on each threat (`threat.signal`). Does not affect triage or keys. */
export function annotateSignals(model) {
  const signals = computeSignals(model);
  for (const t of model.threats) t.signal = signals.get(t.key);
  return model;
}

/**
 * Title for display and reports: a user-edited title always wins; then the enriched specific
 * title (see enrich/); then the signal's evidence-aware title; then the rule title.
 */
export function displayTitle(t) {
  if (t.edited?.includes('title')) return t.title;
  if (t.enriched && t.enriched.class !== 'generic' && t.enriched.specificTitle) return t.enriched.specificTitle;
  return t.signal?.title || t.title;
}

/** Normalize a --signal value: high | medium | all | off. */
export function normalizeSignalLevel(v, fallback = 'high') {
  if (v === undefined || v === null || v === '' || v === true) return fallback;
  const s = String(v).toLowerCase().trim();
  if (['high', 'h'].includes(s)) return 'high';
  if (['medium', 'med', 'm'].includes(s)) return 'medium';
  if (['all', 'generic', 'any'].includes(s)) return 'all';
  if (['off', 'none', 'false', 'no'].includes(s)) return 'off';
  return undefined;
}

/** Signal levels that pass a minimum level ('high' → [high], 'medium' → [high, medium]). */
export function levelsAtLeast(min) {
  if (min === 'high') return ['high'];
  if (min === 'medium') return ['high', 'medium'];
  return [...SIGNAL_LEVELS];
}

/** One sentence (max ~180 chars) from a longer mitigation text. */
export function oneLine(text, max = 180) {
  const s = String(text || '').replace(/\s+/g, ' ').trim();
  if (!s) return '';
  const first = /^(.+?[.!?])(\s|$)/.exec(s)?.[1] || s;
  return first.length > max ? `${first.slice(0, max - 1).trimEnd()}…` : first;
}

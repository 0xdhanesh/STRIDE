// Classification: map a high-signal threat + the evidence on its interaction to a specific,
// testable vulnerability class (IDOR, SSRF, RCE sink, …) with file/line evidence and a short
// "why test this" line. Pure functions over plain data; never touches rule matching or triage.

import { evidenceFile } from '../signal.js';

export const ENRICH_CLASSES = Object.freeze(['rce-sink', 'ssrf', 'idor', 'auth-bypass', 'csrf', 'upload', 'generic']);
export const CONFIDENCE_LEVELS = Object.freeze(['observed-sink', 'hypothesized', 'needs-verification']);

const NEGATIVE = /^(no|false|none|off|missing|disabled|absent|not ?checked|unchecked)$/i;

const RCE = /\b(shell_exec|passthru|proc_open|popen|execSync|execFile|child_process|os\.system|subprocess\.\w+|Runtime\.getRuntime\(\)\.exec|exec\.Command|unserialize|pickle\.loads?|yaml\.load|ObjectInputStream|BinaryFormatter|deserializ\w*)\b|\b(system|exec|eval)\s*\(/i;
const OUTBOUND_HTTP = /\b(fetch|axios(\.\w+)?|requests\.(get|post|put|request)|urlopen|http\.(Get|Post|NewRequest)|HttpClient|RestTemplate|WebClient|curl_exec|curl_init|file_get_contents|httpx\.\w+|net\/http|outbound\s+(http|request)|webhook)\b/i;
const USER_URL = /\b(url|uri|href|link|callback|webhook|redirect|endpoint)\b/i;
const USER_INPUT = /\b(user|client|request|req\.|params|query|body|supplied|controlled|provided|input|args)\b|\$_(GET|POST|REQUEST)/i;
const SSRF_WORD = /\bssrf\b|server[- ]side request forgery/i;
const ROUTE = /(?:^|[\s"'`(])((?:\/[\w{}:.*-]+){1,8})/;
const API_TYPE = /web ?svc|web ?service|web ?app|web ?server|\bapi\b/i;
const OBJECT_ID = /\{\w*id\}|:\w*id\b|[?&]\w*id=|\b[a-z]+_id\b|\b(object|resource|record|post|channel|team|account|order|file|document|user)\s+ids?\b/i;
const CAMEL_ID = /\b[a-z][A-Za-z0-9]*Id\b|\.(Post|User|Channel|Team|Object|Resource)Id\b/;
const AUTHZ_KEY = /authz|authori[sz]|permission|ownership|membership|access.?check|\bacl\b/i;
const AUTHZ_MISSING = /\b(no|missing|without|lacks?|skips?|absent|unchecked)\b[^.;\n]{0,40}\b(authz|authori[sz]ation|permission|ownership|membership|access)\b|\bidor\b|\bbola\b/i;
const WEBSOCKET = /\bweb-?sockets?\b|\bwss?:\/\/|\bsocket\.io\b|upgrade:\s*websocket/i;
const AUTH_WORD = /\b(auth\w*|token|jwt|session|cookie|bearer|credential|login)\b/i;
const CSRF_RULE = /cross[- ]site request forgery|\bcsrf\b|\bxsrf\b/i;
const SESSION = /\b(cookie|cookies|session|set-cookie|phpsessid|jsessionid|sessionid)\b/i;
const WEAK_TOKEN = /\bmd5\s*\(\s*uniqid|\buniqid\s*\(/i;
const UPLOAD = /\b(move_uploaded_file|multer|uploads?|uploaded|uploading|multipart\/form-data|FileUpload|IFormFile|MultipartFile)\b|\$_FILES/i;
const UPLOAD_CONTROL = /\b(max_?file_?size|maxFileSize|size\s*limit|limits\s*:|fileFilter|mime|content-type|allowed_?(types|extensions)|allow-?list|whitelist|getimagesize|finfo|extension\s*check)\b/i;
const UPLOAD_CONTROL_KEY = /size|type|mime|extension|validat|filter/i;
const UPLOAD_MISSING = /\b(no|without|missing|unrestricted|unvalidated|unchecked)\b[^.;\n]{0,30}\b(size|type|mime|extension|validation|check)/i;

/** Class definitions: categories the class explains (first match wins), base title and test hint. */
const CLASSES = {
  'rce-sink': {
    categories: ['elevation of privilege', 'tampering'],
    sink: 'command-exec',
    fix: 'Do not pass request data to a shell or evaluator: call programs with an argument list, allow-list the input, and avoid native deserialization of untrusted data.',
  },
  ssrf: {
    categories: ['information disclosure', 'elevation of privilege', 'spoofing', 'tampering'],
    sink: 'outbound-http',
    fix: 'Allow-list destination hosts and schemes, resolve and block private/link-local addresses, and disable redirects for user-supplied URLs.',
  },
  idor: {
    categories: ['elevation of privilege', 'information disclosure', 'tampering'],
    sink: 'authorization-check',
    fix: 'Check that the caller owns or is a member of the object (channel/team/tenant) on every request, not just that they are authenticated.',
  },
  'auth-bypass': {
    categories: ['spoofing', 'elevation of privilege'],
    sink: 'websocket-auth',
    fix: 'Authenticate the WebSocket handshake with the same checks as HTTP, re-validate the session for every message, and close the socket when it expires.',
  },
  csrf: {
    categories: ['elevation of privilege', 'spoofing', 'tampering'],
    sink: 'session-cookie',
    fix: 'Require an unpredictable per-session anti-CSRF token on state-changing requests, set SameSite=Lax/Strict on session cookies, and check Origin.',
  },
  upload: {
    categories: ['tampering', 'elevation of privilege'],
    sink: 'file-upload',
    fix: 'Enforce size limits and validate type by content server-side, store uploads outside the web root with random names, and never execute them.',
  },
};

/** Lower-case slug used in group keys. */
export function slug(s) {
  return (
    String(s ?? '')
      .toLowerCase()
      .normalize('NFKD')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 60) || 'x'
  );
}

/** Parse an evidence reference: "a/b.go:74-80 — snippet" → { file, line, snippet }. */
export function parseEvidence(ref) {
  const s = String(ref || '').trim();
  const m = /^([^\s:]+?\.[A-Za-z0-9]+)(?::(\d+)(?:-\d+)?)?(?:\s+(?:[—–-]\s*)?(.*))?$/.exec(s);
  if (m) return { file: m[1], line: m[2] ? Number(m[2]) : undefined, snippet: (m[3] || '').trim() };
  return { file: evidenceFile(s), line: undefined, snippet: s.includes(' ') ? s.slice(s.indexOf(' ') + 1).trim() : '' };
}

/** "file:line" (or just the file) for display. */
export function evidenceLocation(e) {
  return e ? `${e.file}${e.line ? `:${e.line}` : ''}` : '';
}

/** Interaction text, tagged by where it came from, used for all pattern tests. */
function interactionTexts(flow, source, target) {
  const out = [];
  const add = (where, el) => {
    if (!el) return;
    if (where === 'flow' && el.name) out.push({ where, text: String(el.name), kind: 'name' });
    for (const ev of el.evidence || []) out.push({ where, text: String(ev), kind: 'evidence', el });
    for (const [k, v] of Object.entries(el.custom || {})) out.push({ where, text: `${k} ${v}`, kind: 'custom', key: k, value: String(v) });
  };
  add('flow', flow);
  add('source', source);
  add('target', target);
  return out;
}

function chainNames(kb, el) {
  if (!el) return '';
  return kb
    .chain(el.typeId)
    .map((c) => `${c} ${kb.element(c)?.name || ''}`)
    .join(' ');
}

/** First REST-ish path in the flow name or evidence → resource segment ("/api/v4/posts/{id}" → "posts"). */
export function endpointResource(texts) {
  for (const { text, kind } of texts) {
    if (kind === 'custom') continue;
    const m = ROUTE.exec(kind === 'evidence' ? parseEvidence(text).snippet || '' : text);
    if (!m) continue;
    const seg = m[1].split('/').find((p) => p && !/^api$/i.test(p) && !/^v\d+$/i.test(p) && !/^[{:*]/.test(p) && !p.includes('.'));
    if (seg) return seg.toLowerCase();
  }
  return '';
}

function fileStem(file) {
  const base = String(file || '').split('/').pop() || '';
  return base.replace(/\.[^.]+$/, '');
}

/**
 * Evidence list for a class hit: entries whose snippet matched first, then the rest of the
 * flow's (then target's, then source's) evidence. Only entries that name a file are kept.
 */
function buildEvidence(texts, sinkLabel, matched) {
  const seen = new Set();
  const out = [];
  const push = (text) => {
    const e = parseEvidence(text);
    if (!e.file || !/\./.test(e.file)) return;
    const k = `${e.file}:${e.line ?? ''}`;
    if (seen.has(k)) return;
    seen.add(k);
    const item = { file: e.file, sink: sinkLabel };
    if (e.line) item.line = e.line;
    out.push(item);
  };
  for (const t of matched) if (t.kind === 'evidence') push(t.text);
  for (const where of ['flow', 'target', 'source']) for (const t of texts) if (t.kind === 'evidence' && t.where === where) push(t.text);
  return out.slice(0, 5);
}

function rceSinkLabel(token) {
  if (/eval/i.test(token)) return 'code-eval';
  if (/serial|pickle|yaml|ObjectInputStream|BinaryFormatter/i.test(token)) return 'deserialization';
  return 'command-exec';
}

/** Match `re` against texts (optionally restricted to some places); returns the hits. */
function hits(texts, re, where) {
  return texts.filter((t) => (!where || where.includes(t.where)) && re.test(t.text));
}

const cleanToken = (s) => String(s).replace(/\s*\(\s*$/, '').trim();

/**
 * Detect the classes that apply to one interaction. Returns a list of
 * { class, title, whyTest, evidence, confidence, groupKey, threatFilter? }.
 */
export function classifyInteraction(kb, flow, source, target) {
  const texts = interactionTexts(flow, source, target);
  const out = [];
  const targetName = target?.name || 'target';
  const sourceName = source?.name || 'source';
  const flowName = String(flow?.name || '').trim();
  const resource = () => {
    const r = endpointResource(texts.filter((t) => t.where === 'flow'));
    if (r) return r;
    const ev = texts.find((t) => t.kind === 'evidence' && t.where === 'flow');
    return ev ? fileStem(parseEvidence(ev.text).file) : '';
  };
  const hasFileEvidence = (list) => list.some((t) => t.kind === 'evidence' && /\./.test(parseEvidence(t.text).file));
  const flowEvidence = texts.filter((t) => t.kind === 'evidence' && t.where === 'flow');

  // 1. Command / code injection sink.
  const rce = hits(texts, RCE);
  if (rce.length) {
    const m = RCE.exec(rce[0].text);
    const token = cleanToken(m[0]);
    const label = rceSinkLabel(token);
    const evidence = buildEvidence(texts, label, rce);
    // Observed when the sink is in a code reference, or the flow that names it carries file evidence.
    const observed = hasFileEvidence(rce) || (rce[0].where === 'flow' && rce[0].kind === 'name' && hasFileEvidence(flowEvidence));
    const loc = evidence[0]?.file;
    out.push({
      class: 'rce-sink',
      title: `Command / code injection sink (${token})${loc ? ` in ${loc}` : ` in ${targetName}`}`,
      whyTest: `Request data from ${sourceName} reaches ${token}${evidence[0] ? ` at ${evidenceLocation(evidence[0])}` : ''}; try shell metacharacters or code payloads in the input.`,
      evidence,
      confidence: observed ? 'observed-sink' : 'needs-verification',
      groupKey: `rce-sink:${slug(targetName)}`,
    });
  }

  // 2. SSRF: outbound HTTP whose URL comes from the user.
  const ssrfWord = hits(texts, SSRF_WORD, ['flow', 'source']);
  const outbound = hits(texts, OUTBOUND_HTTP, ['flow', 'source']);
  const userUrl = texts.some((t) => ['flow', 'source'].includes(t.where) && USER_URL.test(t.text) && USER_INPUT.test(t.text));
  if (ssrfWord.length || (outbound.length && userUrl)) {
    const matched = [...ssrfWord, ...outbound];
    const evidence = buildEvidence(texts, CLASSES.ssrf.sink, matched);
    out.push({
      class: 'ssrf',
      title: `SSRF in outbound request to ${targetName}`,
      whyTest: `${sourceName} makes an outbound request with a user-influenced URL; try internal addresses (169.254.169.254, localhost) and alternate schemes.`,
      evidence,
      confidence: hasFileEvidence(matched) ? 'observed-sink' : 'needs-verification',
      groupKey: `ssrf:${slug(targetName)}`,
    });
  }

  // 3. IDOR / BOLA: API endpoint + object id + evidence that authorization is missing.
  const isApi = API_TYPE.test(chainNames(kb, target)) || texts.some((t) => t.where === 'flow' && t.kind === 'name' && /\/api\/|^(GET|POST|PUT|PATCH|DELETE)\s+\//i.test(t.text));
  const idHits = texts.filter((t) => t.where === 'flow' && (OBJECT_ID.test(t.text) || CAMEL_ID.test(t.text)));
  const authzMissing = [
    ...hits(texts, AUTHZ_MISSING),
    ...texts.filter((t) => t.kind === 'custom' && AUTHZ_KEY.test(t.key) && NEGATIVE.test(t.value.trim())),
  ];
  if (isApi && idHits.length && authzMissing.length) {
    const r = resource();
    const evidence = buildEvidence(texts, CLASSES.idor.sink, [...authzMissing, ...idHits]);
    const reason = authzMissing.find((t) => t.kind !== 'custom');
    const detail = reason ? oneClause(parseEvidence(reason.text).snippet || reason.text) : 'no ownership or membership check is recorded';
    out.push({
      class: 'idor',
      title: `IDOR / BOLA on ${r ? `${r} endpoints` : targetName}`,
      whyTest: `Object ID taken from the request to ${targetName}: ${detail}. Replay with another user's ID.`,
      evidence,
      confidence: 'hypothesized',
      groupKey: `idor:${slug(r || targetName)}`,
    });
  }

  // 4. WebSocket with authentication in play.
  const ws = hits(texts, WEBSOCKET, ['flow']).concat(flow?.typeId && /websocket/i.test(chainNames(kb, flow)) ? [{ where: 'flow', kind: 'type', text: flow.typeId }] : []);
  const auth = hits(texts, AUTH_WORD, ['flow', 'target']);
  if (ws.length && auth.length) {
    const evidence = buildEvidence(texts, CLASSES['auth-bypass'].sink, [...auth, ...ws]);
    out.push({
      class: 'auth-bypass',
      title: `Inconsistent WebSocket authentication on ${targetName}`,
      whyTest: `${/websocket/i.test(flowName) ? flowName : `WebSocket ${flowName || 'connection'}`} may authenticate differently from HTTP; check the handshake and every message for expired, missing or cross-user tokens.`,
      evidence,
      confidence: 'hypothesized',
      groupKey: `auth-bypass:${slug(targetName)}`,
    });
  }

  // 5. CSRF: the CSRF rule fired and the flow carries a cookie/session (or a weak token is observed).
  const session = hits(texts, SESSION);
  const weak = hits(texts, WEAK_TOKEN);
  if (session.length || weak.length) {
    const r = resource();
    const evidence = buildEvidence(texts, weak.length ? 'csrf-token' : CLASSES.csrf.sink, [...weak, ...session]);
    out.push({
      class: 'csrf',
      title: `CSRF on state-changing endpoint${r ? ` (${r})` : flowName ? ` (${flowName})` : ''}`,
      whyTest: weak.length
        ? `The anti-CSRF token is predictable (${cleanToken(WEAK_TOKEN.exec(weak[0].text)[0])}…); forge a request with a guessed token from another origin.`
        : `${flowName || 'The request'} relies on a session cookie; replay it cross-origin without a token and check SameSite.`,
      evidence,
      confidence: weak.length && hasFileEvidence(weak) ? 'observed-sink' : 'hypothesized',
      groupKey: `csrf:${slug(r || targetName)}`,
      // Attach to the CSRF rule's threat. Without one, only an observed weak token still counts.
      ruleMatch: (t) => CSRF_RULE.test(`${t.title} ${t.description}`) || (t.references || []).includes('CWE-352'),
      ruleOnly: !weak.length,
    });
  }

  // 6. File upload with no size/type control recorded.
  const up = hits(texts, UPLOAD, ['flow', 'target']);
  if (up.length) {
    const missing = hits(texts, UPLOAD_MISSING).concat(texts.filter((t) => t.kind === 'custom' && UPLOAD_CONTROL_KEY.test(t.key) && NEGATIVE.test(t.value.trim())));
    const controlled = !missing.length && texts.some((t) => UPLOAD_CONTROL.test(t.text));
    if (!controlled) {
      const evidence = buildEvidence(texts, CLASSES.upload.sink, up);
      out.push({
        class: 'upload',
        title: `Unrestricted file upload to ${targetName}`,
        whyTest: `No size or type check is recorded for uploads to ${targetName}; try an executable script, a polyglot file and an oversized file.`,
        evidence,
        confidence: hasFileEvidence(up) && /move_uploaded_file|multer|\$_FILES|IFormFile|MultipartFile/i.test(up.map((t) => t.text).join(' ')) ? 'observed-sink' : 'hypothesized',
        groupKey: `upload:${slug(targetName)}`,
      });
    }
  }

  return out;
}

/** Shorten a snippet to one clause for the why-test line. */
function oneClause(s) {
  const t = String(s || '').replace(/\s+/g, ' ').trim();
  return t.length > 90 ? `${t.slice(0, 89).trimEnd()}…` : t;
}

/** Categories a class explains (lower-case STRIDE names). */
export function classCategories(cls) {
  return CLASSES[cls]?.categories || [];
}

/** One-line fix for a class. */
export function classFix(cls) {
  return CLASSES[cls]?.fix || '';
}

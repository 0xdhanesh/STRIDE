// Shared, environment-neutral helpers (browser + Node).

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/** True when a key can be used safely as a plain-object property name. */
export function isSafeKey(key) {
  return typeof key === 'string' && key.length > 0 && key.length <= 256 && !FORBIDDEN_KEYS.has(key);
}

/** Copy only safe string keys/values from an untrusted object. */
export function safeStringMap(input) {
  const out = {};
  if (!input || typeof input !== 'object') return out;
  for (const [k, v] of Object.entries(input)) {
    if (!isSafeKey(k)) continue;
    if (v === null || v === undefined) continue;
    out[k] = String(v);
  }
  return out;
}

function randomBytes(n) {
  const bytes = new Uint8Array(n);
  const c = globalThis.crypto;
  if (c && typeof c.getRandomValues === 'function') c.getRandomValues(bytes);
  else for (let i = 0; i < n; i++) bytes[i] = Math.floor(Math.random() * 256);
  return bytes;
}

const ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';

/** Short random id, e.g. "el_k3j9x0q2ab". */
export function uid(prefix = 'id') {
  const bytes = randomBytes(10);
  let s = '';
  for (const b of bytes) s += ALPHABET[b % ALPHABET.length];
  return `${prefix}_${s}`;
}

export function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

/** Deterministic 32-bit string hash (FNV-1a). */
export function hashString(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** Seeded PRNG returning floats in [0, 1). */
export function seededRandom(seed) {
  let a = typeof seed === 'number' ? seed >>> 0 : hashString(String(seed));
  return function next() {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * CSV cell with quoting and spreadsheet formula-injection protection
 * (cells beginning with = + - @ tab or CR are prefixed with a quote).
 */
export function csvCell(value) {
  let s = String(value ?? '');
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  if (/[",\n\r]/.test(s)) s = `"${s.replace(/"/g, '""')}"`;
  return s;
}

export function nowIso() {
  return new Date().toISOString();
}

export function clamp(v, lo, hi) {
  return Math.max(lo, Math.min(hi, v));
}

/** Stable sort by a key function. */
export function sortBy(list, keyFn) {
  return list
    .map((item, index) => ({ item, index, key: keyFn(item) }))
    .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : a.index - b.index))
    .map((x) => x.item);
}

/** Natural compare for ids like "S1", "S7.1", "T13.2". */
export function naturalCompare(a, b) {
  return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
}

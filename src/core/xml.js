// Minimal, safe XML parser used for .tb7 / .tm7 import in both browser and Node.
// - No DTD processing and no custom entity expansion (XXE-safe).
// - Element names are reduced to their local name (namespace prefixes dropped);
//   attributes keep their qualified name.

const PREDEFINED = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };

export class XmlError extends Error {}

export function decodeEntities(text) {
  return text.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g, (m, ent) => {
    if (ent[0] === '#') {
      const code = ent[1] === 'x' || ent[1] === 'X' ? parseInt(ent.slice(2), 16) : parseInt(ent.slice(1), 10);
      if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return m;
      try {
        return String.fromCodePoint(code);
      } catch {
        return m;
      }
    }
    return Object.prototype.hasOwnProperty.call(PREDEFINED, ent) ? PREDEFINED[ent] : m;
  });
}

function localName(qname) {
  const i = qname.indexOf(':');
  return i >= 0 ? qname.slice(i + 1) : qname;
}

/**
 * Parse XML into { name, qname, attrs, children, text }.
 * `text` is the concatenated direct text content (entities decoded, CDATA kept verbatim).
 */
export function parseXml(xml, { maxDepth = 256, maxNodes = 2_000_000 } = {}) {
  if (typeof xml !== 'string') throw new XmlError('XML input must be a string');
  let s = xml;
  if (s.charCodeAt(0) === 0xfeff) s = s.slice(1);
  let i = 0;
  let nodes = 0;
  const root = { name: '#document', qname: '#document', attrs: {}, children: [], text: '' };
  const stack = [root];

  const fail = (msg) => {
    const line = s.slice(0, i).split('\n').length;
    throw new XmlError(`${msg} (line ${line})`);
  };

  while (i < s.length) {
    const lt = s.indexOf('<', i);
    const top = stack[stack.length - 1];
    if (lt === -1) {
      top.text += decodeEntities(s.slice(i));
      break;
    }
    if (lt > i) top.text += decodeEntities(s.slice(i, lt));
    i = lt;

    if (s.startsWith('<?', i)) {
      const end = s.indexOf('?>', i + 2);
      if (end === -1) fail('Unterminated processing instruction');
      i = end + 2;
    } else if (s.startsWith('<!--', i)) {
      const end = s.indexOf('-->', i + 4);
      if (end === -1) fail('Unterminated comment');
      i = end + 3;
    } else if (s.startsWith('<![CDATA[', i)) {
      const end = s.indexOf(']]>', i + 9);
      if (end === -1) fail('Unterminated CDATA section');
      top.text += s.slice(i + 9, end);
      i = end + 3;
    } else if (s.startsWith('<!', i)) {
      // DOCTYPE or other declaration: skip without interpreting (no entity expansion).
      let depth = 0;
      let j = i + 2;
      for (; j < s.length; j++) {
        const ch = s[j];
        if (ch === '[') depth++;
        else if (ch === ']') depth--;
        else if (ch === '>' && depth <= 0) break;
      }
      if (j >= s.length) fail('Unterminated declaration');
      i = j + 1;
    } else if (s[i + 1] === '/') {
      const end = s.indexOf('>', i);
      if (end === -1) fail('Unterminated end tag');
      const qname = s.slice(i + 2, end).trim();
      const node = stack.pop();
      if (!node || node === root || node.qname !== qname) fail(`Mismatched end tag </${qname}>`);
      i = end + 1;
    } else {
      // Start tag.
      let j = i + 1;
      const nameMatch = /^[^\s/>]+/.exec(s.slice(j, j + 512));
      if (!nameMatch) fail('Invalid tag name');
      const qname = nameMatch[0];
      j += qname.length;
      const attrs = {};
      for (;;) {
        while (j < s.length && /\s/.test(s[j])) j++;
        if (s[j] === '>' || s.startsWith('/>', j)) break;
        const am = /^([^\s=/>]+)\s*=\s*("([^"]*)"|'([^']*)')/.exec(s.slice(j, j + 1_000_000));
        if (!am) fail(`Malformed attribute in <${qname}>`);
        const key = am[1];
        if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
          attrs[key] = decodeEntities(am[3] !== undefined ? am[3] : am[4]);
        }
        j += am[0].length;
      }
      const selfClosing = s.startsWith('/>', j);
      i = j + (selfClosing ? 2 : 1);
      if (++nodes > maxNodes) fail('XML document has too many nodes');
      const node = { name: localName(qname), qname, attrs, children: [], text: '' };
      top.children.push(node);
      if (!selfClosing) {
        if (stack.length > maxDepth) fail('XML document is nested too deeply');
        stack.push(node);
      }
    }
  }
  if (stack.length !== 1) fail(`Unclosed element <${stack[stack.length - 1].qname}>`);
  const docEl = root.children[0];
  if (!docEl) throw new XmlError('XML document has no root element');
  return docEl;
}

export function child(node, name) {
  if (!node) return undefined;
  return node.children.find((c) => c.name === name);
}

export function children(node, name) {
  if (!node) return [];
  return name ? node.children.filter((c) => c.name === name) : node.children;
}

/** Text of a named child (trimmed) or of a path like "GenerationFilters/Include". */
export function childText(node, path, fallback = '') {
  let cur = node;
  for (const part of path.split('/')) {
    cur = child(cur, part);
    if (!cur) return fallback;
  }
  return isNil(cur) ? fallback : cur.text.trim();
}

export function isNil(node) {
  return !!node && Object.entries(node.attrs).some(([k, v]) => localName(k) === 'nil' && v === 'true');
}

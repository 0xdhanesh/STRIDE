// Knowledge base (template) model — the MTMT ".tb7" concept.
// Templates are plain JSON; KnowledgeBase wraps one with indexes and the
// hierarchy/attribute logic MTMT implements in KnowledgeBaseModel.

import { isSafeKey, naturalCompare } from './util.js';

export const ROOT = 'ROOT';

/** The seven fixed generic roots MTMT uses (§5.1 of the MTMT report). */
export const GENERIC = Object.freeze({
  PROCESS: 'GE.P',
  EXTERNAL: 'GE.EI',
  STORE: 'GE.DS',
  FLOW: 'GE.DF',
  LINE_BOUNDARY: 'GE.TB.L',
  BOX_BOUNDARY: 'GE.TB.B',
  ANNOTATION: 'GE.A',
});

export const GENERIC_IDS = Object.freeze(Object.values(GENERIC));

/** Shape used to draw each generic family. */
export const REPRESENTATION = Object.freeze({
  'GE.P': 'ellipse',
  'GE.EI': 'rectangle',
  'GE.DS': 'parallel',
  'GE.DF': 'flow',
  'GE.TB.L': 'line-boundary',
  'GE.TB.B': 'box-boundary',
  'GE.A': 'annotation',
});

const REPRESENTATION_TO_GENERIC = {
  ellipse: 'GE.P',
  rectangle: 'GE.EI',
  parallellines: 'GE.DS',
  parallel: 'GE.DS',
  line: 'GE.DF',
  flow: 'GE.DF',
  lineboundary: 'GE.TB.L',
  'line-boundary': 'GE.TB.L',
  borderboundary: 'GE.TB.B',
  'box-boundary': 'GE.TB.B',
  annotation: 'GE.A',
};

export const DEFAULT_THREAT_PROPERTIES = Object.freeze([
  { name: 'Title', label: 'Title', hidden: false, values: [] },
  { name: 'UserThreatCategory', label: 'Category', hidden: false, values: [] },
  { name: 'UserThreatDescription', label: 'Description', hidden: false, values: [] },
  { name: 'StateInformation', label: 'Justification', hidden: false, values: [] },
  { name: 'InteractionString', label: 'Interaction', hidden: false, values: [] },
  { name: 'Priority', label: 'Priority', hidden: false, values: ['High', 'Medium', 'Low'] },
]);

/** Threat columns that are built into every threat and cannot be redefined as custom ones. */
export const RESERVED_THREAT_PROPERTIES = new Set([
  'Title',
  'UserThreatCategory',
  'UserThreatShortDescription',
  'UserThreatDescription',
  'StateInformation',
  'InteractionString',
  'Priority',
]);

export class TemplateError extends Error {}

function str(v, max = 20000) {
  if (v === null || v === undefined) return '';
  return String(v).slice(0, max);
}

function normalizeAttribute(a) {
  const name = str(a?.name, 256).trim();
  if (!isSafeKey(name)) return null;
  const values = Array.isArray(a.values) ? a.values.map((v) => str(v, 1000)).filter((v) => v !== '') : [];
  return {
    name,
    label: str(a.label || name, 256),
    values,
    mode: a.mode === 'static' || a.mode === 'Static' ? 'static' : 'dynamic',
    inheritance: a.inheritance === 'new' || a.inheritance === 'New' ? 'new' : 'virtual',
  };
}

/**
 * Normalize an untrusted template object into the canonical shape.
 * Throws TemplateError on structural problems.
 */
export function normalizeTemplate(input) {
  if (!input || typeof input !== 'object') throw new TemplateError('Template must be an object');
  const manifest = input.manifest || {};
  const tpl = {
    format: 'stride-template',
    version: 1,
    manifest: {
      id: str(manifest.id || 'custom-template', 256),
      name: str(manifest.name || 'Custom template', 256),
      version: str(manifest.version || '1.0.0', 64),
      author: str(manifest.author || '', 256),
      description: str(manifest.description || '', 4000),
    },
    threatProperties: [],
    elements: [],
    categories: [],
    threatTypes: [],
  };

  const seenProps = new Set();
  const props = Array.isArray(input.threatProperties) && input.threatProperties.length ? input.threatProperties : DEFAULT_THREAT_PROPERTIES;
  for (const p of props) {
    const name = str(p?.name, 256).trim();
    if (!isSafeKey(name) || seenProps.has(name)) continue;
    seenProps.add(name);
    tpl.threatProperties.push({
      name,
      label: str(p.label || name, 256),
      hidden: !!p.hidden,
      values: Array.isArray(p.values) ? p.values.map((v) => str(v, 1000)).filter((v) => v !== '') : [],
    });
  }
  if (!seenProps.has('Priority')) tpl.threatProperties.push({ ...DEFAULT_THREAT_PROPERTIES[5], values: ['High', 'Medium', 'Low'] });

  const seenEls = new Set();
  for (const e of Array.isArray(input.elements) ? input.elements : []) {
    const id = str(e?.id, 256).trim();
    if (!id || !isSafeKey(id) || seenEls.has(id) || id === ROOT) continue;
    seenEls.add(id);
    const attrs = [];
    const seenAttr = new Set();
    for (const a of Array.isArray(e.attributes) ? e.attributes : []) {
      const na = normalizeAttribute(a);
      if (na && !seenAttr.has(na.name)) {
        seenAttr.add(na.name);
        attrs.push(na);
      }
    }
    tpl.elements.push({
      id,
      name: str(e.name || id, 256),
      parent: str(e.parent || ROOT, 256),
      description: str(e.description, 4000),
      hidden: !!e.hidden,
      representation: e.representation ? str(e.representation, 64) : undefined,
      attributes: attrs,
    });
  }
  for (const g of GENERIC_IDS) {
    if (!seenEls.has(g)) throw new TemplateError(`Template is missing generic element ${g}`);
  }

  const seenCat = new Set();
  for (const c of Array.isArray(input.categories) ? input.categories : []) {
    const id = str(c?.id, 64).trim();
    if (!id || !isSafeKey(id) || seenCat.has(id)) continue;
    seenCat.add(id);
    tpl.categories.push({ id, name: str(c.name || id, 256), description: str(c.description, 4000) });
  }

  const seenTT = new Set();
  for (const t of Array.isArray(input.threatTypes) ? input.threatTypes : []) {
    const id = str(t?.id, 256).trim();
    if (!id || !isSafeKey(id) || seenTT.has(id)) continue;
    seenTT.add(id);
    const properties = {};
    if (t.properties && typeof t.properties === 'object') {
      for (const [k, v] of Object.entries(t.properties)) if (isSafeKey(k) && v !== null && v !== undefined) properties[k] = str(v, 4000);
    }
    tpl.threatTypes.push({
      id,
      title: str(t.title || id, 1000),
      category: str(t.category, 64),
      description: str(t.description, 20000),
      mitigation: str(t.mitigation, 20000),
      include: str(t.include, 20000),
      exclude: str(t.exclude, 20000),
      priority: str(t.priority, 64),
      properties,
      references: Array.isArray(t.references) ? t.references.map((r) => str(r, 256)).filter(Boolean).slice(0, 32) : [],
      legacy: !!t.legacy,
    });
  }
  return tpl;
}

const kbCache = new WeakMap();

/** Get (cached) KnowledgeBase for a template object. */
export function kbFor(template) {
  let kb = kbCache.get(template);
  if (!kb) {
    kb = new KnowledgeBase(template);
    kbCache.set(template, kb);
  }
  return kb;
}

export class KnowledgeBase {
  constructor(template) {
    this.template = template;
    this.byId = new Map(template.elements.map((e) => [e.id, e]));
    this.categoryById = new Map(template.categories.map((c) => [c.id, c]));
    this.threatTypeById = new Map(template.threatTypes.map((t) => [t.id, t]));
    this._chain = new Map();
    this._attrs = new Map();
  }

  get manifest() {
    return this.template.manifest;
  }
  get threatTypes() {
    return this.template.threatTypes;
  }
  get categories() {
    return this.template.categories;
  }

  element(id) {
    return this.byId.get(id);
  }

  /** Type chain from the element up to ROOT, e.g. ['SE.DS.TMCore.SQL','GE.DS','ROOT']. */
  chain(id) {
    if (this._chain.has(id)) return this._chain.get(id);
    const out = [];
    const seen = new Set();
    let cur = id;
    while (cur && cur !== ROOT && !seen.has(cur)) {
      seen.add(cur);
      const el = this.byId.get(cur);
      if (!el) break;
      out.push(cur);
      cur = el.parent;
    }
    out.push(ROOT);
    this._chain.set(id, out);
    return out;
  }

  /** Is `id` equal to or derived from `ancestor`? */
  isDerived(id, ancestor) {
    if (ancestor === ROOT) return true;
    return this.chain(id).includes(ancestor);
  }

  /** The generic root (GE.*) for a type id, or undefined when unknown. */
  genericOf(id) {
    const chain = this.chain(id);
    for (const c of chain) if (GENERIC_IDS.includes(c)) return c;
    const top = chain.length >= 2 ? this.byId.get(chain[chain.length - 2]) : undefined;
    if (top?.representation) return REPRESENTATION_TO_GENERIC[top.representation.toLowerCase()];
    return undefined;
  }

  /**
   * Effective attributes for a type: parent attributes first, overridden by
   * same-named attributes further down the chain.
   */
  attributes(id) {
    if (this._attrs.has(id)) return this._attrs.get(id);
    const chain = this.chain(id).filter((c) => c !== ROOT).reverse();
    const map = new Map();
    for (const typeId of chain) {
      const el = this.byId.get(typeId);
      for (const a of el?.attributes || []) map.set(a.name, { ...a, definedBy: typeId });
    }
    const list = [...map.values()];
    this._attrs.set(id, list);
    return list;
  }

  attribute(id, name) {
    return this.attributes(id).find((a) => a.name === name);
  }

  /** Non-hidden concrete types for a generic family (generic first, then standard elements). */
  typesFor(generic) {
    return this.template.elements.filter((e) => !e.hidden && this.genericOf(e.id) === generic);
  }

  /** All boundary types (line and box), including subtypes. */
  boundaryTypeIds() {
    if (!this._boundaries) {
      this._boundaries = this.template.elements
        .filter((e) => {
          const g = this.genericOf(e.id);
          return g === GENERIC.LINE_BOUNDARY || g === GENERIC.BOX_BOUNDARY;
        })
        .map((e) => e.id);
    }
    return this._boundaries;
  }

  category(id) {
    return this.categoryById.get(id);
  }

  threatType(id) {
    return this.threatTypeById.get(id);
  }

  /** Threat types sorted by category order then natural id. */
  sortedThreatTypes() {
    const order = new Map(this.categories.map((c, i) => [c.id, i]));
    return [...this.threatTypes].sort((a, b) => (order.get(a.category) ?? 99) - (order.get(b.category) ?? 99) || naturalCompare(a.id, b.id));
  }

  /** Custom (non-reserved) threat properties defined by the template. */
  customThreatProperties() {
    return this.template.threatProperties.filter((p) => !RESERVED_THREAT_PROPERTIES.has(p.name) && !p.hidden);
  }

  priorities() {
    const p = this.template.threatProperties.find((x) => x.name === 'Priority');
    return p && p.values.length ? p.values : ['High', 'Medium', 'Low'];
  }

  /** All attribute names known anywhere in the template (used by rule validation). */
  allAttributeNames() {
    if (!this._allAttrNames) {
      const s = new Set();
      for (const e of this.template.elements) for (const a of e.attributes) s.add(a.name.toUpperCase());
      this._allAttrNames = s;
    }
    return this._allAttrNames;
  }

  stats() {
    const counts = {};
    for (const g of GENERIC_IDS) counts[g] = this.typesFor(g).length;
    return {
      elements: this.template.elements.length,
      categories: this.categories.length,
      threatTypes: this.threatTypes.length,
      byGeneric: counts,
    };
  }
}

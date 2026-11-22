// Import Microsoft Threat Modeling Tool templates (.tb7) into the STRIDE template format.
// See §4 of the MTMT report for the source schema.

import { GENERIC_IDS, ROOT, normalizeTemplate } from './kb.js';
import { child, childText, children, isNil, parseXml } from './xml.js';

export class Tb7Error extends Error {}

const bool = (v) => String(v).trim().toLowerCase() === 'true';

function values(node) {
  return children(child(node, 'AttributeValues') || child(node, 'Values'), 'Value')
    .filter((v) => !isNil(v))
    .map((v) => v.text.trim())
    .filter((v) => v !== '');
}

function elementType(node, isGeneric) {
  const id = childText(node, 'ID') || childText(node, 'Id');
  const parent = childText(node, 'ParentElement') || childText(node, 'ParentId');
  return {
    id,
    name: childText(node, 'Name') || id,
    parent: isGeneric || !parent ? ROOT : parent,
    description: childText(node, 'Description'),
    hidden: bool(childText(node, 'Hidden', 'false')),
    representation: childText(node, 'Representation') || undefined,
    attributes: children(child(node, 'Attributes'), 'Attribute').map((a) => ({
      name: childText(a, 'Name'),
      label: childText(a, 'DisplayName') || childText(a, 'Name'),
      mode: childText(a, 'Mode').toLowerCase() === 'static' ? 'static' : 'dynamic',
      inheritance: childText(a, 'Inheritance').toLowerCase() === 'new' ? 'new' : 'virtual',
      values: values(a),
    })),
  };
}

/** Parse .tb7 XML text into a normalized STRIDE template. */
export function parseTb7(xmlText) {
  let root;
  try {
    root = parseXml(xmlText);
  } catch (e) {
    throw new Tb7Error(`Not a valid .tb7 file: ${e.message}`);
  }
  if (root.name !== 'KnowledgeBase') throw new Tb7Error(`Not a .tb7 knowledge base (root element is <${root.qname}>)`);
  const m = child(root, 'Manifest');
  const meta = child(root, 'ThreatMetaData');
  const threatProperties = children(child(meta, 'PropertiesMetaData'), 'ThreatMetaDatum').map((d) => ({
    name: childText(d, 'Name'),
    label: childText(d, 'Label') || childText(d, 'Name'),
    hidden: bool(childText(d, 'HideFromUI', 'false')),
    values: values(d),
  }));

  const generic = children(child(root, 'GenericElements'), 'ElementType').map((n) => elementType(n, true));
  const standard = children(child(root, 'StandardElements'), 'ElementType').map((n) => elementType(n, false));
  const missing = GENERIC_IDS.filter((g) => !generic.some((e) => e.id === g));
  if (missing.length) throw new Tb7Error(`Template is missing generic elements: ${missing.join(', ')}`);

  const categories = children(child(root, 'ThreatCategories'), 'ThreatCategory').map((c) => ({
    id: childText(c, 'Id'),
    name: childText(c, 'Name'),
    description: childText(c, 'ShortDescription') || childText(c, 'LongDescription'),
  }));

  const threatTypes = children(child(root, 'ThreatTypes'), 'ThreatType').map((t) => {
    const include = childText(t, 'GenerationFilters/Include');
    const properties = {};
    let description = childText(t, 'Description');
    let priority = '';
    for (const d of children(child(t, 'PropertiesMetaData'), 'ThreatMetaDatum')) {
      const name = childText(d, 'Name');
      const vals = values(d);
      const last = vals[vals.length - 1];
      if (!name || last === undefined) continue;
      if (name === 'UserThreatDescription') description = last || description;
      else if (name === 'Priority') priority = last;
      else if (name !== 'UserThreatShortDescription') properties[name] = last;
    }
    return {
      id: childText(t, 'Id'),
      title: childText(t, 'ShortTitle'),
      category: childText(t, 'Category'),
      description,
      include,
      exclude: childText(t, 'GenerationFilters/Exclude'),
      priority,
      properties,
      // MTMT's "(v3)" migration buckets use `source is 'ROOT'`; keep them but never generate.
      legacy: /^\s*source\s+is\s+'ROOT'\s*$/i.test(include),
    };
  });

  return normalizeTemplate({
    manifest: {
      id: m?.attrs.id || 'imported-tb7',
      name: m?.attrs.name || 'Imported template',
      version: m?.attrs.version || '',
      author: m?.attrs.author || '',
      description: 'Imported from a Microsoft Threat Modeling Tool .tb7 template.',
    },
    threatProperties,
    elements: [...generic, ...standard],
    categories,
    threatTypes,
  });
}

/** Detect template format from text and parse (.tb7 XML or STRIDE JSON). */
export function parseTemplateText(text) {
  const trimmed = String(text).trimStart();
  if (trimmed.startsWith('<')) return parseTb7(text);
  const json = JSON.parse(text);
  if (json.format === 'stride-model') return normalizeTemplate(json.template);
  return normalizeTemplate(json);
}

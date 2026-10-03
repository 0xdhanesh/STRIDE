// Local-only Microsoft Threat Modeling Tool import. Native XML parsing does
// not load resources; DTD/entity declarations are rejected before parsing.
import { STENCILS, STRIDE, PRIORITIES, defaultProps } from './stencils.js';
import { newModel } from './store.js';

const XSI = 'http://www.w3.org/2001/XMLSchema-instance';
const SERIALIZATION = 'http://schemas.microsoft.com/2003/10/Serialization/';
const NIL = '00000000-0000-0000-0000-000000000000';
const norm = (s) => String(s).toLowerCase().replace(/[^a-z0-9]/g, '');
const idKey = (s) => /^[{]?[0-9a-f-]{36}[}]?$/i.test(s) ? s.replace(/[{}]/g, '').toLowerCase() : s;
const TYPES = new Map(Object.entries({ 'GE.P': 'process', 'GE.EI': 'external', 'GE.DS': 'store', 'GE.DF': 'flow', 'GE.TB.B': 'boundary', 'GE.TB.L': 'boundaryLine', 'GE.A': 'note' }));
const SHAPES = new Map(Object.entries({ StencilEllipse: 'process', StencilRectangle: 'external', StencilParallelLines: 'store', BorderBoundary: 'boundary', Connector: 'flow', ConnectorBoundary: 'boundaryLine', Annotation: 'note' }));

// Exact catalogue names and explicit aliases only; never first-word/fuzzy matching.
const ALIASES = {
  process: { Process: 'Generic Process', WebApp: 'Web Application', WebAPI: 'Web API / Service', WebService: 'Web API / Service', AzureFunction: 'Serverless Function', WindowsService: 'Background Worker' },
  external: { ExternalInteractor: 'Generic External Entity', ExternalEntity: 'Generic External Entity', User: 'Human User' },
  store: { DataStore: 'Generic Data Store', SQLServer: 'SQL Database', AzureSQLDatabase: 'SQL Database', File: 'File System', AzureBlobStorage: 'Blob / Object Storage' },
  flow: { DataFlow: 'Generic Data Flow', SQL: 'SQL / DB Protocol', TCP: 'Binary / Custom', UDP: 'Binary / Custom', WSS: 'WebSocket Secure (wss://)', WS: 'WebSocket (ws://)' },
  boundary: { TrustBoundary: 'Generic Trust Boundary', TrustBorder: 'Generic Trust Boundary' },
  boundaryLine: { TrustBoundary: 'Generic Trust Boundary', TrustLine: 'Generic Trust Boundary' },
  note: { Annotation: '', Note: '' },
};
const PROPERTY_ALIASES = {
  encrypted: ['Encrypted', 'Provides Confidentiality'], integrity: ['Provides Integrity', 'Integrity Protected'],
  encryptedAtRest: ['Encrypted At Rest'], storesCredentials: ['Stores Credentials', 'Stores Secrets'],
  storesPII: ['Stores PII', 'Stores Sensitive Data'], storesLogs: ['Stores Logs'],
  validatesInput: ['Input Validation'], logsSecurityEvents: ['Audit Logging'],
  sanitizesOutput: ['Sanitizes Output', 'Encodes Output'], handlesSecrets: ['Handles Secrets'],
};
const VALUE_ALIASES = {
  authentication: { Cookie: 'Cookie / Session', Session: 'Cookie / Session', OAuth: 'Token (OAuth / JWT)', JWT: 'Token (OAuth / JWT)', Certificate: 'mTLS / Certificate', WindowsAuthentication: 'Kerberos / Windows' },
  codeType: { Unmanaged: 'Unmanaged (C/C++)', Interpreted: 'Interpreted / Script' },
  runningAs: { System: 'System / root', Root: 'System / root', StandardUser: 'Standard user', LowPrivilege: 'Low privilege / sandboxed' },
};
const lookup = (entries, name) => Object.entries(entries || {}).find(([key]) => norm(key) === norm(name))?.[1];
const commonProperty = (p) => ['name', 'annotation', 'notes', 'description', 'outofscope', 'reasonforoutofscope'].includes(norm(p.name));

export function mapTM7Stencil(genericTypeId, typeId, header, shape, collection) {
  let type = TYPES.get(genericTypeId), inferred = false;
  if (!type) {
    const prefix = [...TYPES].find(([key]) => typeId.startsWith(key.replace('GE.', 'SE.') + '.'));
    type = prefix?.[1] || SHAPES.get(shape) || (collection === 'Lines' ? 'flow' : 'note');
    inferred = true;
  }
  const candidates = [header, typeId.split('.').pop()].filter(Boolean);
  for (const candidate of candidates) {
    const exact = STENCILS[type].subtypes.find((s) => norm(s) === norm(candidate));
    const alias = lookup(ALIASES[type], candidate);
    if (exact !== undefined || alias !== undefined) return { type, subtype: exact ?? alias, mapping: inferred ? 'inferred' : exact !== undefined ? 'exact' : 'alias' };
  }
  const generic = !candidates.length || candidates.every((c) => c === genericTypeId || c === genericTypeId.split('.').pop());
  return { type, subtype: STENCILS[type].subtypes[0] || '', mapping: inferred ? 'unmapped' : generic ? 'generic' : 'unmapped' };
}

export function parseTM7(xmlText) {
  if (typeof xmlText !== 'string' || /<!\s*(?:DOCTYPE|ENTITY)\b/i.test(xmlText)) throw new Error('TMT import does not allow DTD or entity declarations.');
  const doc = new DOMParser().parseFromString(xmlText, 'application/xml');
  if (doc.getElementsByTagNameNS('*', 'parsererror').length) throw new Error('Could not parse the .tm7 file (invalid XML).');
  if (doc.documentElement?.localName !== 'ThreatModel') throw new Error('Not a Microsoft TMT ThreatModel document.');
  const references = new Map();
  for (const el of doc.getElementsByTagNameNS('*', '*')) {
    const id = el.getAttributeNS(SERIALIZATION, 'Id');
    if (!id) continue;
    if (references.has(id)) throw new Error(`TMT import has duplicate XML reference ID "${id}".`);
    references.set(id, el);
  }
  const deref = (el) => {
    const visited = new Set();
    while (el?.getAttributeNS(SERIALIZATION, 'Ref')) {
      const ref = el.getAttributeNS(SERIALIZATION, 'Ref');
      if (visited.has(ref) || !references.has(ref)) throw new Error(`TMT import has an unresolved or cyclic XML reference "${ref}".`);
      visited.add(ref); el = references.get(ref);
    }
    return el;
  };
  const children = (el) => [...(deref(el)?.children || [])];
  const kids = (el, name) => children(el).filter((c) => c.localName === name);
  const kid = (el, name) => deref(kids(el, name)[0]) || null;
  const value = (el, name) => kid(el, name)?.textContent ?? '';
  const txt = (el, name) => value(el, name).trim();
  const readProperties = (el) => {
    const properties = []; let header = '';
    for (const original of children(kid(el, 'Properties'))) {
      const p = deref(original), name = txt(p, 'DisplayName') || txt(p, 'Key') || txt(p, 'Name');
      const attributeType = p.getAttributeNS(XSI, 'type') || '';
      if (attributeType.endsWith('HeaderDisplayAttribute')) { header ||= name; continue; }
      const v = kid(p, 'Value'), selected = kid(p, 'SelectedIndex');
      const options = children(v).map((o) => deref(o).textContent.trim());
      const index = selected ? selected.textContent.trim() : null;
      const validIndex = index !== null && /^\d+$/.test(index) && Number(index) < options.length;
      properties.push({ name, value: selected ? (validIndex ? options[Number(index)] : '') : (v?.textContent ?? ''),
        attributeType, ...(selected ? { selectedIndex: index, options, invalidSelection: !validIndex } : {}) });
    }
    return { header, properties };
  };
  const prop = (properties, ...names) => names.map((name) => properties.find((p) => norm(name) === norm(p.name))).find(Boolean)?.value ?? '';
  const model = newModel(); model.diagrams = []; model.importWarnings = [];
  model.tm7 = { sourceXML: xmlText, importedAt: new Date().toISOString() };
  const warn = (code, text, diagramId = null, elementId = null, threatId = null) => {
    model.importWarnings.push({ code, text: `TMT import: ${text}`, diagramId, elementId, ...(threatId ? { threatIds: [threatId] } : {}) });
  };
  const usedIds = new Set(); let sequence = 0;
  const allocate = (original, label, diagramId = null) => {
    let id = original;
    if (!id || idKey(id) === NIL || usedIds.has(idKey(id))) {
      do { id = `tm7-${label}-${++sequence}`; } while (usedIds.has(idKey(id)));
      warn('remapped-id', `${label} ID "${original || '(missing)'}" was replaced with "${id}".`, diagramId);
    }
    usedIds.add(idKey(id)); return id;
  };
  const register = (map, original, entry) => {
    if (!original || idKey(original) === NIL) return;
    const key = idKey(original), entries = map.get(key) || [];
    if (!entries.includes(entry)) entries.push(entry);
    map.set(key, entries);
  };
  const unique = (map, id) => { const found = map.get(idKey(id)); return found?.length === 1 ? found[0] : null; };
  const meta = kid(doc.documentElement, 'MetaInformation');
  for (const [key, name] of Object.entries({ title: 'ThreatModelName', owner: 'Owner', reviewer: 'Reviewer', contributors: 'Contributors', description: 'HighLevelSystemDescription', assumptions: 'Assumptions', dependencies: 'ExternalDependencies' })) {
    model.meta[key] = value(meta, name) || (key === 'title' ? 'Imported TMT model' : '');
  }
  const diagramRefs = new Map(), contexts = [];
  for (const originalSurface of kids(kid(doc.documentElement, 'DrawingSurfaceList'), 'DrawingSurfaceModel')) {
    const surface = deref(originalSurface), sp = readProperties(surface), originalId = txt(surface, 'Guid');
    const d = { id: allocate(originalId, 'diagram'), name: txt(surface, 'Header') || prop(sp.properties, 'Name') || `Diagram ${model.diagrams.length + 1}`, elements: [], tm7: { originalId, properties: sp.properties } };
    model.diagrams.push(d); register(diagramRefs, originalId, d);
    for (const p of sp.properties) if (norm(p.name) !== 'name') warn('unmapped-diagram-property', `Diagram "${d.name}": property "${p.name}" was preserved without a field mapping.`, d.id);
    const refs = new Map(), lines = [];
    contexts.push({ d, refs });
    for (const collection of ['Borders', 'Lines']) for (const entry of children(kid(surface, collection))) {
      const v = kid(entry, 'Value') || deref(entry), entryKey = txt(entry, 'Key');
      const { properties, header } = readProperties(v), genericTypeId = txt(v, 'GenericTypeId'), typeId = txt(v, 'TypeId');
      const shape = (v.getAttributeNS(XSI, 'type') || '').split(':').pop();
      const mapped = mapTM7Stencil(genericTypeId, typeId, header, shape, collection);
      const originalId = txt(v, 'Guid') || entryKey;
      const el = { id: allocate(originalId, 'element', d.id), type: mapped.type, subtype: mapped.subtype,
        name: prop(properties, 'Name', 'Annotation') || header || mapped.subtype || 'Unmapped TMT element',
        props: { ...defaultProps(mapped.type), ...(STENCILS[mapped.type].subtypeDefaults?.[mapped.subtype] || {}) }, style: {},
        outOfScope: /^(?:true|yes)$/i.test(prop(properties, 'Out Of Scope').trim()), outOfScopeReason: prop(properties, 'Reason For Out Of Scope'),
        notes: prop(properties, 'Notes', 'Description'),
        tm7: { originalId, entryKey, genericTypeId, typeId, header, shape, mapping: mapped.mapping, properties },
      };
      d.elements.push(el); register(refs, originalId, el); register(refs, entryKey, el);
      if (['unmapped', 'inferred'].includes(mapped.mapping)) warn('unmapped-stencil', `"${el.name}": type "${header || typeId || genericTypeId || shape || '(missing)'}" needs review; represented as ${mapped.subtype || STENCILS[mapped.type].label}.`, d.id, el.id);
      const assigned = new Set();
      const scopeValue = prop(properties, 'Out Of Scope').trim();
      if (properties.filter((p) => norm(p.name) === 'outofscope').length > 1) el.outOfScope = false;
      if (scopeValue && !/^(true|false|yes|no)$/i.test(scopeValue)) warn('unmapped-value', `"${el.name}": unrecognized scope value "${scopeValue}"; kept in scope for review.`, d.id, el.id);
      const propertyNames = new Set();
      for (const p of properties) {
        if (propertyNames.has(norm(p.name))) warn('duplicate-property', `"${el.name}": duplicate property "${p.name}" needs review; all original values are preserved.`, d.id, el.id);
        propertyNames.add(norm(p.name));
        if (p.invalidSelection && commonProperty(p)) warn('unmapped-value', `"${el.name}": invalid selection for "${p.name}". Original choices are preserved.`, d.id, el.id);
        if (commonProperty(p)) continue;
        const definition = STENCILS[el.type].props.find((q) => [q.key, q.label, ...(PROPERTY_ALIASES[q.key] || [])].some((name) => norm(name) === norm(p.name)));
        if (!definition) { warn('unmapped-property', `"${el.name}": property "${p.name || '(unnamed)'}" was preserved without a security-property mapping.`, d.id, el.id); continue; }
        const raw = p.value.trim(), normalized = norm(raw);
        let mappedValue = definition.options.find((o) => norm(o) === normalized) ?? lookup(VALUE_ALIASES[definition.key], raw);
        if (definition.options.includes('Yes') && /^(true|false)$/i.test(raw)) mappedValue = normalized === 'true' ? 'Yes' : 'No';
        if (!raw && !p.invalidSelection) mappedValue = 'Not Selected';
        if (assigned.has(definition.key) || !definition.options.includes(mappedValue) || p.invalidSelection) {
          el.props[definition.key] = 'Not Selected';
          warn('unmapped-value', `"${el.name}": ambiguous or unsupported value for "${p.name}"; left Not Selected. Original value is preserved.`, d.id, el.id);
        } else el.props[definition.key] = mappedValue;
        assigned.add(definition.key);
      }
      const num = (field, fallback, positive = false) => {
        const raw = txt(v, field), number = Number(raw);
        if (!raw) return fallback;
        if (Number.isFinite(number) && (!positive || number > 0)) return number;
        warn('invalid-geometry', `"${el.name}": invalid ${field} "${raw}"; used ${fallback}.`, d.id, el.id); return fallback;
      };
      if (el.type === 'flow' || el.type === 'boundaryLine') {
        Object.assign(el, { sourceId: null, targetId: null, x1: num('SourceX', 0), y1: num('SourceY', 0), x2: num('TargetX', 0), y2: num('TargetY', 0), bend: 0 });
        el.tm7.sourceId = txt(v, 'SourceGuid'); el.tm7.targetId = txt(v, 'TargetGuid');
        if (txt(v, 'HandleX') && txt(v, 'HandleY')) {
          const hx = num('HandleX', (el.x1 + el.x2) / 2), hy = num('HandleY', (el.y1 + el.y2) / 2);
          const dx = el.x2 - el.x1, dy = el.y2 - el.y1, len = Math.hypot(dx, dy) || 1;
          el.bend = (((hx - (el.x1 + el.x2) / 2) * -dy + (hy - (el.y1 + el.y2) / 2) * dx) / len) / 2;
        }
        lines.push(el);
      } else Object.assign(el, { x: num('Left', 0), y: num('Top', 0), w: num('Width', STENCILS[el.type].size?.w || 160, true), h: num('Height', STENCILS[el.type].size?.h || 80, true) });
    }
    for (const el of lines) for (const field of ['sourceId', 'targetId']) {
      const original = el.tm7[field]; if (!original || idKey(original) === NIL) continue;
      const endpoint = unique(refs, original);
      if (endpoint && ['process', 'external', 'store'].includes(endpoint.type)) el[field] = endpoint.id;
      else warn('unmapped-endpoint', `"${el.name}": ${field === 'sourceId' ? 'source' : 'target'} "${original}" is missing, ambiguous or unsupported; connector coordinates were retained.`, d.id, el.id);
    }
  }
  if (!model.diagrams.length) throw new Error('No diagrams found in the .tm7 file.');
  if (kid(doc.documentElement, 'KnowledgeBase') || kid(doc.documentElement, 'Template')) warn('unmapped-template', 'The embedded TMT threat template was retained in the original XML. Imported findings are preserved; new STRIDE findings use the built-in rules.');

  const knownThreatProperties = ['Title', 'UserThreatCategory', 'UserThreatDescription', 'UserThreatShortDescription', 'StateInformation', 'InteractionString', 'Priority', 'Severity', 'State', 'Owner', 'AssignedTo', 'Notes', 'Mitigation', 'UserThreatMitigation', 'MitigationDescription'];
  for (const inst of kids(doc.documentElement, 'ThreatInstances')) for (const entry of children(inst)) {
    const v = kid(entry, 'Value') || deref(entry), { properties } = readProperties(v);
    const get = (...names) => prop(properties, ...names) || names.map((name) => value(v, name)).find(Boolean) || '';
    const id = model.nextThreatId++, key = `tm7:${id}`;
    const originalDiagram = txt(v, 'DrawingSurfaceGuid'), originalFlow = txt(v, 'FlowGuid'), originalTarget = txt(v, 'TargetGuid');
    let d = unique(diagramRefs, originalDiagram);
    if (!d && !originalDiagram && originalFlow) {
      const matching = contexts.filter((c) => unique(c.refs, originalFlow)?.type === 'flow');
      if (matching.length === 1) d = matching[0].d;
    }
    const refs = contexts.find((c) => c.d === d)?.refs || new Map();
    const candidateFlow = unique(refs, originalFlow), flow = candidateFlow?.type === 'flow' ? candidateFlow : null;
    const target = unique(refs, originalTarget);
    const originalState = get('State').trim(), originalCategory = get('UserThreatCategory').trim(), originalPriority = get('Severity', 'Priority').trim();
    const category = STRIDE.find((c) => norm(c.key) === norm(originalCategory) || norm(c.name) === norm(originalCategory))?.key;
    const status = new Map([['notstarted', 'open'], ['autogenerated', 'open'], ['needsinvestigation', 'open'], ['open', 'open'], ['mitigated', 'mitigated'], ['accepted', 'accepted'], ['notapplicable', 'not-applicable']]).get(norm(originalState));
    const priority = PRIORITIES.find((p) => norm(p) === norm(originalPriority));
    const missingFlow = originalFlow && idKey(originalFlow) !== NIL && !flow;
    const missingTarget = originalTarget && idKey(originalTarget) !== NIL && !target;
    const t = model.threats[key] = { id, key, auto: false, customText: true, ruleId: txt(v, 'TypeId'),
      diagramId: d?.id || null, flowId: flow?.id || null, elementId: target?.id || flow?.targetId || null,
      category: category || 'S', priority: priority || 'Medium', severity: priority || 'Medium',
      state: originalState || 'Not Started', status: status || 'open',
      title: get('Title') || 'Imported threat', description: get('UserThreatDescription', 'UserThreatShortDescription'),
      justification: get('StateInformation'), notes: get('Notes'), owner: get('Owner', 'AssignedTo'),
      mitigation: get('Mitigation', 'UserThreatMitigation', 'MitigationDescription'), mitigationHint: '',
      interaction: get('InteractionString') || flow?.name || target?.name || 'Unlinked imported threat',
      orphan: !d || !!missingFlow || !!missingTarget, created: txt(v, 'CreatedAt') || model.tm7.importedAt, modified: txt(v, 'ModifiedAt') || null,
      tm7: { originalId: txt(entry, 'Key') || txt(v, 'Id'), originalDiagram, originalFlow, originalTarget, originalState, originalCategory, originalPriority, properties },
    };
    if (!category) warn('unmapped-category', `Threat #${id}: category "${originalCategory || '(missing)'}" is unmapped; temporarily grouped under Spoofing. Review its category.`, t.diagramId, null, id);
    if (!status) warn('unmapped-status', `Threat #${id}: state "${originalState || '(missing)'}" is unmapped; left Open.`, t.diagramId, null, id);
    if (!priority) warn('unmapped-priority', `Threat #${id}: priority "${originalPriority || '(missing)'}" is unmapped; left Medium.`, t.diagramId, null, id);
    if (t.orphan) warn('unmapped-threat-reference', `Threat #${id} has a missing or ambiguous diagram/interaction reference. Its review data was retained.`, t.diagramId, null, id);
    const propertyNames = new Set();
    for (const p of properties) {
      if (propertyNames.has(norm(p.name)) || p.invalidSelection) warn('ambiguous-threat-property', `Threat #${id}: duplicate or invalid property "${p.name}" needs review; all original values are preserved.`, t.diagramId, null, id);
      propertyNames.add(norm(p.name));
    }
    for (const p of properties) if (!knownThreatProperties.some((name) => norm(name) === norm(p.name))) warn('unmapped-threat-property', `Threat #${id}: property "${p.name}" was preserved without a field mapping.`, t.diagramId, null, id);
  }
  const elementCount = model.diagrams.reduce((n, d) => n + d.elements.length, 0);
  model.importNote = `Imported ${model.diagrams.length} diagram(s), ${elementCount} element(s) and ${Object.keys(model.threats).length} threat(s) from TMT. ${model.importWarnings.length} import warning(s); review Validation messages. Original XML is retained in the local model.`;
  return model;
}

// High-level operations shared by the CLI and the MCP server.
// Every function takes a model object and plain arguments and returns JSON-friendly data.

import {
  GENERIC,
  GENERIC_IDS,
  ModelError,
  THREAT_STATE_LABELS,
  addDiagram,
  addElement,
  addNote,
  addUserThreat,
  applyTemplate,
  displayTitle,
  elementIndex,
  explainFlow,
  filterThreats,
  generateThreats,
  kbFor,
  kbOf,
  levelsAtLeast,
  normalizeSignalLevel,
  normalizeState,
  normalizeTemplate,
  stakeholderSummary,
  rectOf,
  removeDiagram,
  removeElements,
  renameDiagram,
  renderDiagramSvg,
  renderExecutiveReport,
  renderHtmlReport,
  renderMarkdownReport,
  requireDiagram,
  requireElement,
  resolveFont,
  resolveTypeId,
  summarize,
  syncModel,
  threatsToCsv,
  unionRect,
  updateElement,
  updateThreat,
  validateModel,
  validateRule,
} from '../core/index.js';

const FAMILY_NAMES = {
  'GE.P': 'process',
  'GE.EI': 'external',
  'GE.DS': 'store',
  'GE.DF': 'flow',
  'GE.TB.L': 'line-boundary',
  'GE.TB.B': 'box-boundary',
  'GE.A': 'annotation',
};

export function listTypes(template, { family } = {}) {
  const kb = kbFor(normalizeTemplate(template));
  const generic = family ? resolveTypeId(kb, family) : undefined;
  if (family && !GENERIC_IDS.includes(generic)) throw new ModelError(`Unknown family '${family}'. Use one of: ${Object.values(FAMILY_NAMES).join(', ')}`);
  return kb.template.elements
    .filter((e) => !e.hidden && (!generic || kb.genericOf(e.id) === generic))
    .map((e) => ({
      id: e.id,
      name: e.name,
      family: FAMILY_NAMES[kb.genericOf(e.id)],
      parent: e.parent,
      attributes: kb.attributes(e.id).map((a) => ({ name: a.name, label: a.label, values: a.values, fixed: a.mode === 'static' })),
    }));
}

export function describeElement(model, el, idx = elementIndex(model)) {
  const kb = kbOf(model);
  const out = {
    id: el.id,
    name: el.name,
    type: el.typeId,
    typeName: kb.element(el.typeId)?.name || el.typeId,
    family: FAMILY_NAMES[el.generic],
  };
  if (el.outOfScope) {
    out.outOfScope = true;
    if (el.outOfScopeReason) out.outOfScopeReason = el.outOfScopeReason;
  }
  if (el.generic === GENERIC.FLOW) {
    out.source = el.source ? { id: el.source, name: idx.get(el.source)?.element.name } : null;
    out.target = el.target ? { id: el.target, name: idx.get(el.target)?.element.name } : null;
  }
  if (el.w !== undefined) out.rect = { x: el.x, y: el.y, w: el.w, h: el.h };
  else if (el.generic === GENERIC.LINE_BOUNDARY) out.line = { x0: el.x0, y0: el.y0, x1: el.x1, y1: el.y1, bend: el.bend };
  if (Object.keys(el.props || {}).length) out.props = el.props;
  if (Object.keys(el.custom || {}).length) out.custom = el.custom;
  if (el.evidence?.length) out.evidence = el.evidence;
  return out;
}

export function describeModel(model, { includeElements = true } = {}) {
  const idx = elementIndex(model);
  return {
    file: undefined,
    meta: model.meta,
    template: model.template.manifest,
    settings: model.settings,
    summary: summarize(model),
    diagrams: model.diagrams.map((d) => ({
      id: d.id,
      name: d.name,
      elements: includeElements ? d.elements.map((e) => describeElement(model, e, idx)) : d.elements.length,
    })),
  };
}

/** Parse "k=v" strings or an object into a plain object. */
export function parsePairs(pairs) {
  if (!pairs) return {};
  if (!Array.isArray(pairs) && typeof pairs === 'object') return { ...pairs };
  const out = {};
  for (const p of [].concat(pairs)) {
    const i = String(p).indexOf('=');
    if (i <= 0) throw new ModelError(`Expected key=value, got '${p}'`);
    out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  }
  return out;
}

/**
 * Add an element. For box boundaries, `around: [refs]` sizes the box to
 * enclose those elements; for line boundaries `points: [x0,y0,x1,y1]`.
 */
export function opAddElement(model, args) {
  const kb = kbOf(model);
  const typeId = resolveTypeId(kb, args.type);
  if (!typeId) throw new ModelError(`Unknown element type '${args.type}'. Run 'stride types' to list types.`);
  const generic = kb.genericOf(typeId);
  const spec = {
    type: typeId,
    name: args.name,
    x: args.x,
    y: args.y,
    w: args.w,
    h: args.h,
    bend: args.bend,
    props: parsePairs(args.props),
    custom: parsePairs(args.custom),
    outOfScope: args.outOfScope,
    outOfScopeReason: args.outOfScopeReason,
  };
  for (const k of Object.keys(spec)) if (spec[k] === undefined) delete spec[k];
  const diagram = requireDiagram(model, args.diagram);
  if (generic === GENERIC.FLOW) {
    if (!args.from || !args.to) throw new ModelError('Data flows need both --from and --to elements');
    spec.source = args.from;
    spec.target = args.to;
  }
  if (generic === GENERIC.BOX_BOUNDARY && args.around?.length) {
    const rects = [].concat(args.around).map((r) => rectOf(requireElement(model, r, diagram.id).element));
    const pad = Number.isFinite(Number(args.padding)) ? Number(args.padding) : 36;
    const u = unionRect(rects);
    Object.assign(spec, { x: u.x - pad, y: u.y - pad - 14, w: u.w + pad * 2, h: u.h + pad * 2 + 14 });
  }
  if (generic === GENERIC.LINE_BOUNDARY) {
    const pts = Array.isArray(args.points) ? args.points : String(args.points || '').split(',').filter(Boolean);
    if (pts.length !== 4 || pts.some((p) => !Number.isFinite(Number(p)))) {
      throw new ModelError('Line (arc) boundaries need --points x0,y0,x1,y1 so the tool can tell which flows cross them');
    }
    [spec.x0, spec.y0, spec.x1, spec.y1] = pts.map(Number);
  }
  const el = addElement(model, diagram.id, spec);
  return describeElement(model, el);
}

export function opUpdateElement(model, args) {
  const patch = {};
  for (const k of ['name', 'type', 'x', 'y', 'w', 'h', 'x0', 'y0', 'x1', 'y1', 'bend', 'order']) if (args[k] !== undefined) patch[k] = args[k];
  if (args.from !== undefined) patch.source = args.from;
  if (args.to !== undefined) patch.target = args.to;
  if (args.outOfScope !== undefined) patch.outOfScope = args.outOfScope;
  if (args.outOfScopeReason !== undefined) patch.outOfScopeReason = args.outOfScopeReason;
  if (args.props) patch.props = parsePairs(args.props);
  if (args.custom) patch.custom = parsePairs(args.custom);
  const el = updateElement(model, args.element, patch);
  return describeElement(model, el);
}

export function opRemoveElements(model, { elements, cascade }) {
  const refs = [].concat(elements || []);
  if (!refs.length) throw new ModelError('No elements given');
  const ids = refs.map((r) => requireElement(model, r).element.id);
  return { removed: removeElements(model, ids, { cascade: !!cascade }) };
}

export function opDiagram(model, { action, diagram, name }) {
  if (action === 'add') return addDiagram(model, name);
  if (action === 'rename') return renameDiagram(model, diagram, name);
  if (action === 'remove') return removeDiagram(model, diagram);
  if (action === 'list') return model.diagrams.map((d) => ({ id: d.id, name: d.name, elements: d.elements.length }));
  throw new ModelError(`Unknown diagram action '${action}'`);
}

export function threatView(model, t) {
  const kb = kbOf(model);
  return {
    id: t.id,
    type: t.typeId,
    category: kb.category(t.category)?.name || t.category,
    title: t.title,
    displayTitle: displayTitle(t),
    state: THREAT_STATE_LABELS[t.state] || t.state,
    priority: t.priority,
    interaction: t.interaction,
    diagram: model.diagrams.find((d) => d.id === t.diagramId)?.name,
    description: t.description,
    mitigation: t.mitigation || undefined,
    justification: t.justification || undefined,
    references: t.references?.length ? t.references : undefined,
    userDefined: t.userDefined || undefined,
    orphan: t.orphan || undefined,
    changedBy: t.changedBy || undefined,
    signal: t.signal
      ? { level: t.signal.level, score: t.signal.score, title: t.signal.title, sink: t.signal.sink, evidence: t.signal.evidence, reasons: t.signal.reasons }
      : undefined,
    enriched:
      t.enriched && t.enriched.class !== 'generic'
        ? (({ specificTitle, class: cls, evidence, whyTest, confidence, groupKey, duplicateOf, relatedFlows, relatedThreats }) => ({
            specificTitle,
            class: cls,
            evidence,
            whyTest,
            confidence,
            groupKey,
            duplicateOf,
            relatedFlows,
            relatedThreats,
          }))(t.enriched)
        : undefined,
  };
}

/** Parse a --signal option; throws a ModelError for unknown values. */
export function parseSignal(v, fallback) {
  const level = normalizeSignalLevel(v, fallback);
  if (!level) throw new ModelError(`Invalid signal level '${v}'. Use high, medium, all or off.`);
  return level;
}

export function opListThreats(model, { state, category, priority, diagram, text, limit, signal } = {}) {
  const kb = kbOf(model);
  const states = state ? [].concat(state).map((s) => normalizeState(s) || s) : undefined;
  const cats = category ? [].concat(category).map((c) => kb.categories.find((x) => x.id === c || x.name.toLowerCase() === String(c).toLowerCase())?.id || c) : undefined;
  const diagramId = diagram ? requireDiagram(model, diagram).id : undefined;
  const level = signal ? parseSignal(signal) : undefined;
  const signals = level && level !== 'off' && level !== 'all' ? levelsAtLeast(level) : undefined;
  let list = filterThreats(model, { states, categories: cats, priorities: priority ? [].concat(priority) : undefined, signals, diagramId, text });
  if (signals) list = [...list].sort((a, b) => (b.signal?.score ?? 0) - (a.signal?.score ?? 0) || a.id - b.id);
  const total = list.length;
  if (limit) list = list.slice(0, Number(limit));
  return { total, threats: list.map((t) => threatView(model, t)) };
}

export function opUpdateThreat(model, args, user) {
  const patch = {};
  for (const k of ['state', 'priority', 'justification', 'title', 'description', 'mitigation']) if (args[k] !== undefined) patch[k] = args[k];
  if (args.custom) patch.custom = parsePairs(args.custom);
  return threatView(model, updateThreat(model, args.threat ?? args.id, patch, user));
}

export function opAddUserThreat(model, args, user) {
  return threatView(model, addUserThreat(model, args.flow, args, user));
}

export function opGenerate(model, { diagram } = {}) {
  const diagramId = diagram ? requireDiagram(model, diagram).id : undefined;
  return generateThreats(model, { diagramId });
}

export function opValidate(model, { includeSuppressed = false } = {}) {
  const msgs = validateModel(model).filter((m) => includeSuppressed || !m.suppressed);
  return {
    errors: msgs.filter((m) => m.severity === 'error').length,
    warnings: msgs.filter((m) => m.severity === 'warning').length,
    info: msgs.filter((m) => m.severity === 'info').length,
    messages: msgs.map((m) => ({ id: m.id, severity: m.severity, issue: m.issue, message: m.message, elements: m.elementIds, diagramId: m.diagramId })),
  };
}

export function opExplain(model, { flow }) {
  const id = requireElement(model, flow).element.id;
  return explainFlow(model, id);
}

export function opReport(model, { format = 'html', diagram, signal, font, top } = {}) {
  const level = parseSignal(signal, 'high');
  try {
    resolveFont(font);
  } catch (e) {
    throw new ModelError(e.message);
  }
  switch (String(format).toLowerCase()) {
    case 'html':
      return renderHtmlReport(model, { signal: level, font });
    case 'exec':
    case 'executive':
      return renderExecutiveReport(model, { font, top: top ? Number(top) : undefined });
    case 'md':
    case 'markdown':
      return renderMarkdownReport(model, { signal: level });
    case 'csv':
      return threatsToCsv(model);
    case 'json':
      return JSON.stringify(
        {
          summary: summarize(model),
          stakeholder: level === 'off' ? undefined : (({ level: l, counts, highByCategory, lines, findings, collapsed }) => ({ level: l, counts, highByCategory, executiveSummary: lines, findings, collapsed }))(stakeholderSummary(model, { signal: level })),
          threats: model.threats.map((t) => threatView(model, t)),
          validation: opValidate(model),
        },
        null,
        2,
      );
    case 'svg':
      return renderDiagramSvg(model, requireDiagram(model, diagram));
    default:
      throw new ModelError(`Unknown report format '${format}'. Use html, exec, md, csv, json or svg.`);
  }
}

export function opCheckRule(template, expression) {
  return validateRule(expression, kbFor(normalizeTemplate(template)));
}

export function opApplyTemplate(model, template) {
  applyTemplate(model, template);
  return { template: model.template.manifest };
}

export function opAddNote(model, { text, author }) {
  if (!text) throw new ModelError('Note text is required');
  return addNote(model, text, author);
}

export function opSetMeta(model, args) {
  for (const k of ['name', 'owner', 'reviewer', 'contributors', 'description', 'assumptions', 'externalDependencies']) {
    if (args[k] !== undefined) model.meta[k] = String(args[k]);
  }
  if (args.threatGeneration !== undefined) model.settings.threatGeneration = !!args.threatGeneration;
  return model.meta;
}

/**
 * Create or update a diagram from an architecture spec (see src/core/sync.js),
 * regenerate threats and validate. Triage is preserved across re-syncs.
 */
export function opSync(model, spec, { diagram, prune = true, layout = 'auto' } = {}) {
  const sync = syncModel(model, spec, { diagram, prune, layout });
  const threats = generateThreats(model);
  const validation = opValidate(model);
  return {
    diagram: sync.diagram,
    elements: { created: sync.created.length, updated: sync.updated.length, removed: sync.removed.length, handDrawnKept: sync.unmanaged },
    emptyZones: sync.emptyZones,
    layoutWarnings: sync.layoutWarnings,
    threats: { total: threats.total, added: threats.added, removed: threats.removed, orphaned: threats.orphaned, restored: threats.restored, ruleErrors: threats.errors },
    validation: { errors: validation.errors, warnings: validation.warnings, info: validation.info, messages: validation.messages.filter((m) => m.severity !== 'info') },
    summary: summarize(model),
  };
}

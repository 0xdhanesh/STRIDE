// Declarative model sync: build or update a diagram from an architecture spec
// (typically produced by an agent that analyzed source code).
//
// spec = {
//   name?, description?, assumptions?, externalDependencies?, owner?,
//   diagram?: "Diagram name",
//   zones:    [{ id?, name, type?: 'SE.TB.B.TMCore.CorpNet' | 'GE.TB.B' | ..., evidence?: [] }],
//   elements: [{ id?, name, type, zone?: zoneId|zoneName, props?, custom?, evidence?: [], outOfScope?, outOfScopeReason? }],
//   flows:    [{ id?, name, from, to, type?, props?, custom?, evidence?: [] }],
// }
//
// Elements get stable ids derived from their id/name, so re-syncing after the
// code changes updates the same elements and keeps threat triage. Each zone
// becomes a box trust boundary; elements without a zone are outside every
// zone (untrusted / third party). The layout is computed so that each flow
// crosses exactly the boundaries of the zones it leaves and enters, and this
// is verified geometrically.

import { GENERIC } from './kb.js';
import { crossedBoundaries } from './engine.js';
import { bendFromMidpoint, center } from './geometry.js';
import { DEFAULT_SIZE, ModelError, addElement, findDiagram, isNodeGeneric, kbOf, lineGeometry, normalizeEvidence, requireDiagram, resolveTypeId, touch } from './model.js';
import { safeStringMap } from './util.js';

const PREFIX = 'spec_';
const CELL_W = 210;
const CELL_H = 150;
const ROWS_PER_COLUMN = 4;
const PAD = 40;
const LABEL = 24;
const ZONE_GAP = 130;
const TOP = 60;
const OUTSIDE_GAP = 130;

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

export const specId = {
  zone: (key) => `${PREFIX}zone_${slug(key)}`,
  element: (key) => `${PREFIX}el_${slug(key)}`,
  flow: (from, to, key) => `${PREFIX}fl_${slug(from)}__${slug(to)}__${slug(key)}`,
};

export function isSpecManaged(id) {
  return typeof id === 'string' && id.startsWith(PREFIX);
}

/** Validate and normalize a spec against the model's template. Throws ModelError listing every problem. */
export function normalizeSpec(model, spec) {
  if (!spec || typeof spec !== 'object') throw new ModelError('Spec must be an object');
  const kb = kbOf(model);
  const problems = [];
  const zones = [];
  const zoneByRef = new Map();
  for (const [i, z] of (Array.isArray(spec.zones) ? spec.zones : []).entries()) {
    const name = String(z?.name ?? '').trim();
    if (!name) {
      problems.push(`zones[${i}]: name is required`);
      continue;
    }
    const typeId = resolveTypeId(kb, z.type || 'GE.TB.B');
    if (!typeId || kb.genericOf(typeId) !== GENERIC.BOX_BOUNDARY) {
      problems.push(`zones[${i}] "${name}": type '${z.type}' is not a box trust boundary type (e.g. GE.TB.B, SE.TB.B.TMCore.CorpNet, SE.TB.B.TMCore.Sandbox)`);
      continue;
    }
    const id = specId.zone(z.id || name);
    if (zones.some((x) => x.id === id)) {
      problems.push(`zones[${i}] "${name}": duplicate zone`);
      continue;
    }
    const zone = { id, name, typeId, evidence: normalizeEvidence(z.evidence), members: [] };
    zones.push(zone);
    for (const ref of [z.id, name]) if (ref) zoneByRef.set(String(ref).toLowerCase(), zone);
  }

  const elements = [];
  const elByRef = new Map();
  for (const [i, e] of (Array.isArray(spec.elements) ? spec.elements : []).entries()) {
    const name = String(e?.name ?? '').trim();
    if (!name) {
      problems.push(`elements[${i}]: name is required`);
      continue;
    }
    const typeId = resolveTypeId(kb, e.type);
    if (!typeId) {
      problems.push(`elements[${i}] "${name}": unknown type '${e.type}'`);
      continue;
    }
    if (!isNodeGeneric(kb.genericOf(typeId))) {
      problems.push(`elements[${i}] "${name}": type '${e.type}' must be a process, external interactor or data store (flows go in "flows", trust zones in "zones")`);
      continue;
    }
    const id = specId.element(e.id || name);
    if (elements.some((x) => x.id === id)) {
      problems.push(`elements[${i}] "${name}": duplicate element (ids and names must be unique)`);
      continue;
    }
    let zone = null;
    if (e.zone) {
      zone = zoneByRef.get(String(e.zone).toLowerCase());
      if (!zone) problems.push(`elements[${i}] "${name}": unknown zone '${e.zone}'`);
    }
    const el = {
      id,
      name,
      typeId,
      generic: kb.genericOf(typeId),
      zone,
      props: safeStringMap(e.props),
      custom: safeStringMap(e.custom),
      evidence: normalizeEvidence(e.evidence),
      outOfScope: !!e.outOfScope,
      outOfScopeReason: String(e.outOfScopeReason || ''),
    };
    for (const [k, v] of Object.entries(el.props)) {
      const a = kb.attribute(typeId, k) || kb.attributes(typeId).find((x) => x.label.toLowerCase() === k.toLowerCase());
      if (!a) problems.push(`elements[${i}] "${name}": property '${k}' is not defined for ${typeId}`);
      else if (a.mode === 'static') problems.push(`elements[${i}] "${name}": property '${a.name}' is fixed by type ${a.definedBy}`);
      else if (a.values.length && !a.values.includes(v)) problems.push(`elements[${i}] "${name}": invalid value '${v}' for '${a.name}' (allowed: ${a.values.join(', ')})`);
    }
    elements.push(el);
    zone?.members.push(el);
    for (const ref of [e.id, name]) if (ref) elByRef.set(String(ref).toLowerCase(), el);
  }

  const flows = [];
  for (const [i, f] of (Array.isArray(spec.flows) ? spec.flows : []).entries()) {
    const from = elByRef.get(String(f?.from ?? '').toLowerCase());
    const to = elByRef.get(String(f?.to ?? '').toLowerCase());
    const name = String(f?.name ?? '').trim() || 'Data flow';
    if (!from) problems.push(`flows[${i}] "${name}": unknown 'from' element '${f?.from}'`);
    if (!to) problems.push(`flows[${i}] "${name}": unknown 'to' element '${f?.to}'`);
    const typeId = resolveTypeId(kb, f?.type || 'GE.DF');
    if (!typeId || kb.genericOf(typeId) !== GENERIC.FLOW) problems.push(`flows[${i}] "${name}": type '${f?.type}' is not a data flow type (e.g. GE.DF, HTTPS, HTTP)`);
    if (!from || !to || !typeId || kb.genericOf(typeId) !== GENERIC.FLOW) continue;
    const id = specId.flow(from.id.slice(PREFIX.length + 3), to.id.slice(PREFIX.length + 3), f.id || name);
    if (flows.some((x) => x.id === id)) {
      problems.push(`flows[${i}] "${name}": duplicate flow (same from, to and name)`);
      continue;
    }
    const props = safeStringMap(f.props);
    for (const [k, v] of Object.entries(props)) {
      const a = kb.attribute(typeId, k) || kb.attributes(typeId).find((x) => x.label.toLowerCase() === k.toLowerCase());
      if (!a) problems.push(`flows[${i}] "${name}": property '${k}' is not defined for ${typeId}`);
      else if (a.mode === 'static') problems.push(`flows[${i}] "${name}": property '${a.name}' is fixed by type ${a.definedBy}`);
      else if (a.values.length && !a.values.includes(v)) problems.push(`flows[${i}] "${name}": invalid value '${v}' for '${a.name}' (allowed: ${a.values.join(', ')})`);
    }
    flows.push({ id, name, typeId, from, to, props, custom: safeStringMap(f.custom), evidence: normalizeEvidence(f.evidence), outOfScope: !!f.outOfScope, outOfScopeReason: String(f.outOfScopeReason || '') });
  }
  if (!elements.length && !problems.length) problems.push('spec has no elements');
  if (problems.length) throw new ModelError(`Invalid spec:\n- ${problems.join('\n- ')}`);
  for (const z of zones) if (!z.members.length) z.empty = true;
  return { zones: zones.filter((z) => !z.empty), emptyZones: zones.filter((z) => z.empty).map((z) => z.name), elements, flows };
}

/** Compute positions for zones and elements. Returns Map id → rect. */
function layout(norm, keep) {
  const rects = new Map();
  const zoneRects = new Map();
  let cursor = 80;
  let bottom = TOP;
  const ORDER = { [GENERIC.PROCESS]: 0, [GENERIC.EXTERNAL]: 1, [GENERIC.STORE]: 2 };
  for (const z of norm.zones) {
    // Processes, then interactors, then stores, each group starting a new column,
    // so flows from a service fan out to its stores instead of running through them.
    const cells = [];
    let col = 0;
    for (const g of [GENERIC.PROCESS, GENERIC.EXTERNAL, GENERIC.STORE]) {
      const group = z.members.filter((m) => m.generic === g);
      group.forEach((el, i) => cells.push({ el, col: col + Math.floor(i / ROWS_PER_COLUMN), row: i % ROWS_PER_COLUMN }));
      if (group.length) col += Math.ceil(group.length / ROWS_PER_COLUMN);
    }
    const rows = Math.max(...cells.map((c) => c.row)) + 1;
    const box = { x: cursor, y: TOP, w: col * CELL_W + PAD * 2, h: rows * CELL_H + PAD * 2 + LABEL };
    for (const { el, col: c, row } of cells) {
      const size = DEFAULT_SIZE[el.generic];
      const cx = box.x + PAD + c * CELL_W + CELL_W / 2;
      const cy = box.y + PAD + LABEL + row * CELL_H + CELL_H / 2;
      rects.set(el.id, { x: Math.round(cx - size.w / 2), y: Math.round(cy - size.h / 2), w: size.w, h: size.h });
    }
    zoneRects.set(z.id, box);
    cursor += box.w + ZONE_GAP;
    bottom = Math.max(bottom, box.y + box.h);
  }

  // Elements outside every zone go below the zoned element they talk to most,
  // so their flows only cross that element's zone border.
  const outside = norm.elements.filter((e) => !e.zone).sort((a, b) => (ORDER[a.generic] ?? 9) - (ORDER[b.generic] ?? 9));
  const placed = []; // {x, y, w, h}
  const loose = [];
  for (const el of outside) {
    const counts = new Map();
    for (const f of norm.flows) {
      const other = f.from === el ? f.to : f.to === el ? f.from : null;
      if (other?.zone) counts.set(other, (counts.get(other) || 0) + 1);
    }
    const best = [...counts.entries()].sort((a, b) => b[1] - a[1] || rects.get(a[0].id).x - rects.get(b[0].id).x)[0];
    if (!best) {
      loose.push(el);
      continue;
    }
    const partner = rects.get(best[0].id);
    const size = DEFAULT_SIZE[el.generic];
    const x0 = Math.round(partner.x + partner.w / 2 - size.w / 2);
    const clash = (r) => placed.some((p) => r.x < p.x + p.w + 50 && p.x < r.x + r.w + 50 && r.y < p.y + p.h + 40 && p.y < r.y + r.h + 40);
    // Nearest free spot on the first row (either side of the partner), then further rows.
    let x = x0;
    let y = bottom + OUTSIDE_GAP;
    search: for (let row = 0; row < 20; row++, y += CELL_H) {
      for (let step = 0; step <= 40; step++) {
        for (const dir of step ? [1, -1] : [1]) {
          const cx = x0 + dir * step * 50;
          if (!clash({ x: cx, y, w: size.w, h: size.h })) {
            x = cx;
            break search;
          }
        }
      }
    }
    const r = { x, y, w: size.w, h: size.h };
    placed.push(r);
    rects.set(el.id, r);
  }
  // Elements with no zoned partners: a column to the left of everything.
  loose.forEach((el, i) => {
    const size = DEFAULT_SIZE[el.generic];
    rects.set(el.id, { x: 80 - CELL_W - Math.floor(i / ROWS_PER_COLUMN) * CELL_W, y: TOP + LABEL + PAD + (i % ROWS_PER_COLUMN) * CELL_H, w: size.w, h: size.h });
  });

  if (keep) {
    for (const [id, r] of keep) if (rects.has(id)) rects.set(id, r);
    // Re-fit zone boxes around their (possibly hand-placed) members.
    for (const z of norm.zones) {
      const rs = z.members.map((m) => rects.get(m.id));
      const x0 = Math.min(...rs.map((r) => r.x)) - PAD;
      const y0 = Math.min(...rs.map((r) => r.y)) - PAD - LABEL;
      const x1 = Math.max(...rs.map((r) => r.x + r.w)) + PAD;
      const y1 = Math.max(...rs.map((r) => r.y + r.h)) + PAD;
      zoneRects.set(z.id, { x: x0, y: y0, w: x1 - x0, h: y1 - y0 });
    }
  }
  return { rects, zoneRects };
}

/**
 * Create or update a diagram from a spec. Elements not in the spec are removed
 * only when they were created by a previous sync (ids starting with "spec_"),
 * so hand-drawn additions survive.
 *
 * Options: { diagram, prune = true, layout: 'auto' | 'keep' }
 * Returns a report with counts and geometry verification.
 */
export function syncModel(model, spec, { diagram: diagramRef, prune = true, layout: layoutMode = 'auto' } = {}) {
  const norm = normalizeSpec(model, spec);
  for (const k of ['name', 'owner', 'description', 'assumptions', 'externalDependencies']) {
    if (spec[k] !== undefined) model.meta[k] = String(spec[k]);
  }
  let diagram = findDiagram(model, diagramRef || spec.diagram);
  if (!diagram && (diagramRef || spec.diagram)) {
    diagram = { id: `${PREFIX}dg_${slug(diagramRef || spec.diagram)}`, name: String(diagramRef || spec.diagram), elements: [] };
    model.diagrams.push(diagram);
  }
  diagram = diagram || requireDiagram(model);
  const existing = new Map(diagram.elements.map((e) => [e.id, e]));
  const keep = layoutMode === 'keep' ? new Map([...existing.values()].filter((e) => e.w !== undefined).map((e) => [e.id, { x: e.x, y: e.y, w: e.w, h: e.h }])) : null;
  const { rects, zoneRects } = layout(norm, keep);
  const report = { diagram: { id: diagram.id, name: diagram.name }, created: [], updated: [], removed: [], unmanaged: 0, emptyZones: norm.emptyZones, layoutWarnings: [] };
  const wanted = new Set();

  const upsert = (id, spec2) => {
    wanted.add(id);
    const cur = existing.get(id);
    if (cur && cur.typeId !== spec2.type && kbOf(model).genericOf(spec2.type) !== cur.generic) {
      diagram.elements = diagram.elements.filter((e) => e !== cur);
      existing.delete(id);
    }
    const el = existing.get(id);
    if (!el) {
      addElement(model, diagram.id, { ...spec2, id });
      report.created.push(id);
      return;
    }
    el.typeId = spec2.type;
    el.name = spec2.name;
    el.props = { ...spec2.props };
    el.custom = { ...spec2.custom };
    el.outOfScope = !!spec2.outOfScope;
    el.outOfScopeReason = spec2.outOfScopeReason || '';
    if (spec2.evidence?.length) el.evidence = spec2.evidence;
    else delete el.evidence;
    for (const k of ['x', 'y', 'w', 'h', 'source', 'target', 'bend']) if (spec2[k] !== undefined) el[k] = spec2[k];
    report.updated.push(id);
  };

  for (const z of norm.zones) {
    upsert(z.id, { type: z.typeId, name: z.name, props: {}, custom: {}, evidence: z.evidence, ...zoneRects.get(z.id) });
  }
  for (const e of norm.elements) {
    upsert(e.id, { type: e.typeId, name: e.name, props: e.props, custom: e.custom, evidence: e.evidence, outOfScope: e.outOfScope, outOfScopeReason: e.outOfScopeReason, ...rects.get(e.id) });
  }

  // Flows: straight between adjacent zones; arcs above intermediate zones otherwise;
  // opposite/parallel flows between the same pair are fanned out.
  const zoneIndex = new Map(norm.zones.map((z, i) => [z.id, i]));
  const top = Math.min(TOP, ...[...zoneRects.values()].map((r) => r.y));
  const pairCount = new Map();
  for (const f of norm.flows) {
    const key = [f.from.id, f.to.id].sort().join('|');
    const n = pairCount.get(key) || 0;
    pairCount.set(key, n + 1);
    const a = center(rects.get(f.from.id));
    const b = center(rects.get(f.to.id));
    let bend = 0;
    const za = f.from.zone ? zoneIndex.get(f.from.zone.id) : undefined;
    const zb = f.to.zone ? zoneIndex.get(f.to.zone.id) : undefined;
    const spansZones = za !== undefined && zb !== undefined && Math.abs(za - zb) > 1;
    if (spansZones) {
      bend = bendFromMidpoint(a, b, { x: (a.x + b.x) / 2, y: top - 60 - n * 45 });
    } else if (n > 0) {
      const reverse = norm.flows.some((g) => g !== f && g.from === f.to && g.to === f.from);
      bend = (reverse ? 34 : 0) + Math.ceil(n / (reverse ? 2 : 1)) * 34 * (n % 2 && !reverse ? -1 : 1);
    } else if (norm.flows.some((g) => g !== f && g.from === f.to && g.to === f.from)) {
      bend = 34;
    }
    upsert(f.id, { type: f.typeId, name: f.name, props: f.props, custom: f.custom, evidence: f.evidence, outOfScope: f.outOfScope, outOfScopeReason: f.outOfScopeReason, source: f.from.id, target: f.to.id, bend: Math.round(bend) });
  }

  if (prune) {
    const ids = diagram.elements.filter((e) => isSpecManaged(e.id) && !wanted.has(e.id)).map((e) => e.id);
    if (ids.length) {
      const drop = new Set(ids);
      diagram.elements = diagram.elements.filter((e) => !drop.has(e.id));
      // Flows from hand-drawn elements to removed ones become loose; validation reports them.
      for (const e of diagram.elements) {
        if (e.generic !== GENERIC.FLOW) continue;
        for (const end of ['source', 'target']) {
          if (e[end] && drop.has(e[end])) {
            const g = lineGeometry(model, { ...diagram, elements: [...diagram.elements] }, { ...e, [end]: undefined });
            e[end] = undefined;
            if (end === 'source') Object.assign(e, { x0: g.p0.x, y0: g.p0.y });
            else Object.assign(e, { x1: g.p1.x, y1: g.p1.y });
          }
        }
      }
      report.removed = ids;
    }
  }
  report.unmanaged = diagram.elements.filter((e) => !isSpecManaged(e.id)).length;

  // Verify: every flow crosses exactly the zones it leaves/enters.
  const byId = new Map(diagram.elements.map((e) => [e.id, e]));
  for (const f of norm.flows) {
    const expected = new Set([f.from.zone?.id, f.to.zone?.id].filter(Boolean));
    if (f.from.zone && f.to.zone && f.from.zone === f.to.zone) expected.clear();
    const actual = new Set(crossedBoundaries(model, diagram, byId.get(f.id)).filter((b) => isSpecManaged(b.id)).map((b) => b.id));
    const same = expected.size === actual.size && [...expected].every((z) => actual.has(z));
    if (!same) {
      const nameOf = (id) => byId.get(id)?.name || id;
      report.layoutWarnings.push({
        flow: f.name,
        from: f.from.name,
        to: f.to.name,
        expectedZones: [...expected].map(nameOf),
        crossedZones: [...actual].map(nameOf),
        hint: 'Adjust the flow with stride_update_element (bend) or the zone/element positions, then verify with stride_explain_flow.',
      });
    }
  }
  touch(model);
  return report;
}


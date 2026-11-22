// Diagram validation — MTMT's Messages pane (§9 of the MTMT report).
// Issue ids that correspond to MTMT issues carry the MTMT GUID in `mtmt`.

import { GENERIC } from './kb.js';
import { rectInside, rectOf, rectsOverlap } from './geometry.js';
import { computeThreats, crossedBoundaries } from './engine.js';
import { elementIndex, lineGeometry } from './model.js';
import { polylinesIntersect } from './geometry.js';

export const ISSUES = Object.freeze({
  'flow.unconnected': { severity: 'error', mtmt: '102BE8A5-2C83-439A-9157-F7C7E9AC1321', title: 'Data flow not attached to two elements' },
  'boundary.partial': { severity: 'warning', mtmt: 'D1D17B88-2150-4B52-9A80-B17BF6463DB9', title: 'Trust boundary does not cover all interactions' },
  'flow.multiple-arc': { severity: 'warning', mtmt: '61A64450-242E-4607-B59E-DD63268F706B', title: 'Several arc boundaries of the same type on one flow' },
  'flow.self': { severity: 'warning', title: 'Data flow connects an element to itself' },
  'flow.ds-ds': { severity: 'warning', title: 'Data flow between two data stores' },
  'flow.ei-ei': { severity: 'warning', title: 'Data flow between two external interactors' },
  'flow.ei-ds': { severity: 'warning', title: 'External interactor connected directly to a data store' },
  'external.no-boundary': { severity: 'warning', title: 'External interactor not separated by a trust boundary' },
  'diagram.no-boundaries': { severity: 'warning', title: 'Diagram has no trust boundaries' },
  'diagram.no-flows': { severity: 'info', title: 'Diagram has no data flows' },
  'element.isolated': { severity: 'info', title: 'Element has no data flows' },
  'element.overlap': { severity: 'info', title: 'Elements overlap' },
  'boundary.line-unused': { severity: 'info', title: 'Arc trust boundary crosses no data flow' },
  'boundary.box-empty': { severity: 'info', title: 'Border trust boundary encloses nothing' },
  'rule.error': { severity: 'error', title: 'Threat rule could not be evaluated' },
});

const SEVERITY_ORDER = { error: 0, warning: 1, info: 2 };

function msg(issue, diagram, elementIds, message) {
  const ids = [...elementIds].sort();
  return {
    id: `${issue}:${diagram ? diagram.id : 'model'}:${ids.join(',')}`,
    issue,
    severity: ISSUES[issue].severity,
    mtmt: ISSUES[issue].mtmt,
    title: ISSUES[issue].title,
    message,
    diagramId: diagram?.id || '',
    elementIds: ids,
  };
}

const label = (el) => `'${el?.name || el?.id || '?'}'`;

export function validateModel(model, { includeRuleErrors = true } = {}) {
  const out = [];
  const idx = elementIndex(model);

  for (const diagram of model.diagrams) {
    const els = diagram.elements;
    const nodes = els.filter((e) => e.generic === GENERIC.PROCESS || e.generic === GENERIC.EXTERNAL || e.generic === GENERIC.STORE);
    const flows = els.filter((e) => e.generic === GENERIC.FLOW);
    const lineBoundaries = els.filter((e) => e.generic === GENERIC.LINE_BOUNDARY);
    const boxBoundaries = els.filter((e) => e.generic === GENERIC.BOX_BOUNDARY);
    const touched = new Set();
    const crossing = new Map(); // flowId -> boundaries

    for (const f of flows) {
      const s = f.source ? idx.get(f.source)?.element : undefined;
      const t = f.target ? idx.get(f.target)?.element : undefined;
      if (s) touched.add(s.id);
      if (t) touched.add(t.id);
      if (!s || !t) {
        out.push(msg('flow.unconnected', diagram, [f.id], `The data flow ${label(f)} should be attached to two elements.`));
        continue;
      }
      if (f.outOfScope) continue;
      crossing.set(f.id, crossedBoundaries(model, diagram, f));
      if (s.id === t.id) out.push(msg('flow.self', diagram, [f.id], `The data flow ${label(f)} starts and ends at ${label(s)}.`));
      const pair = [s.generic, t.generic];
      if (pair[0] === GENERIC.STORE && pair[1] === GENERIC.STORE) {
        out.push(msg('flow.ds-ds', diagram, [f.id], `${label(f)} connects two data stores directly. Data moves between stores through a process; add the process.`));
      } else if (pair[0] === GENERIC.EXTERNAL && pair[1] === GENERIC.EXTERNAL) {
        out.push(msg('flow.ei-ei', diagram, [f.id], `${label(f)} connects two external interactors. Flows outside your system are usually out of scope.`));
      } else if (pair.includes(GENERIC.EXTERNAL) && pair.includes(GENERIC.STORE)) {
        out.push(msg('flow.ei-ds', diagram, [f.id], `${label(f)} connects an external interactor directly to a data store. Model the process that mediates the access.`));
      }
      const arcs = crossing.get(f.id).filter((b) => b.generic === GENERIC.LINE_BOUNDARY);
      const byType = new Map();
      for (const b of arcs) byType.set(b.typeId, [...(byType.get(b.typeId) || []), b]);
      for (const [typeId, list] of byType) {
        if (list.length > 1) {
          out.push(msg('flow.multiple-arc', diagram, [f.id, ...list.map((b) => b.id)], `More than one arc trust boundary of type '${typeId}' crosses ${label(f)}.`));
        }
      }
    }

    // Every interaction between the same pair of elements should cross the same boundaries.
    const pairs = new Map();
    for (const f of flows) {
      if (!crossing.has(f.id)) continue;
      const k = [f.source, f.target].sort().join('|');
      pairs.set(k, [...(pairs.get(k) || []), f]);
    }
    for (const list of pairs.values()) {
      if (list.length < 2) continue;
      const sets = list.map((f) => new Set(crossing.get(f.id).map((b) => b.id)));
      const all = new Set(sets.flatMap((s) => [...s]));
      for (const bId of all) {
        const missing = list.filter((_, i) => !sets[i].has(bId));
        if (!missing.length) continue;
        const b = idx.get(bId)?.element;
        out.push(
          msg(
            'boundary.partial',
            diagram,
            [bId, ...missing.map((f) => f.id)],
            `Trust boundary ${label(b)} should cover all interactions between two elements: ${missing.map(label).join(', ')} do${missing.length > 1 ? '' : 'es'} not cross it.`,
          ),
        );
      }
    }

    for (const n of nodes) {
      if (!touched.has(n.id) && !n.outOfScope) out.push(msg('element.isolated', diagram, [n.id], `${label(n)} has no data flows, so no threats will be generated for it.`));
    }
    for (const e of nodes.filter((n) => n.generic === GENERIC.EXTERNAL && touched.has(n.id) && !n.outOfScope)) {
      const its = flows.filter((f) => (f.source === e.id || f.target === e.id) && crossing.has(f.id));
      if (its.length && its.every((f) => crossing.get(f.id).length === 0)) {
        out.push(msg('external.no-boundary', diagram, [e.id], `None of the data flows to or from external interactor ${label(e)} cross a trust boundary.`));
      }
    }
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        if (rectsOverlap(rectOf(nodes[i]), rectOf(nodes[j]))) {
          out.push(msg('element.overlap', diagram, [nodes[i].id, nodes[j].id], `${label(nodes[i])} and ${label(nodes[j])} overlap.`));
        }
      }
    }
    for (const b of lineBoundaries) {
      const pts = lineGeometry(model, diagram, b).points;
      if (!flows.some((f) => f.source && f.target && polylinesIntersect(lineGeometry(model, diagram, f).points, pts))) {
        out.push(msg('boundary.line-unused', diagram, [b.id], `Arc trust boundary ${label(b)} does not cross any data flow.`));
      }
    }
    for (const b of boxBoundaries) {
      const r = rectOf(b);
      const encloses = nodes.some((n) => rectInside(rectOf(n), r));
      const crossed = [...crossing.values()].some((list) => list.includes(b));
      if (!encloses && !crossed) out.push(msg('boundary.box-empty', diagram, [b.id], `Border trust boundary ${label(b)} encloses no elements and no flow crosses it.`));
    }
    if (nodes.length && !flows.length) out.push(msg('diagram.no-flows', diagram, [], `Diagram '${diagram.name}' has no data flows. Threats are generated from data flows.`));
    if (flows.length && !lineBoundaries.length && !boxBoundaries.length) {
      out.push(msg('diagram.no-boundaries', diagram, [], `Diagram '${diagram.name}' has no trust boundaries. Many threats only apply to flows that cross one.`));
    }
  }

  if (includeRuleErrors) {
    const { errors } = computeThreats(model);
    for (const e of errors) {
      const hit = idx.get(e.flowId);
      out.push(msg('rule.error', hit?.diagram, [`rule:${e.threatTypeId}`], `Threat type '${e.threatTypeId}': ${e.message}`));
    }
  }

  const suppressed = new Set(model.suppressedMessages || []);
  for (const m of out) m.suppressed = suppressed.has(m.id);
  out.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.issue.localeCompare(b.issue));
  return out;
}

export function suppressMessage(model, id, suppressed = true) {
  const set = new Set(model.suppressedMessages || []);
  if (suppressed) set.add(id);
  else set.delete(id);
  model.suppressedMessages = [...set];
}

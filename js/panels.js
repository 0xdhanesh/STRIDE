// Left "properties" panel (like Excalidraw's style panel + TMT's property sheet)
// and the right "Analysis" panel with the threat list and threat editor.

import { store } from './store.js';
import { esc, uid, isLine } from './util.js';
import { icon, hydrateIcons } from './icons.js';
import { STENCILS, STRIDE, STRIDE_BY_KEY, PRIORITIES, STROKES, FILLS, BOUNDARY_COLOR } from './stencils.js';
import { applySubtype, deleteElements, duplicateElements, reorder, reverseFlow, fitNote } from './ops.js';
import { threatList, isOpen } from './engine.js';
import { STATUSES, STATUS_LABELS, threatStatus, threatSeverity, updateThreat, matchesThreat, contributingFlowText } from './threats.js';
import { renderThreatSummary } from './summary.js';

const $ = (s, r = document) => r.querySelector(s);
const TOOL_ICON = { process: 'process', external: 'external', store: 'store', flow: 'flow', boundary: 'boundary', boundaryLine: 'boundaryLine', note: 'text' };
const THREATABLE = ['process', 'external', 'store', 'flow'];

const threatsFor = (id) => threatList(store.model).filter((t) => (t.flowId === id || (!t.flowId && t.elementId === id) || t.contributingFlows?.some((f) => f.id === id)) && !t.orphan);

/* ================================================================ properties */

export function initPropsPanel(canvas) {
  const root = $('#props');

  const swatches = (kind, colors, current, fallback) => `<div class="swatches">${colors.map((c) => {
    const active = (current || fallback) === c;
    return `<button class="swatch${c ? '' : ' none'}${active ? ' active' : ''}" data-a="${kind}" data-color="${c || ''}" style="${c ? `background:${c}` : ''}" title="${c || 'Transparent'}"></button>`;
  }).join('')}</div>`;

  const actions = (single) => `<div class="actions">
      <button class="icon-btn" data-a="duplicate" title="Duplicate (Ctrl+D)">${icon('copy', 18)}</button>
      <button class="icon-btn" data-a="front" title="Bring to front (Ctrl+])">${icon('front', 18)}</button>
      <button class="icon-btn" data-a="back" title="Send to back (Ctrl+[)">${icon('back', 18)}</button>
      ${single && single.type === 'flow' ? `<button class="icon-btn" data-a="reverse" title="Reverse direction">${icon('swap', 18)}</button>` : ''}
      <span style="flex:1"></span>
      <button class="icon-btn danger" data-a="delete" title="Delete (Del)">${icon('trash', 18)}</button>
    </div>`;

  function single(el) {
    const st = STENCILS[el.type];
    const byId = store.byId();
    let h = `<div class="kind">${icon(TOOL_ICON[el.type], 18)} ${esc(st.label)}</div>`;
    if (el.tm7) {
      const warnings = (store.model.importWarnings || []).filter((w) => w.elementId === el.id && w.diagramId === store.diagram.id);
      h += `<details class="props-sec"${warnings.length ? ' open' : ''}><summary>Microsoft TMT import${warnings.length ? ' — review needed' : ''}</summary>
        <p class="small">Original type: ${esc(el.tm7.header || el.tm7.typeId || el.tm7.genericTypeId || '(unknown)')}</p>
        ${warnings.map((w) => `<p class="small">${esc(w.text)}</p>`).join('')}
        <dl class="small">${(el.tm7.properties || []).map((p) => `<dt>${esc(p.name)}</dt><dd>${esc(p.value)}</dd>`).join('')}</dl></details>`;
    }
    h += el.type === 'note'
      ? `<label class="field"><span>Text</span><textarea data-f="name" rows="3">${esc(el.name)}</textarea></label>`
      : `<label class="field"><span>Name</span><input data-f="name" value="${esc(el.name)}"></label>`;
    if (st.subtypes.length) {
      h += `<label class="field"><span>Type</span><select data-f="subtype">${st.subtypes.map((s) => `<option${s === el.subtype ? ' selected' : ''}>${esc(s)}</option>`).join('')}</select></label>`;
    }
    if (el.type === 'flow') {
      const a = byId.get(el.sourceId), b = byId.get(el.targetId);
      h += `<div class="flow-ends"><b>${esc(a?.name || '(unconnected)')}</b> → <b>${esc(b?.name || '(unconnected)')}</b></div>`;
    }
    const isBoundary = el.type === 'boundary' || el.type === 'boundaryLine';
    h += `<h3>Stroke</h3>${swatches('stroke', isBoundary ? [BOUNDARY_COLOR, ...STROKES.filter((c) => c !== BOUNDARY_COLOR)] : STROKES, el.style.stroke, isBoundary ? BOUNDARY_COLOR : STROKES[0])}`;
    if (!isLine(el) && el.type !== 'note') h += `<h3>Background</h3>${swatches('fill', FILLS, el.style.fill, null)}`;
    if (st.props.length) {
      h += `<details class="props-sec" open><summary>Security properties</summary><div class="prop-grid">${st.props.map((p) => {
        const v = el.props[p.key] ?? p.options[0];
        const cls = v === 'Not Selected' ? 'unset' : v === 'Yes' ? 'yes' : v === 'No' || v === 'None' ? 'no' : '';
        return `<label class="prop-row"><span>${esc(p.label)}</span><select data-p="${p.key}" class="${cls}">${p.options.map((o) => `<option${o === v ? ' selected' : ''}>${esc(o)}</option>`).join('')}</select></label>`;
      }).join('')}</div></details>`;
    }
    if (el.type !== 'note') {
      h += `<h3>Scope</h3><label class="check-label"><input type="checkbox" data-f="outOfScope"${el.outOfScope ? ' checked' : ''}> Out of scope</label>`;
      if (el.outOfScope) h += `<label class="field" style="margin-top:6px"><textarea data-f="outOfScopeReason" rows="2" placeholder="Reason for out of scope">${esc(el.outOfScopeReason)}</textarea></label>`;
      h += `<details class="props-sec"${el.notes ? ' open' : ''}><summary>Notes</summary><textarea data-f="notes" rows="3" placeholder="Free-form notes">${esc(el.notes)}</textarea></details>`;
    }
    if (THREATABLE.includes(el.type)) {
      const ts = threatsFor(el.id);
      const open = ts.filter(isOpen).length;
      h += `<div class="threat-sum"><span>${ts.length} threat${ts.length === 1 ? '' : 's'} · <b>${open}</b> open</span><button class="btn small" data-a="show-threats">View</button></div>`;
    }
    return h + actions(el);
  }

  function multi(els) {
    return `<div class="kind">${els.length} elements selected</div>` +
      `<h3>Stroke</h3>${swatches('stroke', STROKES, null, null)}` +
      `<h3>Background</h3>${swatches('fill', FILLS, undefined, undefined)}` + actions(null);
  }

  function render() {
    const sel = store.selected();
    const hide = !sel.length || (store.ui.analysis && innerWidth < 900);
    root.hidden = hide;
    if (hide) return;
    root.innerHTML = sel.length === 1 ? single(sel[0]) : multi(sel);
    hydrateIcons(root);
  }

  store.on((type, detail) => {
    if (type === 'change' && detail.source === 'props') return; // keep focus while typing
    if (type === 'change' || type === 'loaded' || (type === 'ui' && detail.source !== 'threat')) render();
  });

  const current = () => store.selected()[0];

  root.addEventListener('input', (e) => {
    const f = e.target.dataset.f;
    const el = current();
    if (!el) return;
    if (f === 'name') { el.name = e.target.value; store.render(); }
    if (['name', 'notes', 'outOfScopeReason'].includes(f)) {
      el[f] = e.target.value;
      store.persist();
    }
  });

  root.addEventListener('change', (e) => {
    const t = e.target;
    const el = current();
    if (!el) return;
    if (t.dataset.p) {
      el.props[t.dataset.p] = t.value;
      t.className = t.value === 'Not Selected' ? 'unset' : t.value === 'Yes' ? 'yes' : t.value === 'No' || t.value === 'None' ? 'no' : '';
      store.commit('props');
      refreshSummary();
      return;
    }
    switch (t.dataset.f) {
      case 'name':
        if (el.type !== 'note' && !t.value.trim()) { t.value = el.name = STENCILS[el.type].label; }
        if (el.type === 'note') fitNote(el);
        store.commit('props');
        break;
      case 'subtype': applySubtype(el, t.value); store.commit(); break;
      case 'outOfScope': el.outOfScope = t.checked; store.commit(); break;
      case 'outOfScopeReason': el.outOfScopeReason = t.value; store.commit('props'); break;
      case 'notes': el.notes = t.value; store.commit('props'); break;
    }
  });

  function refreshSummary() {
    const el = current();
    const box = root.querySelector('.threat-sum span');
    if (!el || !box) return;
    const ts = threatsFor(el.id);
    box.innerHTML = `${ts.length} threat${ts.length === 1 ? '' : 's'} · <b>${ts.filter(isOpen).length}</b> open`;
  }

  root.addEventListener('click', (e) => {
    const b = e.target.closest('[data-a]');
    if (!b) return;
    const d = store.diagram;
    const ids = new Set(store.ui.selection);
    switch (b.dataset.a) {
      case 'stroke':
      case 'fill':
        for (const el of store.selected()) {
          if (b.dataset.a === 'fill' && (isLine(el) || el.type === 'note')) continue;
          el.style[b.dataset.a] = b.dataset.color || null;
        }
        store.commit();
        break;
      case 'duplicate': store.select(duplicateElements(d, ids)); store.commit(); break;
      case 'front': reorder(d, ids, true); store.commit(); break;
      case 'back': reorder(d, ids, false); store.commit(); break;
      case 'reverse': reverseFlow(current()); store.commit(); break;
      case 'delete': deleteElements(d, ids); store.select([]); store.commit(); break;
      case 'show-threats':
        store.ui.filter.scope = 'selection';
        store.setUI({ analysis: true }, 'analysis');
        break;
    }
  });

  return { render };
}

/* =================================================================== threats */

export function initThreatPanel(canvas) {
  const root = $('#threats');
  const list = $('#threat-list');
  const editor = $('#threat-editor');
  const chips = $('#stride-chips');
  const fText = $('#f-text'), fState = $('#f-state'), fPrio = $('#f-priority'), fScope = $('#f-scope');
  const summary = $('#dlg-summary');
  const renderSummary = () => { $('#summary-content').innerHTML = renderThreatSummary(threatList(store.model)); };
  $('#show-summary').addEventListener('click', () => { renderSummary(); summary.showModal(); });
  const f = store.ui.filter;

  fState.innerHTML = `<option value="">All statuses</option>${STATUSES.map((s) => `<option value="${s}">${STATUS_LABELS[s]}</option>`).join('')}`;
  fPrio.innerHTML = `<option value="">All severities</option>${PRIORITIES.map((s) => `<option>${s}</option>`).join('')}`;

  const scoped = () => {
    const d = store.diagram;
    const sel = store.ui.selection;
    return threatList(store.model).filter((t) => {
      if (t.diagramId && t.diagramId !== d.id) return false;
      if (f.scope === 'selection' && sel.size) return sel.has(t.flowId) || sel.has(t.elementId) || t.contributingFlows?.some((flow) => sel.has(flow.id));
      return true;
    });
  };

  const filtered = () => scoped().filter((t) => matchesThreat(t, f));

  function renderChips() {
    const ts = scoped();
    const all = `<button class="chip${!f.category ? ' active' : ''}" data-cat=""><span class="cat" style="background:#868e96">∑</span>${ts.length}</button>`;
    chips.innerHTML = all + STRIDE.map((c) => {
      const n = ts.filter((t) => t.category === c.key).length;
      return `<button class="chip${f.category === c.key ? ' active' : ''}" data-cat="${c.key}" title="${c.name}: ${c.desc}"><span class="cat" style="background:${c.color}">${c.key}</span>${n}</button>`;
    }).join('');
  }

  function renderList() {
    // Template text, element names and review fields are untrusted. Every
    // dynamic text/attribute value below must pass through esc() or an enum.
    const ts = filtered();
    const sel = store.ui.selection;
    const scopeNote = `<div class="muted small" style="padding:4px 8px">${f.scope === 'selection' && sel.size ? `Selected elements in ${esc(store.diagram.name)}` : `Current diagram: ${esc(store.diagram.name)}`} · ${ts.length} shown</div>`;
    if (!ts.length) {
      const any = threatList(store.model).length;
      list.innerHTML = scopeNote + `<div class="empty">${any ? 'No threats match the filters.' : 'No threats yet.<br><br>Connect two elements with a <b>Data flow</b> (5). Threats are generated for every interaction, especially flows that cross a <b>Trust boundary</b> (6).'}</div>`;
      return;
    }
    list.innerHTML = scopeNote + ts.map((t) => {
      const c = STRIDE_BY_KEY[t.category] || STRIDE[0];
      return `<div class="t-row${t.key === store.ui.activeThreat ? ' active' : ''}" data-key="${esc(t.key)}" role="listitem" tabindex="0">
        <span class="cat" style="background:${c.color}" title="${c.name}">${c.key}</span>
        <div><div class="t-title">${esc(t.title)}${t.orphan ? '<span class="orphan-tag" title="The interaction for this threat no longer exists">orphaned</span>' : ''}${!t.auto ? '<span class="orphan-tag">custom</span>' : ''}</div>
          <div class="t-sub">${esc(t.interaction)}</div>${t.contributingFlows?.length ? `<div class="t-sub">${esc(contributingFlowText(t))}</div>` : ''}${t.owner ? `<div class="t-sub">Owner: ${esc(t.owner)}</div>` : ''}</div>
        <div class="t-meta"><span class="t-id">#${esc(t.id)}</span><span class="state" data-s="${STATUS_LABELS[threatStatus(t)]}">${STATUS_LABELS[threatStatus(t)]}</span><span class="prio" data-p="${threatSeverity(t)}">${threatSeverity(t)}</span></div>
      </div>`;
    }).join('');
  }

  function renderEditor() {
    const t = store.model.threats[store.ui.activeThreat];
    if (!t || t.suppressed) { editor.hidden = true; editor.innerHTML = ''; return; }
    editor.hidden = false;
    const opt = (arr, v, label = (x) => x) => arr.map((x) => `<option value="${esc(x)}"${x === v ? ' selected' : ''}>${esc(label(x))}</option>`).join('');
    editor.innerHTML = `
      <h3><span class="cat" style="background:${STRIDE_BY_KEY[t.category]?.color}">${esc(t.category)}</span>Threat #${esc(t.id)}
        <span style="flex:1"></span>
        <button class="icon-btn small" data-t="locate" title="Show on diagram">${icon('pointer', 16)}</button>
        <button class="icon-btn small" data-t="close" title="Close">${icon('x', 16)}</button></h3>
      <label class="field"><span>Title</span><input data-tf="title" value="${esc(t.title)}"></label>
      <div class="grid3">
        <label class="field"><span>Category</span><select data-tf="category">${opt(STRIDE.map((c) => c.key), t.category, (k) => STRIDE_BY_KEY[k].name)}</select></label>
        <label class="field"><span>Severity</span><select data-tf="severity">${opt(PRIORITIES, threatSeverity(t))}</select></label>
        <label class="field"><span>Status</span><select data-tf="status">${opt(STATUSES, threatStatus(t), (s) => STATUS_LABELS[s])}</select></label>
      </div>
      <label class="field"><span>Owner</span><input data-tf="owner" value="${esc(t.owner)}" placeholder="Person or team responsible"></label>
      <label class="field"><span>Interaction</span><input value="${esc(t.interaction)}" disabled></label>
      ${t.contributingFlows?.length ? `<label class="field"><span>Contributing flows</span><textarea rows="3" disabled>${esc(contributingFlowText(t))}</textarea></label>` : ''}
      <label class="field"><span>Description</span><textarea data-tf="description" rows="4">${esc(t.description)}</textarea></label>
      <label class="field"><span>Justification</span><textarea data-tf="justification" rows="2" placeholder="Why was this status chosen? Include the reason for acceptance or non-applicability.">${esc(t.justification)}</textarea></label>
      <label class="field"><span>Notes</span><textarea data-tf="notes" rows="3" placeholder="Review notes, evidence references, and follow-up actions">${esc(t.notes)}</textarea></label>
      <label class="field"><span>Mitigation description</span><textarea data-tf="mitigation" rows="3" placeholder="How is / will this threat be mitigated?">${esc(t.mitigation)}</textarea></label>
      ${t.legacyState || (t.status == null && t.state === 'Needs Investigation') ? `<p class="muted small">Original state: ${esc(t.legacyState || t.state)}</p>` : ''}
      ${t.mitigationHint ? `<div class="hint"><b>Suggested mitigation:</b> ${esc(t.mitigationHint)} <button class="btn small" data-t="use-hint" style="margin-top:6px">Use suggestion</button></div>` : ''}
      <div class="row between" style="margin-top:10px">
        <span class="muted small">${t.auto ? `Generated by rule ${esc(t.ruleId)}` : 'Custom threat'}${t.modified ? ` · edited ${new Date(t.modified).toLocaleString()}` : ''}</span>
        <span class="row gap">
          ${t.auto && t.customText ? '<button class="btn small" data-t="reset-text" title="Restore generated title & description">Reset text</button>' : ''}
          ${!t.auto || t.orphan ? '<button class="btn small danger" data-t="delete">Delete</button>' : ''}
        </span>
      </div>`;
  }

  function renderAll() {
    const on = store.ui.analysis;
    root.hidden = !on;
    if (!on) return;
    fText.value = f.text; fState.value = f.status; fPrio.value = f.severity; fScope.checked = f.scope === 'selection';
    renderChips();
    renderList();
    renderEditor();
  }

  store.on((type, detail) => {
    if (summary.open && ['change', 'loaded'].includes(type)) renderSummary();
    if (!store.ui.analysis) { if (type === 'ui') root.hidden = true; return; }
    if (type === 'change') {
      renderChips(); renderList();
      if (detail.source !== 'threat-editor') renderEditor();
    } else if (type === 'ui' || type === 'loaded') {
      if (detail?.source === 'selection') { renderChips(); renderList(); } else renderAll();
    }
  });

  fText.addEventListener('input', () => { f.text = fText.value; renderList(); });
  fState.addEventListener('change', () => { f.status = fState.value; renderList(); });
  fPrio.addEventListener('change', () => { f.severity = fPrio.value; renderList(); });
  fScope.addEventListener('change', () => { f.scope = fScope.checked ? 'selection' : 'all'; renderChips(); renderList(); });
  chips.addEventListener('click', (e) => {
    const b = e.target.closest('[data-cat]');
    if (!b) return;
    f.category = f.category === b.dataset.cat ? '' : b.dataset.cat;
    renderChips(); renderList();
  });

  const openThreat = (key) => { store.setUI({ activeThreat: key }, 'threat'); };
  list.addEventListener('click', (e) => { const r = e.target.closest('.t-row'); if (r) openThreat(r.dataset.key); });
  list.addEventListener('keydown', (e) => {
    const r = e.target.closest('.t-row');
    if (!r) return;
    if (e.key === 'Enter') openThreat(r.dataset.key);
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const next = e.key === 'ArrowDown' ? r.nextElementSibling : r.previousElementSibling;
      if (next?.classList.contains('t-row')) { next.focus(); openThreat(next.dataset.key); }
    }
  });

  const active = () => store.model.threats[store.ui.activeThreat];
  editor.addEventListener('input', (e) => {
    const t = active(), k = e.target.dataset.tf;
    if (!t || !k) return;
    if (e.target.tagName === 'SELECT') return; // One commit per select change.
    updateThreat(t, k, e.target.value);
    store.persist();
  });
  editor.addEventListener('change', (e) => {
    const t = active(), k = e.target.dataset.tf;
    if (!t || !k) return;
    updateThreat(t, k, e.target.value);
    store.commit(k === 'category' ? '' : 'threat-editor');
  });
  editor.addEventListener('click', (e) => {
    const b = e.target.closest('[data-t]');
    const t = active();
    if (!b || !t) return;
    switch (b.dataset.t) {
      case 'close': store.setUI({ activeThreat: null }, 'threat'); break;
      case 'use-hint': updateThreat(t, 'mitigation', t.mitigationHint); store.commit(); break;
      case 'reset-text': t.customText = false; store.commit(); break;
      case 'delete': delete store.model.threats[t.key]; store.ui.activeThreat = null; store.commit(); break;
      case 'locate': {
        const d = store.model.diagrams.find((x) => x.id === t.diagramId);
        if (!d) return;
        if (d.id !== store.diagram.id) store.setUI({ diagramId: d.id });
        const el = d.elements.find((x) => x.id === (t.flowId || t.elementId));
        if (el) { store.select([el.id]); canvas.fit([el]); }
        break;
      }
    }
  });

  return {
    render: renderAll,
    addThreat() {
      const sel = store.selected();
      const el = sel.length === 1 ? sel[0] : null;
      const byId = store.byId();
      let interaction = 'General';
      if (el?.type === 'flow') interaction = `${byId.get(el.sourceId)?.name || '?'} → ${byId.get(el.targetId)?.name || '?'}${el.name ? ` (${el.name})` : ''}`;
      else if (el) interaction = el.name;
      const key = `m:${uid()}`;
      store.model.threats[key] = {
        id: store.model.nextThreatId++, key, auto: false, ruleId: null, diagramId: store.diagram.id,
        flowId: el?.type === 'flow' ? el.id : null, elementId: el && el.type !== 'flow' ? el.id : null,
        category: 'S', priority: 'Medium', state: 'Not Started', title: 'New threat', description: '',
        status: 'open', severity: 'Medium', notes: '', owner: '',
        mitigation: '', mitigationHint: '', justification: '', interaction, customText: true,
        created: new Date().toISOString(), modified: new Date().toISOString(),
      };
      store.ui.activeThreat = key;
      store.commit();
      setTimeout(() => { const i = editor.querySelector('[data-tf="title"]'); i?.focus(); i?.select(); }, 0);
    },
  };
}

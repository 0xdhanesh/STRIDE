// Palette, inspector and drawer (threat list, threat editor, messages, notes).

import {
  FLOW_PALETTE,
  GENERIC,
  entityColor,
  flowColor,
  SIGNAL_LABELS,
  THREAT_STATES,
  THREAT_STATE_LABELS,
  addUserThreat,
  attributeValue,
  changeType,
  deleteThreat,
  displayTitle,
  elementIndex,
  filterThreats,
  findThreat,
  suppressMessage,
  threatsForElement,
  updateElement,
  updateThreat,
} from '../core/index.js';
import { clear, confirmDialog, field, h, icon, select, textInput, toast } from './dom.js';

const FAMILIES = [
  { generic: GENERIC.PROCESS, label: 'Processes', glyph: 'process' },
  { generic: GENERIC.EXTERNAL, label: 'External interactors', glyph: 'external' },
  { generic: GENERIC.STORE, label: 'Data stores', glyph: 'store' },
  { generic: GENERIC.FLOW, label: 'Data flows', glyph: 'flow' },
  { generic: GENERIC.LINE_BOUNDARY, label: 'Trust boundaries (arc)', glyph: 'line-boundary' },
  { generic: GENERIC.BOX_BOUNDARY, label: 'Trust boundaries (box)', glyph: 'box-boundary' },
  { generic: GENERIC.ANNOTATION, label: 'Annotations', glyph: 'annotation' },
];
const FAMILY_LABEL = Object.fromEntries(FAMILIES.map((f) => [f.generic, f.label.replace(/s( \(|$)/, '$1')]));
const OPEN = new Set(['NotStarted', 'NeedsInvestigation']);
const USER = 'web user';

function focusInside(el) {
  return el.contains(document.activeElement) && document.activeElement !== document.body;
}

// ====================================================================== palette
export class Palette {
  constructor(store, root) {
    this.store = store;
    this.root = root;
    this.query = '';
    store.on('model', (d) => d?.replaced && this.render());
    store.on('tool', () => this.syncActive());
    store.on('template', () => this.render());
    this.render();
  }
  render() {
    const kb = this.store.kb;
    const search = h('input', { type: 'search', placeholder: 'Search stencils…', 'aria-label': 'Search stencils', value: this.query });
    search.addEventListener('input', () => {
      this.query = search.value;
      this.renderList();
    });
    this.list = h('div');
    clear(this.root).append(search, this.list, h('p', { class: 'palette-hint' }, 'Click a stencil then click the canvas, or drag it onto the canvas. ', kb.manifest.name, ' template.'));
    this.renderList();
  }
  renderList() {
    const kb = this.store.kb;
    const q = this.query.trim().toLowerCase();
    clear(this.list);
    for (const fam of FAMILIES) {
      const types = kb.typesFor(fam.generic).filter((t) => !q || t.name.toLowerCase().includes(q) || t.id.toLowerCase().includes(q));
      if (!types.length) continue;
      this.list.appendChild(h('h3', null, fam.label));
      for (const t of types) {
        const btn = h(
          'button',
          {
            class: 'stencil',
            type: 'button',
            draggable: 'true',
            title: `${t.name}${t.description ? ` — ${t.description}` : ''}`,
            'data-type': t.id,
            onClick: () => this.store.setTool({ kind: 'place', typeId: t.id }),
          },
          icon(fam.glyph, 22),
          h('span', null, t.id === fam.generic ? `${t.name.replace(/^Generic /, '')}` : t.name),
        );
        btn.addEventListener('dragstart', (e) => {
          e.dataTransfer.setData('application/x-stride-type', t.id);
          e.dataTransfer.effectAllowed = 'copy';
        });
        this.list.appendChild(btn);
      }
    }
    this.syncActive();
  }
  syncActive() {
    const t = this.store.tool;
    for (const b of this.root.querySelectorAll('.stencil')) b.classList.toggle('active', t.kind === 'place' && b.dataset.type === t.typeId);
  }
}

// ====================================================================== inspector
export class Inspector {
  constructor(store, root, app) {
    this.store = store;
    this.root = root;
    this.app = app;
    const rerender = () => this.render();
    store.on('selection', rerender);
    store.on('model', (d) => {
      if (d?.preview) return;
      if (!focusInside(this.root)) this.render();
      else this.pending = true;
    });
    store.on('processed', () => !focusInside(this.root) && this.render());
    this.root.addEventListener('focusout', () =>
      setTimeout(() => {
        if (this.pending && !focusInside(this.root)) {
          this.pending = false;
          this.render();
        }
      }, 0),
    );
    this.render();
  }

  render() {
    const { diagram, selection } = this.store;
    const sel = diagram.elements.filter((e) => selection.has(e.id));
    const box = h('div', { class: 'insp' });
    if (sel.length === 1) this.renderElement(box, sel[0]);
    else if (sel.length > 1) this.renderMulti(box, sel);
    else this.renderModel(box);
    clear(this.root).appendChild(box);
  }

  renderMulti(box, sel) {
    box.append(
      h('h2', null, `${sel.length} elements selected`),
      h('p', { class: 'sub' }, 'Drag to move together. Alt-drag duplicates.'),
      h(
        'div',
        { class: 'row' },
        h('button', { class: 'btn outline small', type: 'button', title: 'Group (Ctrl/⌘+G)', onClick: () => this.app.canvas.groupSelection() }, 'Group'),
        h('button', { class: 'btn outline small', type: 'button', title: 'Ungroup (Ctrl/⌘+Shift+G)', onClick: () => this.app.canvas.ungroupSelection() }, 'Ungroup'),
      ),
      h('button', { class: 'btn outline danger', type: 'button', onClick: () => this.app.canvas.deleteSelection() }, icon('trash', 16), 'Delete selected'),
    );
  }

  /** Colour picker row: swatches, a custom colour input and a reset. */
  colorField(label, current, isCustom, apply, hint) {
    const swatches = FLOW_PALETTE.map((c) =>
      h('button', { class: 'swatch', type: 'button', title: c, 'aria-label': `${label} ${c}`, 'aria-pressed': String(current.toLowerCase() === c), style: { background: c }, onClick: () => apply(c) }),
    );
    const input = h('input', { type: 'color', class: 'swatch-input', value: current, 'aria-label': `${label} (custom)`, onChange: (e) => apply(e.target.value) });
    const reset = h('button', { class: 'btn outline small', type: 'button', disabled: !isCustom || undefined, onClick: () => apply('') }, 'Reset');
    const f = field(label, h('div', { class: 'swatches' }, swatches, input, reset));
    if (hint) f.append(h('p', { class: 'small muted' }, hint));
    return f;
  }

  renderElement(box, el) {
    const { store } = this;
    const kb = store.kb;
    const def = kb.element(el.typeId);
    const { diagram } = store;
    const commit = (fn) => {
      try {
        store.commit(fn);
      } catch (e) {
        toast(e.message);
      }
    };
    box.append(h('h2', null, el.name || '(unnamed)'), h('p', { class: 'sub' }, `${FAMILY_LABEL[el.generic] || ''} · ${def?.name || el.typeId}`));
    box.append(field('Name', textInput(el.name, (v) => commit(() => (el.name = v)), { 'aria-label': 'Name' })));
    if (el.generic === GENERIC.FLOW) {
      box.append(this.colorField('Line colour', flowColor(diagram, el) || '#1e1e1e', !!el.color, (v) => commit((m) => updateElement(m, el.id, { color: v })), 'Defaults to the colour of the source entity.'));
    } else if (el.w !== undefined && el.generic !== GENERIC.BOX_BOUNDARY && el.generic !== GENERIC.ANNOTATION) {
      box.append(this.colorField('Egress colour', entityColor(diagram, el), !!el.color, (v) => commit((m) => updateElement(m, el.id, { color: v })), 'Colour of every flow leaving this entity (a flow can override it).'));
    }
    if (el.groupId) {
      box.append(h('div', { class: 'row' }, h('span', { class: 'small muted' }, 'Part of a group'), h('button', { class: 'btn outline small', type: 'button', onClick: () => this.app.canvas.ungroupSelection() }, 'Ungroup')));
    }
    const types = kb.typesFor(el.generic);
    if (types.length > 1) {
      box.append(
        field(
          'Type',
          select(
            types.map((t) => ({ value: t.id, label: t.name })),
            el.typeId,
            (v) => commit((m) => changeType(m, el, v)),
          ),
        ),
      );
    }
    if (def?.description) box.append(h('p', { class: 'small muted' }, def.description));
    if (el.evidence?.length) {
      box.append(h('h4', null, 'Source evidence'), h('ul', { class: 'small', style: { margin: '0 0 8px', paddingLeft: '18px' } }, el.evidence.map((x) => h('li', null, h('code', null, x)))));
    }

    if (el.generic === GENERIC.FLOW) {
      const idx = elementIndex(store.model);
      const s = idx.get(el.source)?.element;
      const t = idx.get(el.target)?.element;
      box.append(
        h('h4', null, 'Connection'),
        h('p', { class: 'small' }, s ? s.name : h('b', { class: 'p-High' }, 'Not connected'), '  →  ', t ? t.name : h('b', { class: 'p-High' }, 'Not connected')),
        h(
          'div',
          { class: 'row' },
          h(
            'button',
            {
              class: 'btn outline small',
              type: 'button',
              disabled: !(s && t) || undefined,
              onClick: () =>
                commit(() => {
                  [el.source, el.target] = [el.target, el.source];
                }),
            },
            icon('swap', 15),
            'Reverse direction',
          ),
          h(
            'button',
            {
              class: 'btn outline small',
              type: 'button',
              onClick: () => {
                try {
                  let th;
                  store.commit((m) => (th = addUserThreat(m, el.id, { title: 'New threat' }, USER)));
                  this.app.drawer.show('threats');
                  store.selectThreat(th.key);
                } catch (e) {
                  toast(e.message);
                }
              },
            },
            icon('plus', 15),
            'Add threat',
          ),
        ),
      );
    }

    // Scope
    box.append(h('h4', null, 'Scope'));
    const oos = h('input', { type: 'checkbox', checked: el.outOfScope, id: 'oos' });
    oos.addEventListener('change', () => commit(() => (el.outOfScope = oos.checked)));
    box.append(h('label', { class: 'check', for: 'oos' }, oos, 'Out of scope (no threats generated)'));
    if (el.outOfScope) box.append(field('Reason for out of scope', textInput(el.outOfScopeReason, (v) => commit(() => (el.outOfScopeReason = v)), {}, true)));

    // Template attributes
    const attrs = kb.attributes(el.typeId);
    const statics = attrs.filter((a) => a.mode === 'static');
    const dynamics = attrs.filter((a) => a.mode !== 'static');
    if (dynamics.length) {
      box.append(h('h4', null, 'Properties'));
      for (const a of dynamics) {
        const cur = attributeValue(kb, el, a);
        const control = a.values.length
          ? select(a.values, cur, (v) =>
              commit(() => {
                el.props = { ...el.props, [a.name]: v };
              }),
            )
          : textInput(cur, (v) => commit(() => (el.props = { ...el.props, [a.name]: v })));
        box.append(field(a.label, control));
      }
    }
    if (statics.length) {
      box.append(h('h4', null, 'Fixed by type'));
      for (const a of statics) box.append(h('div', { class: 'field fixed' }, h('span', null, a.label), h('div', { class: 'value' }, a.values[0] ?? '')));
    }

    // Custom properties
    box.append(h('h4', null, 'Custom properties'));
    const custom = Object.entries(el.custom || {});
    for (const [k, v] of custom) {
      box.append(
        h(
          'div',
          { class: 'kvrow' },
          h('input', { value: k, disabled: true, 'aria-label': 'Property name' }),
          textInput(v, (nv) => commit(() => (el.custom = { ...el.custom, [k]: nv })), { 'aria-label': `${k} value` }),
          h(
            'button',
            {
              class: 'btn small',
              type: 'button',
              'aria-label': `Remove ${k}`,
              onClick: () =>
                commit(() => {
                  const next = { ...el.custom };
                  delete next[k];
                  el.custom = next;
                }),
            },
            icon('x', 14),
          ),
        ),
      );
    }
    const nk = h('input', { placeholder: 'name', 'aria-label': 'New property name' });
    const nv = h('input', { placeholder: 'value', 'aria-label': 'New property value' });
    const add = () => {
      const k = nk.value.trim();
      if (!k) return;
      if (['__proto__', 'constructor', 'prototype'].includes(k)) return toast('That property name is not allowed.');
      commit(() => (el.custom = { ...el.custom, [k]: nv.value }));
    };
    nv.addEventListener('keydown', (e) => e.key === 'Enter' && add());
    box.append(h('div', { class: 'kvrow' }, nk, nv, h('button', { class: 'btn small outline', type: 'button', onClick: add, 'aria-label': 'Add property' }, icon('plus', 14))));
    box.append(h('p', { class: 'small muted' }, 'Custom properties can be used in rules, e.g. ', h('code', null, "target.dataClass is 'PII'"), '.'));

    // Threats
    const threats = threatsForElement(store.model, el.id).filter((t) => !t.orphan);
    const open = threats.filter((t) => OPEN.has(t.state)).length;
    box.append(
      h('h4', null, 'Threats'),
      h('p', { class: 'small' }, `${threats.length} threat(s) involve this element, ${open} open.`),
      threats.length
        ? h(
            'button',
            {
              class: 'btn outline small',
              type: 'button',
              onClick: () => {
                this.app.drawer.filters.element = el.id;
                this.app.drawer.show('threats');
              },
            },
            'Show in threat list',
          )
        : null,
      h('h4', null, 'Danger zone'),
      h('button', { class: 'btn outline danger small', type: 'button', onClick: () => this.app.canvas.deleteSelection() }, icon('trash', 15), 'Delete element'),
    );
  }

  renderModel(box) {
    const { store } = this;
    const m = store.model;
    const s = store.lastGeneration;
    const commit = (fn) => store.commit(fn);
    const byState = Object.fromEntries(THREAT_STATES.map((st) => [st, m.threats.filter((t) => t.state === st).length]));
    box.append(
      h('h2', null, 'Threat model'),
      h('p', { class: 'sub' }, `${m.diagrams.length} diagram(s) · template ${store.kb.manifest.name} ${store.kb.manifest.version}`),
      h(
        'div',
        { class: 'stat-grid' },
        THREAT_STATES.map((st) => h('div', { class: 'stat' }, h('b', null, byState[st]), h('span', null, THREAT_STATE_LABELS[st]))),
      ),
    );
    if (s?.errors?.length) box.append(h('p', { class: 'rule-err' }, `${s.errors.length} rule error(s) — see Messages.`));
    box.append(h('h4', null, 'Details'));
    const meta = [
      ['name', 'Name'],
      ['owner', 'Owner'],
      ['reviewer', 'Reviewer'],
      ['contributors', 'Contributors'],
      ['description', 'High-level system description', true],
      ['assumptions', 'Assumptions', true],
      ['externalDependencies', 'External dependencies', true],
    ];
    for (const [k, label, multi] of meta) {
      box.append(
        field(
          label,
          textInput(
            m.meta[k],
            (v) =>
              commit(() => {
                m.meta[k] = v;
              }),
            {},
            multi,
          ),
        ),
      );
    }
    const gen = h('input', { type: 'checkbox', checked: m.settings.threatGeneration !== false, id: 'gen' });
    gen.addEventListener('change', () => store.commit(() => (m.settings.threatGeneration = gen.checked), { immediate: true }));
    box.append(h('h4', null, 'Analysis'), h('label', { class: 'check', for: 'gen' }, gen, 'Generate threats automatically'));
    box.append(h('button', { class: 'btn outline small', type: 'button', onClick: () => this.app.openTemplate() }, icon('book', 15), 'Template & rules…'));
    box.append(h('p', { class: 'small muted', style: { marginTop: '14px' } }, 'Tip: select an element to edit its properties. Everything stays in this browser unless you save or export.'));
  }
}

// ====================================================================== drawer
export class Drawer {
  constructor(store, root, app) {
    this.store = store;
    this.root = root;
    this.app = app;
    this.tab = 'threats';
    this.filters = { text: '', state: '', category: '', priority: '', element: '', scope: 'diagram', highSignal: false };
    this.sort = { key: 'id', dir: 1 };
    this.showSuppressed = false;
    this.build();
    const update = (d) => {
      if (d?.preview) return;
      if (focusInside(this.body)) {
        // Keep the focused editor intact; refresh the list beside it.
        this.pending = true;
        this.updateCounts();
        if (this.tab === 'threats' && this.tableWrap?.isConnected) this.renderTable();
        return;
      }
      this.renderBody();
    };
    store.on('model', update);
    store.on('processed', update);
    store.on('threat', () => this.renderBody());
    store.on('view', () => this.syncCollapsed());
    this.body.addEventListener('focusout', () =>
      setTimeout(() => {
        if (this.pending && !focusInside(this.body)) {
          this.pending = false;
          this.renderBody();
        }
      }, 0),
    );
  }

  build() {
    this.tabs = {};
    const mk = (id, label) => {
      const count = h('span', { class: 'count' }, '0');
      const b = h('button', { class: 'tab', type: 'button', role: 'tab', onClick: () => this.show(id) }, label, count);
      this.tabs[id] = { b, count };
      return b;
    };
    this.collapseBtn = h('button', { class: 'btn small', type: 'button', title: 'Collapse/expand panel', 'aria-label': 'Toggle panel', onClick: () => this.toggle() }, icon('chevron', 16));
    const resizer = h('div', { class: 'drawer-resizer', 'aria-hidden': 'true' });
    resizer.addEventListener('pointerdown', (e) => {
      const startY = e.clientY;
      const app = document.getElementById('app');
      const start = this.root.getBoundingClientRect().height;
      resizer.setPointerCapture(e.pointerId);
      const move = (ev) => {
        const hgt = Math.max(120, Math.min(window.innerHeight - 160, start + (startY - ev.clientY)));
        app.style.setProperty('--drawer-h', `${hgt}px`);
      };
      const up = () => {
        resizer.removeEventListener('pointermove', move);
        resizer.removeEventListener('pointerup', up);
      };
      resizer.addEventListener('pointermove', move);
      resizer.addEventListener('pointerup', up);
    });
    this.body = h('div', { class: 'drawer-body' });
    this.root.append(resizer, h('div', { class: 'drawer-head', role: 'tablist' }, mk('threats', 'Threats'), mk('messages', 'Messages'), mk('notes', 'Notes'), h('span', { class: 'spacer' }), this.collapseBtn), this.body);
    this.renderBody();
  }

  toggle() {
    document.getElementById('app').classList.toggle('drawer-collapsed');
  }
  syncCollapsed() {
    const app = document.getElementById('app');
    if (this.store.view === 'analyze') app.classList.remove('drawer-collapsed');
    app.style.removeProperty('--drawer-h');
  }
  show(tab) {
    this.tab = tab;
    document.getElementById('app').classList.remove('drawer-collapsed');
    this.renderBody();
  }

  updateCounts() {
    const { model, messages } = this.store;
    const open = model.threats.filter((t) => OPEN.has(t.state)).length;
    this.tabs.threats.count.textContent = String(open);
    this.tabs.threats.b.title = `${open} open of ${model.threats.length} threats`;
    const visible = messages.filter((m) => !m.suppressed);
    const errs = visible.filter((m) => m.severity === 'error').length;
    this.tabs.messages.count.textContent = String(visible.length);
    this.tabs.messages.count.classList.toggle('err', errs > 0);
    this.tabs.notes.count.textContent = String(model.notes.length);
    for (const [id, t] of Object.entries(this.tabs)) t.b.setAttribute('aria-selected', String(id === this.tab));
  }

  renderBody() {
    this.updateCounts();
    clear(this.body);
    this.body.classList.remove('has-detail');
    if (this.tab === 'threats') this.renderThreats();
    else if (this.tab === 'messages') this.renderMessages();
    else this.renderNotes();
  }

  // ---------------------------------------------------------------- threats
  currentThreats() {
    const { model, diagram } = this.store;
    const f = this.filters;
    let list = filterThreats(model, {
      text: f.text,
      states: f.state ? [f.state] : undefined,
      categories: f.category ? [f.category] : undefined,
      priorities: f.priority ? [f.priority] : undefined,
      signals: f.highSignal ? ['high'] : undefined,
      diagramId: f.scope === 'diagram' ? diagram.id : undefined,
    });
    if (f.element) list = list.filter((t) => t.flowId === f.element || t.sourceId === f.element || t.targetId === f.element);
    // The high-signal view ranks by score unless the user picked another column.
    const { key, dir } = f.highSignal && this.sort.key === 'id' ? { key: 'signal', dir: -1 } : this.sort;
    const val = (t) =>
      key === 'id'
        ? t.id
        : key === 'state'
          ? THREAT_STATES.indexOf(t.state)
          : key === 'priority'
            ? this.store.kb.priorities().indexOf(t.priority)
            : key === 'signal'
              ? (t.signal?.score ?? 0)
              : key === 'title'
                ? displayTitle(t).toLowerCase()
                : String(t[key] ?? '').toLowerCase();
    return [...list].sort((a, b) => (val(a) < val(b) ? -dir : val(a) > val(b) ? dir : a.id - b.id));
  }

  renderThreats() {
    const { store } = this;
    const kb = store.kb;
    const f = this.filters;
    const setF = (k) => (v) => {
      this.filters[k] = v;
      this.renderBody();
    };
    const search = h('input', { type: 'search', placeholder: 'Search threats…', value: f.text, 'aria-label': 'Search threats' });
    let t;
    search.addEventListener('input', () => {
      clearTimeout(t);
      t = setTimeout(() => {
        this.filters.text = search.value;
        this.renderTable();
      }, 180);
    });
    const idx = elementIndex(store.model);
    const highCount = store.model.threats.filter((x) => x.signal?.level === 'high').length;
    const hs = h('input', { type: 'checkbox', checked: f.highSignal, id: 'hsview' });
    hs.addEventListener('change', () => setF('highSignal')(hs.checked));
    const filters = h(
      'div',
      { class: 'filters' },
      h(
        'label',
        { class: 'check hs-toggle', for: 'hsview', title: 'Only threats backed by source evidence, dangerous sinks or weak controls, ranked by signal score' },
        hs,
        `High-signal view (${highCount})`,
      ),
      search,
      select([{ value: 'diagram', label: 'This diagram' }, { value: 'all', label: 'All diagrams' }], f.scope, setF('scope'), { 'aria-label': 'Scope' }),
      select([{ value: '', label: 'All states' }, ...THREAT_STATES.map((s) => ({ value: s, label: THREAT_STATE_LABELS[s] }))], f.state, setF('state'), { 'aria-label': 'State filter' }),
      select([{ value: '', label: 'All categories' }, ...kb.categories.map((c) => ({ value: c.id, label: c.name }))], f.category, setF('category'), { 'aria-label': 'Category filter' }),
      select([{ value: '', label: 'All priorities' }, ...kb.priorities().map((p) => ({ value: p, label: p }))], f.priority, setF('priority'), { 'aria-label': 'Priority filter' }),
      f.element
        ? h('button', { class: 'btn small outline', type: 'button', onClick: () => setF('element')('') }, `Element: ${idx.get(f.element)?.element.name || '?'}`, icon('x', 13))
        : null,
    );
    this.tableWrap = h('div', { class: 'table-wrap' });
    const pane = h('div', { class: 'threat-pane' }, filters, this.tableWrap);
    this.body.appendChild(pane);
    this.renderTable();
    const th = store.selectedThreatKey ? findThreat(store.model, store.selectedThreatKey) : null;
    if (th) {
      this.body.classList.add('has-detail');
      this.body.appendChild(this.renderThreatDetail(th));
    }
  }

  renderTable() {
    const { store } = this;
    const kb = store.kb;
    const list = this.currentThreats();
    clear(this.tableWrap);
    if (!list.length) {
      const any = store.model.threats.length;
      this.tableWrap.appendChild(
        h(
          'div',
          { class: 'empty' },
          any ? 'No threats match the filters.' : 'No threats yet. Connect elements with data flows, and draw trust boundaries across flows that change trust level.',
        ),
      );
      return;
    }
    const cols = [
      ['id', 'ID'],
      ['state', 'State'],
      ['priority', 'Priority'],
      ['category', 'Category'],
      ['signal', 'Signal'],
      ['title', 'Title'],
      ['interaction', 'Interaction'],
    ];
    const head = h(
      'tr',
      null,
      cols.map(([k, label]) =>
        h(
          'th',
          {
            scope: 'col',
            'aria-sort': this.sort.key === k ? (this.sort.dir > 0 ? 'ascending' : 'descending') : undefined,
            onClick: () => {
              this.sort = { key: k, dir: this.sort.key === k ? -this.sort.dir : 1 };
              this.renderTable();
            },
          },
          label,
          this.sort.key === k ? (this.sort.dir > 0 ? ' ▲' : ' ▼') : '',
        ),
      ),
    );
    const rows = list.map((t) => {
      const tr = h(
        'tr',
        {
          'aria-selected': String(t.key === store.selectedThreatKey),
          class: t.orphan ? 'orphan' : undefined,
          tabindex: '0',
          onClick: () => this.pickThreat(t),
          onKeydown: (e) => e.key === 'Enter' && this.pickThreat(t),
        },
        h('td', null, String(t.id)),
        h('td', null, h('span', { class: `pill s-${t.state}` }, THREAT_STATE_LABELS[t.state])),
        h('td', { class: `p-${t.priority}` }, t.priority),
        h('td', null, kb.category(t.category)?.name || t.category),
        h(
          'td',
          { title: (t.signal?.reasons || []).join(', ') || 'No evidence-backed signal' },
          h('span', { class: `pill g-${t.signal?.level || 'generic'}` }, `${SIGNAL_LABELS[t.signal?.level] || SIGNAL_LABELS.generic} · ${t.signal?.score ?? 0}`),
        ),
        h(
          'td',
          { class: 'title' },
          displayTitle(t),
          displayTitle(t) !== t.title ? h('span', { class: 'muted small' }, `  (rule: ${t.title})`) : null,
          t.userDefined ? h('span', { class: 'muted small' }, '  (user-defined)') : null,
        ),
        h('td', { class: 'small muted' }, t.orphan ? 'No longer present in the diagram' : t.interaction),
      );
      return tr;
    });
    this.tableWrap.appendChild(h('table', { class: 'grid' }, h('thead', null, head), h('tbody', null, rows)));
  }

  pickThreat(t) {
    const { store } = this;
    store.selectThreat(t.key);
    if (!t.orphan) {
      if (t.diagramId !== store.activeDiagramId && store.model.diagrams.some((d) => d.id === t.diagramId)) store.setDiagram(t.diagramId);
      store.setHighlight([t.flowId, t.sourceId, t.targetId].filter(Boolean));
      this.app.canvas.reveal(t.flowId);
    }
  }

  renderThreatDetail(t) {
    const { store } = this;
    const kb = store.kb;
    const upd = (patch) => {
      try {
        store.commit((m) => updateThreat(m, t.key, patch, USER));
      } catch (e) {
        toast(e.message);
      }
    };
    const box = h('div', { class: 'detail', 'aria-label': 'Threat details' });
    box.append(
      h(
        'div',
        { class: 'row', style: { justifyContent: 'space-between' } },
        h('b', null, `Threat ${t.id}`),
        h('button', { class: 'btn small', type: 'button', 'aria-label': 'Close details', onClick: () => store.selectThreat(null) }, icon('x', 15)),
      ),
      h('p', { class: 'small muted' }, t.orphan ? 'This interaction no longer exists in the diagram; kept because it was triaged.' : t.interaction),
      t.signal
        ? h(
            'div',
            { class: 'signal-box' },
            h('span', { class: `pill g-${t.signal.level}` }, `${SIGNAL_LABELS[t.signal.level]} · score ${t.signal.score}`),
            t.signal.title ? h('p', { class: 'small' }, h('b', null, 'Finding: '), t.signal.title) : null,
            t.signal.reasons.length ? h('p', { class: 'small muted' }, `Why: ${t.signal.reasons.join(', ')}`) : null,
            t.signal.evidence?.length ? h('p', { class: 'small muted' }, `Evidence: ${t.signal.evidence.join(', ')}`) : null,
            t.signal.fix ? h('p', { class: 'small' }, h('b', null, 'Fix: '), t.signal.fix) : null,
          )
        : null,
      field('Title', textInput(t.title, (v) => upd({ title: v }))),
      h(
        'div',
        { class: 'row' },
        field('State', select(THREAT_STATES.map((s) => ({ value: s, label: THREAT_STATE_LABELS[s] })), t.state, (v) => upd({ state: v }))),
        field('Priority', select(kb.priorities(), t.priority, (v) => upd({ priority: v }))),
      ),
      field('Category', select(kb.categories.map((c) => ({ value: c.id, label: c.name })), t.category, (v) => upd({ category: v }))),
      field(
        'Justification',
        textInput(t.justification, (v) => upd({ justification: v }), { placeholder: t.state === 'NotApplicable' ? 'Explain why this threat does not apply' : 'How is this threat mitigated or why was this state chosen?' }, true),
      ),
      field('Description', textInput(t.description, (v) => upd({ description: v }), {}, true)),
      field('Mitigation', textInput(t.mitigation, (v) => upd({ mitigation: v }), {}, true)),
    );
    for (const p of kb.customThreatProperties()) {
      const cur = t.custom?.[p.name] ?? '';
      box.append(field(p.label, p.values.length ? select(['', ...p.values], cur, (v) => upd({ custom: { [p.name]: v } })) : textInput(cur, (v) => upd({ custom: { [p.name]: v } }))));
    }
    if (t.references?.length) box.append(h('p', { class: 'small' }, h('b', null, 'References: '), t.references.join(', ')));
    box.append(h('p', { class: 'small muted' }, `Type ${t.userDefined ? 'user-defined' : t.typeId}${t.changedBy ? ` · last changed by ${t.changedBy}` : ''}${t.modifiedAt ? ` on ${new Date(t.modifiedAt).toLocaleString()}` : ''}`));
    if (t.userDefined || t.orphan) {
      box.append(
        h(
          'button',
          {
            class: 'btn outline danger small',
            type: 'button',
            onClick: async () => {
              if (!(await confirmDialog('Delete threat', `Delete threat ${t.id} “${t.title}”?`, 'Delete', true))) return;
              store.commit((m) => deleteThreat(m, t.key));
              store.selectThreat(null);
            },
          },
          icon('trash', 15),
          'Delete threat',
        ),
      );
    }
    return box;
  }

  // ---------------------------------------------------------------- messages
  renderMessages() {
    const { store } = this;
    const all = store.messages;
    const list = all.filter((m) => this.showSuppressed || !m.suppressed);
    const toggle = h('input', { type: 'checkbox', checked: this.showSuppressed, id: 'showsup' });
    toggle.addEventListener('change', () => {
      this.showSuppressed = toggle.checked;
      this.renderBody();
    });
    const pane = h(
      'div',
      { class: 'list-pane' },
      h('div', { class: 'filters' }, h('label', { class: 'check', for: 'showsup', style: { margin: 0 } }, toggle, `Show suppressed (${all.filter((m) => m.suppressed).length})`)),
    );
    if (!list.length) pane.appendChild(h('div', { class: 'empty' }, 'No validation messages. Nice.'));
    for (const m of list) {
      const row = h(
        'div',
        { class: `msg${m.suppressed ? ' suppressed' : ''}`, tabindex: '0', role: 'button' },
        h('span', { class: `sev ${m.severity}` }, m.severity),
        h('span', { class: 'text' }, m.message, m.mtmt ? h('span', { class: 'small muted' }, '  (MTMT check)') : null),
        h(
          'button',
          {
            class: 'btn small',
            type: 'button',
            title: m.suppressed ? 'Show this message again' : 'Hide this message',
            onClick: (e) => {
              e.stopPropagation();
              store.commit((model) => suppressMessage(model, m.id, !m.suppressed), { immediate: true });
            },
          },
          m.suppressed ? 'Unhide' : 'Hide',
        ),
      );
      const go = () => {
        if (m.diagramId && m.diagramId !== store.activeDiagramId) store.setDiagram(m.diagramId);
        const ids = m.elementIds.filter((id) => !id.startsWith('rule:'));
        if (ids.length) {
          store.select(ids);
          this.app.canvas.reveal(ids[0]);
        } else if (m.issue === 'rule.error') this.app.openTemplate(m.elementIds[0]?.slice(5));
      };
      row.addEventListener('click', go);
      row.addEventListener('keydown', (e) => e.key === 'Enter' && go());
      pane.appendChild(row);
    }
    this.body.appendChild(pane);
  }

  // ---------------------------------------------------------------- notes
  renderNotes() {
    const { store } = this;
    const ta = h('textarea', { placeholder: 'Add a note: decisions, open questions, review comments…', 'aria-label': 'New note', rows: 2, style: { flex: 1 } });
    const add = () => {
      const text = ta.value.trim();
      if (!text) return;
      store.commit((m) => m.notes.push({ id: `nt_${Date.now().toString(36)}`, text, author: store.model.meta.owner || '', date: new Date().toISOString() }));
    };
    const pane = h(
      'div',
      { class: 'list-pane' },
      h('div', { class: 'filters', style: { alignItems: 'stretch' } }, ta, h('button', { class: 'btn primary', type: 'button', onClick: add }, 'Add note')),
    );
    const notes = [...store.model.notes].reverse();
    if (!notes.length) pane.appendChild(h('div', { class: 'empty' }, 'No notes yet. Notes are included in reports.'));
    for (const n of notes) {
      pane.appendChild(
        h(
          'div',
          { class: 'note' },
          h(
            'div',
            { class: 'row', style: { justifyContent: 'space-between' } },
            h('span', { class: 'who' }, `${n.author || 'Anonymous'} · ${n.date ? new Date(n.date).toLocaleString() : ''}`),
            h(
              'button',
              { class: 'btn small', type: 'button', 'aria-label': 'Delete note', onClick: () => store.commit((m) => (m.notes = m.notes.filter((x) => x.id !== n.id))) },
              icon('trash', 14),
            ),
          ),
          h('div', { style: { whiteSpace: 'pre-wrap' } }, n.text),
        ),
      );
    }
    this.body.appendChild(pane);
  }
}

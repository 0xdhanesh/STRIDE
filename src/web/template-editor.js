// Template & rule editor (MTMT "Template Editor"): threat types with live rule
// validation, element types and attributes, import/export of templates.

import {
  DEFAULT_TEMPLATE,
  GENERIC,
  GENERIC_IDS,
  applyTemplate,
  clone,
  elementIndex,
  interactionContext,
  isApplicable,
  kbFor,
  normalizeTemplate,
  parseTemplateText,
  validateRule,
} from '../core/index.js';
import { clear, confirmDialog, downloadText, field, h, icon, modal, pickFile, promptDialog, select, toast } from './dom.js';

export async function openTemplateEditor(store, focusThreatTypeId) {
  let work = clone(store.model.template);
  let tab = focusThreatTypeId ? 'threats' : 'overview';
  let selTT = focusThreatTypeId || work.threatTypes[0]?.id;
  let selEl = work.elements.find((e) => !GENERIC_IDS.includes(e.id))?.id || work.elements[0]?.id;
  let query = '';
  const root = h('div');
  const kbOf = () => {
    try {
      return kbFor(normalizeTemplate(work));
    } catch {
      return null;
    }
  };

  const selectedFlowCtx = () => {
    const { model, diagram, selection } = store;
    const flow = diagram.elements.find((e) => selection.has(e.id) && e.generic === GENERIC.FLOW);
    if (!flow) return null;
    const idx = elementIndex(model);
    const s = idx.get(flow.source)?.element;
    const t = idx.get(flow.target)?.element;
    if (!s || !t) return null;
    // Evaluate against the working template.
    const tmp = { ...model, template: normalizeTemplate(work) };
    return { flow, ctx: interactionContext(tmp, diagram, flow, s, t) };
  };

  const render = () => {
    const tabs = h(
      'div',
      { class: 'seg', role: 'tablist', style: { marginBottom: '14px' } },
      [
        ['overview', 'Overview'],
        ['threats', `Threat types (${work.threatTypes.length})`],
        ['elements', `Element types (${work.elements.length})`],
      ].map(([id, label]) =>
        h(
          'button',
          {
            type: 'button',
            'aria-pressed': String(tab === id),
            onClick: () => {
              tab = id;
              render();
            },
          },
          label,
        ),
      ),
    );
    clear(root).append(tabs, tab === 'overview' ? overview() : tab === 'threats' ? threats() : elements());
  };

  // ---------------------------------------------------------------- overview
  const overview = () => {
    const m = work.manifest;
    const inp = (k, label, multi) => {
      const el = h(multi ? 'textarea' : 'input', { value: m[k] || '' });
      el.value = m[k] || '';
      el.addEventListener('input', () => (m[k] = el.value));
      return field(label, el);
    };
    const kb = kbOf();
    return h(
      'div',
      null,
      h('div', { class: 'row', style: { gap: '14px', alignItems: 'flex-start' } }, h('div', { style: { flex: 1 } }, inp('name', 'Name'), inp('version', 'Version'), inp('author', 'Author'), inp('description', 'Description', true)),
        h(
          'div',
          { style: { width: '260px' } },
          h('div', { class: 'stat-grid' }, h('div', { class: 'stat' }, h('b', null, work.threatTypes.length), h('span', null, 'Threat types')), h('div', { class: 'stat' }, h('b', null, work.elements.length), h('span', null, 'Element types')), h('div', { class: 'stat' }, h('b', null, work.categories.length), h('span', null, 'Categories')), h('div', { class: 'stat' }, h('b', null, kb ? kb.boundaryTypeIds().length : '—'), h('span', null, 'Boundary types'))),
        ),
      ),
      h('h4', null, 'Import / export'),
      h('p', { class: 'small muted' }, 'Import a Microsoft Threat Modeling Tool template (.tb7) or a STRIDE template (.json). The import replaces this working copy; nothing changes until you press Apply.'),
      h(
        'div',
        { class: 'row', style: { flexWrap: 'wrap' } },
        h(
          'button',
          {
            class: 'btn outline',
            type: 'button',
            onClick: async () => {
              const f = await pickFile('.tb7,.json,application/json,text/xml');
              if (!f) return;
              try {
                work = clone(parseTemplateText(f.text));
                selTT = work.threatTypes[0]?.id;
                toast(`Loaded “${work.manifest.name}” — press Apply to use it.`);
                render();
              } catch (e) {
                toast(`Could not import template: ${e.message}`, 5000);
              }
            },
          },
          icon('upload', 16),
          'Import template…',
        ),
        h('button', { class: 'btn outline', type: 'button', onClick: () => downloadText(`${slug(work.manifest.name)}.template.json`, JSON.stringify(normalizeTemplate(work), null, 2), 'application/json') }, icon('download', 16), 'Export template JSON'),
        h(
          'button',
          {
            class: 'btn outline',
            type: 'button',
            onClick: async () => {
              if (!(await confirmDialog('Reset template', 'Replace the working copy with the built-in STRIDE Core template?', 'Reset'))) return;
              work = clone(DEFAULT_TEMPLATE);
              render();
            },
          },
          'Reset to STRIDE Core',
        ),
      ),
      h('h4', null, 'Rule language'),
      h(
        'div',
        { class: 'small' },
        h('p', null, 'Rules are evaluated for every data flow as source → flow → target. A threat is created when Include matches and Exclude does not.'),
        h(
          'ul',
          null,
          h('li', null, h('code', null, "source is 'GE.P'"), ' — type test; matches subtypes (a Web Application is a GE.P).'),
          h('li', null, h('code', null, "flow.providesConfidentiality is 'Yes'"), ' — property test (property name, case-insensitive).'),
          h('li', null, h('code', null, "flow crosses 'GE.TB.B'"), ' — the drawn flow crosses a boundary of that type.'),
          h('li', null, h('code', null, 'and'), ', ', h('code', null, 'or'), ', ', h('code', null, 'not'), ' (single rule only) and parentheses.'),
          h('li', null, 'Titles and descriptions can use ', h('code', null, '{source.Name}'), ', ', h('code', null, '{flow.Name}'), ', ', h('code', null, '{target.Name}'), ' and any property.'),
        ),
      ),
    );
  };

  // ---------------------------------------------------------------- threat types
  const threats = () => {
    const kb = kbOf();
    const list = h('div', { class: 'tpl-list' });
    const fill = () => {
      clear(list);
      const q = query.toLowerCase();
      for (const t of work.threatTypes.filter((x) => !q || `${x.id} ${x.title} ${x.category}`.toLowerCase().includes(q))) {
        const bad = !validateRule(t.include, kb).ok || !validateRule(t.exclude, kb).ok;
        list.appendChild(
          h(
            'button',
            {
              type: 'button',
              'aria-selected': String(t.id === selTT),
              onClick: () => {
                selTT = t.id;
                render();
              },
            },
            h('div', { class: 'id' }, `${t.category} · ${t.id}${t.legacy ? ' · legacy' : ''}${bad ? ' · ⚠ rule error' : ''}`),
            t.title,
          ),
        );
      }
    };
    const search = h('input', { type: 'search', placeholder: 'Filter threat types', value: query, style: { width: '100%', marginBottom: '8px' } });
    search.addEventListener('input', () => {
      query = search.value;
      fill();
    });
    fill();
    const tt = work.threatTypes.find((t) => t.id === selTT);
    const left = h(
      'div',
      null,
      search,
      list,
      h(
        'div',
        { class: 'row', style: { marginTop: '8px' } },
        h(
          'button',
          {
            class: 'btn outline small',
            type: 'button',
            onClick: async () => {
              const id = (await promptDialog('New threat type', 'Unique id (e.g. T20)', nextId(work)))?.trim();
              if (!id) return;
              if (work.threatTypes.some((t) => t.id === id)) return toast('That id is already used.');
              work.threatTypes.push({ id, title: 'New threat on {target.Name}', category: work.categories[0]?.id || 'S', priority: 'Medium', include: "target is 'GE.P'", exclude: '', description: '', mitigation: '', properties: {}, references: [] });
              selTT = id;
              render();
            },
          },
          icon('plus', 14),
          'Add',
        ),
        tt
          ? h(
              'button',
              {
                class: 'btn outline small',
                type: 'button',
                onClick: () => {
                  const copy = { ...clone(tt), id: nextId(work, tt.id) };
                  work.threatTypes.push(copy);
                  selTT = copy.id;
                  render();
                },
              },
              'Duplicate',
            )
          : null,
      ),
    );
    return h('div', { class: 'tpl-layout' }, left, tt ? threatEditor(tt, kb) : h('div', { class: 'empty' }, 'Select a threat type.'));
  };

  const threatEditor = (tt, kb) => {
    const ruleStatus = (key) => {
      const out = h('div');
      const check = () => {
        clear(out);
        const r = validateRule(tt[key], kb);
        if (!tt[key].trim()) out.appendChild(h('div', { class: 'muted small' }, key === 'include' ? 'Empty include never matches.' : 'No exclusions.'));
        else if (r.ok) out.appendChild(h('div', { class: 'rule-ok' }, '✔ Valid rule'));
        for (const e of r.errors) out.appendChild(h('div', { class: 'rule-err' }, e));
        for (const w of r.warnings) out.appendChild(h('div', { class: 'rule-warn' }, w));
      };
      check();
      return { out, check };
    };
    const testOut = h('div', { class: 'small' });
    const runTest = () => {
      clear(testOut);
      const sel = selectedFlowCtx();
      if (!sel) {
        testOut.appendChild(h('span', { class: 'muted' }, 'Select a connected data flow on the canvas to test this rule against it.'));
        return;
      }
      try {
        const yes = isApplicable(tt, sel.ctx);
        testOut.appendChild(h('span', { class: yes ? 'rule-ok' : 'muted' }, `${yes ? '✔ Generates' : '✘ Does not generate'} for flow “${sel.flow.name}”.`));
      } catch (e) {
        testOut.appendChild(h('span', { class: 'rule-err' }, `Evaluation error on “${sel.flow.name}”: ${e.message}`));
      }
    };
    const text = (key, label, multi = false, cls = '') => {
      const el = h(multi ? 'textarea' : 'input', { class: cls, spellcheck: multi && !cls ? 'true' : 'false' });
      el.value = tt[key] || '';
      const status = key === 'include' || key === 'exclude' ? ruleStatus(key) : null;
      el.addEventListener('input', () => {
        tt[key] = el.value;
        status?.check();
        if (status) runTest();
      });
      return h('div', null, field(label, el), status?.out);
    };
    const refs = h('input', { value: (tt.references || []).join(', ') });
    refs.addEventListener('input', () => (tt.references = refs.value.split(',').map((s) => s.trim()).filter(Boolean)));
    runTest();
    return h(
      'div',
      null,
      h('div', { class: 'row', style: { justifyContent: 'space-between' } }, h('h3', { style: { margin: 0 } }, `Threat type ${tt.id}`), h(
        'button',
        {
          class: 'btn outline danger small',
          type: 'button',
          onClick: async () => {
            if (!(await confirmDialog('Delete threat type', `Delete threat type ${tt.id}? Existing untouched threats of this type will be removed on Apply.`, 'Delete', true))) return;
            work.threatTypes = work.threatTypes.filter((t) => t !== tt);
            selTT = work.threatTypes[0]?.id;
            render();
          },
        },
        icon('trash', 14),
        'Delete',
      )),
      text('title', 'Title (supports {source.Name}, {flow.Name}, {target.Name})'),
      h(
        'div',
        { class: 'row' },
        field('Category', select(work.categories.map((c) => ({ value: c.id, label: c.name })), tt.category, (v) => (tt.category = v))),
        field('Default priority', select(['', ...(kb?.priorities() || ['High', 'Medium', 'Low'])], tt.priority || '', (v) => (tt.priority = v))),
      ),
      text('include', 'Include rule', true, 'code'),
      text('exclude', 'Exclude rule', true, 'code'),
      h('div', { style: { margin: '2px 0 10px' } }, testOut),
      text('description', 'Description', true),
      text('mitigation', 'Mitigation guidance', true),
      field('References (comma separated, e.g. CWE-79, OWASP-A03)', refs),
    );
  };

  // ---------------------------------------------------------------- element types
  const elements = () => {
    const kb = kbOf();
    const list = h('div', { class: 'tpl-list' });
    const order = [...work.elements].sort((a, b) => (kb?.genericOf(a.id) || '').localeCompare(kb?.genericOf(b.id) || '') || (GENERIC_IDS.includes(b.id) ? 1 : 0) - (GENERIC_IDS.includes(a.id) ? 1 : 0));
    for (const e of order) {
      list.appendChild(
        h(
          'button',
          {
            type: 'button',
            'aria-selected': String(e.id === selEl),
            onClick: () => {
              selEl = e.id;
              render();
            },
          },
          h('div', { class: 'id' }, e.id),
          GENERIC_IDS.includes(e.id) ? h('b', null, e.name) : e.name,
        ),
      );
    }
    const el = work.elements.find((e) => e.id === selEl);
    const left = h(
      'div',
      null,
      list,
      h(
        'button',
        {
          class: 'btn outline small',
          type: 'button',
          style: { marginTop: '8px' },
          onClick: async () => {
            const parent = el && el.id !== 'ROOT' ? el.id : 'GE.P';
            const name = (await promptDialog('New element type', `Name of the new type (derived from ${parent})`, 'New element'))?.trim();
            if (!name) return;
            const base = `SE.${(kb?.genericOf(parent) || 'GE.P').slice(3)}.Custom.${name.replace(/[^A-Za-z0-9]+/g, '')}` || 'SE.Custom';
            let id = base;
            for (let i = 2; work.elements.some((e) => e.id === id); i++) id = `${base}${i}`;
            work.elements.push({ id, name, parent, description: '', hidden: false, attributes: [] });
            selEl = id;
            render();
          },
        },
        icon('plus', 14),
        'Add derived type',
      ),
    );
    return h('div', { class: 'tpl-layout' }, left, el ? elementEditor(el, kb) : h('div', { class: 'empty' }, 'Select an element type.'));
  };

  const elementEditor = (el, kb) => {
    const isGeneric = GENERIC_IDS.includes(el.id);
    const inp = (k, label, multi) => {
      const x = h(multi ? 'textarea' : 'input');
      x.value = el[k] || '';
      x.addEventListener('input', () => (el[k] = x.value));
      return field(label, x);
    };
    const hidden = h('input', { type: 'checkbox', checked: el.hidden });
    hidden.addEventListener('change', () => (el.hidden = hidden.checked));
    const attrsBox = h('div');
    const drawAttrs = () => {
      clear(attrsBox);
      el.attributes.forEach((a, i) => {
        const name = h('input', { value: a.name, 'aria-label': 'Attribute name', class: 'code' });
        name.addEventListener('input', () => (a.name = name.value.trim()));
        const label = h('input', { value: a.label, 'aria-label': 'Label' });
        label.addEventListener('input', () => (a.label = label.value));
        const values = h('input', { value: (a.values || []).join(', '), 'aria-label': 'Values (comma separated, first is default)' });
        values.addEventListener('input', () => (a.values = values.value.split(',').map((s) => s.trim()).filter(Boolean)));
        const fixed = h('input', { type: 'checkbox', checked: a.mode === 'static', title: 'Fixed value (static)' });
        fixed.addEventListener('change', () => (a.mode = fixed.checked ? 'static' : 'dynamic'));
        attrsBox.appendChild(
          h(
            'div',
            { style: { display: 'grid', gridTemplateColumns: '1fr 1fr 2fr auto auto', gap: '6px', marginBottom: '6px', alignItems: 'center' } },
            name,
            label,
            values,
            h('label', { class: 'small', title: 'Fixed by this type' }, fixed, ' fixed'),
            h(
              'button',
              {
                class: 'btn small',
                type: 'button',
                'aria-label': 'Remove attribute',
                onClick: () => {
                  el.attributes.splice(i, 1);
                  drawAttrs();
                },
              },
              icon('x', 14),
            ),
          ),
        );
      });
    };
    drawAttrs();
    const inherited = kb ? kb.attributes(el.parent && el.parent !== 'ROOT' ? el.parent : el.id).filter((a) => a.definedBy !== el.id) : [];
    return h(
      'div',
      null,
      h('div', { class: 'row', style: { justifyContent: 'space-between' } }, h('h3', { style: { margin: 0 } }, el.name), isGeneric
        ? h('span', { class: 'muted small' }, 'Generic root type')
        : h(
            'button',
            {
              class: 'btn outline danger small',
              type: 'button',
              onClick: async () => {
                const children = work.elements.filter((e) => e.parent === el.id);
                if (children.length) return toast('Delete or re-parent derived types first.');
                if (!(await confirmDialog('Delete element type', `Delete “${el.name}”? Elements of this type fall back to their generic type on Apply.`, 'Delete', true))) return;
                work.elements = work.elements.filter((e) => e !== el);
                selEl = work.elements[0]?.id;
                render();
              },
            },
            icon('trash', 14),
            'Delete',
          )),
      h('p', { class: 'small muted' }, `Id ${el.id} · parent ${el.parent}`),
      inp('name', 'Name'),
      inp('description', 'Description', true),
      h('label', { class: 'check' }, hidden, 'Hidden from the stencil palette'),
      h('h4', null, 'Attributes defined by this type'),
      h('p', { class: 'small muted' }, 'Name (used in rules) · label · values (first is the default) · fixed. An attribute with the same name as an inherited one overrides it.'),
      attrsBox,
      h(
        'button',
        {
          class: 'btn outline small',
          type: 'button',
          onClick: () => {
            el.attributes.push({ name: `attr${el.attributes.length + 1}`, label: 'New attribute', values: ['No', 'Yes'], mode: 'dynamic', inheritance: 'virtual' });
            drawAttrs();
          },
        },
        icon('plus', 14),
        'Add attribute',
      ),
      inherited.length ? h('h4', null, 'Inherited attributes') : null,
      inherited.length ? h('p', { class: 'small muted' }, inherited.map((a) => `${a.label} (${a.name})`).join(' · ')) : null,
    );
  };

  render();
  const result = await modal({
    title: 'Template & rules',
    content: root,
    wide: true,
    buttons: [
      { label: 'Cancel', value: null },
      { label: 'Apply to model', value: 'apply', class: 'primary' },
    ],
  });
  if (result !== 'apply') return false;
  try {
    const tpl = normalizeTemplate(work);
    store.commit((m) => applyTemplate(m, tpl), { immediate: true });
    store.emit('template');
    toast(`Template “${tpl.manifest.name}” applied.`);
    return true;
  } catch (e) {
    toast(`Template not applied: ${e.message}`, 5000);
    return false;
  }
}

function slug(s) {
  return String(s || 'template').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'template';
}
function nextId(work, base = 'U') {
  const prefix = String(base).replace(/[0-9.]+$/, '') || 'U';
  for (let i = 1; ; i++) if (!work.threatTypes.some((t) => t.id === `${prefix}${i}`)) return `${prefix}${i}`;
}

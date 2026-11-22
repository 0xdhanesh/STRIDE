// Tiny DOM helpers. All text goes through textContent; no untrusted innerHTML.

const SVG_NS = 'http://www.w3.org/2000/svg';

/** h('div', {class:'x', onClick: fn}, child, 'text', [more]) */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === 'class') el.className = v;
      else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
      else if (k === 'value') el.value = v;
      else if (k === 'checked') el.checked = !!v;
      else if (k === 'text') el.textContent = v;
      else el.setAttribute(k, v === true ? '' : String(v));
    }
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children) {
    if (c === undefined || c === null || c === false) continue;
    if (Array.isArray(c)) append(el, c);
    else if (c instanceof Node) el.appendChild(c);
    else el.appendChild(document.createTextNode(String(c)));
  }
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

/** Icons are static, trusted strings authored here. */
const ICONS = {
  select: '<path d="M5 3l14 8-6 1.5L10 19z"/>',
  hand: '<path d="M8 13V5.5a1.5 1.5 0 013 0V11m0-1.5V4a1.5 1.5 0 013 0v6m0-1.5V5.5a1.5 1.5 0 013 0V14a7 7 0 01-7 7h-.5a6 6 0 01-5-2.7L3.3 15a1.5 1.5 0 012.4-1.8L8 15"/>',
  process: '<ellipse cx="12" cy="12" rx="9" ry="7"/>',
  external: '<rect x="3.5" y="6" width="17" height="12" rx="1"/>',
  store: '<path d="M3 7h18M3 17h18"/>',
  flow: '<path d="M4 18C9 6 15 6 20 6"/><path d="M15 3.5l5 2.5-3.5 4"/>',
  'line-boundary': '<path d="M5 20C6 12 12 5 20 4" stroke-dasharray="3 3"/>',
  'box-boundary': '<rect x="3.5" y="4.5" width="17" height="15" rx="1.5" stroke-dasharray="3 3"/>',
  annotation: '<path d="M6 6h12M12 6v13M9 19h6"/>',
  undo: '<path d="M9 14L4 9l5-5"/><path d="M4 9h10a6 6 0 010 12h-3"/>',
  redo: '<path d="M15 14l5-5-5-5"/><path d="M20 9H10a6 6 0 000 12h3"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  minus: '<path d="M5 12h14"/>',
  menu: '<path d="M4 7h16M4 12h16M4 17h16"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M20 14.5A8 8 0 019.5 4a8 8 0 1010.5 10.5z"/>',
  trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
  download: '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
  upload: '<path d="M12 20V9M7 14l5-5 5 5M5 4h14"/>',
  report: '<path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5M10 13h6M10 17h6"/>',
  book: '<path d="M4 5a2 2 0 012-2h13v16H6a2 2 0 00-2 2z"/><path d="M4 19V5M8 7h7"/>',
  fit: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',
  keyboard: '<rect x="2.5" y="6" width="19" height="12" rx="2"/><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M7 14h10"/>',
  chevron: '<path d="M6 9l6 6 6-6"/>',
  x: '<path d="M6 6l12 12M18 6L6 18"/>',
  swap: '<path d="M7 7h12l-4-4M17 17H5l4 4"/>',
  panel: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M15 4v16"/>',
};

export function icon(name, size = 18) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.8');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  svg.innerHTML = ICONS[name] || '';
  return svg;
}

let toastTimer;
export function toast(message, ms = 2600) {
  let el = document.querySelector('.toast');
  if (!el) {
    el = h('div', { class: 'toast', role: 'status', 'aria-live': 'polite' });
    document.body.appendChild(el);
  }
  el.textContent = message;
  el.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), ms);
}

export function downloadText(filename, text, type = 'text/plain') {
  const blob = new Blob([text], { type: `${type};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

export function openBlob(text, type = 'text/html') {
  const url = URL.createObjectURL(new Blob([text], { type: `${type};charset=utf-8` }));
  window.open(url, '_blank', 'noopener');
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

/** Ask the user for a file; resolves { name, text } or null. */
export function pickFile(accept) {
  return new Promise((resolve) => {
    const input = h('input', { type: 'file', accept, class: 'hidden' });
    input.addEventListener('change', async () => {
      const file = input.files?.[0];
      input.remove();
      if (!file) return resolve(null);
      if (file.size > 64 * 1024 * 1024) {
        toast('File is too large (max 64 MB).');
        return resolve(null);
      }
      resolve({ name: file.name, text: await file.text() });
    });
    document.body.appendChild(input);
    input.click();
  });
}

/** Modal dialog. content: Node; buttons: [{label, value, class}] → resolves clicked value. */
export function modal({ title, content, buttons = [{ label: 'Close', value: null }], wide = false, onOpen }) {
  return new Promise((resolve) => {
    const dlg = h('dialog', { 'aria-label': title, style: wide ? undefined : { maxWidth: '560px' } });
    const done = (v) => {
      dlg.close();
      dlg.remove();
      resolve(v);
    };
    const foot = h(
      'div',
      { class: 'dlg-foot' },
      buttons.map((b) => h('button', { class: `btn ${b.class || 'outline'}`, type: 'button', onClick: () => done(typeof b.value === 'function' ? b.value() : b.value) }, b.label)),
    );
    dlg.appendChild(
      h(
        'div',
        { class: 'dlg' },
        h('div', { class: 'dlg-head' }, h('h2', null, title), h('button', { class: 'btn', type: 'button', 'aria-label': 'Close', onClick: () => done(null) }, icon('x'))),
        h('div', { class: 'dlg-body' }, content),
        buttons.length ? foot : null,
      ),
    );
    dlg.addEventListener('cancel', (e) => {
      e.preventDefault();
      done(null);
    });
    document.body.appendChild(dlg);
    dlg.showModal();
    onOpen?.(dlg);
  });
}

export async function confirmDialog(title, message, okLabel = 'OK', danger = false) {
  const v = await modal({
    title,
    content: h('p', { style: { margin: 0 } }, message),
    buttons: [
      { label: 'Cancel', value: false },
      { label: okLabel, value: true, class: danger ? 'primary danger' : 'primary' },
    ],
  });
  return v === true;
}

export async function promptDialog(title, label, initial = '') {
  const input = h('input', { type: 'text', value: initial, style: { width: '100%' } });
  const v = await modal({
    title,
    content: h('label', { class: 'field' }, h('span', null, label), input),
    buttons: [
      { label: 'Cancel', value: null },
      { label: 'OK', value: () => input.value, class: 'primary' },
    ],
    onOpen: () => {
      input.focus();
      input.select();
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') input.closest('dialog').querySelector('.btn.primary').click();
      });
    },
  });
  return v;
}

export function field(label, control, cls = '') {
  return h('label', { class: `field ${cls}` }, h('span', null, label), control);
}

export function select(options, value, onChange, attrs = {}) {
  const el = h(
    'select',
    attrs,
    options.map((o) => {
      const opt = typeof o === 'string' ? { value: o, label: o } : o;
      return h('option', { value: opt.value, selected: opt.value === value ? true : undefined }, opt.label);
    }),
  );
  el.value = value ?? '';
  if (onChange) el.addEventListener('change', () => onChange(el.value));
  return el;
}

/** Debounced input binding: commits on change/blur, and live after a pause. */
export function textInput(value, onCommit, attrs = {}, multiline = false) {
  const el = h(multiline ? 'textarea' : 'input', { type: multiline ? undefined : 'text', ...attrs });
  el.value = value ?? '';
  let last = el.value;
  let t;
  const commit = () => {
    clearTimeout(t);
    if (el.value !== last) {
      last = el.value;
      onCommit(el.value);
    }
  };
  el.addEventListener('input', () => {
    clearTimeout(t);
    t = setTimeout(commit, 500);
  });
  el.addEventListener('change', commit);
  el.addEventListener('blur', commit);
  if (!multiline) el.addEventListener('keydown', (e) => e.key === 'Enter' && commit());
  return el;
}

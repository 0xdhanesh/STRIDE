// Technology symbols drawn inside DFD shapes (24×24 stroke icons, generic —
// not vendor logos). Used on the canvas, in exports and in the stencil library.

const heptagon = (() => {
  const pts = [], spokes = [];
  for (let i = 0; i < 7; i++) {
    const a = -Math.PI / 2 + (i * 2 * Math.PI) / 7;
    pts.push(`${(12 + 10 * Math.cos(a)).toFixed(1)} ${(12 + 10 * Math.sin(a)).toFixed(1)}`);
    spokes.push(`M${(12 + 3 * Math.cos(a)).toFixed(1)} ${(12 + 3 * Math.sin(a)).toFixed(1)}L${(12 + 7 * Math.cos(a)).toFixed(1)} ${(12 + 7 * Math.sin(a)).toFixed(1)}`);
  }
  return `<path d="M${pts.join('L')}Z"/><circle cx="12" cy="12" r="3"/><path d="${spokes.join('')}"/>`;
})();

export const GLYPHS = {
  database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  eventlog: '<rect x="2" y="7" width="17" height="10" rx="1"/><path d="M6.5 7v10M11 7v10M15 7v10"/><path d="M19 12h3M20.5 10.5 22 12l-1.5 1.5"/>',
  ivr: '<path d="M5 3h3.5l1.8 4.6-2.3 1.4a11 11 0 0 0 5 5l1.4-2.3 4.6 1.8V17a2 2 0 0 1-2 2A15 15 0 0 1 3 5a2 2 0 0 1 2-2z"/><path d="M15 2.5a6.5 6.5 0 0 1 6.5 6.5M15 6a3 3 0 0 1 3 3"/>',
  headset: '<path d="M3.5 15v-3a8.5 8.5 0 0 1 17 0v3"/><rect x="2" y="13.5" width="4" height="6.5" rx="1.5"/><rect x="18" y="13.5" width="4" height="6.5" rx="1.5"/><path d="M20 20c0 1.4-2.2 2-5 2h-2.5"/>',
  kubernetes: heptagon,
  container: '<path d="M12 2l9 5v10l-9 5-9-5V7z"/><path d="M3 7l9 5 9-5M12 12v10"/>',
  mcp: '<path d="M8.5 2v5M15.5 2v5"/><path d="M5.5 7h13v4a6.5 6.5 0 0 1-13 0z"/><path d="M12 17.5V22"/>',
  orchestrator: '<circle cx="12" cy="12" r="3"/><circle cx="4" cy="4.5" r="2"/><circle cx="20" cy="4.5" r="2"/><circle cx="4" cy="19.5" r="2"/><circle cx="20" cy="19.5" r="2"/><path d="M9.8 9.8 5.4 6M14.2 9.8 18.6 6M9.8 14.2 5.4 18M14.2 14.2 18.6 18"/>',
  agent: '<rect x="4" y="8" width="16" height="12" rx="3"/><path d="M12 4.5V8M9 13.5v1.5M15 13.5v1.5"/><circle cx="12" cy="3.5" r="1.2"/><path d="M2 13v3M22 13v3"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  phone: '<rect x="7" y="2" width="10" height="20" rx="2"/><path d="M11 18h2"/>',
  browser: '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="M2 9h20M5.5 6.5h.01M8 6.5h.01"/>',
  cloud: '<path d="M7 19a5 5 0 0 1-.9-9.9A6.5 6.5 0 0 1 18.5 9 4.5 4.5 0 0 1 17.5 19z"/>',
  key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3 21 2M17 6l3 3M15 8l2 2"/>',
  queue: '<rect x="2" y="8" width="5" height="8" rx="1"/><rect x="9.5" y="8" width="5" height="8" rx="1"/><rect x="17" y="8" width="5" height="8" rx="1"/>',
  gateway: '<path d="M12 2 3 6v6c0 5 4 8.5 9 10 5-1.5 9-5 9-10V6z"/><path d="M8 12h8M13 9l3 3-3 3"/>',
  function: '<path d="M14 3h-1a3 3 0 0 0-3 3v12a3 3 0 0 1-3 3H6M7 11h8"/>',
  file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
  cache: '<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>',
  log: '<path d="M4 5h16M4 10h16M4 15h10M4 20h7"/>',
  iot: '<rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M10 2v5M14 2v5M10 17v5M14 17v5M2 10h5M2 14h5M17 10h5M17 14h5"/>',
  attacker: '<path d="M12 2a8 8 0 0 0-8 8v4l2 2v4h12v-4l2-2v-4a8 8 0 0 0-8-8z"/><path d="M8.5 11.5h.01M15.5 11.5h.01M10 16h4"/>',
  idp: '<circle cx="12" cy="9" r="3.5"/><path d="M5.5 20a6.5 6.5 0 0 1 13 0"/><path d="M17 3.5 19 5.5l3.5-3.5"/>',
  vm: '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>',
};

export function glyphSVG(name, x, y, size, color, strokeWidth = 1.7) {
  const body = GLYPHS[name];
  if (!body) return '';
  const k = size / 24;
  return `<g transform="translate(${x} ${y}) scale(${k})" fill="none" stroke="${color}" stroke-width="${strokeWidth / k}" stroke-linecap="round" stroke-linejoin="round" pointer-events="none">${body}</g>`;
}

export function glyphIcon(name, size = 20) {
  return `<svg class="icon" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${GLYPHS[name] || ''}</svg>`;
}

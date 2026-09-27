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
  websocket: '<path d="M3 8h14M13.5 4.5 17 8l-3.5 3.5"/><path d="M21 16H7M10.5 12.5 7 16l3.5 3.5"/><circle cx="20.5" cy="8" r="1.5"/><circle cx="3.5" cy="16" r="1.5"/>',
  globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/>',
  loadbalancer: '<circle cx="12" cy="5" r="2.5"/><circle cx="4.5" cy="19" r="2.5"/><circle cx="12" cy="19" r="2.5"/><circle cx="19.5" cy="19" r="2.5"/><path d="M12 7.5v9M11 7.2 5.5 16.8M13 7.2l5.5 9.6"/>',
  proxy: '<rect x="8" y="3" width="8" height="18" rx="2"/><path d="M2 8h6M16 8h6M2 16h6M16 16h6"/>',
  firewall: '<rect x="2" y="4" width="20" height="16" rx="1"/><path d="M2 9.3h20M2 14.6h20M8 4v5.3M16 4v5.3M12 9.3v5.3M6 14.6V20M18 14.6V20"/>',
  vpn: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/><path d="M1 16h4M19 16h4"/>',
  lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/><circle cx="12" cy="16" r="1.3"/>',
  policy: '<path d="M12 3v18M5 21h14M5 7h14"/><path d="M5 7 2 14a3 3 0 0 0 6 0zM19 7l-3 7a3 3 0 0 0 6 0z"/>',
  cert: '<rect x="3" y="3" width="18" height="13" rx="1.5"/><path d="M7 8h10M7 11.5h6"/><circle cx="16.5" cy="17.5" r="3"/><path d="M15 20l-.5 3 2-1 2 1-.5-3"/>',
  directory: '<rect x="9" y="2" width="6" height="5" rx="1"/><rect x="2" y="17" width="6" height="5" rx="1"/><rect x="16" y="17" width="6" height="5" rx="1"/><path d="M12 7v5M5 17v-5h14v5"/>',
  pipeline: '<circle cx="5" cy="12" r="2.5"/><circle cx="19" cy="12" r="2.5"/><path d="M7.5 12h9M14 9l3 3-3 3"/><path d="M5 9.5V5h7"/>',
  registry: '<path d="M12 2 3 6.5l9 4.5 9-4.5z"/><path d="M3 12l9 4.5 9-4.5M3 17.5 12 22l9-4.5"/>',
  branch: '<circle cx="6" cy="5" r="2.5"/><circle cx="6" cy="19" r="2.5"/><circle cx="18" cy="7" r="2.5"/><path d="M6 7.5v9M18 9.5c0 5-6 4-11 8"/>',
  server: '<rect x="3" y="3" width="18" height="7" rx="1.5"/><rect x="3" y="14" width="18" height="7" rx="1.5"/><path d="M7 6.5h.01M7 17.5h.01M11 6.5h6M11 17.5h6"/>',
  terminal: '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="M6 9l3 3-3 3M11 15h6"/>',
  eye: '<path d="M1.5 12S5.5 4.5 12 4.5 22.5 12 22.5 12 18.5 19.5 12 19.5 1.5 12 1.5 12z"/><circle cx="12" cy="12" r="3.2"/>',
  radar: '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="5.5"/><path d="M12 12 19 5"/><circle cx="12" cy="12" r="1"/>',
  mail: '<rect x="2" y="4.5" width="20" height="15" rx="2"/><path d="m2.5 6 9.5 7 9.5-7"/>',
  wifi: '<path d="M2 8.5a15 15 0 0 1 20 0M5 12a10.5 10.5 0 0 1 14 0M8.5 15.5a5.5 5.5 0 0 1 7 0"/><circle cx="12" cy="19" r="1.2"/>',
  factory: '<path d="M2 21V10l6 4V10l6 4V6h4l2 15z"/><path d="M6 17h2M11 17h2"/>',
  gauge: '<path d="M4 18a9 9 0 1 1 16 0z"/><path d="M12 14l4-5"/><circle cx="12" cy="14" r="1.3"/>',
  chip: '<rect x="6" y="6" width="12" height="12" rx="1.5"/><rect x="9.5" y="9.5" width="5" height="5"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
  warehouse: '<ellipse cx="12" cy="4.5" rx="9" ry="2.5"/><path d="M3 4.5v15c0 1.4 4 2.5 9 2.5s9-1.1 9-2.5v-15M3 9.5c0 1.4 4 2.5 9 2.5s9-1.1 9-2.5M3 14.5c0 1.4 4 2.5 9 2.5s9-1.1 9-2.5"/>',
  search: '<circle cx="10.5" cy="10.5" r="7"/><path d="m16 16 6 6"/>',
  clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
  graph: '<circle cx="12" cy="3.5" r="2"/><circle cx="4" cy="8" r="2"/><circle cx="20" cy="8" r="2"/><circle cx="4" cy="16" r="2"/><circle cx="20" cy="16" r="2"/><circle cx="12" cy="20.5" r="2"/><path d="M12 5.5 5.7 7M12 5.5 18.3 7M4 10v4M20 10v4M5.7 17 12 18.5M18.3 17 12 18.5M5.7 9l12.6 6M18.3 9 5.7 15"/>',
  card: '<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20M6 15h4"/>',
  puzzle: '<path d="M4 7h4a2 2 0 1 1 4 0h4v4a2 2 0 1 1 0 4v4h-4a2 2 0 1 0-4 0H4v-4a2 2 0 1 0 0-4z"/>',
  cpu: '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 9h6v6H9z"/>',
  chain: '<rect x="2" y="8" width="8" height="8" rx="2"/><rect x="14" y="8" width="8" height="8" rx="2"/><path d="M10 12h4"/>',
  brain: '<path d="M9 3a3 3 0 0 0-3 3 3 3 0 0 0-2 5 3 3 0 0 0 1 5 3 3 0 0 0 4 4h0a3 3 0 0 0 3-3V6a3 3 0 0 0-3-3z"/><path d="M15 3a3 3 0 0 1 3 3 3 3 0 0 1 2 5 3 3 0 0 1-1 5 3 3 0 0 1-4 4h0a3 3 0 0 1-3-3"/>',
  mesh: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><path d="M10 6.5h4M10 17.5h4M6.5 10v4M17.5 10v4"/>',
  insider: '<circle cx="9" cy="8" r="4"/><path d="M2 21a7 7 0 0 1 12.5-4.3"/><path d="M19 13v4M19 20.5h.01"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>',
  usb: '<path d="M12 2v15M8 7l4-4 4 4M7 11v3l5 3 5-3v-3"/><circle cx="12" cy="20" r="2"/>',
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

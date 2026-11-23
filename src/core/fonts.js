// Report fonts. Reports are standalone HTML, so a font is a CSS stack of fonts the reader's
// machine already has (nothing is downloaded and nothing external is loaded).

export const REPORT_FONTS = Object.freeze({
  system: { label: 'System default', stack: 'system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif' },
  arial: { label: 'Arial', stack: 'Arial,"Helvetica Neue",Helvetica,sans-serif' },
  verdana: { label: 'Verdana (very clear, wide letters)', stack: 'Verdana,Tahoma,Geneva,sans-serif' },
  tahoma: { label: 'Tahoma', stack: 'Tahoma,Verdana,Geneva,sans-serif' },
  trebuchet: { label: 'Trebuchet MS', stack: '"Trebuchet MS","Lucida Grande",Tahoma,sans-serif' },
  calibri: { label: 'Calibri', stack: 'Calibri,Candara,"Segoe UI",Optima,sans-serif' },
  georgia: { label: 'Georgia (serif)', stack: 'Georgia,"Times New Roman",serif' },
  times: { label: 'Times New Roman (serif)', stack: '"Times New Roman",Times,serif' },
  mono: { label: 'Monospace', stack: 'ui-monospace,SFMono-Regular,Menlo,Consolas,monospace' },
});

export const DEFAULT_REPORT_FONT = 'system';

export class FontError extends Error {}

/**
 * Resolve a font choice: a preset id (see REPORT_FONTS) or the plain name of any font installed on
 * the reader's machine, e.g. "Segoe UI". Names are restricted to letters, digits, spaces and hyphens
 * so they can never break out of the stylesheet.
 */
export function resolveFont(font) {
  if (font === undefined || font === null || font === '') return null;
  const raw = String(font).trim();
  const preset = REPORT_FONTS[raw.toLowerCase()];
  if (preset) return { id: raw.toLowerCase(), label: preset.label, stack: preset.stack };
  if (/^[A-Za-z0-9][A-Za-z0-9 \-]{0,39}$/.test(raw)) return { id: 'custom', label: raw, stack: `"${raw}",${REPORT_FONTS.system.stack}` };
  throw new FontError(`Unknown font '${raw}'. Use one of: ${Object.keys(REPORT_FONTS).join(', ')} — or the plain name of a font installed on the reader's computer (letters, digits, spaces and hyphens only).`);
}

/** CSS that applies a font everywhere in a report, including the diagram labels. Empty when no font was chosen. */
export function fontCss(font) {
  const f = resolveFont(font);
  if (!f) return '';
  return `body,table,button,input,select,textarea{font-family:${f.stack}}.dg text,figure svg text{font-family:inherit!important}`;
}

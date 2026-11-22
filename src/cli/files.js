// File I/O helpers for the CLI and MCP server (Node only).

import fs from 'node:fs';
import path from 'node:path';
import { DEFAULT_TEMPLATE, loadModel, normalizeTemplate, parseTemplateText, serializeModel } from '../core/index.js';

export const MAX_FILE_BYTES = 64 * 1024 * 1024;

export function readText(file) {
  const st = fs.statSync(file);
  if (!st.isFile()) throw new Error(`Not a file: ${file}`);
  if (st.size > MAX_FILE_BYTES) throw new Error(`File too large: ${file}`);
  return fs.readFileSync(file, 'utf8');
}

/** Atomic write: temp file in the same directory, then rename. */
export function writeTextAtomic(file, text) {
  const dir = path.dirname(path.resolve(file));
  fs.mkdirSync(dir, { recursive: true });
  const tmp = path.join(dir, `.${path.basename(file)}.${process.pid}.${Date.now()}.tmp`);
  fs.writeFileSync(tmp, text, 'utf8');
  fs.renameSync(tmp, file);
}

export function loadModelFile(file) {
  if (!fs.existsSync(file)) throw new Error(`Model file not found: ${file}`);
  return loadModel(readText(file));
}

export function saveModelFile(file, model) {
  writeTextAtomic(file, serializeModel(model) + '\n');
}

export function loadTemplateFile(file) {
  if (!file) return normalizeTemplate(DEFAULT_TEMPLATE);
  return parseTemplateText(readText(file));
}

/**
 * Sandbox for paths supplied by MCP clients: resolve against `root` and refuse
 * anything outside it or with an unexpected extension.
 */
export function sandboxPath(root, p, { write = false, extensions } = {}) {
  if (typeof p !== 'string' || !p.trim()) throw new Error('A file path is required');
  if (p.includes('\0')) throw new Error('Invalid path');
  const base = fs.realpathSync(root);
  const abs = path.resolve(base, p);
  // Resolve symlinks of the existing portion of the path.
  let probe = abs;
  while (!fs.existsSync(probe)) probe = path.dirname(probe);
  const realProbe = fs.realpathSync(probe);
  const real = path.join(realProbe, path.relative(probe, abs));
  const rel = path.relative(base, real);
  if (rel.startsWith('..') || path.isAbsolute(rel)) throw new Error(`Path is outside the allowed root (${base}): ${p}`);
  const allowed = extensions || (write ? ['.json', '.html', '.htm', '.csv', '.md', '.svg'] : null);
  if (allowed && !allowed.includes(path.extname(real).toLowerCase())) {
    throw new Error(`File extension not allowed: ${path.extname(real) || '(none)'}. Allowed: ${allowed.join(', ')}`);
  }
  return real;
}

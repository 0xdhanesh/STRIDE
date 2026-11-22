// `stride` command-line interface.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createModel, kbOf } from '../core/index.js';
import { loadModelFile, loadTemplateFile, readText, saveModelFile, writeTextAtomic } from './files.js';
import * as ops from './ops.js';
import { runMcpServer } from './mcp.js';

const BOOLEAN = new Set(['json', 'dry-run', 'cascade', 'no-generate', 'in-scope', 'strict', 'force', 'help', 'all', 'no-prune']);
const REPEATABLE = new Set(['prop', 'custom', 'state', 'category', 'priority', 'around']);
const SHORT = { o: 'out', h: 'help', t: 'template', n: 'name', d: 'diagram' };

export function parseArgs(argv) {
  const pos = [];
  const opts = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') {
      pos.push(...argv.slice(i + 1));
      break;
    }
    let key;
    let val;
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      key = eq > 0 ? a.slice(2, eq) : a.slice(2);
      if (eq > 0) val = a.slice(eq + 1);
    } else if (/^-[a-zA-Z]$/.test(a)) key = SHORT[a[1]] || a[1];
    else {
      pos.push(a);
      continue;
    }
    if (val === undefined) {
      if (BOOLEAN.has(key)) val = true;
      else if (key === 'out-of-scope') {
        val = argv[i + 1] && !argv[i + 1].startsWith('-') ? argv[++i] : true;
      } else {
        if (i + 1 >= argv.length) throw new UsageError(`Option --${key} needs a value`);
        val = argv[++i];
      }
    }
    if (REPEATABLE.has(key)) {
      opts[key] = [...(opts[key] || []), ...(key === 'around' ? String(val).split(',') : [val])];
    } else opts[key] = val;
  }
  return { pos, opts };
}

export class UsageError extends Error {}

const HELP = `stride — STRIDE threat modeling (Microsoft Threat Modeling Tool compatible)

Usage: stride <command> [arguments] [options]

Models
  new <model.json> [--name N] [--template T]     Create a model (T: .tb7 or template .json)
  info <model.json> [--json]                     Summary, diagrams and elements
  meta <model.json> [--name --owner --reviewer --description --assumptions ...]
  diagram <model.json> list|add|rename|rm [diagram] [--name N]

From source-code analysis
  sync <model.json> <spec.json> [--diagram D] [--layout auto|keep] [--no-prune]
        Create/update the model from an architecture spec (zones, elements, flows,
        evidence). Creates the model if missing; keeps triage across re-syncs.

Diagram elements (threats are regenerated after every change unless --no-generate)
  types [--template T] [--family process|external|store|flow|line-boundary|box-boundary]
  add <model.json> <type> [--name N] [--diagram D] [--x --y --w --h]
        [--prop key=value]... [--custom key=value]...
        flows:            --from <element> --to <element> [--bend n]
        box boundaries:   --around a,b,c [--padding 36]   or --x --y --w --h
        line boundaries:  --points x0,y0,x1,y1
  set <model.json> <element> [--name] [--type] [--prop k=v]... [--custom k=v]...
        [--out-of-scope [reason] | --in-scope] [--from] [--to] [--x --y --w --h]
  rm <model.json> <element>... [--cascade]

Analysis
  generate <model.json> [--diagram D] [--dry-run]  Generate/merge threats
  validate <model.json> [--strict]                 Diagram checks (exit 1 on errors)
  threats <model.json> [--state S] [--category C] [--priority P] [--search Q]
  threat <model.json> <id> [--state S] [--priority P] [--justification J]
        [--title] [--description] [--mitigation]
  threat-add <model.json> --flow F --title T [--category S] [--description] [--priority]
  explain <model.json> <flow>                      Why each rule does or does not fire
  note <model.json> <text> [--author A]

Output
  report <model.json> [--format html|md|csv|json|svg] [--diagram D] [-o file]

Templates
  template import <in.tb7> [-o out.json]           Convert an MTMT template
  template info <template>
  template apply <model.json> <template>
  rule check "<expression>" [--template T]

Integrations
  mcp [--root dir]                                 Model Context Protocol server on stdio

Global: --json for machine-readable output. Elements may be referenced by id or unique name.`;

function out(io, data, json) {
  if (json || typeof data !== 'string') io.stdout.write((typeof data === 'string' ? data : JSON.stringify(data, null, 2)) + '\n');
  else io.stdout.write(data.endsWith('\n') ? data : data + '\n');
}

function user() {
  try {
    return os.userInfo().username || 'cli';
  } catch {
    return 'cli';
  }
}

function num(v) {
  if (v === undefined) return undefined;
  const n = Number(v);
  if (!Number.isFinite(n)) throw new UsageError(`Expected a number, got '${v}'`);
  return n;
}

function need(v, what) {
  if (v === undefined || v === '') throw new UsageError(`Missing ${what}`);
  return v;
}

function formatThreats(res) {
  if (!res.threats.length) return 'No threats.';
  const lines = res.threats.map((t) => `${String(t.id).padStart(4)}  ${t.state.padEnd(22)} ${String(t.priority).padEnd(7)} ${t.category.padEnd(23)} ${t.title}\n      ${t.interaction}${t.orphan ? ' (no longer present)' : ''}`);
  return `${lines.join('\n')}\n\n${res.total} threat(s)`;
}

function formatValidation(res) {
  if (!res.messages.length) return 'No validation messages.';
  const icon = { error: 'ERROR  ', warning: 'WARN   ', info: 'INFO   ' };
  return res.messages.map((m) => `${icon[m.severity]}${m.message}`).join('\n') + `\n\n${res.errors} error(s), ${res.warnings} warning(s), ${res.info} info`;
}

function formatGenerate(r) {
  if (!r.enabled) return 'Threat generation is disabled for this model.';
  let s = `Threats: ${r.total} (added ${r.added}, updated ${r.updated}, removed ${r.removed}, orphaned ${r.orphaned})`;
  for (const e of r.errors) s += `\nRule error in ${e.threatTypeId}: ${e.message}`;
  return s;
}

function formatInfo(d) {
  const s = d.summary;
  let o = `${d.meta.name}\nTemplate: ${s.template}\nThreats: ${s.threats} (${Object.entries(s.byState)
    .map(([k, v]) => `${k} ${v}`)
    .join(', ')})\n`;
  for (const dg of d.diagrams) {
    o += `\nDiagram "${dg.name}" [${dg.id}]\n`;
    for (const e of dg.elements) {
      const link = e.family === 'flow' ? `  ${e.source?.name ?? '?'} -> ${e.target?.name ?? '?'}` : '';
      o += `  ${e.id.padEnd(16)} ${e.family.padEnd(14)} ${e.name}  (${e.typeName})${link}${e.outOfScope ? ' [out of scope]' : ''}\n`;
    }
  }
  return o;
}

/** Run one CLI invocation. Returns the exit code. */
export async function main(argv, io = { stdout: process.stdout, stderr: process.stderr, stdin: process.stdin }) {
  let parsed;
  try {
    parsed = parseArgs(argv);
  } catch (e) {
    io.stderr.write(`stride: ${e.message}\n`);
    return 2;
  }
  const { pos, opts } = parsed;
  const [cmd, ...rest] = pos;
  const json = !!opts.json;
  if (!cmd || cmd === 'help' || opts.help) {
    out(io, HELP);
    return cmd || opts.help ? 0 : 2;
  }

  const mutate = (file, fn) => {
    const model = loadModelFile(file);
    const result = fn(model);
    const gen = opts['no-generate'] ? null : ops.opGenerate(model);
    saveModelFile(file, model);
    return { result, gen };
  };
  const report = ({ result, gen }, text) => {
    if (json) return out(io, { result, threats: gen }, true);
    out(io, text ?? JSON.stringify(result, null, 2));
    if (gen) out(io, formatGenerate(gen));
  };

  try {
    switch (cmd) {
      case 'new': {
        const file = need(rest[0], 'model file');
        if (fs.existsSync(file) && !opts.force) throw new UsageError(`${file} already exists (use --force to overwrite)`);
        const model = createModel({ template: loadTemplateFile(opts.template), name: opts.name || path.basename(file).replace(/(\.stride)?\.json$/i, '') });
        saveModelFile(file, model);
        out(io, json ? { file, id: model.id, template: model.template.manifest } : `Created ${file} with template "${model.template.manifest.name}"`, json);
        return 0;
      }
      case 'info': {
        const d = ops.describeModel(loadModelFile(need(rest[0], 'model file')));
        out(io, json ? d : formatInfo(d), json);
        return 0;
      }
      case 'sync': {
        const file = need(rest[0], 'model file');
        const spec = JSON.parse(readText(need(rest[1], 'spec file')));
        const model = fs.existsSync(file) ? loadModelFile(file) : createModel({ template: loadTemplateFile(opts.template), name: spec.name || path.basename(file).replace(/(\.stride)?\.json$/i, '') });
        const r = ops.opSync(model, spec, { diagram: opts.diagram, prune: !opts['no-prune'], layout: opts.layout || 'auto' });
        saveModelFile(file, model);
        if (json) out(io, r, true);
        else {
          let t = `Synced ${file}: ${r.elements.created} created, ${r.elements.updated} updated, ${r.elements.removed} removed\n`;
          t += `Threats: ${r.threats.total} (added ${r.threats.added}, removed ${r.threats.removed}, orphaned ${r.threats.orphaned})\n`;
          t += `Validation: ${r.validation.errors} error(s), ${r.validation.warnings} warning(s)`;
          for (const w of r.layoutWarnings) t += `\nLayout: "${w.flow}" should cross [${w.expectedZones.join(', ')}] but crosses [${w.crossedZones.join(', ')}]`;
          for (const m of r.validation.messages) t += `\n${m.severity.toUpperCase()}: ${m.message}`;
          out(io, t);
        }
        return r.validation.errors || r.threats.ruleErrors.length ? 1 : 0;
      }
      case 'meta': {
        const file = need(rest[0], 'model file');
        const r = mutate(file, (m) => ops.opSetMeta(m, opts));
        report(r);
        return 0;
      }
      case 'types': {
        const types = ops.listTypes(loadTemplateFile(opts.template), { family: opts.family });
        if (json) out(io, types, true);
        else out(io, types.map((t) => `${t.id.padEnd(34)} ${t.family.padEnd(14)} ${t.name}`).join('\n'));
        return 0;
      }
      case 'diagram': {
        const file = need(rest[0], 'model file');
        const action = { rm: 'remove', delete: 'remove' }[rest[1]] || rest[1] || 'list';
        if (action === 'list') {
          out(io, ops.opDiagram(loadModelFile(file), { action }), true);
          return 0;
        }
        const r = mutate(file, (m) => ops.opDiagram(m, { action, diagram: rest[2], name: opts.name ?? rest[3] }));
        report(r);
        return 0;
      }
      case 'add': {
        const file = need(rest[0], 'model file');
        const args = {
          type: need(rest[1], 'element type'),
          name: opts.name ?? rest[2],
          diagram: opts.diagram,
          x: num(opts.x),
          y: num(opts.y),
          w: num(opts.w),
          h: num(opts.h),
          bend: num(opts.bend),
          props: opts.prop,
          custom: opts.custom,
          from: opts.from,
          to: opts.to,
          around: opts.around,
          padding: opts.padding,
          points: opts.points,
          outOfScope: opts['out-of-scope'] ? true : undefined,
          outOfScopeReason: typeof opts['out-of-scope'] === 'string' ? opts['out-of-scope'] : undefined,
        };
        const r = mutate(file, (m) => ops.opAddElement(m, args));
        report(r, `Added ${r.result.family} "${r.result.name}" [${r.result.id}]`);
        return 0;
      }
      case 'set': {
        const file = need(rest[0], 'model file');
        const args = {
          element: need(rest[1], 'element'),
          name: opts.name,
          type: opts.type,
          x: num(opts.x),
          y: num(opts.y),
          w: num(opts.w),
          h: num(opts.h),
          bend: num(opts.bend),
          props: opts.prop,
          custom: opts.custom,
          from: opts.from,
          to: opts.to,
        };
        if (opts['out-of-scope']) {
          args.outOfScope = true;
          if (typeof opts['out-of-scope'] === 'string') args.outOfScopeReason = opts['out-of-scope'];
        }
        if (opts['in-scope']) args.outOfScope = false;
        const r = mutate(file, (m) => ops.opUpdateElement(m, args));
        report(r, `Updated "${r.result.name}" [${r.result.id}]`);
        return 0;
      }
      case 'rm': {
        const file = need(rest[0], 'model file');
        const r = mutate(file, (m) => ops.opRemoveElements(m, { elements: rest.slice(1), cascade: opts.cascade }));
        report(r, `Removed ${r.result.removed.length} element(s)`);
        return 0;
      }
      case 'generate': {
        const file = need(rest[0], 'model file');
        const model = loadModelFile(file);
        const r = ops.opGenerate(model, { diagram: opts.diagram });
        if (!opts['dry-run']) saveModelFile(file, model);
        out(io, json ? r : formatGenerate(r) + (opts['dry-run'] ? ' (dry run, not saved)' : ''), json);
        return r.errors.length ? 1 : 0;
      }
      case 'validate': {
        const res = ops.opValidate(loadModelFile(need(rest[0], 'model file')));
        out(io, json ? res : formatValidation(res), json);
        return res.errors || (opts.strict && res.warnings) ? 1 : 0;
      }
      case 'threats': {
        const res = ops.opListThreats(loadModelFile(need(rest[0], 'model file')), {
          state: opts.state,
          category: opts.category,
          priority: opts.priority,
          diagram: opts.diagram,
          text: opts.search,
          limit: opts.limit,
        });
        out(io, json ? res : formatThreats(res), json);
        return 0;
      }
      case 'threat': {
        const file = need(rest[0], 'model file');
        const id = need(rest[1], 'threat id');
        const model = loadModelFile(file);
        const args = { threat: id };
        for (const k of ['state', 'priority', 'justification', 'title', 'description', 'mitigation']) if (opts[k] !== undefined) args[k] = opts[k];
        if (opts.custom) args.custom = opts.custom;
        const changed = Object.keys(args).length > 1;
        const t = changed ? ops.opUpdateThreat(model, args, user()) : ops.threatView(model, model.threats.find((x) => String(x.id) === String(id) || x.key === id) || need(undefined, `threat ${id}`));
        if (changed) saveModelFile(file, model);
        out(io, t, true);
        return 0;
      }
      case 'threat-add': {
        const file = need(rest[0], 'model file');
        const model = loadModelFile(file);
        const t = ops.opAddUserThreat(model, { flow: need(opts.flow, '--flow'), title: need(opts.title, '--title'), category: opts.category, description: opts.description, priority: opts.priority, mitigation: opts.mitigation }, user());
        saveModelFile(file, model);
        out(io, t, true);
        return 0;
      }
      case 'explain': {
        const r = ops.opExplain(loadModelFile(need(rest[0], 'model file')), { flow: need(rest[1], 'flow') });
        if (json) out(io, r, true);
        else {
          let s = r.connected ? `Crosses: ${r.crosses.map((b) => `${b.name} (${b.typeId})`).join(', ') || 'no trust boundaries'}\n` : 'Flow is not connected at both ends.\n';
          for (const x of r.results) s += `${x.applies ? '✔' : x.error ? '!' : '·'} ${x.id.padEnd(8)} ${x.title}${x.error ? `  — ${x.error}` : ''}\n`;
          out(io, s);
        }
        return 0;
      }
      case 'note': {
        const file = need(rest[0], 'model file');
        const model = loadModelFile(file);
        const n = ops.opAddNote(model, { text: need(rest.slice(1).join(' '), 'note text'), author: opts.author || user() });
        saveModelFile(file, model);
        out(io, n, true);
        return 0;
      }
      case 'report': {
        const model = loadModelFile(need(rest[0], 'model file'));
        let format = opts.format;
        if (!format && opts.out) format = { '.html': 'html', '.htm': 'html', '.md': 'md', '.csv': 'csv', '.json': 'json', '.svg': 'svg' }[path.extname(opts.out).toLowerCase()];
        const text = ops.opReport(model, { format: format || 'html', diagram: opts.diagram });
        if (opts.out) {
          writeTextAtomic(opts.out, text);
          out(io, json ? { file: opts.out } : `Wrote ${opts.out}`, json);
        } else io.stdout.write(text);
        return 0;
      }
      case 'template': {
        const sub = rest[0];
        if (sub === 'import') {
          const tpl = loadTemplateFile(need(rest[1], 'template file'));
          const text = JSON.stringify(tpl, null, 2) + '\n';
          if (opts.out) {
            writeTextAtomic(opts.out, text);
            out(io, json ? { file: opts.out, manifest: tpl.manifest } : `Imported "${tpl.manifest.name}" (${tpl.threatTypes.length} threat types) to ${opts.out}`, json);
          } else io.stdout.write(text);
          return 0;
        }
        if (sub === 'info') {
          const tpl = loadTemplateFile(need(rest[1], 'template file'));
          const kb = kbOf({ template: tpl });
          const info = { manifest: tpl.manifest, ...kb.stats(), categories: tpl.categories.map((c) => `${c.id} ${c.name}`) };
          out(io, info, true);
          return 0;
        }
        if (sub === 'apply') {
          const file = need(rest[1], 'model file');
          const r = mutate(file, (m) => ops.opApplyTemplate(m, loadTemplateFile(need(rest[2], 'template file'))));
          report(r, `Applied template "${r.result.template.name}"`);
          return 0;
        }
        throw new UsageError('Usage: stride template import|info|apply ...');
      }
      case 'rule': {
        if (rest[0] !== 'check') throw new UsageError('Usage: stride rule check "<expression>"');
        const expr = need(rest.slice(1).join(' '), 'rule expression');
        const r = ops.opCheckRule(loadTemplateFile(opts.template), expr);
        out(io, json ? r : r.ok ? `OK${r.warnings.length ? `\n${r.warnings.map((w) => `warning: ${w}`).join('\n')}` : ''}` : r.errors.map((e) => `error: ${e}`).join('\n'), json);
        return r.ok ? 0 : 1;
      }
      case 'mcp': {
        await runMcpServer({ root: opts.root || process.cwd(), stdin: io.stdin, stdout: io.stdout, stderr: io.stderr });
        return 0;
      }
      case 'read': {
        // Hidden helper: print a model file normalized (useful for diffing).
        out(io, JSON.parse(JSON.stringify(loadModelFile(need(rest[0], 'model file')))), true);
        return 0;
      }
      default:
        throw new UsageError(`Unknown command '${cmd}'. Run 'stride help'.`);
    }
  } catch (e) {
    io.stderr.write(`stride: ${e.message}\n`);
    return e instanceof UsageError ? 2 : 1;
  }
}


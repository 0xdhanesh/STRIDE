// Model Context Protocol server (stdio, newline-delimited JSON-RPC 2.0).
// Exposes the threat modeling operations as MCP tools. Every tool that takes a
// file path is sandboxed to the server root (default: the working directory).

import fs from 'node:fs';
import readline from 'node:readline';
import { createModel } from '../core/index.js';
import { loadModelFile, loadTemplateFile, readText, sandboxPath, saveModelFile, writeTextAtomic } from './files.js';
import * as ops from './ops.js';

export const SERVER_INFO = { name: 'stride-threat-modeler', version: '1.0.0' };
export const PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];

const INSTRUCTIONS = `STRIDE threat modeling (Microsoft Threat Modeling Tool compatible).
Primary workflow after analyzing a codebase: describe the architecture you found as a spec of
trust zones, elements (processes, external interactors, data stores) and data flows, each with
file:line evidence, and call stride_sync_model. It lays out the diagram so flows cross exactly
the zone boundaries they leave/enter, generates threats, validates, and keeps triage when you
re-sync after code changes. Then stride_list_threats, verify each threat against the code, and
triage with stride_update_threat citing evidence; add code-specific findings with
stride_add_user_threat; export with stride_export_report. Use stride_list_element_types for exact
type ids and property values. Paths are relative to the server root. See MCPUsage.md.`;

const str = (description, extra = {}) => ({ type: 'string', description, ...extra });
const num = (description) => ({ type: 'number', description });
const kv = (description) => ({ type: 'object', description, additionalProperties: { type: 'string' } });
const MODEL = str('Path to the model JSON file, relative to the server root (e.g. "models/shop.json").');
const GENERATE = { type: 'boolean', description: 'Regenerate threats after the change (default true).' };

const TOOLS = [
  {
    name: 'stride_sync_model',
    description:
      'PRIMARY TOOL after analyzing source code. Create or update a threat model from an architecture spec: trust zones (become box trust boundaries), elements (processes, external interactors, data stores; omit "zone" for anything outside your trust zones such as users and third parties) and data flows, each with optional properties and file:line evidence. The diagram is laid out automatically so each flow crosses exactly the zones it leaves/enters (verified; mismatches are returned as layoutWarnings). Threats are generated and the model validated. Ids are derived from names, so re-syncing the same spec after code changes keeps all triage. Creates the model file if it does not exist.',
    inputSchema: {
      type: 'object',
      required: ['model'],
      properties: {
        model: MODEL,
        spec: {
          type: 'object',
          description: 'Architecture spec. Provide this or specFile.',
          properties: {
            name: str('Model name.'),
            description: str('High-level system description.'),
            assumptions: str('Assumptions (what is trusted / out of scope).'),
            externalDependencies: str(''),
            zones: {
              type: 'array',
              description: 'Trust zones, ordered from least to most trusted (laid out left to right).',
              items: { type: 'object', required: ['name'], properties: { id: str('Stable key (default: name).'), name: str(''), type: str('Box boundary type, e.g. GE.TB.B, SE.TB.B.TMCore.CorpNet, SE.TB.B.TMCore.Sandbox.'), evidence: { type: 'array', items: { type: 'string' } } } },
            },
            elements: {
              type: 'array',
              items: {
                type: 'object',
                required: ['name', 'type'],
                properties: {
                  id: str('Stable key (default: name). Keep it stable across syncs.'),
                  name: str('Display name used in threat titles.'),
                  type: str('Type id (e.g. SE.P.TMCore.WebSvc), type name, or family (process, external, store).'),
                  zone: str('Zone id or name. Omit for elements outside all trust zones.'),
                  props: kv('Template properties (exact names/values from stride_list_element_types).'),
                  custom: kv('Free-form facts, e.g. {"framework":"FastAPI","dataClass":"PII"}.'),
                  evidence: { type: 'array', items: { type: 'string' }, description: 'Source references, e.g. "api/app.py:12".' },
                  outOfScope: { type: 'boolean' },
                  outOfScopeReason: str(''),
                },
              },
            },
            flows: {
              type: 'array',
              items: {
                type: 'object',
                required: ['from', 'to', 'name'],
                properties: {
                  id: str('Stable key (default: name).'),
                  name: str('What data moves, e.g. "Invoice queries".'),
                  from: str('Element id or name.'),
                  to: str('Element id or name.'),
                  type: str('Flow type: HTTPS, HTTP, GE.DF (default), SE.DF.TMCore.* ...'),
                  props: kv('Flow properties, e.g. {"JSON":"Yes","providesConfidentiality":"Yes"}.'),
                  custom: kv(''),
                  evidence: { type: 'array', items: { type: 'string' } },
                },
              },
            },
          },
        },
        specFile: str('Path to a spec JSON file (relative to root), e.g. "threatmodel/spec.json". Alternative to spec.'),
        diagram: str('Diagram name (created if missing). Default: first diagram.'),
        layout: str('"auto" (default) recomputes positions; "keep" keeps positions of existing shapes (e.g. after a human rearranged them).', { enum: ['auto', 'keep'] }),
        prune: { type: 'boolean', description: 'Remove elements from a previous sync that are no longer in the spec (default true). Hand-drawn elements are never removed.' },
        template: str('Template file used only when creating a new model.'),
      },
    },
  },
  {
    name: 'stride_list_element_types',
    description: 'List element types (stencils) of a template with their configurable properties and allowed values.',
    inputSchema: {
      type: 'object',
      properties: {
        family: str('Filter by family.', { enum: ['process', 'external', 'store', 'flow', 'line-boundary', 'box-boundary', 'annotation'] }),
        template: str('Optional template file (.tb7 or template .json). Defaults to the built-in STRIDE Core template.'),
        model: str('Optional model file; lists the types of the template embedded in that model.'),
      },
    },
    annotations: { readOnlyHint: true },
  },
  {
    name: 'stride_create_model',
    description: 'Create a new, empty threat model file.',
    inputSchema: {
      type: 'object',
      required: ['model'],
      properties: { model: MODEL, name: str('Model name.'), owner: str('Owner.'), template: str('Optional template file (.tb7 or .json).'), overwrite: { type: 'boolean' } },
    },
  },
  {
    name: 'stride_describe_model',
    description: 'Summarize a model: metadata, threat counts, diagrams and every element with ids, types and properties.',
    inputSchema: { type: 'object', required: ['model'], properties: { model: MODEL } },
    annotations: { readOnlyHint: true },
  },
  {
    name: 'stride_set_model_info',
    description: 'Set model metadata (name, owner, reviewer, contributors, description, assumptions, externalDependencies) or toggle threat generation.',
    inputSchema: {
      type: 'object',
      required: ['model'],
      properties: {
        model: MODEL,
        name: str(''),
        owner: str(''),
        reviewer: str(''),
        contributors: str(''),
        description: str(''),
        assumptions: str(''),
        externalDependencies: str(''),
        threatGeneration: { type: 'boolean' },
      },
    },
  },
  {
    name: 'stride_add_element',
    description:
      'Add an element. type is a type id (e.g. "SE.P.TMCore.WebApp"), a type name ("Web Application") or a family ("process", "external", "store", "flow", "box-boundary", "line-boundary", "annotation"). Flows need from/to. Box boundaries can use around=[element refs]; line boundaries need points=[x0,y0,x1,y1]. Shapes without x/y are auto-placed.',
    inputSchema: {
      type: 'object',
      required: ['model', 'type'],
      properties: {
        model: MODEL,
        type: str('Element type id, type name or family.'),
        name: str('Display name (used in threat titles).'),
        diagram: str('Diagram id or name (default: first diagram).'),
        x: num('Left (shapes).'),
        y: num('Top (shapes).'),
        w: num('Width (shapes).'),
        h: num('Height (shapes).'),
        from: str('Flow source element id or unique name.'),
        to: str('Flow target element id or unique name.'),
        bend: num('Flow/line curvature offset in px.'),
        around: { type: 'array', items: { type: 'string' }, description: 'Box boundary: elements to enclose.' },
        padding: num('Box boundary padding around enclosed elements (default 36).'),
        points: { type: 'array', items: { type: 'number' }, minItems: 4, maxItems: 4, description: 'Line boundary endpoints [x0,y0,x1,y1].' },
        props: kv('Template property values, e.g. {"providesConfidentiality":"Yes"}.'),
        custom: kv('Free-form custom properties.'),
        outOfScope: { type: 'boolean' },
        outOfScopeReason: str(''),
        generate: GENERATE,
      },
    },
  },
  {
    name: 'stride_update_element',
    description: 'Update an element: name, type (same family), properties, custom properties, scope, position, or flow endpoints.',
    inputSchema: {
      type: 'object',
      required: ['model', 'element'],
      properties: {
        model: MODEL,
        element: str('Element id or unique name.'),
        name: str(''),
        type: str('New type (same family).'),
        props: kv('Template property values to set.'),
        custom: kv('Custom properties to set (value null to remove).'),
        outOfScope: { type: 'boolean' },
        outOfScopeReason: str(''),
        from: str('New flow source.'),
        to: str('New flow target.'),
        x: num(''),
        y: num(''),
        w: num(''),
        h: num(''),
        bend: num(''),
        generate: GENERATE,
      },
    },
  },
  {
    name: 'stride_remove_elements',
    description: 'Remove elements. Flows attached to removed shapes are detached unless cascade is true.',
    inputSchema: {
      type: 'object',
      required: ['model', 'elements'],
      properties: { model: MODEL, elements: { type: 'array', items: { type: 'string' } }, cascade: { type: 'boolean' }, generate: GENERATE },
    },
    annotations: { destructiveHint: true },
  },
  {
    name: 'stride_manage_diagram',
    description: 'List, add, rename or remove diagrams in a model.',
    inputSchema: {
      type: 'object',
      required: ['model', 'action'],
      properties: { model: MODEL, action: str('', { enum: ['list', 'add', 'rename', 'remove'] }), diagram: str('Diagram id or name.'), name: str('New name.') },
    },
  },
  {
    name: 'stride_generate_threats',
    description: 'Generate threats from the template rules and merge them with existing triage. Returns added/updated/removed counts and rule errors.',
    inputSchema: { type: 'object', required: ['model'], properties: { model: MODEL, diagram: str('Limit to one diagram.') } },
  },
  {
    name: 'stride_validate_model',
    description: 'Run diagram validation (unconnected flows, missing trust boundaries, partial boundary coverage, rule errors, ...).',
    inputSchema: { type: 'object', required: ['model'], properties: { model: MODEL } },
    annotations: { readOnlyHint: true },
  },
  {
    name: 'stride_list_threats',
    description: 'List threats with optional filters.',
    inputSchema: {
      type: 'object',
      required: ['model'],
      properties: {
        model: MODEL,
        state: str('NotStarted | NeedsInvestigation | NotApplicable | Mitigated'),
        category: str('Category id or name, e.g. "S" or "Spoofing".'),
        priority: str('High | Medium | Low'),
        diagram: str(''),
        text: str('Search text.'),
        limit: num('Maximum number of threats.'),
        signal: str('Only threats at or above this signal level, best first: high | medium.', { enum: ['high', 'medium', 'all'] }),
      },
    },
    annotations: { readOnlyHint: true },
  },
  {
    name: 'stride_update_threat',
    description: 'Triage a threat: state, priority, justification, or edited title/description/mitigation.',
    inputSchema: {
      type: 'object',
      required: ['model', 'threat'],
      properties: {
        model: MODEL,
        threat: str('Threat id number or key.'),
        state: str('NotStarted | NeedsInvestigation | NotApplicable | Mitigated'),
        priority: str('High | Medium | Low'),
        justification: str('Why the state was chosen / how it is mitigated.'),
        title: str(''),
        description: str(''),
        mitigation: str(''),
      },
    },
  },
  {
    name: 'stride_add_user_threat',
    description: 'Add a user-defined threat to a data flow (for threats the template does not generate).',
    inputSchema: {
      type: 'object',
      required: ['model', 'flow', 'title'],
      properties: { model: MODEL, flow: str('Data flow id or name.'), title: str(''), category: str('Category id (S, T, R, I, D, E).'), description: str(''), mitigation: str(''), priority: str('') },
    },
  },
  {
    name: 'stride_explain_flow',
    description: 'Show which trust boundaries a flow crosses and whether each threat rule applies to it.',
    inputSchema: { type: 'object', required: ['model', 'flow'], properties: { model: MODEL, flow: str('Data flow id or name.') } },
    annotations: { readOnlyHint: true },
  },
  {
    name: 'stride_check_rule',
    description: "Validate a threat rule expression, e.g. \"source is 'GE.P' and flow crosses 'GE.TB.B'\".",
    inputSchema: { type: 'object', required: ['expression'], properties: { expression: str(''), template: str('Optional template file.') } },
    annotations: { readOnlyHint: true },
  },
  {
    name: 'stride_export_report',
    description: 'Render a report (html, md, csv, json, or svg of one diagram). Writes to output when given, otherwise returns the text.',
    inputSchema: {
      type: 'object',
      required: ['model'],
      properties: {
        model: MODEL,
        format: str('', { enum: ['html', 'md', 'csv', 'json', 'svg'] }),
        diagram: str('Diagram for svg.'),
        signal: str('Stakeholder section (html, md, json): executive summary plus findings at or above this level, before the full register. Default high; off = classic report.', { enum: ['high', 'medium', 'all', 'off'] }),
        output: str('Output file path (relative to root).'),
      },
    },
  },
  {
    name: 'stride_import_template',
    description: 'Convert a Microsoft Threat Modeling Tool .tb7 template to a STRIDE template JSON file.',
    inputSchema: { type: 'object', required: ['input', 'output'], properties: { input: str('.tb7 file.'), output: str('Output .json file.') } },
  },
  {
    name: 'stride_apply_template',
    description: "Replace a model's embedded template (elements of unknown types fall back to their generic type) and regenerate threats.",
    inputSchema: { type: 'object', required: ['model', 'template'], properties: { model: MODEL, template: str('Template file (.tb7 or .json).') } },
  },
  {
    name: 'stride_add_note',
    description: 'Add a note to the model (shown in reports).',
    inputSchema: { type: 'object', required: ['model', 'text'], properties: { model: MODEL, text: str(''), author: str('') } },
  },
];

class ToolError extends Error {}

function createHandlers(root) {
  const readPath = (p, extensions) => sandboxPath(root, p, { extensions });
  const writePath = (p, extensions) => sandboxPath(root, p, { write: true, extensions });
  const modelPath = (p) => sandboxPath(root, p, { extensions: ['.json'] });
  const tplPath = (p) => (p ? readPath(p, ['.tb7', '.json']) : undefined);

  const mutate = (args, fn) => {
    const file = modelPath(args.model);
    const model = loadModelFile(file);
    const result = fn(model);
    const threats = args.generate === false ? undefined : ops.opGenerate(model);
    saveModelFile(file, model);
    return threats ? { result, threats } : { result };
  };

  return {
    stride_sync_model: (a) => {
      const file = modelPath(a.model);
      let spec = a.spec;
      if (!spec && a.specFile) spec = JSON.parse(readText(readPath(a.specFile, ['.json'])));
      if (!spec || typeof spec !== 'object') throw new ToolError('Provide "spec" (object) or "specFile" (path to a .json spec).');
      const model = fs.existsSync(file) ? loadModelFile(file) : createModel({ template: loadTemplateFile(tplPath(a.template)), name: spec.name || 'Threat model' });
      const result = ops.opSync(model, spec, { diagram: a.diagram, prune: a.prune !== false, layout: a.layout || 'auto' });
      saveModelFile(file, model);
      return { model: a.model, ...result };
    },
    stride_list_element_types: (a) => {
      const template = a.model ? loadModelFile(modelPath(a.model)).template : loadTemplateFile(tplPath(a.template));
      return ops.listTypes(template, { family: a.family });
    },
    stride_create_model: (a) => {
      const file = modelPath(a.model);
      if (fs.existsSync(file) && !a.overwrite) throw new ToolError(`${a.model} already exists (set overwrite to replace it)`);
      const model = createModel({ template: loadTemplateFile(tplPath(a.template)), name: a.name || 'Untitled threat model', owner: a.owner || '' });
      saveModelFile(file, model);
      return { model: a.model, id: model.id, template: model.template.manifest, diagram: model.diagrams[0] };
    },
    stride_describe_model: (a) => ops.describeModel(loadModelFile(modelPath(a.model))),
    stride_set_model_info: (a) => mutate({ ...a, generate: false }, (m) => ops.opSetMeta(m, a)),
    stride_add_element: (a) => mutate(a, (m) => ops.opAddElement(m, a)),
    stride_update_element: (a) => mutate(a, (m) => ops.opUpdateElement(m, a)),
    stride_remove_elements: (a) => mutate(a, (m) => ops.opRemoveElements(m, a)),
    stride_manage_diagram: (a) => {
      if (a.action === 'list') return ops.opDiagram(loadModelFile(modelPath(a.model)), a);
      return mutate(a, (m) => ops.opDiagram(m, a));
    },
    stride_generate_threats: (a) => mutate({ ...a, generate: false }, (m) => ops.opGenerate(m, a)).result,
    stride_validate_model: (a) => ops.opValidate(loadModelFile(modelPath(a.model))),
    stride_list_threats: (a) => ops.opListThreats(loadModelFile(modelPath(a.model)), a),
    stride_update_threat: (a) => mutate({ ...a, generate: false }, (m) => ops.opUpdateThreat(m, a, 'mcp')).result,
    stride_add_user_threat: (a) => mutate({ ...a, generate: false }, (m) => ops.opAddUserThreat(m, a, 'mcp')).result,
    stride_explain_flow: (a) => ops.opExplain(loadModelFile(modelPath(a.model)), a),
    stride_check_rule: (a) => ops.opCheckRule(loadTemplateFile(tplPath(a.template)), a.expression),
    stride_export_report: (a) => {
      const text = ops.opReport(loadModelFile(modelPath(a.model)), { format: a.format || 'md', diagram: a.diagram, signal: a.signal });
      if (!a.output) return text;
      writeTextAtomic(writePath(a.output), text);
      return { written: a.output, bytes: Buffer.byteLength(text) };
    },
    stride_import_template: (a) => {
      const tpl = loadTemplateFile(readPath(a.input, ['.tb7', '.json']));
      writeTextAtomic(writePath(a.output, ['.json']), JSON.stringify(tpl, null, 2) + '\n');
      return { written: a.output, manifest: tpl.manifest, threatTypes: tpl.threatTypes.length, elements: tpl.elements.length };
    },
    stride_apply_template: (a) => mutate(a, (m) => ops.opApplyTemplate(m, loadTemplateFile(tplPath(a.template)))),
    stride_add_note: (a) => mutate({ ...a, generate: false }, (m) => ops.opAddNote(m, a)).result,
  };
}

/** Process a single JSON-RPC message; returns a response object or null for notifications. */
export function createMcpHandler({ root = process.cwd() } = {}) {
  const handlers = createHandlers(root);
  let initialized = false;
  return function handle(msg) {
    const isRequest = msg && Object.prototype.hasOwnProperty.call(msg, 'id') && msg.id !== null;
    const reply = (result) => (isRequest ? { jsonrpc: '2.0', id: msg.id, result } : null);
    const fail = (code, message) => (isRequest ? { jsonrpc: '2.0', id: msg.id, error: { code, message } } : null);
    if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return fail(-32600, 'Invalid request');

    switch (msg.method) {
      case 'initialize': {
        const requested = msg.params?.protocolVersion;
        initialized = true;
        return reply({
          protocolVersion: PROTOCOL_VERSIONS.includes(requested) ? requested : PROTOCOL_VERSIONS[0],
          capabilities: { tools: { listChanged: false } },
          serverInfo: SERVER_INFO,
          instructions: INSTRUCTIONS,
        });
      }
      case 'notifications/initialized':
      case 'notifications/cancelled':
        return null;
      case 'ping':
        return reply({});
      case 'tools/list':
        return reply({ tools: TOOLS });
      case 'tools/call': {
        const name = msg.params?.name;
        const args = msg.params?.arguments && typeof msg.params.arguments === 'object' ? msg.params.arguments : {};
        const fn = handlers[name];
        if (!fn) return fail(-32602, `Unknown tool: ${name}`);
        try {
          const result = fn(args);
          const text = typeof result === 'string' ? result : JSON.stringify(result, null, 2);
          const payload = { content: [{ type: 'text', text }], isError: false };
          if (result && typeof result === 'object' && !Array.isArray(result)) payload.structuredContent = result;
          return reply(payload);
        } catch (e) {
          return reply({ content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true });
        }
      }
      default:
        if (!initialized && msg.method !== 'initialize' && isRequest) return fail(-32002, 'Server not initialized');
        return fail(-32601, `Method not found: ${msg.method}`);
    }
  };
}

/** Run the server over stdio until stdin closes. */
export function runMcpServer({ root = process.cwd(), stdin = process.stdin, stdout = process.stdout, stderr = process.stderr } = {}) {
  const handle = createMcpHandler({ root });
  const rl = readline.createInterface({ input: stdin, crlfDelay: Infinity });
  stderr.write(`stride MCP server ready (root: ${root})\n`);
  return new Promise((resolve) => {
    rl.on('line', (line) => {
      if (!line.trim()) return;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n');
        return;
      }
      const batch = Array.isArray(msg) ? msg : [msg];
      const responses = batch.map((m) => handle(m)).filter(Boolean);
      if (Array.isArray(msg)) {
        if (responses.length) stdout.write(JSON.stringify(responses) + '\n');
      } else if (responses[0]) stdout.write(JSON.stringify(responses[0]) + '\n');
    });
    rl.on('close', resolve);
  });
}

export { TOOLS };

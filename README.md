# STRIDE Threat Modeler

Client-first STRIDE threat modeling. You draw a data flow diagram on an Excalidraw-style canvas, and
threats are generated as you draw. The rule engine, templates and diagram semantics are compatible
with the **Microsoft Threat Modeling Tool** (MTMT). The same engine is also available as a **CLI**
and an **MCP server**, so you can model from scripts and AI agents.

- **Runs locally.** No account, no server, no telemetry. The web app is static files, or a single
  offline HTML file.
- **No runtime dependencies.** Plain ES modules on Node ≥ 20 and in modern browsers.
- **MTMT-compatible.** It imports `.tb7` templates, uses the same element types, properties and rule
  language, decides whether a flow crosses a boundary by geometry, and keeps your triage when threats
  are regenerated.

## Quick start

```bash
npm start                  # http://127.0.0.1:8000 — the web app
npm run build:offline      # dist/STRIDE.html — one file, works from file://
npx stride help            # CLI (or: node bin/stride.mjs help)
npx stride mcp             # MCP server on stdio
```

The first run opens an example model. **File → New model** starts an empty one.

## How it works

MTMT is a rule engine that runs over a diagram. This tool follows the same model; see
`.localdev/Microsoft_ThreatModellingTool.md` for the reverse-engineered reference.

1. **Draw** processes, external interactors and data stores. Connect them with **data flows**, then
   draw **trust boundaries** across the flows that change trust level. A boundary can be an arc
   (line) or a box (border).
2. **Generate.** For every data flow (*source → flow → target*), each threat type in the template is
   evaluated. A threat is created when its **Include** rule matches and its **Exclude** rule does not.
   This re-runs automatically about 200 ms after each edit.
3. **Triage.** Set the state (Not Started, Needs Investigation, Not Applicable, Mitigation
   Implemented), the priority and a justification. A threat is identified by
   `type + source + flow + target`:
   - your triage survives renames, moves and regeneration;
   - threats that no longer apply are dropped if nobody touched them;
   - threats you triaged are kept as "no longer present".
4. **Validate.** The Messages tab reports unconnected flows, missing or partial trust boundaries,
   flows between two data stores, rule errors, and so on.
5. **Report.** You can export a full HTML report with diagrams, Markdown, CSV (protected against
   formula injection) or SVG.
6. **Signal.** After generation every threat gets a signal score from the evidence behind it, with no
   LLM and no change to the rules or triage:

   | Points | When |
   |---:|---|
   | +40 | source-code evidence on the source, flow or target |
   | +30 | the flow name or evidence hits a dangerous sink (`shell_exec`, `system(`, `include($_GET`, `'$id'` in SQL, `move_uploaded_file`, `md5(uniqid())`, `eval(`, `unserialize(` …) relevant to the threat's category |
   | +20 | custom properties indicating weak controls (`hardcoded`, `md5`, `unvalidated`, `unsalted`, `sanitized: no` …) |
   | +15 | the target is an OS process, a configuration file or a web-served file system |
   | +10 | High priority and Not Started |
   | −30 | Not Applicable |

   50 or more is **High Signal**, 25–49 **Medium**, the rest **Generic**. Each sink on a flow becomes one
   finding with a specific title, such as *Command injection via shell_exec of user-controlled IP*,
   shown in the web threat list, the CLI and reports. The rule title is kept, and a title you edit
   always wins. HTML, Markdown and JSON reports start with an executive summary and the high-signal
   findings table, followed by the full threat register. The web threat list has a **High-signal
   view** toggle.

### Rule language

```text
source is 'GE.P' and (target is 'GE.P' or target is 'GE.DS') and flow crosses 'GE.TB.B'
flow.providesConfidentiality is 'Yes' or source.implementsAuthenticationScheme is 'Yes'
not target is 'SE.DS.TMCore.SQL'
```

- `X is 'Type'` matches subtypes. For example, a *Web Application* is a `GE.P`.
- `X.property is 'value'` compares the selected value. Property names are case-insensitive.
- `flow crosses 'Boundary'` is true when the drawn flow intersects a boundary of that type, including
  subtypes of that type.
- `and` binds tighter than `or`, and both short-circuit. `not` applies to a single rule only.
- Titles and descriptions can use `{source.Name}`, `{flow.Name}`, `{target.Name}` or any property.

### Templates

The built-in **STRIDE Core** template uses MTMT's core element types and property names
(`GE.P`, `SE.DS.TMCore.SQL`, `providesConfidentiality`, …) and the same rule logic. The threat
descriptions and mitigations are written for this project and include CWE references.

To use Microsoft's own templates, choose **File → Import template** in the app, or run
`stride template import Default.tb7 -o mtmt.json`. Both bundled MTMT templates import cleanly
(Core: 47 threat types; Azure: 191). Under the core template, the test scenario gives exactly the
same threats as STRIDE Core.

**Template & rules…** opens the template editor. In it you can:
- edit threat types, with live rule validation and a "does this fire on the selected flow?" check;
- add derived element types and attributes;
- export a template as JSON.

## Web app

| Action | How |
|---|---|
| Place a shape | Toolbar or keys `2` process, `3` external, `4` store, `8` annotation; or drag a stencil from the palette |
| Data flow | `5`/`F`, then drag from the source element to the target |
| Trust boundary | `6`/`L` arc: drag across flows · `7`/`B` box: drag a rectangle |
| Rename | Double-click or `Enter` |
| Bend a flow / re-attach an end | Drag its middle or end handle |
| Pan / zoom | Wheel, `Space`+drag, `H` · `Ctrl/⌘`+wheel, `+`/`−`, `Shift+1` to fit |
| Undo, copy, duplicate | `⌘Z`/`⌘⇧Z`, `⌘C`/`⌘V`, `⌘D` or Alt-drag |
| Analyze | **Analyze** switches to a larger threat list. Selecting a threat highlights its interaction |

Models autosave to browser storage. **File → Save** writes a `.stride.json` file, using the File
System Access API where the browser supports it. Imported files are treated as untrusted: they are
validated, keys that could pollute object prototypes are dropped, and all text is escaped when
rendered. The offline build has a strict Content Security Policy with no network access.

## CLI

```bash
stride new shop.json --name "Shop"
stride add shop.json "Human User" --name Customer
stride add shop.json SE.P.TMCore.WebApp --name Storefront --prop hasInputSanitizers=Yes
stride add shop.json "SQL Database" --name "Orders DB"
stride add shop.json HTTPS --name "Place order" --from Customer --to Storefront
stride add shop.json flow --name "Write order" --from Storefront --to "Orders DB"
stride add shop.json SE.TB.B.TMCore.CorpNet --name Backend --around Storefront,"Orders DB"
stride validate shop.json                 # exit 1 on errors (--strict: also on warnings)
stride threats shop.json --state NotStarted --priority High
stride threat shop.json 3 --state mitigated --justification "Parameterized queries"
stride explain shop.json "Place order"    # which rules fire, which boundaries are crossed
stride report shop.json -o report.html    # html | md | csv | json | svg
stride report shop.json --signal medium   # stakeholder table: high (default) | medium | all | off
stride threats shop.json --signal high    # only high-signal threats, best first
stride rule check "source is 'GE.P' and flow crosses 'GE.TB.L'"
```

`stride sync <model.json> <spec.json>` creates or updates a model from an architecture spec (see
[MCPUsage.md](MCPUsage.md) §8). Elements can be referenced by id or by unique name. After every change the CLI regenerates threats;
pass `--no-generate` to skip this. Add `--json` to any command for machine-readable output.
`stride types --family flow` lists the element types and their properties.

## MCP server

`stride mcp` speaks the Model Context Protocol over stdio and exposes 20 tools, led by `stride_sync_model`. They cover creating
models, listing element types, adding and updating elements, generating and validating, listing and
triaging threats, explaining a flow, checking rules, importing and applying templates, and exporting
reports. File paths are restricted to `--root`, which defaults to the working directory. Writes are
limited to `.json`, `.html`, `.csv`, `.md` and `.svg`.

The main use is **agent-driven threat modeling from source code**. An AI agent analyzes a
repository and describes what it found as a spec: trust zones, components, data flows, properties
and `path:line` evidence. It then calls **`stride_sync_model`**, which lays out the diagram so flows
cross exactly the right trust boundaries, generates and validates the threats, and keeps triage when
the agent re-syncs after code changes.

- **[MCPUsage.md](MCPUsage.md)** is the guide to give the agent as context. It covers what to look
  for in code, mapping code to element types and properties, triage with code evidence, and a
  verified worked example.
- [`examples/billing-service/`](examples/billing-service/) is a sample codebase with the spec an
  agent derived from it, plus the resulting model and reports.
- The same sync runs without an agent: `stride sync threatmodel/model.json threatmodel/spec.json`
  (useful in CI).

```bash
claude mcp add stride -- node /path/to/STRIDE/bin/stride.mjs mcp --root /path/to/models
```

```json
{ "mcpServers": { "stride": { "command": "node", "args": ["/path/to/STRIDE/bin/stride.mjs", "mcp", "--root", "/path/to/models"] } } }
```

## Development

```text
src/core/        engine: knowledge base, rule language, geometry, model, generation, validation, reports, SVG, .tb7 import
src/templates/   built-in STRIDE Core template
src/web/         Excalidraw-style app: canvas, panels, template editor, state/undo
src/cli/         CLI, MCP server, shared operations, sandboxed file I/O
scripts/         dev server, offline build, acceptance and browser UI checks
tests/           node:test suites
```

```bash
npm test                        # unit and integration tests
npm run test:acceptance         # offline build + CLI session + browser UI check (needs Chrome; skipped otherwise)
node scripts/ui-check.mjs       # drives the real UI over the Chrome DevTools Protocol
MTMT_TB7=path/to/Default.tb7 npm test   # also checks parity with Microsoft's template
```

Generated threats are a starting point for expert review. They do not guarantee that a system is
secure.

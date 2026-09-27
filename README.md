# STRIDE Threat Modeler

A client-side threat-modeling tool with an Excalidraw-style canvas and the core feature set of the
Microsoft Threat Modeling Tool. You draw a data-flow diagram, mark trust boundaries and set security
properties, and STRIDE threats are generated for every interaction.

Everything runs in the browser, with **no build step, no backend and no dependencies**. Models are autosaved
to `localStorage` and can be saved and opened as files.

## Features

| Area | What you get |
| --- | --- |
| **Canvas** | Infinite canvas, pan (space/wheel/hand), zoom, marquee select, move, resize, bend flows, copy/paste, duplicate, z-order, undo/redo, eraser, notes, hand-drawn or clean style, dark mode, touch pinch-zoom |
| **DFD stencils** | Process (incl. *Multiple Processes*), External Entity, Data Store, Data Flow, Trust Boundary box, Trust Boundary line, each with subtypes (Web App, API, SQL DB, Key Vault, HTTPS, gRPC…) |
| **Properties** | Per-element security properties (encrypted, authenticated, validates input, runs as root…) that drive threat generation; out-of-scope with justification; notes |
| **Threat engine** | STRIDE-per-interaction plus element-level rules (38 built-in rules modelled on the TMT SDL template, extended with injection, XSS, CSRF, deserialization, replay, rate limiting…). Boundary-crossing detection for boxes *and* curved lines |
| **Analysis view** | Threat list with STRIDE chips, search, state/priority filters, selection filter; editor for title, category, priority, state, description, justification and mitigation, with suggested mitigations; custom threats; open-threat badges on the diagram |
| **Stable threats** | IDs, states and justifications survive diagram edits. When an interaction disappears, untouched threats are removed and edited ones are kept as *orphaned* |
| **Validation** | Messages for unconnected flows, invalid DFD links (store→store, entity→store), duplicate names, missing boundaries, unjustified out-of-scope |
| **Multiple diagrams** | Tabs: add, rename, duplicate, reorder, delete |
| **Reports & export** | Printable HTML report (summary, per-diagram images, element properties, threats by interaction), CSV, PNG, SVG, JSON |
| **Templates** | View and edit the threat template as JSON; import/export; it's stored inside the model file |
| **Interop** | Opens Microsoft TMT `.tm7` files (best effort: diagrams, elements, flows, boundaries, threats with state and justification) |
| **Sharing** | "Copy share link" compresses the whole model into the URL fragment, so nothing is uploaded |

## Run locally

ES modules need to be served over HTTP (opening `index.html` via `file://` won't work):

```sh
python3 -m http.server 8000
# open http://localhost:8000
```

Tests for the threat engine (Node 20+):

```sh
npm test
```

## Deploy to GitHub Pages

1. Create a repository (e.g. `stride`, or `<user>.github.io` for a root site) and push these files.
2. On GitHub go to **Settings → Pages → Build and deployment**, choose **Deploy from a branch**, and select
   `main` with the `/ (root)` folder.
3. After a minute it's live at `https://<user>.github.io/<repo>/`.

The `.nojekyll` file makes GitHub serve the files as-is. All paths are relative, so the app works from
a sub-path.

## Keyboard shortcuts

`H` hand · `V`/`1` select · `P`/`2` process · `E`/`3` external entity · `D`/`4` data store · `A`/`5` data flow ·
`B`/`6` boundary · `L`/`7` boundary line · `T`/`8` note · `X`/`0` eraser · `Q` keep tool ·
`Enter` rename · `Del` delete · `Ctrl+D` duplicate · `Ctrl+Z`/`Ctrl+Shift+Z` undo/redo ·
`Shift+1` fit · `Shift+A` toggle Analysis · `Ctrl+S` save · `?` help.

## Threat template format

A template is a JSON array of rules:

```json
{
  "id": "I01",
  "scope": "interaction",
  "category": "I",
  "priority": "High",
  "focus": "flow",
  "title": "Data Flow Sniffing on {flow.name}",
  "description": "Data flowing across {flow.name} may be sniffed…",
  "mitigation": "Encrypt the channel with TLS 1.2+…",
  "when": [["flow.crossesBoundary", "eq", true], ["flow.props.encrypted", "ne", "Yes"]]
}
```

- `scope`: `interaction` is evaluated per data flow with context `source`, `target` and `flow`. `element` is
  evaluated per process, external entity or data store, with context `element`.
- `category`: one of `S T R I D E`. `priority`: `High`, `Medium` or `Low`.
- `focus`: `source`, `target`, `flow` or `element`. If that element is out of scope, the rule is skipped.
- `when`: an array means AND; `{ "any": [...] }` means OR and `{ "not": cond }` negates. A clause is
  `[path, op, value]` with `op` ∈ `eq ne in nin exists`.
- Paths: `source.type` (`process`/`external`/`store`), `source.subtype`, `source.props.<key>`, the same for
  `target.*` and `element.*`, `flow.subtype`, `flow.props.<key>`, `flow.crossesBoundary`, `flow.boundaries`.
- Text fields can use `{source.name}`, `{target.name}`, `{flow.name}`, `{flow.boundaries}`, `{element.name}`
  and any other path.

Property keys are defined in `js/stencils.js`. Unset properties have the value `"Not Selected"`, so rules
written as `ne "Yes"` generate threats until someone confirms the control is in place.

## Project layout

```
index.html        UI shell (toolbar, panels, dialogs)
css/app.css       Excalidraw-like styling, light/dark
js/main.js        Wiring: actions, menus, tabs, keyboard, clipboard
js/canvas.js      Interactive SVG canvas
js/render.js      SVG renderer (canvas, exports, report)
js/store.js       Model, undo/redo, autosave
js/engine.js      STRIDE rule engine, threat sync, validation
js/rules.js       Built-in threat template
js/stencils.js    Element types, subtypes, properties
js/panels.js      Properties panel and threat panel
js/io.js          Save/open, PNG/SVG/CSV, report, share link, .tm7 import
js/ops.js         Element operations (create, delete, paste, bend…)
js/util.js        Geometry and hand-drawn path generation
```

## Privacy

There is no server component. Nothing is sent anywhere, except that the page loads the *Kalam* web font from
Google Fonts (and fetches it again to embed it in PNG exports). Remove the font `<link>` in `index.html` if
you need a fully offline build. The app falls back to a system cursive font.

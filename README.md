# STRIDE Threat Modeler

**Threat modeling entirely in your browser. No backend. No uploads. No desktop installation.**

A web-based alternative to Microsoft Threat Modeling Tool, with an Excalidraw-style canvas,
150+ technology stencils and 97 STRIDE threat rules. Built for environments where architecture
and security data must stay on the machine.

**[Open the app](https://0xdhanesh.github.io/STRIDE/)**

[Feature reference](USAGE.md) · [Step-by-step modeling guide](GUIDE.md) · [Black-box demos](DEMO.md)

## Client-side by design

- Diagrams, threat generation, reviews, imports and report exports are processed locally in the browser.
- Models autosave to **IndexedDB**, with a local recovery journal. Save the complete model as a
  **`.stride` file** and reopen it with diagrams, review decisions and custom rules intact.
- No telemetry, cloud storage, external fonts or CDN assets. A Content Security Policy blocks
  network connections.
- The hosted app fetches its static files on startup. The standalone file below needs **zero
  network traffic, including startup and refresh**.

## Use it offline

From a local copy of this repository, a maintainer with Node.js can create the standalone file:

```sh
npm run build:offline
```

Distribute **`dist/STRIDE.html`**. Users open it directly in a modern browser—no installation,
server or internet connection needed. Scripts, styles, icons, rules and PDF fonts are embedded.
No package installation is required to generate it. Rebuild after source changes.

For a GitHub release, create and publish a release with a tag pointing to the commit you want
to distribute. GitHub Actions runs the tests, builds the standalone file from that tag, and
attaches **`STRIDE.html`** to the release assets. The workflow also runs the tests on pushes
and pull requests to `main`.

## Model → review → export

1. **Draw:** add processes, external entities, stores and flows; mark trust boundaries and set
   security properties. Use `/` to search stencils or `Y` to open the symbol library.
2. **Review:** generated threats include suggested mitigations. Set Open, Mitigated, Accepted or
   Not Applicable, with owner, severity, notes and mitigation. The dashboard counts by status
   and STRIDE category. New flows into a reviewed group require another review; previous
   decisions and evidence remain visible.
3. **Save:** use **Ctrl/Cmd+S** for a local `.stride` file; **Ctrl/Cmd+O** reopens it. Autosave
   recovers work after refresh. Keep local files as durable backups: browser storage can be cleared
   and multiple tabs share one recovery slot.
4. **Export:** PDF, Markdown and lossless report JSON include diagram images, an elements table
   and threats grouped by STRIDE category and interaction. HTML, CSV, SVG and PNG are also available.

The canvas supports multiple diagrams, snapping connectors, undo/redo, pan/zoom and dark mode.
**Open** also imports Microsoft TMT **`.tm7`** files: known stencils are mapped, original XML and
reviews are preserved, and unmapped content is flagged for review. Custom templates can be edited
through **Menu → Threat template**.

Direct PDF supports Latin, Greek and Cyrillic; use **Printable HTML → Print → Save as PDF** for
other scripts. Markdown images need a viewer that permits embedded SVG data URLs.

## Develop and verify

Plain HTML, CSS and JavaScript modules. No package installation or build step is required to
serve the source app. Development checks use Node.js 20+ and Python 3.

```sh
npm start                 # Static server at http://localhost:8000 (Python 3)
npm test                  # Rules, reviews, persistence, imports, exports and offline packaging
npm run test:acceptance   # Local save/reopen and report checks with network APIs blocked
```

Source `index.html` needs a static HTTP server; use `dist/STRIDE.html` for opening directly from disk.
PDF rendering code and fonts are bundled locally; see [third-party notices](THIRD_PARTY.md).

- [Stencils and security properties](js/stencils.js)
- [Threat rules and template schema](js/rules.js)
- [Architecture, review notes and browser verification steps](REVIEW.md)

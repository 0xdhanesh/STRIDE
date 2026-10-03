# STRIDE verification handoff

Prepared 2026-10-04 for independent review. Application changes are committed through
`a54083e`; the following acceptance-check commit adds this document and extends the
existing report QA script. No production code or dependencies changed in this pass.

## Review scope

Review the implementation against the user's requirements, not only these notes.
Use `git diff 29db50d..HEAD` for all four features and rule fixes, or
`git diff 77ab8e2..010c089` for the rule/engine/security task alone.

| Commit | Change |
| --- | --- |
| `77ab8e2` | Local files, recovery, threat reviews/dashboard, report exports |
| `1b72bba` | Protocol, cookie authentication, backup and boundary rule fixes |
| `fda7672` | Narrow broad threats by trust crossing and exposure |
| `903dd55` | Endpoint deduplication, supersession, E03 removal |
| `8649a20` | Imported rule schema and path validation |
| `7a88b56` | Prototype traversal and threat-output safety |
| `010c089` | Rule regressions, lossless reports and native DOM test page |
| `a54083e` | Local TM7 import, source/review preservation, explicit warnings |

The source application remains plain HTML/CSS/JavaScript modules, served as static
files without a required build. The optional offline packaging script embeds those
files in `dist/STRIDE.html` for opening locally without startup network traffic.
The existing PDF renderer and fonts are vendored locally; see `THIRD_PARTY.md`.
No packages need installing to run the application or the Node tests.

## Code map and model

| Concern | Entry points |
| --- | --- |
| Model normalization, undo/redo, commits | `js/store.js` |
| IndexedDB transaction and synchronous recovery journal | `js/persistence.js` |
| Save/open and export actions | `js/io.js`, `js/main.js` |
| Threat conditions and interpolation | `resolve`, `evalCond`, `interpolate` in `js/engine.js` |
| Deduplication, supersession and preserved decisions | `generateThreats`, `syncThreats` in `js/engine.js` |
| Rule schema/import validation | `validateRules` in `js/rules.js`; template dialog in `js/main.js`; model validation in `js/store.js` |
| Threat DOM sinks | `js/panels.js` uses escaped HTML through `esc`; editor inputs use values; summary in `js/summary.js` |
| Report text sinks | `js/reports.js`, `js/io.js`, `js/render.js`, `js/pdf-report.js` |
| Native XML import | `js/tm7.js`; encoding/file handling in `js/io.js` |
| Offline policy and packaging | `index.html`, `scripts/build-offline.mjs`, `tests/offline.test.mjs` |

The version-1 model contains metadata, multiple diagrams and their elements, a
threat map keyed by stable generation identity, `nextThreatId`, and an optional
custom template. Elements contain geometry, references, subtype and security
properties. Threats contain identity, rule/category, diagram/element/flow references,
review status/severity/owner/notes/mitigation/justification and generated text.
Grouped threats list their contributing flows. Suppressed reviewed records remain
in model JSON while visible threat lists and reports exclude them.

State lives in memory while editing. Recovery uses IndexedDB `stride-tm`, object
store `models`, key `current`, plus localStorage journal `stride-tm:recovery:v1`.
The old localStorage model is migrated after a successful durable write. Local
`.stride` files and report JSON preserve the editable model, including extension
fields. Selection, viewport and undo history are session-only; UI preferences use
localStorage. No model data is uploaded.

## Rule changes to verify

There are **81 default rules**. **E03 is the only removed ID**. The only new property
option is flow authentication **`Cookie / Session`**. Process `internetFacing` and
`validatesInput` with Yes / No / Not Selected already existed.

| Rule | Change and reason |
| --- | --- |
| W02 | Only `WebSocket` and `WebSocket (ws://)` with encryption not Yes; excludes wss false positives. Supersedes I01. |
| P01 | Removes NTLM from cleartext protocols; P03 still covers NTLM. Supersedes I01/T02 for the same interaction. |
| E04 | Requires Cookie / Session authentication so bearer-token APIs avoid CSRF findings. |
| W01 | Requires Cookie / Session; removes redundant source-type condition for cookie-authenticated socket hijacking. |
| D03 | Title interpolates both target and source names. |
| X04 | Backups not Yes, including unset, trigger the finding. |
| R01 | Requires boundary crossing; groups by target to avoid repeated logging findings. |
| R02 | Requires boundary crossing to match its description. |
| R03 | Requires boundary crossing to match its description. |
| T03 | Removes Vector Database from SQL/NoSQL injection targets. |
| S04 | Requires boundary crossing and authentication Not Selected/None. |
| S05 | Requires boundary crossing and authentication Not Selected/None. |
| S02 | Requires boundary crossing. |
| S06 | Requires boundary crossing. |
| E01 | Requires boundary crossing. |
| E02 | Requires boundary crossing plus internetFacing Yes or validatesInput not Yes; groups by target. |
| D01 | Requires boundary crossing; groups by target. |
| I05 | Skips internetFacing No; groups by target. |
| T01 | Groups by target; incorporates E03 execution-flow and memory-safety guidance. |
| E03 | Removed because its condition duplicated T01. |
| W03 | Supersedes S03/S07 on the same interaction. |
| K01 | Supersedes S03/S07 on the same interaction. |
| P13 | Supersedes S07 on the same interaction. |

Optional `dedupeKey` defaults to per-flow behavior; `supersedes` defaults to no
supersession. Older custom templates do not need either field. Paths reject
prototype-related segments and traverse own properties only. Import rejects invalid
schema values, malformed conditions, unknown operators/roots and missing superseded
rule IDs, with the offending rule ID in the error.

## Verification performed

Run from the repository root:

```sh
npm test
npm run test:acceptance
```

- `npm test`: **122 passed, 0 failed, 0 skipped**, plus the original engine checks.
  The offline test builds `dist/STRIDE.html`, checks its script CSP hash, parses its
  JavaScript and executes its dependencies before DOM bootstrap.
- Acceptance script: **35 threats** generated and marked mitigated with owner,
  notes and mitigation. Identity and review fields survived regeneration. Actual
  `.stride` bytes were written and reopened, with full model equality. Report JSON
  was written and reopened with full equality. Every visible threat appeared once
  in category/interaction groups and Markdown; PDFs were generated. Calls to
  fetch, XMLHttpRequest, WebSocket and EventSource were denied and counted: **0**.
- PDF content/layout check: **19-page sample** and **26-page long-notes report**.
  All threats and 25 interaction headings retained; page bounds and footers passed.
  Each of 450 numbered evidence paragraphs occurred exactly once, including the
  final marker. Rendered contact sheets and detailed diagram/threat/notes pages
  were visually inspected with no clipping or overlapping content found.

Artifacts are generated locally and ignored by Git:

| File | Purpose |
| --- | --- |
| `dist/STRIDE.html` | Standalone offline application |
| `output/pdf/stride-example-model.stride` | Reviewed model to open for manual QA |
| `output/pdf/stride-example-report.pdf` | Sample audit report |
| `tmp/pdfs/example-report.json` | Lossless report envelope |
| `tmp/pdfs/example.md` | Self-contained Markdown report |
| `tmp/pdfs/long-notes.pdf` | Pagination stress report |
| `tmp/pdfs/*-contact.png` | PDF contact sheets |

Optional PDF inspection uses the development-only `scripts/verify-report-pdf.py`
with PyMuPDF. This environment already has it at
`/private/tmp/stride-pdf-qa/bin/python`; it is not an application dependency.
On a reviewer machine with PyMuPDF available, run
`python3 scripts/verify-report-pdf.py` after the acceptance command.

## Browser checks still required

**Browser acceptance is not signed off.** The browser tool returned “No browser is
available” and an empty browser list. Node persistence tests substitute the database
boundary; TM7 Node tests use Python's standard-library XML parser as a DOM test
adapter. These prove application logic but do not prove native IndexedDB, DOMParser,
browser event handling or actual browser network traffic.

1. Open `dist/STRIDE.html` directly. In DevTools Network, preserve the log, reload,
   then draw/connect nodes, add a trust boundary and generate threats. Verify no
   HTTP(S), WebSocket or other remote requests. Local file/data/blob resources are
   expected. Source mode served by `npm start` needs initial static asset requests;
   use the standalone file to test zero traffic including startup.
2. Mark each threat Mitigated, fill notes, owner, severity and mitigation. Save a
   `.stride` file. Refresh while a notes field still has focus, then verify recovery.
   Reopen the file and compare the diagram, IDs, every review field and dashboard.
3. Test undo/redo and unavailable browser storage. An IndexedDB failure must show
   fallback/error status without claiming a durable save. Verify explicit file save
   remains usable.
4. Export PDF, Markdown and report JSON. Inspect the PDF and reopen JSON. Verify
   diagram images, element tables, groups, contributing flows and review decisions.
5. Run `npm start`, then visit `/tests/security.html` and `/tests/tm7-browser.html`.
   Both should report PASS using native browser APIs. Confirm the injected element
   name displays literally and creates no image, alert or request.
6. Open a representative real Microsoft TMT `.tm7` file, including any bank-specific
   stencil/template. Inspect mappings and warnings; save/reopen and export. Unknown
   content must remain visible and original source/reviews must remain in JSON.

## Focus for independent review

- Check rule conditions against their descriptions and positive/negative fixtures.
  Five inbound flows must yield one T01; Telnet must show P01 while hiding I01/T02;
  wss must not show W02; bearer-token flows must not show E04.
- Check grouping and suppression migrations carefully: conflicting older reviews
  are retained in suppressed model records; the visible grouped threat adopts one
  reviewed record. Evaluate whether that review policy fits the intended workflow.
- Trace attacker-controlled names, imported templates, TM7 text and review fields
  through every DOM/export sink. Validate unsafe templates before replacing a model.
- Verify TM7 variants with real files. Unknown/custom/localized content is preserved
  and warned about; embedded Microsoft templates are retained in original XML rather
  than translated into executable rules. Import warnings remain as historical records.
- Direct PDF uses locally embedded Roboto (Latin/Greek/Cyrillic). Other glyphs cause
  an explicit error; printable HTML with system fonts is the documented fallback.
- Recovery has one slot per browser storage location. Multiple tabs share it;
  standalone file storage behavior depends on the browser. Local files are the
  durable user-controlled backup.

# STRIDE feature reference

STRIDE draws data-flow diagrams, generates potential threats, records reviews, and exports reports **entirely in your browser**. Models, imported files, diagrams, and threat text are processed locally. There is no backend, account, telemetry, or upload service.

This reference describes the current application. For a worked introduction and progressively more complex models, follow [GUIDE.md](GUIDE.md). For running or maintaining the application, see [README.md](README.md).

## Contents

- [Local operation and privacy](#local-operation-and-privacy)
- [Workspace and menus](#workspace-and-menus)
- [Drawing and editing](#drawing-and-editing)
- [Trust boundaries and scope](#trust-boundaries-and-scope)
- [Security properties](#security-properties)
- [Threat generation and review](#threat-generation-and-review)
- [Saving, loading, and recovery](#saving-loading-and-recovery)
- [Reports and exports](#reports-and-exports)
- [Microsoft TMT import](#microsoft-tmt-import)
- [Custom threat templates](#custom-threat-templates)
- [Validation and troubleshooting](#validation-and-troubleshooting)
- [Keyboard and pointer reference](#keyboard-and-pointer-reference)
- [Complete stencil catalogue](#complete-stencil-catalogue)
- [Built-in rule index](#built-in-rule-index)

## Local operation and privacy

| How you open STRIDE | Network behavior | Requirements |
| --- | --- | --- |
| Hosted app | Fetches static application assets at startup; modeling, analysis, storage, import, and export run locally. | A modern browser and access to the site for loading it. |
| Standalone `STRIDE.html` | No network requests are needed, including startup and refresh. | A modern browser; open the file directly. |
| Source checkout served locally | Loads assets from your local static server; model processing remains in the browser. | See the development commands in [README.md](README.md). |

For a disconnected workstation, obtain the standalone file from your maintainer. Maintainers generate it with `npm run build:offline`; users do not need Node.js, Python, package installation, or a running server. The source `index.html` uses JavaScript modules and should be served over HTTP; it is not the standalone distribution.

Scripts, icons, rules, PDF rendering code, and PDF fonts are local assets. The app's Content Security Policy blocks network connections. There are no remote scanners, AI services, external font downloads, or server-side report generators. PDF components and fonts are bundled; their licenses are in [THIRD_PARTY.md](THIRD_PARTY.md).

Local does not mean encrypted: STRIDE does not add password protection to model files or browser storage. Apply your normal workstation, backup, and document-handling controls. Browser extensions, operating-system backups, and a download folder synchronized by another application are outside STRIDE's control. A downloaded report or deliberately shared link contains the information you chose to put in the model.

## Workspace and menus

| Area | Purpose |
| --- | --- |
| Top-left **Menu** | Open/save files, export, share, model metadata, templates, example model, display preferences, and help. |
| Top toolbar | Select, pan, draw DFD elements, open the symbol library, erase, or keep a drawing tool active. |
| Canvas | Draw and arrange your architecture. |
| Left properties panel | Edit the selected element's name, type, appearance, security properties, scope, and notes. |
| **Design / Analysis** | Switch between drawing and reviewing threats. Analysis adds threat badges and the threat panel. |
| Right threat panel | Filter findings, edit a threat, add a manual threat, or open **Summary**. |
| Bottom-left controls | Zoom and undo/redo. |
| Bottom-center tabs | Switch, add, rename, duplicate, reorder, and delete diagrams. |
| Bottom-right controls | Local autosave status, validation messages, and shortcut help. |

On narrow windows, the properties panel is hidden while Analysis is open. Switch to Design to edit element properties, or widen the window.

### Model-level actions

- **New model** starts a blank model. Save the current one first if you need a durable copy.
- **Load example model** opens the bundled example. This replaces the current model; it does not append a diagram.
- **Model properties…** edits **Title**, **Owner**, **Reviewer**, **Contributors**, **High-level system description**, **Assumptions**, and **External dependencies**. These fields travel with the model and reports. Title is required.
- **Hand-drawn style** changes the sketch appearance; **Show grid** toggles a visual positioning aid; **Dark mode** changes the interface theme. These are display choices, not security properties.
- **Help & shortcuts** opens the in-app reference.

### Multiple diagrams

Click **+** beside the tabs to add a diagram. Double-click a tab to rename it. Right-click a tab for **Rename**, **Duplicate**, **Move left**, **Move right**, and **Delete diagram**.

Each diagram has its own elements and flows. There are no cross-diagram connectors or synchronized representations of an element. Two shapes with the same name in different diagrams remain independent. Duplicating a diagram copies its shapes and properties with new identities; threat review records are not copied to those new identities.

Deleting a diagram also deletes its threat records. Save a checkpoint before removing a reviewed diagram; Undo is available in the current session. At least one diagram must remain.

Use multiple diagrams for different architectural views, but remember that the summary and full reports include all of them. Repeating the same scenario in several diagrams can produce multiple findings for the same real-world risk.

## Drawing and editing

### Element kinds

| Kind | Represents | Examples |
| --- | --- | --- |
| **Process** | Code that executes or transforms data. | API, service, worker, gateway, client application. |
| **External Entity** | A person or system outside the modeled system's control. | Customer, partner, external identity provider. |
| **Data Store** | Data at rest, including persistent queues and credentials. | Database, object storage, topic, vault. |
| **Data Flow** | A directed movement of data between two nodes. | Request, response, query, event, token exchange. |
| **Trust Boundary** | A box around a trust zone. | Internet-facing service zone, management network, tenant. |
| **Trust Boundary (line)** | A straight or curved separation crossed by flows. | A trust transition that is easier to show with a line. |
| **Note** | Free-text annotation. | Assumption, evidence reference, legend, or open question. |

Select a tool, then click or drag on the canvas. The tool normally returns to Select after creation; **Q** locks it for repeated drawing. Hold Shift while drawing a shape to constrain its proportions. Select an element and change **Type** to choose a subtype. Subtypes affect icons, some default properties, and applicable rules; they are more than labels.

Press **Y** for the curated symbol library or **/** to search tools and stencils. The library is a subset of the full catalogue; use search or the Type dropdown for other choices. The [catalogue](#complete-stencil-catalogue) lists every available subtype.

### Connect and name flows

1. Hover a node to expose connection points and drag toward another node, or choose **Data Flow** and drag between nodes.
2. Allow the endpoints to snap to their shapes.
3. Select the flow. Its properties panel must show the intended **source → target**, not `(unconnected)`.
4. Give it a meaningful name and select its protocol/type and security properties.

Arrow direction defines source and target for rule evaluation. Model responses separately when their data, authentication, or trust implications differ. Selecting a flow exposes endpoint handles for reattachment and a middle handle for bending. Parallel flows are curved to help distinguish them. **Reverse direction** in the properties panel swaps the endpoints.

A free-standing arrow can be drawn, but it produces no interaction threats until both ends connect to supported nodes. A line merely touching a shape is not proof of a connection; check the displayed endpoint names.

### Selection, layout, and annotations

- Click to select; Shift-click to add or remove elements from the selection. Drag on empty canvas to select an area.
- Drag selected elements to move them; use resize handles to change shape size. Arrow keys make small adjustments.
- Double-click or press Enter to edit a label. Notes support multiple lines; Ctrl/Cmd+Enter finishes multiline editing.
- Change **Stroke** and **Background** colors in the properties panel. Multiple selections support shared appearance changes.
- Use **Bring to front** and **Send to back** for overlapping objects. These change drawing order, not trust or access.
- Duplicate or copy/paste a selection to reuse layouts. Clipboard content is STRIDE element data, not an arbitrary diagram/image importer. New copies receive new identities and generate their own threats.
- Delete via the properties panel, context menu, keyboard, or Eraser. Deleting a node leaves any surviving connectors detached; reconnect or remove them.
- Right-click a selected element for editing, scope, threat-view, and zoom actions. Right-click empty canvas for paste, selection, zoom, grid, model properties, and PNG export.

Use the Hand tool, Space-drag, or scrolling to pan. Use zoom controls, Ctrl/Cmd+wheel, or touch pinch to zoom. **Shift+1** fits the diagram; **Shift+2** fits the selection. The grid is a visual guide; connector snapping is what establishes node attachments.

Undo/redo covers model edits during the current session. Undo history is not a durable version history and is not restored after refresh.

## Trust boundaries and scope

### How crossings are calculated

A boundary box counts as crossed when **one endpoint node's center is inside and the other is outside**. Put nodes clearly inside or outside the box. A flow that visually leaves and re-enters a box while both endpoint centers remain inside does not count as crossing that box.

A boundary line counts as crossed when its drawn curve intersects the flow curve. Recheck crossings after bending or moving lines. Nested boundaries are allowed: a flow can cross more than one, and their names can appear in generated text. The engine does not infer a trust hierarchy or access policy from nesting or a boundary's subtype.

Moving a boundary box also moves enclosed elements. Hold **Alt** while dragging the box to move the boundary without carrying its contents. Resizing or moving a boundary can change which rules fire.

External Entity **Trust level**, colors, names such as “DMZ,” and process **Internet facing** do not create a geometric boundary automatically. Draw the boundary and set those properties separately.

### Out of scope

Select an element or flow, enable **Out of scope**, and record a reason. This is a modeling decision, not a mitigation.

Interaction rules skip an out-of-scope flow or their out-of-scope focus element. Marking one node out of scope therefore does **not** necessarily suppress every threat on every connected flow: a rule may focus on the other endpoint or the flow itself. Mark affected flows explicitly when the whole interaction is excluded. Out-of-scope boundaries are not a substitute for removing or correcting boundary geometry.

## Security properties

Properties express what you know about the architecture. They do not enable controls in the modeled system. **Not Selected** means unknown or unrecorded. Many rules treat anything other than Yes as lacking a demonstrated control; others require a particular subtype, exposure, or explicit value. An unknown setting does not universally generate the same threats as No.

In the tables below, **YN** means the exact options **Not Selected / Yes / No**. Property keys are included for custom-template authors.

### Processes

| Property | Key | Options |
| --- | --- | --- |
| Code type | `codeType` | Not Selected; Managed; Unmanaged (C/C++); Interpreted / Script |
| Running as | `runningAs` | Not Selected; Kernel; System / root; Standard user; Low privilege / sandboxed |
| Isolation | `isolation` | Not Selected; None; Container; Virtual machine; Sandbox |
| Authenticates callers | `authenticatesCallers` | YN |
| Authorizes requests | `authorizesRequests` | YN |
| Validates input | `validatesInput` | YN |
| Encodes / sanitizes output | `sanitizesOutput` | YN |
| Logs security events | `logsSecurityEvents` | YN |
| Handles secrets / keys | `handlesSecrets` | YN |
| Internet facing | `internetFacing` | YN |

These describe the specific process, not every upstream control. A gateway authenticating a request does not by itself establish that a downstream API checks object ownership or validates its inputs.

### External entities

| Property | Key | Options |
| --- | --- | --- |
| Authenticates itself | `authenticatesItself` | YN |
| Trust level | `trustLevel` | Not Selected; Untrusted; Partially trusted; Trusted |

An authenticated user can still supply hostile input. A Trusted setting does not globally suppress spoofing or other threats.

### Data stores

| Property | Key | Options |
| --- | --- | --- |
| Encrypted at rest | `encryptedAtRest` | YN |
| Integrity protected (signed) | `integrity` | YN |
| Access control | `accessControl` | Not Selected; Fine-grained; Coarse; None |
| Stores credentials / secrets | `storesCredentials` | YN |
| Stores PII / sensitive data | `storesPII` | YN |
| Stores log data | `storesLogs` | YN |
| Backed up | `backedUp` | YN |

Encryption at rest and encryption of the connecting flow are independent. A backup's existence also does not prove recoverability: put restoration evidence and recovery requirements in notes.

### Data flows

| Property | Key | Options |
| --- | --- | --- |
| Encrypted in transit | `encrypted` | YN |
| Authentication | `authentication` | Not Selected; None; Password; Cookie / Session; Token (OAuth / JWT); mTLS / Certificate; API key; Kerberos / Windows |
| Integrity protected | `integrity` | YN |
| Replay protection | `replayProtection` | YN |
| Rate limited | `rateLimited` | YN |
| Carries credentials / tokens | `carriesCredentials` | YN |
| Carries sensitive data | `carriesSensitiveData` | YN |

Describe the actual authentication on that leg. **Cookie / Session** enables the relevant cookie-authenticated CSRF and WebSocket hijacking checks; a bearer-token API should use **Token (OAuth / JWT)**. Use notes for mechanisms that do not fit a dropdown precisely. Do not choose a different mechanism just to remove a finding.

Boundaries and notes have no security-property dropdowns.

### Subtype presets

Subtype presets fill **unset** properties. They do not overwrite an explicit existing choice. In particular, changing an HTTP flow to HTTPS can leave **Encrypted in transit = No** until you update that field yourself.

| Subtype(s) | Preset |
| --- | --- |
| Container / Pod; Kubernetes Pod | Isolation = Container |
| Log Store; Kafka Topic / Event Log; Audit Trail | Stores log data = Yes |
| Key Vault / Secret Store; HSM / Key Management; Directory (LDAP / AD); Session Store; Certificate Store | Stores credentials / secrets = Yes |
| Call Recording Store | Stores PII / sensitive data = Yes |
| HTTPS; SSH; WebSocket Secure (wss://); LDAPS; FTPS; DNS over HTTPS / TLS; VPN / IPsec | Encrypted in transit = Yes |
| HTTP; WebSocket (ws://); FTP; LDAP; SNMP; DNS; DNP3 | Encrypted in transit = No |
| Telnet | Encrypted in transit = No; Authentication = Password |
| TFTP; Modbus; CAN Bus | Encrypted in transit = No; Authentication = None |
| OAuth 2.0 / OIDC | Authentication = Token (OAuth / JWT) |
| Kerberos; NTLM | Authentication = Kerberos / Windows |

Other subtypes do not imply those settings. For example, REST / JSON, gRPC, SQL / DB Protocol, and File Transfer (SFTP / SMB) do not establish that transport encryption is enabled. Inspect and document every leg.

## Threat generation and review

### What the engine does

The built-in template contains **81 rules**. Interaction rules inspect connected flows, endpoint types/properties, and boundary crossings. Element rules inspect individual processes, entities, or stores. Threats regenerate as you commit modeling changes; there is no separate network scan to run.

| Category | Security question |
| --- | --- |
| S — Spoofing | Can someone impersonate this caller, service, or destination? |
| T — Tampering | Can data, code, or messages be changed without authorization? |
| R — Repudiation | Can someone deny an action because evidence is missing or unreliable? |
| I — Information Disclosure | Can information reach an unauthorized party? |
| D — Denial of Service | Can availability or capacity be exhausted or disrupted? |
| E — Elevation of Privilege | Can someone act beyond their permitted authority? |

Generated findings are review prompts based on the model, **not confirmed vulnerabilities**. The engine does not inspect the actual application, scan endpoints, verify a control, infer every attack chain, or certify compliance. Missing findings and a zero-open summary do not prove security.

Rule IDs such as `T01` identify a rule; displayed numbers such as `#18` identify a finding within the model. Technical rule families such as W, K, M, and P still map into the six STRIDE categories; they are not additional categories.

### List, selection, counts, and summary

Open **Analysis** to view the current diagram's threat list. Filter by STRIDE category, text, status, severity, and **Selection only**. Search covers finding number, title, description, interaction/contributing paths, owner, notes, justification, and mitigation. A rule ID is displayed in the detail header; search is not a dedicated rule-ID filter.

The selected element's properties show total and open findings. **View** opens Analysis with Selection only and clears the previous text search. Category, severity, and status filters remain active; clear them if “shown” is lower than expected. Right-click **Show threats** also scopes the list, but check any existing search text.

A finding belongs to a selected element or flow when its primary element, primary flow, or a contributing flow has that identity. Orphan findings are excluded from these element counts and selection views. A node count is not a count of every threat anywhere on its neighboring flows.

Canvas badges count open findings using the same membership rule. One grouped finding can contribute to several badges, so do not add badge counts to calculate the model total.

**Analysis → Summary** covers all diagrams and is independent of list filters. It reports status, STRIDE category, severity, and orphan totals. It includes visible generated and manual findings, including retained orphans; permanently suppressed merge history is excluded.

### Threat detail fields

| Field/action | Use |
| --- | --- |
| Title and Description | Explain the specific threat; edits to generated text survive regeneration. |
| Category | Choose one of the six STRIDE categories. |
| Severity | High, Medium, or Low; initialized from the rule's priority and then reviewable. |
| Status | Open, Mitigated, Accepted, or Not Applicable. |
| Owner | Record who is responsible. No account or assignment notification is created. |
| Notes | Record review observations, test/evidence references, dates, and open questions. |
| Justification | Explain the decision, especially acceptance or non-applicability. |
| Mitigation description | Record the implemented or proposed control and its scope. |
| Suggested mitigation / Use suggestion | Copy generated guidance into the mitigation field; this does not change status or prove implementation. |
| Locate control | Find the related element or flow on the canvas. |
| Reset text | Restore generated title and description after customization. |
| Delete | Available for manual and orphan findings; active generated findings are governed by the rules/model. |

Use **Open** for unresolved or unverified threats, **Mitigated** for controls with sufficient supporting evidence, **Accepted** for an explicit risk decision, and **Not Applicable** for a documented mismatch between the threat and the real scenario. The application records your decision; it does not approve it or require particular evidence fields.

### Grouped findings and review coverage

`T01`, `R01`, `D01`, `E02`, and `I05` group matching flows by target within a diagram. For example, five unvalidated inbound paths to one process create one T01 finding with five contributing flows, not five identical paragraphs. Grouping uses element identities, not names. Custom templates may also group by source.

Setting a grouped finding to a non-open status records which contributing flow IDs were reviewed. If another matching flow later joins:

1. The previous status, notes, and mitigation remain visible.
2. **New flows since review: …** identifies the new paths.
3. The finding counts and filters as **Open**, including in the summary and reports.
4. Review the added paths and use **Confirm status for current flows**, or choose the appropriate status, to confirm current coverage and clear the review flag.

This coverage check detects new flow identities. It does not automatically invalidate a review for every semantic change to an existing flow with the same ID. Review altered data, permissions, properties, and assumptions yourself.

Older per-flow reviews can be merged into a group. Conflicting decisions use the more conservative status: Open before Accepted before Mitigated/Not Applicable. Non-empty notes and mitigations are combined with source-flow labels; conflicting reviews require confirmation. Folded records remain suppressed in model JSON as audit history and are not repeatedly merged or displayed as orphans.

### Supersession and retained findings

Some specific rules hide more general findings on the **same interaction**:

| Specific rule | General rules it supersedes |
| --- | --- |
| P01 — cleartext legacy protocol | I01, T02 |
| W02 — unencrypted WebSocket | I01 |
| W03 — missing WebSocket authentication | S03, S07 |
| K01 — missing Kafka authentication | S03, S07 |
| P13 — unauthenticated industrial protocol | S07 |

When an ordinary generated finding stops matching, an untouched record can disappear; a reviewed or edited record is retained as an **orphan**. Orphans remain in the general list and reports for review, but not element badges or Selection only. Delete an obsolete orphan explicitly only when its retention is no longer needed.

A grouped record retains its identity across disappearance and reappearance. Edited unmatched groups can appear as orphans; untouched unmatched groups stay hidden. If the rule matches again, the existing review is reused. This is separate from explicitly deleting an entire diagram, which removes that diagram's records.

### Manual threats

Use **Analysis → + Add** for business-logic abuse, environmental risks, or missing rule coverage. A single selected node or flow becomes its attachment; with no single selection it is a general finding for the current diagram. Set the title, description, category, severity, owner, and review fields. New manual findings start Open, Medium, and Spoofing, so adjust the defaults.

Manual findings are not replaced by template regeneration. Deleting their attached element can make them orphans. The tool does not include a separate task tracker, evidence-file attachment system, or approval workflow; use textual references to your approved evidence repository.

## Saving, loading, and recovery

### Local model files

**Menu → Save .stride file** or **Ctrl/Cmd+S** downloads a complete JSON model with a `.stride` extension. It includes:

- Model metadata, diagrams, element identities/geometry, styles, properties, scope decisions, and notes.
- Threat identities, generated/manual text, status, severity, owner, notes, justification, and mitigation.
- Group contributors, review coverage, orphan/suppression state, and retained audit records.
- The model's custom template, if any, and preserved Microsoft TMT import information when present.

Saving downloads a snapshot; it does not keep writing to the originally opened file. Your browser controls the download location and duplicate-filename handling. Use meaningful versioned names for handoff and checkpoints.

**Menu → Open…** or **Ctrl/Cmd+O** loads `.stride`, supported model `.json`, lossless report JSON, or `.tm7`. Opening replaces the current model rather than merging files. Invalid model/template data is rejected before replacement. Saved reviews are restored, rather than discarded and rebuilt on open. Further modeling changes regenerate applicable findings.

### Autosave

The working model is saved to **IndexedDB** with a synchronous **localStorage recovery journal** for recent changes. There is one current-model recovery slot per browser storage location/origin. Other tabs using that location can overwrite it; use one active editing tab and save files when switching models.

| Status shown | Meaning / action |
| --- | --- |
| Restoring local model… | Startup recovery is being read. |
| Saving locally… | A local save is in progress. |
| Autosaved locally / Local autosave ready | Local persistence is available; continue keeping file checkpoints. |
| Recovery copy only — save a .stride file | The recovery journal worked but the main autosave did not; download a model now. |
| Autosave failed — save a .stride file | Browser persistence failed; download a model now. |
| Recovery unreadable — open a .stride file | Recovery cannot be safely loaded; reopen a saved checkpoint. |

Clearing site data, private browsing policies, storage limits, or moving to another browser/origin can affect recovery. Standalone file storage behavior also depends on the browser and file location. Refresh recovery is a convenience, not a substitute for saved model files. UI preferences are local; selection, viewport, filters, and undo history are not a portable review archive.

### Sharing

**Copy share link** compresses a snapshot into the URL's `#model=…` fragment and copies it to the clipboard. It does not upload the model. The fragment is not part of an ordinary HTTP request, but anyone receiving the full link has the encoded model; compression is not encryption.

Share links can be very long and require browser compression/clipboard support. The recipient still needs to load the application. Use `.stride` files for disconnected handoff or a standalone `file://` installation; a file-origin share link is not a portable distribution mechanism. There is no real-time collaboration or automatic merging of reviewers' files.

## Reports and exports

All exports are assembled locally. Full reports use a model snapshot, include all diagrams, and are not narrowed by the current threat-list filters. They include metadata, a status/category summary, diagram images, element inventories with properties, validation/import notes, and visible threats grouped by STRIDE category and interaction. Reviewed findings include their decisions and supporting text. Grouped findings include contributing paths and outstanding review notices.

| Menu action | Scope and purpose | Can reopen as an editable model? |
| --- | --- | --- |
| Save .stride file | Complete working model and preserved history. | Yes |
| Export report as PDF | Self-contained report generated directly in-browser. | No |
| Export report as Markdown | Text report with embedded SVG diagram data URLs. | No |
| Export report as JSON | Structured report plus a complete embedded model. | Yes |
| Printable HTML report | Self-contained report opened in another tab, with a Print action. | No |
| Export threats (CSV) | Threat register across the model, including review fields; no diagram image or full element inventory. | No |
| Export diagram as SVG | Vector image of the current diagram. | No |
| Export diagram as PNG | Raster image of the current diagram. | No |

The report JSON uses a `stride-report` envelope containing `model` and derived report data. Reopening uses the model, preserving editable content and audit fields. PDF, Markdown, CSV, and images are presentation outputs, not lossless model backups.

Direct PDF includes locally bundled Latin, Greek, and Cyrillic fonts. For unsupported characters, use **Printable HTML report → Print → Save as PDF** with suitable system fonts, then inspect the result. If the report popup is blocked, the application downloads the HTML instead. Long threat text can span pages; check layout and readability before distributing a final report.

Some Markdown viewers, including common repository renderers, block SVG data URLs. The image is embedded, but the viewer may not display it. Use PDF/HTML for predictable visual delivery, or export a separate diagram image for your document workflow.

CSV cells are protected against spreadsheet formula interpretation. Visible orphan findings are included in reports; permanently merged/suppressed history is retained in the model payload rather than repeated in the report's threat register. A finding needing review counts as Open, with its earlier recorded decision and review notice still available.

## Microsoft TMT import

Use **Open…** and select a Microsoft Threat Modeling Tool **`.tm7`** file. Parsing and mapping happen locally.

The importer reads diagrams, geometry, elements, connectors, available metadata, security properties, and existing threat reviews. Known types map to current stencils. Imported threat records are retained as manual findings; STRIDE-generated findings may also appear as the model is subsequently edited. Review overlaps instead of assuming the two tools have identical rule identities.

Review the validation messages after every import and select flagged elements to see **Microsoft TMT import**, original type information, source properties, and mapping warnings.

| Import situation | Handling |
| --- | --- |
| Recognized type and family | Map to an existing stencil. |
| Unknown subtype with a recognized family | Preserve a generic element in that family and flag the mapping. |
| Shape with no recognizable family | Preserve as a note with a warning; choose a proper model element manually if needed. |
| Unknown connector or unresolved endpoint | Preserve what can be drawn; flag incomplete mapping/connections for repair. |
| Ambiguous property value | Preserve source information and leave uncertain controls unset rather than infer security. |
| Unknown threat status, priority, or category | Use a fallback with a warning; inspect the review rather than accepting the fallback as an assessment. |

Unknown threat values can fall back to Open, Medium, or Spoofing respectively. Original XML is retained under the model's import data for traceability. Embedded Microsoft templates are preserved as source information, not automatically translated into executable STRIDE JSON rules. Malformed or unsafe XML is rejected.

Warnings record import-time mapping issues and may remain after you correct the model. Document the correction in notes. Save the repaired result as `.stride`; exporting back to `.tm7` is not supported. This is a best-effort migration, not a promise of semantic equivalence with every Microsoft/custom template.

## Custom threat templates

Open **Menu → Threat template…**. The editor contains a JSON array of rules:

- **Import…** reads a local template into the editor; **Apply** validates and activates it.
- **Export** downloads the editor's JSON so it can be reused.
- **Apply** replaces the model's active rule set; it does not automatically append your rules to the built-ins.
- **Reset to built-in** immediately restores the built-in template.
- **Close** leaves unapplied editor changes inactive.

Save a model checkpoint before replacing a template. To extend the existing rules, export/copy the full template, add rules with unique IDs, then apply the combined array. Custom templates are saved inside the model and need no server.

### Rule fields

| Field | Meaning |
| --- | --- |
| `id` | Required non-empty unique string. Keep it stable to preserve finding identity. |
| `category` | Required: `S`, `T`, `R`, `I`, `D`, or `E`. |
| `title` | Required string; may interpolate context paths. |
| `when` | Required non-empty condition. |
| `scope` | `interaction` (default) or `element`. |
| `priority` | `High`, `Medium` (default), or `Low`; initial finding severity. |
| `focus` | `source`, `target`, `flow`, or `element`; use a focus appropriate to the scope. For interaction rules the omitted focus is the flow. |
| `description`, `mitigation` | Optional strings with interpolation. Mitigation becomes the suggested mitigation. |
| `dedupeKey` | `flow` (default), `source`, or `target`; endpoint grouping applies to interaction rules within each diagram. |
| `supersedes` | Optional array of other rule IDs present in the same template; suppresses their matches on the same interaction. |

Interaction conditions can use `source`, `target`, and `flow`; element conditions can use only `element`. Context objects expose `id`, `name`, `type`, `subtype`, `props`, and `outOfScope`. Flow context additionally supplies boolean `flow.crossesBoundary` and the text `flow.boundaries`. Use the exact property keys and option strings documented above; names and option comparisons are case-sensitive.

### Condition syntax

| Form | Meaning |
| --- | --- |
| `["target.type", "eq", "process"]` | Strict equality. |
| `["target.props.validatesInput", "ne", "Yes"]` | Inequality; also matches missing/unset values. |
| `["flow.props.authentication", "in", ["None", "Not Selected"]]` | Membership; missing/null values are treated as Not Selected for `in`/`nin`. |
| `["flow.subtype", "nin", ["HTTPS", "SSH"]]` | Non-membership. |
| `["target.name", "exists", true]` | Present and neither null nor empty string; use false for the inverse. |
| `[condition1, condition2]` or `{"all": [condition1, condition2]}` | Every child must match (AND). |
| `{"any": [condition1, condition2]}` | At least one child must match (OR). |
| `{"not": condition}` | Negate a condition. |

Here is a complete demonstration template. Applying it by itself intentionally runs only this one rule; append the object to a full exported template if you want to retain built-in coverage.

```json
[
  {
    "id": "ORG01",
    "scope": "interaction",
    "category": "R",
    "priority": "Medium",
    "focus": "target",
    "dedupeKey": "target",
    "title": "Audit evidence required for {target.name}",
    "description": "Confirm that {target.name} records attributable security events for every contributing path.",
    "mitigation": "Record actor, action, outcome, time, and correlation ID in protected audit storage.",
    "when": {
      "all": [
        ["target.type", "eq", "process"],
        ["flow.crossesBoundary", "eq", true],
        ["target.props.logsSecurityEvents", "ne", "Yes"]
      ]
    }
  }
]
```

Titles, descriptions, and mitigations interpolate placeholders such as `{target.name}`, `{flow.name}`, or `{element.name}`. Missing values leave their placeholders visible. For grouped rules, write text about the grouped endpoint; if text differs between contributors, the engine uses the first contributor's text and lists the paths separately.

Validation rejects invalid categories/scopes/priorities/focus/grouping values, duplicate IDs, unknown superseded IDs, unsupported operators, malformed clauses, empty AND/OR groups, conditions deeper than 64 nesting levels, inappropriate roots for the scope, and unsafe path segments (`__proto__`, `prototype`, `constructor`). Error messages identify the affected rule. Paths cannot traverse inherited properties. Template and element text is rendered as text/escaped content rather than executable markup.

The validator does not prove your rule is logically useful or that a property name exists. Test custom rules with both a model that should match and one that should not. The definitive built-in conditions and schema are in [js/rules.js](js/rules.js).

## Validation and troubleshooting

Click the validation-message indicator at the bottom right. Checks include disconnected flows, non-process-to-non-process flows, isolated nodes, duplicate names, diagrams without trust boundaries, unjustified scope exclusions, retained orphan findings, and import warnings. These are modeling checks, not vulnerability scans.

| Symptom | Check |
| --- | --- |
| A flow generates no threats | Confirm both endpoint names, scope settings, active template, type/properties, and conditions. A connected flow does not guarantee any particular rule must match. |
| A boundary-dependent threat is missing | Check endpoint centers for boxes and actual intersections for line boundaries. Trust labels alone do not create crossings. |
| View lists fewer threats than the properties count | Clear category, status, and severity filters. View clears text search, but the context-menu route may retain it. |
| Summary differs from the current list | Summary covers all diagrams; the list is diagram/filter-specific. Check retained orphans and grouped review flags. |
| A mitigated finding is counted Open | Inspect its new-flow/review-required notice and confirm coverage after reviewing all contributors. |
| A threat remains after a property is corrected | It may be an edited orphan retained as review history, a different rule, or a manual finding. Inspect its ID and status. |
| HTTPS still shows unencrypted findings | Inspect Encrypted in transit. Subtype changes preserve explicit old values. |
| A typed property seems to have no effect | Use the defined option strings. Some rules intentionally remain review prompts even when other controls are declared. |
| An imported shape looks generic or flows are detached | Read TM7 warnings, compare the original type/properties, and repair uncertain mappings. |
| A refreshed browser opens an unexpected model | Check browser/origin/file location and other tabs sharing the recovery slot. Reopen your `.stride` checkpoint. |
| Model autosave is unavailable | Download a `.stride` file and check browser storage restrictions. |
| Direct PDF rejects characters or text is missing | Use Printable HTML with appropriate system fonts and inspect the printed PDF. |
| Markdown diagram is not visible | Use a renderer that supports SVG data URLs, or deliver PDF/HTML/separate PNG/SVG. |
| Properties disappear in Analysis | Switch to Design or use a wider window. |

## Keyboard and pointer reference

**Ctrl/Cmd** means Ctrl on Windows/Linux or Command on macOS. Most canvas shortcuts are inactive while typing in a field or while a dialog is open.

| Action | Shortcut / gesture |
| --- | --- |
| Select | V or 1 |
| Hand / pan | H; Space-drag; scroll |
| Process | P or 2 |
| External entity | E or 3 |
| Data store | D or 4 |
| Data flow | A or 5 |
| Boundary box | B or 6 |
| Boundary line | L or 7 |
| Note | T or 8 |
| Eraser | X or 0 |
| Keep drawing tool active | Q |
| Symbol library | Y |
| Search tools/stencils | / |
| Rename/edit selected label | Enter or double-click |
| Finish multiline label | Ctrl/Cmd+Enter |
| Add/remove selection | Shift-click |
| Constrain drawn shape | Shift while drawing |
| Move boundary without contents | Alt-drag |
| Nudge selection | Arrow keys; Shift for larger steps |
| Duplicate | Ctrl/Cmd+D |
| Copy / cut / paste | Ctrl/Cmd+C / X / V |
| Select all | Ctrl/Cmd+A |
| Delete | Delete or Backspace |
| Bring to front / send to back | Ctrl/Cmd+] / [ |
| Undo | Ctrl/Cmd+Z |
| Redo | Ctrl/Cmd+Shift+Z or Ctrl/Cmd+Y |
| Open / save model | Ctrl/Cmd+O / S |
| Zoom in / out | Ctrl/Cmd++ / −; Ctrl/Cmd+wheel; touch pinch |
| Reset zoom | Shift+0 or Ctrl/Cmd+0 |
| Fit diagram / fit selection | Shift+1 / Shift+2 |
| Horizontal pan | Shift+wheel |
| Toggle Analysis | Shift+A |
| Help | ? |
| Leave editing/tool/menu/selection | Esc, depending on current focus |

## Complete stencil catalogue

The catalogue below lists exact Type dropdown values. The symbol library provides convenient presets from this catalogue; availability of a stencil does not imply a dedicated threat rule for every technology.

### Process (57)

- Generic Process
- Web Application
- Web API / Service
- GraphQL API
- Browser Client (SPA)
- Mobile App
- Desktop / Thick Client
- Browser Extension
- Microservice
- Serverless Function
- Background Worker
- Scheduled Job / Cron
- ETL / Data Pipeline
- Container / Pod
- Kubernetes Pod
- Kubernetes Control Plane
- Service Mesh / Sidecar
- Orchestrator (Workflow / Agents)
- MCP Server
- AI Agent / LLM App
- ML Model Serving
- IVR System
- Genesys Contact Center
- Kafka Broker
- WebSocket Server / Gateway
- Message Broker
- API Gateway
- Load Balancer
- Reverse Proxy
- CDN / Edge
- Web Application Firewall
- Network Firewall
- VPN Gateway
- Bastion / Jump Host
- DNS Server
- Mail Server
- File Transfer Server
- Identity Provider
- Authentication Service
- Authorization / Policy Engine
- Active Directory Domain Controller
- Certificate Authority / PKI
- Secrets Manager
- Payment Service
- CI/CD Pipeline
- Build Agent / Runner
- SIEM / Log Collector
- EDR / Security Agent
- Vulnerability Scanner
- Admin Console / Management Plane
- Virtual Machine
- Mainframe / Legacy System
- Kernel Driver / Service
- IoT Gateway
- PLC / Controller
- SCADA / HMI
- Multiple Processes

### External Entity (26)

- Generic External Entity
- Human User
- Anonymous User
- Authenticated User
- Administrator
- Privileged Insider
- Browser
- Third-Party Service
- SaaS Application
- Payment Gateway
- OAuth / Social Login Provider
- Mobile Device
- IoT Device
- Partner System
- Supplier / Vendor
- Cloud Provider Service
- Email Recipient
- Phone Caller (PSTN)
- Genesys Cloud (SaaS)
- MCP Client / AI Assistant
- LLM Provider API
- Open-Source Dependency
- External Attacker (Internet)
- Malicious Insider
- Compromised Supply Chain
- Attacker

### Data Store (33)

- Generic Data Store
- Database
- SQL Database
- NoSQL Database
- Vector Database
- Data Warehouse / Lake
- Search Index
- Time-Series Database
- Kafka Topic / Event Log
- File System
- File Share (SMB / NFS)
- Blob / Object Storage
- Cache
- Session Store
- Key Vault / Secret Store
- HSM / Key Management
- Certificate Store
- Directory (LDAP / AD)
- Message Queue
- Log Store
- Audit Trail
- Call Recording Store
- Source Code Repository
- Container Registry
- Package / Artifact Registry
- ML Model / Training Data
- Email Mailbox
- Ledger / Blockchain
- Browser Storage
- Mobile Device Storage
- Configuration / Registry
- Cloud Instance Metadata
- Backup

### Data Flow (53)

- Generic Data Flow
- HTTP
- HTTPS
- REST / JSON
- GraphQL
- SOAP / XML
- gRPC
- WebSocket Secure (wss://)
- WebSocket (ws://)
- WebSocket
- Webhook Callback
- SQL / DB Protocol
- Message (AMQP / MQTT / Kafka)
- Kafka Produce / Consume
- MCP (JSON-RPC)
- SIP / RTP (Voice)
- OAuth 2.0 / OIDC
- SAML
- Kerberos
- NTLM
- LDAP
- LDAPS
- RADIUS
- DNS
- DNS over HTTPS / TLS
- NTP
- Syslog
- SNMP
- SMTP
- Email (SMTP)
- File Transfer (SFTP / SMB)
- SMB
- NFS
- FTP
- FTPS
- TFTP
- SSH
- Telnet
- RDP
- VNC
- IPC / Named Pipe
- RPC / DCOM
- WinRM / PowerShell Remoting
- VPN / IPsec
- Bluetooth / BLE
- NFC
- Wi-Fi
- USB / Physical Media
- Modbus
- DNP3
- OPC UA
- CAN Bus
- Binary / Custom

### Trust Boundary (23)

- Generic Trust Boundary
- Internet Boundary
- Machine Boundary
- Process Boundary
- Corporate Network
- DMZ
- Cloud VPC / VNet
- Cloud Account / Subscription
- Tenant Boundary
- Kubernetes Cluster
- Kubernetes Namespace
- Container Boundary
- Sandbox
- Browser Sandbox
- Kernel / User Mode
- Management Network
- PCI Zone (CDE)
- Partner Network
- Remote Access / VPN
- Wireless Network
- OT / ICS Network
- Physical Boundary
- Endpoint / Device

### Trust Boundary (line) (11)

- Generic Trust Boundary
- Internet Boundary
- Machine Boundary
- Process Boundary
- Corporate Network
- DMZ
- Management Network
- PCI Zone (CDE)
- OT / ICS Network
- Wireless Network
- Kernel / User Mode

## Built-in rule index

There are **81 built-in rules**. `E03` was folded into `T01`, so the E-series intentionally skips that ID. The category column is the STRIDE category; the ID prefix alone is not the category for specialist rules. Titles below show their interpolation placeholders. For full conditions and mitigation guidance, read [js/rules.js](js/rules.js).

| ID | Category | Scope | Generated title |
| --- | --- | --- | --- |
| S01 | S | interaction | Spoofing the {source.name} External Entity |
| S02 | S | interaction | Spoofing the {target.name} Process |
| S03 | S | interaction | Spoofing the {source.name} Process |
| S04 | S | interaction | Spoofing of Destination Data Store {target.name} |
| S05 | S | interaction | Spoofing of Source Data Store {source.name} |
| S06 | S | interaction | Spoofing of the {target.name} External Destination Entity |
| S07 | S | interaction | Weak or Missing Authentication on {flow.name} |
| T01 | T | interaction | Potential Lack of Input Validation for {target.name} |
| T02 | T | interaction | Data Flow {flow.name} Is Potentially Tampered |
| T03 | T | interaction | Potential Injection Vulnerability for {target.name} |
| T04 | T | interaction | Cross Site Scripting in {target.name} |
| T05 | T | interaction | Replay Attacks against {target.name} |
| T06 | T | interaction | Tampering with Data in {target.name} |
| R01 | R | interaction | Potential Data Repudiation by {target.name} |
| R02 | R | interaction | External Entity {target.name} Potentially Denies Receiving Data |
| R03 | R | interaction | Data Store {target.name} Denies {source.name} Potentially Writing Data |
| R04 | R | interaction | Lower Trusted Subject Updates Logs in {target.name} |
| I01 | I | interaction | Data Flow Sniffing on {flow.name} |
| I02 | I | interaction | Weak Access Control for a Resource: {source.name} |
| I03 | I | interaction | Credentials Exposed on {flow.name} |
| I04 | I | interaction | Sensitive Data Sent to External Entity {target.name} |
| I05 | I | interaction | Information Disclosure Through Error Messages of {target.name} |
| D01 | D | interaction | Potential Process Crash or Stop for {target.name} |
| D02 | D | interaction | Data Flow {flow.name} Is Potentially Interrupted |
| D03 | D | interaction | Data Store {target.name} Inaccessible from {source.name} |
| D04 | D | interaction | Potential Excessive Resource Consumption for {source.name} or {target.name} |
| D05 | D | interaction | Missing Rate Limiting on {target.name} |
| E01 | E | interaction | Elevation Using Impersonation |
| E02 | E | interaction | {target.name} May be Subject to Elevation of Privilege Using Remote Code Execution |
| E04 | E | interaction | Cross Site Request Forgery against {target.name} |
| E05 | E | interaction | Unsafe Deserialization in {target.name} |
| E06 | E | interaction | Missing Authorization in {target.name} |
| M01 | T | interaction | Tool Poisoning / Indirect Prompt Injection from {source.name} |
| M02 | E | interaction | Excessive Agency: Over-privileged Tools in {target.name} |
| M03 | S | interaction | Token Passthrough / Confused Deputy at {target.name} |
| M04 | I | interaction | Sensitive Data Sent to LLM Provider {target.name} |
| K01 | S | interaction | Unauthenticated Producer Writes to {target.name} |
| K02 | T | interaction | Event Injection / Poisoned Messages in {target.name} |
| W01 | S | interaction | Cross-Site WebSocket Hijacking against {target.name} |
| W02 | I | interaction | Unencrypted WebSocket (ws://) on {flow.name} |
| W03 | S | interaction | Unauthenticated WebSocket Handshake to {target.name} |
| W04 | E | interaction | Stale Authorization on Long-Lived WebSocket to {target.name} |
| W05 | T | interaction | Malicious WebSocket Message Injection into {target.name} |
| W06 | D | interaction | WebSocket Connection / Message Flooding of {target.name} |
| V01 | S | interaction | Caller ID Spoofing against {target.name} |
| V02 | I | interaction | Sensitive Data Captured in Call Recordings / Transcripts |
| V03 | D | interaction | Telephony DoS / Toll Fraud on {target.name} |
| V04 | S | interaction | Social Engineering of Contact-Center Agents via {target.name} |
| O01 | T | interaction | Workflow / Task Injection into {target.name} |
| P01 | I | interaction | Cleartext Legacy Protocol ({flow.subtype}) on {flow.name} |
| P02 | E | interaction | Remote Administration Exposed Across Trust Boundary ({flow.subtype} to {target.name}) |
| P03 | S | interaction | NTLM Relay / Pass-the-Hash on {flow.name} |
| P04 | E | interaction | Directory Credential Attacks against {target.name} |
| P05 | S | interaction | SSO Token / Assertion Forgery or Replay on {flow.name} |
| P06 | S | interaction | DNS Spoofing / Hijacking of {flow.name} |
| P07 | S | interaction | Forged Webhook Callbacks to {target.name} |
| P08 | D | interaction | GraphQL Introspection, Batching and Query-Depth Abuse on {target.name} |
| P09 | T | interaction | HTTP Request Smuggling / Header Spoofing via {source.name} |
| P10 | I | interaction | Cloud Credential Theft from Instance Metadata ({target.name}) |
| P11 | T | interaction | Malicious or Vulnerable Artifact from {source.name} |
| P12 | S | interaction | Email Spoofing / Phishing via {flow.name} |
| P13 | T | interaction | Unauthenticated Industrial Control Commands on {flow.name} |
| P14 | I | interaction | Wireless Eavesdropping, Pairing and Relay Attacks on {flow.name} |
| P15 | T | interaction | Malicious Removable Media into {target.name} |
| P16 | I | interaction | Data Exfiltration or Misuse by Insider {source.name} |
| P17 | D | interaction | Volumetric DDoS against {target.name} |
| P18 | R | interaction | Log Forging or Suppression before Reaching {target.name} |
| X01 | I | element | Sensitive Data Stored Unencrypted in {element.name} |
| X02 | E | element | {element.name} Runs With Elevated Privileges |
| X03 | I | element | Secrets Leakage from {element.name} |
| X04 | D | element | Data Loss in {element.name} |
| X05 | E | element | Memory Corruption in {element.name} |
| C01 | E | element | Container Escape from {element.name} |
| C02 | E | element | Kubernetes Control Plane Compromise via {element.name} |
| C03 | E | element | High-Value Orchestration Target: {element.name} |
| P19 | E | element | Server-Side Request Forgery (SSRF) in {element.name} |
| P20 | T | element | Poisoned Pipeline Execution in {element.name} |
| P21 | I | element | Secrets Committed to {element.name} |
| P22 | E | element | Compromise of Administrative Access Path {element.name} |
| P23 | I | element | Session Tokens in {element.name} Exposed to XSS |
| P24 | I | element | Unprotected Data on Device Storage ({element.name}) |

# STRIDE Threat Modeler

A client-side threat-modeling tool with an Excalidraw-style canvas and the core feature set of the
Microsoft Threat Modeling Tool. You draw a data-flow diagram, mark trust boundaries and set security
properties, and STRIDE threats are generated for every interaction. A library of more than 150 technology
stencils and 82 threat rules, including penetration-testing specific ones, gets you from a whiteboard sketch
to a reviewable threat list.

Everything runs in the browser, with **no build step, no backend and no dependencies**. Models are autosaved
to `localStorage` and can be saved and opened as files.

**Live:** https://0xdhanesh.github.io/STRIDE/

## Features

| Area | What you get |
| --- | --- |
| **Canvas** | Infinite canvas, pan (space/wheel/hand), zoom, marquee select, move, resize, curved flows, copy/paste, duplicate, z-order, undo/redo, eraser, notes, hand-drawn or clean style, dark mode, touch pinch-zoom |
| **DFD elements** | Process (incl. *Multiple Processes*), External Entity, Data Store, Data Flow, Trust Boundary box, Trust Boundary line |
| **Stencils** | 57 process, 26 external-entity, 33 data-store, 53 data-flow (protocol) and 23 trust-zone types, most with their own symbol. Databases draw as cylinders, Kafka topics as segmented logs |
| **Symbol library** | `Y` or the toolbar button opens 110 curated symbols in 13 groups. Click to add or drag onto the canvas; the library closes once the symbol is placed |
| **Quick search** | `/` searches every drawing tool and every stencil. Use `↑` `↓` to move, `Enter` to pick a tool or insert a symbol at the cursor, and `Esc` to close |
| **Connectors** | Hover a shape to get connection dots and drag one to create a data flow. Ends snap magnetically to the nearest shape and preview the attachment while dragging. Aligned shapes get straight connectors, request/response pairs curve apart, and loose ends attach when a shape is dropped on them |
| **Properties** | Per-element security properties (encrypted, authentication, validates input, runs as root, internet facing…) that drive threat generation. Picking a protocol presets them (HTTPS/wss/LDAPS → encrypted; Telnet/FTP/ws → not). Out-of-scope with justification; notes |
| **Threat engine** | 82 rules: STRIDE-per-interaction and element-level (modelled on the TMT SDL template), plus web, cloud, AI/MCP, WebSocket, Kafka, contact-center, Kubernetes and penetration-testing threats. Detects boundary crossings for boxes *and* curved lines |
| **Analysis view** | Threat list with STRIDE chips, search, state/priority filters and a selection filter. Editor for title, category, priority, state, description, justification and mitigation, with suggested mitigations. Custom threats; open-threat badges on the diagram |
| **Stable threats** | IDs, states and justifications survive diagram edits. When an interaction disappears, untouched threats are removed and edited ones are kept as *orphaned* |
| **Validation** | Messages for unconnected flows, invalid DFD links (store→store, entity→store), duplicate names, missing boundaries and unjustified out-of-scope |
| **Multiple diagrams** | Tabs: add, rename, duplicate, reorder, delete |
| **Reports & export** | Printable HTML report (summary, per-diagram images, element properties, threats by interaction), CSV, PNG, SVG, JSON |
| **Templates** | View and edit the threat template as JSON; import/export; it's stored inside the model file |
| **Interop** | Opens Microsoft TMT `.tm7` files (best effort: diagrams, elements, flows, boundaries, threats with state and justification) |
| **Sharing** | "Copy share link" compresses the whole model into the URL fragment, so nothing is uploaded |

## Stencil catalogue

Every stencil below is available from the element's **Type** dropdown, from quick search (`/`) and, for the
most common ones, from the symbol library (`Y`).

### Processes (circles)

| Group | Types |
| --- | --- |
| Apps & APIs | Generic Process, Web Application, Web API / Service, GraphQL API, Browser Client (SPA), Mobile App, Desktop / Thick Client, Browser Extension, Microservice, Payment Service, Admin Console / Management Plane |
| Compute & platform | Serverless Function, Background Worker, Scheduled Job / Cron, ETL / Data Pipeline, Container / Pod, Kubernetes Pod, Kubernetes Control Plane, Service Mesh / Sidecar, Orchestrator (Workflow / Agents), Virtual Machine, Mainframe / Legacy System, Kernel Driver / Service, Multiple Processes |
| Messaging & realtime | Kafka Broker, Message Broker, WebSocket Server / Gateway |
| Network & edge | API Gateway, Load Balancer, Reverse Proxy, CDN / Edge, Web Application Firewall, Network Firewall, VPN Gateway, Bastion / Jump Host, DNS Server, Mail Server, File Transfer Server |
| Identity & crypto | Identity Provider, Authentication Service, Authorization / Policy Engine, Active Directory Domain Controller, Certificate Authority / PKI, Secrets Manager |
| AI | MCP Server, AI Agent / LLM App, ML Model Serving |
| DevOps & SecOps | CI/CD Pipeline, Build Agent / Runner, SIEM / Log Collector, EDR / Security Agent, Vulnerability Scanner |
| Contact center | IVR System, Genesys Contact Center |
| OT / IoT | IoT Gateway, PLC / Controller, SCADA / HMI |

### External entities (rectangles)

Generic External Entity, Human User, Anonymous User, Authenticated User, Administrator, Privileged Insider,
Browser, Third-Party Service, SaaS Application, Payment Gateway, OAuth / Social Login Provider, Mobile Device,
IoT Device, Partner System, Supplier / Vendor, Cloud Provider Service, Email Recipient, Phone Caller (PSTN),
Genesys Cloud (SaaS), MCP Client / AI Assistant, LLM Provider API, Open-Source Dependency, and the threat actors
**External Attacker (Internet)**, **Malicious Insider**, **Compromised Supply Chain** and **Attacker**.

### Data stores

| Group | Types |
| --- | --- |
| Databases *(cylinder)* | Database, SQL Database, NoSQL Database, Vector Database, Data Warehouse / Lake, Time-Series Database |
| Streams & queues | Kafka Topic / Event Log *(segmented log)*, Message Queue |
| Files & objects | File System, File Share (SMB / NFS), Blob / Object Storage, Backup |
| Identity & secrets | Key Vault / Secret Store, HSM / Key Management, Certificate Store, Directory (LDAP / AD), Session Store |
| Logs | Log Store, Audit Trail, Call Recording Store |
| Supply chain | Source Code Repository, Container Registry, Package / Artifact Registry, ML Model / Training Data |
| Other | Generic Data Store, Search Index, Cache, Email Mailbox, Ledger / Blockchain, Browser Storage, Mobile Device Storage, Configuration / Registry, Cloud Instance Metadata |

### Data flows (protocols)

| Group | Types |
| --- | --- |
| Web & APIs | HTTP, HTTPS, REST / JSON, GraphQL, SOAP / XML, gRPC, WebSocket Secure (wss://), WebSocket (ws://), Webhook Callback |
| Messaging | Message (AMQP / MQTT / Kafka), Kafka Produce / Consume, MCP (JSON-RPC), SIP / RTP (Voice) |
| Identity | OAuth 2.0 / OIDC, SAML, Kerberos, NTLM, LDAP, LDAPS, RADIUS |
| Infrastructure | DNS, DNS over HTTPS / TLS, NTP, Syslog, SNMP, SMTP, VPN / IPsec |
| File & remote access | File Transfer (SFTP / SMB), SMB, NFS, FTP, FTPS, TFTP, SSH, Telnet, RDP, VNC, WinRM / PowerShell Remoting |
| Local & physical | SQL / DB Protocol, IPC / Named Pipe, RPC / DCOM, Bluetooth / BLE, NFC, Wi-Fi, USB / Physical Media |
| OT | Modbus, DNP3, OPC UA, CAN Bus |

### Trust boundaries

Generic Trust Boundary, Internet Boundary, Machine Boundary, Process Boundary, Corporate Network, DMZ,
Cloud VPC / VNet, Cloud Account / Subscription, Tenant Boundary, Kubernetes Cluster, Kubernetes Namespace,
Container Boundary, Sandbox, Browser Sandbox, Kernel / User Mode, Management Network, PCI Zone (CDE),
Partner Network, Remote Access / VPN, Wireless Network, OT / ICS Network, Physical Boundary, Endpoint / Device.

## Threat rule catalogue

| IDs | Area | Examples |
| --- | --- | --- |
| S01–S07 | Spoofing | Spoofed external entities / processes / data stores, weak authentication across boundaries |
| T01–T06 | Tampering | Missing input validation, tampered flows, SQL/NoSQL injection, XSS, replay, data-store tampering |
| R01–R04 | Repudiation | Missing audit logging, lower-trusted subjects writing logs |
| I01–I05 | Information disclosure | Sniffing, weak access control, credentials in transit, verbose errors |
| D01–D05 | Denial of service | Process crash, interrupted flows, inaccessible stores, resource exhaustion, missing rate limiting |
| E01–E06 | Elevation of privilege | Impersonation, RCE, execution-flow changes, CSRF, unsafe deserialization, missing authorization |
| X01–X05 | Element-level | Unencrypted sensitive data, root processes, secrets leakage, missing backups, memory corruption |
| M01–M04 | AI & MCP | Tool poisoning / indirect prompt injection, excessive agency, token passthrough, data sent to LLM providers |
| W01–W06 | WebSockets | Cross-site WebSocket hijacking, ws://, unauthenticated handshake, stale authorization, message injection, flooding |
| K01–K02 | Kafka | Unauthenticated producers, poisoned events |
| V01–V04 | Contact center | Caller-ID spoofing, card data in recordings, telephony DoS / toll fraud, social engineering of agents |
| O01, C01–C03 | Platform | Workflow injection, container escape, control-plane compromise, orchestrator as high-value target |
| **P01–P24** | **Penetration testing** | Cleartext legacy protocols, exposed RDP/SSH/VNC, NTLM relay, AD attacks (Kerberoasting, DCSync), SAML/OIDC forgery, DNS spoofing, forged webhooks, GraphQL abuse, request smuggling, SSRF & cloud-metadata theft, supply-chain artifacts, email spoofing, unauthenticated OT commands, wireless attacks, removable media, insider exfiltration, DDoS, log forging, poisoned pipelines, secrets in repos, bastion compromise, tokens in browser storage, unprotected device storage |

Each rule includes a description and a suggested mitigation. All rules live in `js/rules.js` and can be
viewed, edited, exported and replaced from **Menu → Threat template**.

## Using it for penetration-test scoping

1. **Draw the attack surface.** Add threat actors (*External Attacker*, *Malicious Insider*,
   *Compromised Supply Chain*) as external entities and connect them to what they can reach.
2. **Mark trust zones.** Use *Internet Boundary*, *DMZ*, *Management Network*, *PCI Zone*,
   *OT / ICS Network* and so on. Flows that cross them get boundary-specific threats (sniffing, tampering, exposed remote admin…).
3. **Pick real protocols.** Set each flow's type (Telnet, RDP, NTLM, SAML, Modbus, GraphQL…). The type presets
   properties such as encryption and drives protocol-specific threats.
4. **Set properties honestly.** Leave a property on *Not Selected* until the control is verified. Unknown
   controls generate threats, which gives you a test checklist.
5. **Triage in Analysis.** Filter by STRIDE category or priority, and record results as *Mitigated*,
   *Not Applicable* (with justification) or *Needs Investigation*.
6. **Report.** Generate the HTML report (print to PDF) or export CSV to track findings.

## Keyboard shortcuts

| Keys | Action |
| --- | --- |
| `H` · `V`/`1` | Hand (pan) · Select |
| `P`/`2` · `E`/`3` · `D`/`4` | Process · External entity · Data store |
| `A`/`5` · `B`/`6` · `L`/`7` | Data flow · Trust boundary · Boundary line |
| `T`/`8` · `X`/`0` · `Q` | Note · Eraser · Keep tool active |
| `Y` · `/` | Symbol library · Quick search tools and symbols |
| `Enter` / double-click | Rename selected |
| `Del` · `Ctrl+D` · `Ctrl+C/X/V` · `Ctrl+A` | Delete · Duplicate · Copy/cut/paste · Select all |
| `Ctrl+Z` / `Ctrl+Shift+Z` | Undo / redo |
| Arrows (`Shift` ×10) · `Ctrl+]` / `Ctrl+[` | Nudge · Bring forward / send back |
| `Shift+1` · `Shift+2` · `Shift+0` | Zoom to fit · Zoom to selection · Reset zoom |
| `Shift+A` | Toggle Analysis view |
| `Ctrl+S` · `Ctrl+O` · `?` | Save · Open · Help |

## Run locally

ES modules need to be served over HTTP (opening `index.html` via `file://` won't work):

```sh
npm start          # python3 -m http.server 8000, then open http://localhost:8000
npm test           # threat-engine tests (Node 20+)
```

## Deploy to GitHub Pages

1. Push this repository to GitHub.
2. Go to **Settings → Pages → Build and deployment**, choose **Deploy from a branch**, and select `main`
   with the `/ (root)` folder.
3. After a minute or two it's live at `https://<user>.github.io/<repo>/`.

The `.nojekyll` file makes GitHub serve the files as-is. All paths are relative, so the app works from
a sub-path.

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
- Text fields can use `{source.name}`, `{target.name}`, `{flow.name}`, `{flow.subtype}`, `{flow.boundaries}`,
  `{element.name}` and any other path.

Property keys and subtype names are defined in `js/stencils.js`. Unset properties have the value
`"Not Selected"`, so rules written as `ne "Yes"` generate threats until someone confirms the control is in place.

## Project layout

```
index.html        UI shell (toolbar, panels, library, quick search, dialogs)
css/app.css       Excalidraw-like styling, light/dark
js/main.js        Wiring: actions, menus, tabs, library, quick search, keyboard, clipboard
js/canvas.js      Interactive SVG canvas (selection, connectors, snapping)
js/render.js      SVG renderer (canvas, exports, report)
js/store.js       Model, undo/redo, autosave
js/engine.js      STRIDE rule engine, threat sync, validation
js/rules.js       Built-in threat template (82 rules)
js/stencils.js    Element types, subtypes, properties, symbol mapping, library groups
js/glyphs.js      Technology symbols
js/panels.js      Properties panel and threat panel
js/io.js          Save/open, PNG/SVG/CSV, report, share link, .tm7 import
js/ops.js         Element operations (create, delete, paste, bend…)
js/util.js        Geometry, connector anchoring and hand-drawn path generation
tests/            Engine tests and a .tm7 fixture
```

## Privacy

There is no server component. Nothing is sent anywhere, except that the page loads the *Kalam* web font from
Google Fonts (and fetches it again to embed it in PNG exports). Remove the font `<link>` in `index.html` if
you need a fully offline build. The app falls back to a system cursive font.

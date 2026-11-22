# MCPUsage.md — From source code to threat model with the STRIDE MCP server

**Audience: AI agents.** Load this file as context when you are asked to threat model a codebase.
You do the code analysis; this server turns your findings into a STRIDE threat model that is
compatible with the Microsoft Threat Modeling Tool, then generates, validates and reports threats.

Everything below was verified against this server. The worked example in §13 uses the real sample
codebase in [`examples/billing-service/`](examples/billing-service/).

---

## 1. Division of labour

| You (the agent) | The server |
|---|---|
| Read the code, configuration and infrastructure files | Validates your architecture spec against the template |
| Identify components, data stores, external parties, trust zones and data flows | Lays out the data flow diagram so each flow crosses exactly the right trust boundaries, and checks this |
| Derive security properties from code (TLS, authentication, validation, logging) | Generates STRIDE threats from template rules for every flow |
| Cite evidence (`path:line`) for every element, flow and decision | Validates the diagram (unconnected flows, missing boundaries, …) |
| Verify each generated threat against the code and triage it | Keeps your triage when you re-sync after code changes |
| Add code-specific findings the template cannot know about | Exports HTML, Markdown, CSV and SVG reports |

**Never invent architecture.** Every element and flow must come from something you saw in the
repository. If something cannot be confirmed from code (for example, a firewall rule or the TLS
setup of a managed service), put it in `assumptions` rather than modeling it as fact.

## 2. Setup

```bash
# Root = the repository being analyzed. All tool paths are relative to it.
claude mcp add stride -- node /path/to/STRIDE/bin/stride.mjs mcp --root /path/to/analyzed-repo
```

Suggested files in the analyzed repository:

```text
threatmodel/spec.json        # the architecture spec you write (commit it; re-sync from it)
threatmodel/model.json       # the threat model (generated + triage; commit it)
threatmodel/report.html      # human report
threatmodel/report.md        # for pull requests / chat
```

Path rules:
- Paths outside the root are rejected, including paths that escape through symlinks.
- Model and spec files must be `.json`.
- Reports must be `.html`, `.md`, `.csv`, `.json` or `.svg`.

---

## 3. Workflow

| Phase | What you do | Tools |
|---|---|---|
| A. Discover | Map the architecture from code (§4). | your own file reading and search |
| B. Specify | Write the spec: zones, elements, flows, properties, evidence (§5–§8). | `stride_list_element_types` (exact types and values) |
| C. Build | Create or update the model from the spec. | **`stride_sync_model`** |
| D. Verify | Fix spec errors, layout warnings and validation messages. Spot-check boundary crossings. | `stride_sync_model` result, `stride_explain_flow` |
| E. Triage | Check every generated threat against the code and set its state with evidence (§10). | `stride_list_threats`, `stride_update_threat` |
| F. Findings | Add threats specific to this code that the template did not produce (§11). | `stride_add_user_threat` |
| G. Report | Export reports and summarize for the user (§12). | `stride_export_report` |
| H. Maintain | After code changes, update the spec and re-sync. Triage is preserved. | `stride_sync_model` |

---

## 4. Phase A — discovering the architecture from code

Work from **deployment** first (it defines the trust zones), then **entry points** (inbound flows),
then **outbound clients** (outbound flows and stores). Record `path:line` as you go.

### 4.1 Where to look

| Look at | Signals (examples across stacks) | Gives you |
|---|---|---|
| Deployment / IaC | `docker-compose.yml` (services, `networks`, `ports`, `internal: true`); Kubernetes (`Deployment`, `Service`, `Ingress`, `NetworkPolicy`, namespaces); Terraform (`aws_vpc`, `aws_subnet`, security groups, `aws_lb`, `aws_lambda_function`); serverless.yml; Helm values | **Trust zones**, which component is public, process boundaries, managed data stores |
| Entry points | HTTP routes (`@app.get`, `router.post`, `@RestController`, `http.HandleFunc`, `app.MapGet`), GraphQL resolvers, gRPC services, CLI `main`, queue consumers, cron/scheduled jobs, webhook handlers | **Processes** and **inbound flows** |
| Outbound HTTP/SDK clients | `fetch`, `axios`, `requests`, `httpx`, `HttpClient`, `RestTemplate`, cloud SDKs (`boto3`, `@aws-sdk/*`), `stripe`, `twilio`, `openai` | **External interactors** and **outbound flows** |
| Data access | ORM/driver setup (`psycopg`, `SQLAlchemy`, `pg`, `prisma`, `mongoose`, `gorm`, `JDBC`), `redis`, S3/Blob clients, filesystem writes | **Data stores** and **read/write flows** |
| Async | Queues and topics (`SQS`, `Kafka`, `RabbitMQ`, Redis lists, Celery/Sidekiq/BullMQ) | A **data store** (the queue) plus producer→queue and queue→consumer flows |
| Identity | OIDC/OAuth clients, JWT verification (`jwt.decode`, `jwks`), session middleware, API key checks, RBAC decorators | **Authorization provider** element, and authentication/authorization properties |
| Front end | SPA entry, API client module, auth SDK, rendering of server data (`dangerouslySetInnerHTML`, `v-html`, `innerHTML`) | **Browser client** process, client flows, front-end findings |
| Configuration | Environment variables (`DATABASE_URL`, `*_API_KEY`, `*_URL`), TLS settings (`sslmode`, `verify=False`, `rejectUnauthorized`), CORS, cookie flags | Flow properties, secrets, external dependencies |
| Logging / audit | Audit tables, log shippers, `logger.info(user…)` on security events | Log **data stores** with `storesLogData: "Yes"` |

### 4.2 What becomes what

- **Process (`GE.P` family):** code that *you* deploy and run, such as a service, worker, function,
  SPA, mobile app or gateway you configure. One element per deployable unit, not per class or
  module.
- **External interactor (`GE.EI`):** anything outside your control that talks to your system, such
  as people, browsers you do not ship, SaaS APIs and identity providers.
- **Data store (`GE.DS`):** anything that persists or buffers data, such as databases, caches,
  queues, buckets, files and log stores. One element per logical store. Two schemas in one
  database server can be two elements if they have different data or access paths; say so in
  `custom`.
- **Flow (`GE.DF`):** one direction of data movement. Model the request and the response
  separately when both carry meaningful data (for example, a query and the rows it returns). A
  queue is producer → queue → consumer, which is two flows.
- **Trust zone (box boundary):** a set of components that share a trust level and network or
  process isolation, such as a private network, VPC, cluster, DMZ/edge, the user's device or a
  sandbox. Anything **outside** every zone (users, third parties) is left without a zone.

Not modeled: internal function calls inside one process, libraries (record them in `custom`
instead), and build-time tooling. CI/CD is in scope only when the task asks for supply chain.

---

## 5. Choosing element types

Prefer specific types: many rules target them. Get exact ids from `stride_list_element_types`.

| Component found in code | `type` |
|---|---|
| End user / admin / operator | `SE.EI.TMCore.User` |
| React/Vue/Angular SPA, front-end JS | `SE.P.TMCore.BrowserClient` |
| Server-rendered web app (Django views, Rails, ASP.NET MVC, Next.js SSR) | `SE.P.TMCore.WebApp` |
| REST/GraphQL/gRPC API (FastAPI, Express, Spring, Gin) | `SE.P.TMCore.WebSvc` |
| Reverse proxy / gateway / ingress (nginx, Envoy, API Gateway) | `SE.P.TMCore.WebServer` |
| Background worker / consumer / cron / daemon | `SE.P.TMCore.Win32Service` (any OS) or `GE.P` |
| Mobile / desktop app you ship | `SE.P.TMCore.ThickClient` (`SE.P.TMCore.NonMS` for iOS/Android/Linux) |
| Serverless function | `GE.P` (custom `{"runtime":"lambda"}`) |
| Container host / VM | `SE.P.TMCore.VM` |
| PostgreSQL / MySQL / SQL Server / SQLite | `SE.DS.TMCore.SQL` |
| MongoDB / DynamoDB / Cosmos / Firestore | `SE.DS.TMCore.NoSQL` |
| Redis / Memcached (cache **or** queue) | `SE.DS.TMCore.Cache` |
| S3 / GCS / Azure Blob | `SE.DS.TMCore.CloudStorage` |
| Kafka / SQS / RabbitMQ / Pub/Sub | `GE.DS` (custom `{"engine":"Kafka"}`) |
| Files / volumes | `SE.DS.TMCore.FS` |
| Config / secrets files | `SE.DS.TMCore.ConfigFile` |
| Audit or application log store | `GE.DS` with `storesLogData: "Yes"` |
| Browser localStorage / cookies | `SE.DS.TMCore.HTML5LS` / `SE.DS.TMCore.Cookie` |
| Auth0 / Okta / Entra ID / Cognito / Keycloak | `SE.EI.TMCore.AuthProvider` |
| Stripe / Twilio / SendGrid / OpenAI / any SaaS API | `SE.EI.TMCore.WebSvc` |
| Partner web app calling you | `SE.EI.TMCore.WebApp` |
| HTTPS / gRPC over TLS | flow `HTTPS` (`SE.DF.TMCore.HTTPS`) |
| Plain HTTP (for example, behind a TLS-terminating proxy) | flow `HTTP` |
| DB/Redis/AMQP/SMTP wire protocols | flow `GE.DF`, then set the confidentiality and integrity properties from the config |
| Zones: VPC / private network / cluster / DMZ | `SE.TB.B.TMCore.CorpNet` |
| Zones: user device / browser / sandbox / container isolation | `SE.TB.B.TMCore.Sandbox` |
| Zones: anything else | `GE.TB.B` |

---

## 6. Deriving properties from code

Set a property only when the code or configuration shows it. Otherwise leave the default (the
first allowed value, usually `No` or `Not Selected`). Unset properties make the engine assume the
worse case, which is what you want when you are unsure. Properties marked `fixed` (for example,
HTTPS confidentiality) come from the type and cannot be set.

| Property (element) | Set to `Yes` when the code shows … | Evidence examples |
|---|---|---|
| `providesConfidentiality`, `providesIntegrity` (flow) | TLS on that hop: `sslmode=require/verify-full`, `rediss://`, `starttls()`, `ssl=True`, mTLS sidecar | `db.py:2` without `sslmode` → leave `No` |
| `authenticatesSource` (flow) | The receiver verifies the sender: JWT/session check, HMAC/webhook signature, mTLS client certs, API keys | `payments.py:8` `construct_event` (Stripe signature) |
| `authenticatesDestination` (flow) | The client verifies the server: TLS certificate validation (fixed `Yes` for HTTPS). Set `No` if `verify=False` | — |
| `implementsAuthenticationScheme` (process) | The process authenticates callers (it verifies tokens, manages sessions, checks passwords) | `auth.py:6` `require_user` |
| `implementsCustomAuthorizationMechanism` (process) | Hand-written permission checks (role decorators, ownership checks, policy code) | `auth.py:12` `require_role` |
| `implementsCommunicationProtocol` (process) | It implements its own wire protocol or framing | custom TCP/binary protocol code |
| `hasInputSanitizers` / `hasOutputSanitizers` (process) | Systematic validation (schemas, typed models) / context-aware output encoding everywhere. **Both** `Yes` suppresses XSS threats, so only set both when you checked the templates/renderers | pydantic models; auto-escaping templates |
| `codeType` (process) | `Managed` for JVM/.NET/Python/JS/Go; `Unmanaged` for C/C++/Rust `unsafe` | — |
| `acceptsInputFrom` (process) | `Any Remote User or Entity` for internet-reachable services | `docker-compose.yml:5` ports 443 |
| `storesCredentials` (store) | Password hashes, API keys, tokens or secrets are stored | `users.password_hash` column |
| `storesLogData` (store) | Audit or security logs | `audit.py:3` |
| `Encrypted` (store) | Encryption at rest is configured (KMS, TDE, SSE) | Terraform `storage_encrypted = true` |
| `JSON` / `XMLenc` / `SOAP` / `REST` (flow) | The payload format | `fetch(... JSON)`; XML parsers |
| `Cookies` (flow) | Session cookies travel on the flow (the default is `Yes`; set `No` for pure bearer-token APIs) | `Authorization: Bearer` in `api.ts:5` |
| `HTTPOnly` (cookie store) | Cookie flags in code | `set_cookie(httponly=True)` |
| `MS` (auth provider) | `Yes` only for Microsoft identity platforms | — |

Use `custom` for facts the template has no property for, such as
`{"framework":"FastAPI","dataClass":"PII","rendersHtmlFromData":"invoice.memo"}`. Custom values
appear in the model and report, and they guide your later triage.

---

## 7. Trust zones and layout

Zones are listed **from least trusted to most trusted**, and the server places them left to right:

```text
[outside: users, SaaS]   →   [Customer device]   →   [Edge / DMZ]   →   [Backend network]
 no zone (bottom row)          Sandbox                CorpNet           CorpNet
```

- Each zone becomes a box trust boundary around its members.
- Elements without a `zone` are placed in a row below, under the component they talk to most.
- Flows between non-adjacent zones are drawn as arcs over the zones in between.
- The server then **verifies geometrically** that every flow crosses exactly the boundaries of the
  zones it leaves and enters. A flow inside one zone crosses nothing.
- Any mismatch is returned in `layoutWarnings`. With a correct spec this list is empty.
- Nested zones (for example, a subnet inside a VPC) are not modeled. Pick the zone that best reflects
  the isolation you can prove from code, and describe the rest in `assumptions`.

How to decide zones from code:
- A Docker network with `internal: true`, a private subnet, or a namespace protected by a
  NetworkPolicy is a backend zone.
- A service that publishes `ports` or sits behind an `Ingress` or load balancer is an edge/DMZ
  component; give it its own zone when there is a separate tier.
- Code that runs on user hardware (SPA, mobile app) goes in a "device" zone, typically `Sandbox`.
- Third-party SaaS and identity providers have no zone.

---

## 8. The spec (`stride_sync_model`)

```jsonc
{
  "name": "Billing service",
  "description": "…what the system does…",
  "assumptions": "…what you could not verify from code…",
  "externalDependencies": "Auth0, Stripe, SendGrid",
  "zones": [
    { "name": "Customer device", "type": "SE.TB.B.TMCore.Sandbox", "evidence": ["web/src/api.ts:1"] },
    { "name": "Backend network", "type": "SE.TB.B.TMCore.CorpNet", "evidence": ["docker-compose.yml:31"] }
  ],
  "elements": [
    { "name": "Billing API", "type": "SE.P.TMCore.WebSvc", "zone": "Backend network",
      "props": { "implementsCustomAuthorizationMechanism": "Yes" },
      "custom": { "framework": "FastAPI" },
      "evidence": ["api/app.py:8", "api/auth.py:12"] },
    { "name": "Stripe", "type": "SE.EI.TMCore.WebSvc", "evidence": ["api/payments.py:2"] }
  ],
  "flows": [
    { "name": "Payment intents", "from": "Billing API", "to": "Stripe", "type": "HTTPS", "evidence": ["api/payments.py:5"] }
  ]
}
```

Rules:
- **`name`** values are used in threat titles. Use the names developers use ("Billing API", not
  "Service 1").
- **Identity is the `id`, or the `name` when there is no `id`.** Keep it stable across re-syncs; a
  rename without a stable `id` is treated as remove + add, and that element's triage is orphaned.
  Set `id` when a name may change.
- `from` and `to` refer to element `id` or `name`. `zone` refers to a zone `id` or `name`.
- `type` accepts a type id, an exact type name (`"SQL Database"`) or a family (`process`,
  `external`, `store`).
- `evidence` is a list of `path:line` (or `path:start-end`) strings, at most 25 per item. It appears
  in the model, the web inspector and the HTML report.
- `outOfScope: true` with `outOfScopeReason` keeps an element for context without generating
  threats.
- Pass the spec inline (`spec`), or save it to the repo and pass `specFile`. Use `specFile` for
  anything you will re-sync.
- All spec problems are reported at once (unknown types, unknown zones, invalid property values,
  dangling flow endpoints). Fix all of them and call again.

Options:
- `diagram`: name of the diagram; it is created if missing. Use one per view, for example
  "Production", "Admin plane".
- `layout: "keep"`: keep the positions of existing shapes. Use it after a human rearranged the
  diagram in the web app.
- `prune: false`: keep elements from earlier syncs that are no longer in the spec. Hand-drawn
  elements are never removed in either case.

### Reading the result

```json
{
  "elements": { "created": 30, "updated": 0, "removed": 0, "handDrawnKept": 0 },
  "layoutWarnings": [],
  "threats": { "total": 96, "added": 96, "removed": 0, "orphaned": 0, "ruleErrors": [] },
  "validation": { "errors": 0, "warnings": 0, "messages": [] },
  "summary": { "byCategory": { … }, "byPriority": { … } }
}
```

| Field | Action |
|---|---|
| `layoutWarnings` (non-empty) | A flow crosses the wrong boundaries. Usually a third party talks to many zones. Check with `stride_explain_flow`, then adjust with `stride_update_element` (`bend`, or `x`/`y` of the outside element). |
| `validation.errors` | Fix the spec (for example, a flow endpoint is missing) and re-sync. |
| `validation.warnings` | Read each one (§9). Fix the spec, or record why it is acceptable with `stride_add_note`. |
| `threats.ruleErrors` | A template rule failed. Report it to the user; this is not your modeling error. |
| `threats.orphaned` > 0 on a re-sync | Triaged threats whose interaction disappeared. Review them: did the code really change, or did an `id` drift? |

---

## 9. Validation messages

| Issue | Meaning | Typical fix from code |
|---|---|---|
| `flow.unconnected` (error) | A flow is missing an endpoint. | Fix `from` or `to`. |
| `flow.ds-ds` | Two stores are connected directly. | Add the process that moves the data (replication job, ETL, trigger). |
| `flow.ei-ds` | An external party touches a store directly. | Add the mediating process, or confirm direct access (for example, a public bucket) and note it. |
| `flow.ei-ei` | Two external parties are connected. | Usually out of scope; remove it. |
| `external.no-boundary` | An external party reaches you without crossing a zone. | Put the component it talks to in a zone. |
| `boundary.partial` | Two flows between the same pair cross different boundaries. | Usually fixed by a re-sync; otherwise adjust positions. |
| `element.isolated` (info) | An element has no flows. | Add the missing flows (look again at the code) or remove it. |

---

## 10. Phase E — triaging generated threats against the code

Generated threats are **hypotheses** produced from the architecture. Your job is to settle each one
with evidence from the code. Start with `priority: "High"`, then work through by category.

```json
{ "model": "threatmodel/model.json", "priority": "High" }
```

### 10.1 Decision procedure for each threat

1. Read the threat's `interaction` (source → flow → target) and `description`.
2. Find the code that implements that interaction, starting from your evidence for the flow.
3. Decide the state:

| Verdict | `state` | `justification` must contain |
|---|---|---|
| A control exists and covers this interaction | `Mitigated` | The control and where it is: *"Parameterized queries in all data access (api/db.py:5, :8, :11)."* |
| The threat cannot happen in this architecture | `NotApplicable` | The architectural reason: *"Flow is in-process; no network hop (worker/receipts.py:6)."* |
| A weakness is confirmed in the code | `NeedsInvestigation` + `priority: "High"` | `CONFIRMED:` + the vulnerable code + impact: *"CONFIRMED: GET /invoices/{id} loads by id without a tenant check (api/app.py:16-17) — IDOR across tenants."* |
| You cannot tell from the code (infrastructure, managed service, missing files) | `NeedsInvestigation` | What must be checked, and by whom: *"Verify Postgres requires TLS at the server (not visible in repo)."* |

4. Adjust `priority` to the real risk. Template defaults are generic; data sensitivity and
   internet exposure should raise or lower them.
5. Never mark a threat `Mitigated` because a library is "probably" used correctly. Cite the call
   site.

```json
{ "model": "threatmodel/model.json", "threat": 72, "state": "NeedsInvestigation", "priority": "High",
  "justification": "CONFIRMED: GET /invoices/{invoice_id} calls get_invoice(invoice_id) without tenant filter (api/app.py:16-17, api/db.py:8). Any authenticated user can read other tenants' invoices." }
```

### 10.2 Where to look for each threat type

| Threat (id) | Check in code |
|---|---|
| Spoofing a process/entity (S1, S2, S3, S8) | Authentication of the caller (token or session verification, signature checks, mTLS) and of the callee (TLS verification, pinned hosts) |
| Spoofing data stores (S7, S7.1) | How the connection target is configured (env/DNS), credential scoping |
| Input validation (T1), JSON processing (T12), XML DTD/XSLT (T11) | Request schemas, parsers, deserialization settings, entity resolution |
| SQL injection (T7, T8) | Query construction: parameters vs string building, raw queries in ORMs |
| XSS (T13.1, T13.2) | Template auto-escaping, `innerHTML`/`dangerouslySetInnerHTML`/`v-html`/`|safe`, Content Security Policy |
| Data store corruption (T18), logging risks (T5) | Write authorization, validation before persisting, log injection/encoding |
| Repudiation (R1–R8) | Audit events: who/what/when, append-only storage, separation from the app's write rights |
| Authorization bypass (I2), weak access control (I23) | Ownership/tenant checks on every object access, deny-by-default policies, DB user privileges |
| Sniffing (I6), weak credential transit (I25) | TLS on each hop (`sslmode`, `rediss`, `verify`), plaintext internal links |
| Weak credential storage (I24) | Password hashing algorithm, secrets in code/config, KMS/vault use |
| Weak authentication scheme (I26) | Custom auth code, token lifetime/signature algorithm, brute-force protection |
| DoS (D2–D5) | Rate limits, timeouts, pagination, payload limits, retries/circuit breakers |
| Remote code execution (E6), execution flow (E7) | `eval`, shell/subprocess with input, unsafe deserialization, template injection, debug endpoints |
| Impersonation (E5) | Confused-deputy calls, service tokens forwarded on behalf of users |
| SSO weakness (E3) | Token validation (issuer, audience, expiry, algorithm), redirect URI handling, state/PKCE |
| CSRF (E8) | Cookie-based auth plus state-changing requests; SameSite flags and anti-forgery tokens |

---

## 11. Phase F — code-specific findings

The template reasons about architecture, not about specific lines of code. Add a user-defined
threat for every concrete issue you find that is not already captured, attached to the most
relevant flow:

```json
{ "model": "threatmodel/model.json", "flow": "API responses",
  "title": "Stored XSS via invoice memo rendered as HTML",
  "category": "T", "priority": "High",
  "description": "InvoiceView renders invoice.memo with dangerouslySetInnerHTML (web/src/InvoiceView.tsx:3). A customer-controlled memo executes script in other users' sessions.",
  "mitigation": "Render memo as text, or sanitize with DOMPurify before insertion; add a strict CSP." }
```

Common sources of findings: missing object-level authorization (IDOR), secrets in code, disabled TLS
verification, permissive CORS, unsafe HTML rendering, SSRF through user-supplied URLs, open
redirects, missing rate limits on login or OTP, verbose errors, debug modes, and, for AI features,
prompt injection, tool misuse and data exfiltration through model output.

Category ids: `S` Spoofing, `T` Tampering, `R` Repudiation, `I` Information disclosure,
`D` Denial of service, `E` Elevation of privilege.

---

## 12. Phase G — reporting back

```json
{ "model": "threatmodel/model.json", "format": "html", "output": "threatmodel/report.html" }
{ "model": "threatmodel/model.json", "format": "md",   "output": "threatmodel/report.md" }
```

HTML, Markdown and JSON reports open with an executive summary and a **high-signal findings**
table: threats backed by evidence, dangerous sinks or weak controls, ranked by signal score and
titled after the sink they hit (e.g. *Command injection via shell_exec of user-controlled IP*). The
full register follows. Pass `"signal": "medium"` to widen the table, or `"off"` for the classic
layout. Attach precise `evidence` (file, line and the offending call) to flows in the spec: it is
what earns the high-signal rating. `stride_list_threats` with `"signal": "high"` gives the same
ranked list.

In your answer to the user, give:
- the counts: threats by state, and how many are High priority and open;
- the **confirmed** issues first, with file references;
- the threats you could not settle, with what is needed to settle them;
- the assumptions you made;
- the paths of the spec, model and reports.

## 13. Phase H — keeping the model in sync

When the code changes, update `threatmodel/spec.json` (new routes, stores, clients) and call
`stride_sync_model` with the same `specFile`.

- Unchanged elements keep their ids, so threats and triage are untouched.
- New interactions add new threats, with state `NotStarted`.
- Threats whose interaction disappeared are removed if nobody triaged them. Triaged ones are kept as
  orphans for review.
- In CI, the same thing runs as `stride sync threatmodel/model.json threatmodel/spec.json`. It exits
  1 on validation errors or rule errors.

---

## 14. Worked example — `examples/billing-service`

The sample repository contains a React SPA, an nginx gateway, a FastAPI API, a receipt worker,
Postgres, Redis, Auth0, Stripe and SendGrid. Its full spec is in
[`examples/billing-service/threatmodel/spec.json`](examples/billing-service/threatmodel/spec.json).

**A. Findings from the code (excerpt):**

| Evidence | Finding → spec |
|---|---|
| `docker-compose.yml:31` `backend: { internal: true }` | Zone "Backend network" (CorpNet) containing api, worker, db, cache |
| `docker-compose.yml:3-7` gateway publishes 443 and joins `edge` + `backend` | Zone "Edge" with "Gateway" (`SE.P.TMCore.WebServer`); TLS terminates here, so Gateway → API is `HTTP` |
| `api/auth.py:6`, `:12` JWT check + custom RBAC | Billing API: `implementsAuthenticationScheme: Yes`, `implementsCustomAuthorizationMechanism: Yes` |
| `api/db.py:2` no `sslmode` | "Invoice queries" is `GE.DF` with no confidentiality property (stays `No`) |
| `api/app.py:23` + `worker/receipts.py:5` Redis list | "Job queue" (`SE.DS.TMCore.Cache`) with flows API → queue → worker |
| `api/app.py:26`, `api/payments.py:8` signed Stripe webhook | Flow Stripe → Gateway with `authenticatesSource: Yes` |
| `worker/receipts.py:7-8` SMTP + `starttls()` | Flow worker → SendGrid with confidentiality and integrity `Yes` |
| `api/audit.py:3` audit table | "Audit log" store with `storesLogData: Yes` |

**B. Sync:**

```json
{ "model": "examples/billing-service/threatmodel/model.json", "specFile": "examples/billing-service/threatmodel/spec.json" }
```

Result: 30 elements created, `layoutWarnings: []`, 0 validation errors or warnings, 96 threats
across 29 threat types.

**C. Spot check:**

```json
{ "model": "examples/billing-service/threatmodel/model.json", "flow": "Payment intents" }
```

It crosses "Backend network" only. Stripe is outside every zone.

**D. Triage (threat ids come from this run; yours may differ):**

```text
T7  SQL injection (API → Invoices DB)       Mitigated            "psycopg parameters in every query (api/db.py:5, :8, :11)."
I2  Authorization bypass (API → Invoices DB) NeedsInvestigation   "CONFIRMED: no tenant check on GET /invoices/{id} (api/app.py:16-17)." priority High
I6  Sniffing (Gateway → Billing API)        NeedsInvestigation   "Plain HTTP inside internal network (docker-compose.yml:31); decide if TLS to upstream is required."
S2  Spoofing Billing API (Gateway → API)     Mitigated            "API verifies Auth0 RS256 JWT on every route (api/auth.py:9)."
T13.1 XSS (… → Gateway)                     NotApplicable        "Gateway proxies JSON only; no HTML rendering (docker-compose.yml:3)."
```

**E. Code-specific findings:**
- *Stored XSS via invoice memo* (`web/src/InvoiceView.tsx:3`), attached to "API responses".
- *Missing tenant isolation*, already captured by I2, so no duplicate is added.

**F. Report:** `threatmodel/report.html` and `threatmodel/report.md`.

---

## 15. Tool reference

Mutating tools return the result plus a threat summary. Failures return `isError: true` with a
message that states what is wrong and the allowed values. Correct the call; do not repeat it
unchanged.

| Tool | Required | Optional | Use |
|---|---|---|---|
| **`stride_sync_model`** | `model`, and `spec` or `specFile` | `diagram`, `layout` (`auto`/`keep`), `prune`, `template` | **Primary.** Create or update the model from your spec. |
| `stride_list_element_types` | — | `family`, `template`, `model` | Exact type ids, properties and allowed values. |
| `stride_explain_flow` | `model`, `flow` | — | Boundaries crossed, plus applies/does-not-apply for each rule. |
| `stride_list_threats` | `model` | `state`, `category`, `priority`, `diagram`, `text`, `limit`, `signal` | Review queue (`signal: high` = evidence-backed first). |
| `stride_update_threat` | `model`, `threat` | `state`, `priority`, `justification`, `title`, `description`, `mitigation` | Triage with evidence. |
| `stride_add_user_threat` | `model`, `flow`, `title` | `category`, `description`, `mitigation`, `priority` | Code-specific findings. |
| `stride_validate_model` | `model` | — | Re-check after manual edits. |
| `stride_describe_model` | `model` | — | Every element with id, type, properties and evidence. |
| `stride_export_report` | `model` | `format` (`md`, `html`, `csv`, `json`, `svg`), `output`, `diagram`, `signal` (`high`, `medium`, `all`, `off`) | Reports. |
| `stride_set_model_info` | `model` | `name`, `owner`, `reviewer`, `contributors`, `description`, `assumptions`, `externalDependencies`, `threatGeneration` | Metadata. |
| `stride_add_note` | `model`, `text` | `author` | Decisions and accepted warnings. |
| `stride_add_element`, `stride_update_element`, `stride_remove_elements` | `model`, … | see schemas | Fine-grained edits (for example, `bend` to fix a layout warning). Prefer editing the spec and re-syncing. |
| `stride_manage_diagram` | `model`, `action` | `diagram`, `name` | List/add/rename/remove diagrams. |
| `stride_generate_threats` | `model` | `diagram` | Rarely needed; mutating tools regenerate. |
| `stride_check_rule` | `expression` | `template` | Validate a custom rule. |
| `stride_import_template`, `stride_apply_template` | see schemas | — | Use a Microsoft `.tb7` template (for example, Azure) instead of STRIDE Core. |
| `stride_create_model` | `model` | `name`, `owner`, `template`, `overwrite` | Usually unnecessary; `stride_sync_model` creates the model. |

---

## 16. Checklist before you answer

- [ ] Every deployable unit, data store, external party and trust zone from the repository is in the spec, and each has evidence.
- [ ] Requests and responses with meaningful data are separate flows; queues are modeled producer → queue → consumer.
- [ ] Properties are set only where the code proves them; everything you could not verify is in `assumptions`.
- [ ] `stride_sync_model` returned no layout warnings, no validation errors and no rule errors, and each warning is fixed or noted.
- [ ] Every High-priority threat is triaged, with a `path:line` justification; confirmed issues are marked `CONFIRMED:`.
- [ ] Concrete code issues the template missed were added as user-defined threats.
- [ ] The spec, model and reports are saved under `threatmodel/`, and the user got a summary that leads with confirmed issues.

## 17. Anti-patterns

- One element per class or module. Model deployable units and their data flows.
- Modeling a framework or library as a process. Put it in `custom`.
- Marking `Mitigated` on the basis of naming ("uses an ORM") without checking the call sites.
- Bulk-setting `NotApplicable` to shorten the list.
- Setting `providesConfidentiality: Yes` because TLS is "usual". Prove it from config, or leave it.
- Renaming elements in the spec without a stable `id`, which orphans their triage.
- Putting third-party SaaS inside your trust zones, or your own services outside them.
- Retrying a failed call unchanged instead of reading the error.

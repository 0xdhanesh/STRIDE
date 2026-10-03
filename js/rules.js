// Default threat template ("STRIDE-per-interaction", modelled on the Microsoft
// Threat Modeling Tool SDL template, extended with modern web/cloud threats).
//
// Rule shape (also the format for custom templates imported by users):
// {
//   id:        unique string
//   scope:     'interaction' (evaluated for every connected data flow, context: source, target, flow)
//              | 'element'   (evaluated for every node, context: element)
//   category:  one of S T R I D E
//   priority:  High | Medium | Low
//   focus:     which context object the threat is "about"; when that element is
//              marked out-of-scope the threat is not generated
//   title, description, mitigation: text; {source.name}, {target.name}, {flow.name},
//              {element.name}, {flow.boundaries} … are interpolated
//   when:      conditions; an array is AND, {any:[…]} is OR, {not: cond} negates,
//              a clause is [path, op, value] with op in eq ne in nin exists
//   dedupeKey: optional 'target' | 'source' | 'flow' (default); group matching flows
//   supersedes: optional array of rule IDs hidden on the same matching interaction
// }
//
// Paths: source.type, source.subtype, source.props.<key>, target.*, flow.subtype,
// flow.props.<key>, flow.crossesBoundary (boolean), element.*

// Protocol / subtype groups used by the penetration-testing rules.
const LEGACY = ['Telnet', 'FTP', 'TFTP', 'HTTP', 'LDAP', 'SNMP'];
const REMOTE_ADMIN = ['RDP', 'VNC', 'SSH', 'Telnet', 'WinRM / PowerShell Remoting'];
const EDGE = ['Load Balancer', 'Reverse Proxy', 'CDN / Edge', 'API Gateway', 'Web Application Firewall'];
const WEB_APPS = ['Web Application', 'Web API / Service', 'GraphQL API', 'Microservice', 'Serverless Function'];
const ARTIFACT_SOURCES = ['Container Registry', 'Package / Artifact Registry', 'Open-Source Dependency', 'Compromised Supply Chain', 'Source Code Repository'];

// Any WebSocket flow (plain, secure or unspecified).
const WS = ['flow.subtype', 'in', ['WebSocket', 'WebSocket (ws://)', 'WebSocket Secure (wss://)']];

export const DEFAULT_RULES = [
  /* ------------------------------------------------------------ Spoofing */
  {
    id: 'S01', scope: 'interaction', category: 'S', priority: 'High', focus: 'source',
    title: 'Spoofing the {source.name} External Entity',
    description: '{source.name} may be spoofed by an attacker and this may lead to unauthorized access to {target.name}. Consider using a standard authentication mechanism to identify the external entity.',
    mitigation: 'Authenticate the entity with a strong, standard mechanism (OpenID Connect / OAuth 2.0, mTLS, signed tokens). Require MFA for human users and protect credential recovery flows.',
    when: [['source.type', 'eq', 'external']],
  },
  {
    id: 'S02', scope: 'interaction', category: 'S', priority: 'Medium', focus: 'target',
    title: 'Spoofing the {target.name} Process',
    description: '{target.name} may be spoofed by an attacker and this may lead to information disclosure by {source.name}. Consider using a standard authentication mechanism to identify the destination process.',
    mitigation: 'Use server authentication (TLS with validated certificates, mTLS or signed service identities). Validate host names and consider certificate pinning for high-value clients.',
    when: [['target.type', 'eq', 'process'], ['flow.crossesBoundary', 'eq', true]],
  },
  {
    id: 'S03', scope: 'interaction', category: 'S', priority: 'Medium', focus: 'source',
    title: 'Spoofing the {source.name} Process',
    description: '{source.name} may be spoofed by an attacker and this may lead to unauthorized access to {target.name}. The flow "{flow.name}" does not declare a caller authentication mechanism.',
    mitigation: 'Authenticate the calling process (workload identity, mTLS, signed tokens, Kerberos). Avoid network-location based trust.',
    when: [['source.type', 'eq', 'process'], ['flow.props.authentication', 'in', ['Not Selected', 'None']]],
  },
  {
    id: 'S04', scope: 'interaction', category: 'S', priority: 'Medium', focus: 'target',
    title: 'Spoofing of Destination Data Store {target.name}',
    description: '{target.name} may be spoofed by an attacker and this may lead to data being written to the attacker\'s target instead of {target.name}. Consider using a standard authentication mechanism to identify the destination data store.',
    mitigation: 'Connect to the data store over an authenticated channel (TLS with certificate validation, managed identity). Pin connection strings in protected configuration.',
    when: [['target.type', 'eq', 'store'], ['flow.crossesBoundary', 'eq', true], ['flow.props.authentication', 'in', ['Not Selected', 'None']]],
  },
  {
    id: 'S05', scope: 'interaction', category: 'S', priority: 'Medium', focus: 'source',
    title: 'Spoofing of Source Data Store {source.name}',
    description: '{source.name} may be spoofed by an attacker and this may lead to incorrect data delivered to {target.name}. Consider using a standard authentication mechanism to identify the source data store.',
    mitigation: 'Authenticate the data store endpoint (TLS certificate validation, private endpoints) and verify integrity of data read from it.',
    when: [['source.type', 'eq', 'store'], ['flow.crossesBoundary', 'eq', true], ['flow.props.authentication', 'in', ['Not Selected', 'None']]],
  },
  {
    id: 'S06', scope: 'interaction', category: 'S', priority: 'Medium', focus: 'target',
    title: 'Spoofing of the {target.name} External Destination Entity',
    description: '{target.name} may be spoofed by an attacker and this may lead to data being sent to the attacker\'s target instead of {target.name}. Consider using a standard authentication mechanism to identify the external entity.',
    mitigation: 'Verify the identity of the destination (TLS certificate validation, allow-listed endpoints, signed webhooks).',
    when: [['target.type', 'eq', 'external'], ['flow.crossesBoundary', 'eq', true]],
  },
  {
    id: 'S07', scope: 'interaction', category: 'S', priority: 'High', focus: 'flow',
    title: 'Weak or Missing Authentication on {flow.name}',
    description: '"{flow.name}" crosses the trust boundary ({flow.boundaries}) but does not declare a strong authentication mechanism. An attacker on the other side of the boundary may be able to impersonate {source.name}.',
    mitigation: 'Require authentication for every request crossing the boundary. Prefer token-based (OAuth 2.0 / OIDC) or certificate-based (mTLS) authentication over passwords or static API keys.',
    when: [['flow.crossesBoundary', 'eq', true], ['flow.props.authentication', 'in', ['Not Selected', 'None', 'Password', 'API key']]],
  },

  /* ----------------------------------------------------------- Tampering */
  {
    id: 'T01', scope: 'interaction', category: 'T', priority: 'High', focus: 'target', dedupeKey: 'target',
    title: 'Potential Lack of Input Validation for {target.name}',
    description: 'Data flowing across {flow.name} may be tampered with by an attacker. This may lead to denial of service, elevation of privilege or information disclosure in {target.name}. Crafted input may also change program execution to the attacker\'s choosing. Failure to verify input is a root cause of many exploitable issues; consider every input path and parser.',
    mitigation: 'Validate all input with an allow-list approach (type, length, format, range) at the trust boundary. Use schema validation and safe parsers; reject rather than sanitize where possible. Prefer memory-safe languages and compile with exploit mitigations (ASLR, DEP, CFG).',
    when: [['target.type', 'eq', 'process'], ['target.props.validatesInput', 'ne', 'Yes']],
  },
  {
    id: 'T02', scope: 'interaction', category: 'T', priority: 'High', focus: 'flow',
    title: 'Data Flow {flow.name} Is Potentially Tampered',
    description: 'Data flowing across "{flow.name}" crosses a trust boundary ({flow.boundaries}) without integrity protection, so it may be modified in transit by an attacker.',
    mitigation: 'Protect the channel with TLS 1.2+ (authenticated encryption) or sign messages (HMAC, JWS). Verify integrity before processing.',
    when: [['flow.crossesBoundary', 'eq', true], ['flow.props.integrity', 'ne', 'Yes'], ['flow.props.encrypted', 'ne', 'Yes']],
  },
  {
    id: 'T03', scope: 'interaction', category: 'T', priority: 'High', focus: 'target',
    title: 'Potential Injection Vulnerability for {target.name}',
    description: 'Queries sent by {source.name} to {target.name} may include attacker-controlled data. Injection (SQL, NoSQL operator, command) can lead to data tampering, disclosure or full compromise of the data store.',
    mitigation: 'Use parameterised queries / prepared statements or a safe ORM. Never concatenate untrusted input into queries. Run the data store account with least privilege.',
    when: [['target.type', 'eq', 'store'], ['target.subtype', 'in', ['Database', 'SQL Database', 'NoSQL Database']]],
  },
  {
    id: 'T04', scope: 'interaction', category: 'T', priority: 'High', focus: 'target',
    title: 'Cross Site Scripting in {target.name}',
    description: 'The web application {target.name} may be subject to a cross-site scripting attack because it does not declare that it encodes or sanitizes untrusted output.',
    mitigation: 'Context-aware output encoding, a strict Content-Security-Policy, templating engines that auto-escape, and sanitization of rich HTML input.',
    when: [['target.subtype', 'in', ['Web Application', 'Browser Client (SPA)']], ['target.props.sanitizesOutput', 'ne', 'Yes']],
  },
  {
    id: 'T05', scope: 'interaction', category: 'T', priority: 'Medium', focus: 'flow',
    title: 'Replay Attacks against {target.name}',
    description: 'Packets or messages sent over "{flow.name}" may be captured and replayed by an attacker to {target.name}, e.g. to repeat a transaction or re-use a token.',
    mitigation: 'Use nonces, timestamps and short-lived tokens; make state-changing operations idempotent; rely on TLS which provides replay protection at the transport layer.',
    when: [['flow.crossesBoundary', 'eq', true], ['flow.props.replayProtection', 'ne', 'Yes'], ['target.type', 'in', ['process', 'store']]],
  },
  {
    id: 'T06', scope: 'interaction', category: 'T', priority: 'Medium', focus: 'target',
    title: 'Tampering with Data in {target.name}',
    description: 'Data written by {source.name} and stored in {target.name} may be modified by an attacker with access to the store, and later trusted by consumers.',
    mitigation: 'Restrict write access with fine-grained ACLs, enable integrity protection (signing / checksums), and audit changes.',
    when: [['target.type', 'eq', 'store'], ['target.props.integrity', 'ne', 'Yes']],
  },

  /* --------------------------------------------------------- Repudiation */
  {
    id: 'R01', scope: 'interaction', category: 'R', priority: 'Medium', focus: 'target', dedupeKey: 'target',
    title: 'Potential Data Repudiation by {target.name}',
    description: '{target.name} claims that it did not receive data from a source outside the trust boundary. Consider using logging or auditing to record the source, time, and summary of the received data.',
    mitigation: 'Log security-relevant events (who, what, when, from where) to an append-only store; synchronise clocks; include correlation IDs.',
    when: [['target.type', 'eq', 'process'], ['target.props.logsSecurityEvents', 'ne', 'Yes'], ['flow.crossesBoundary', 'eq', true]],
  },
  {
    id: 'R02', scope: 'interaction', category: 'R', priority: 'Low', focus: 'target',
    title: 'External Entity {target.name} Potentially Denies Receiving Data',
    description: '{target.name} claims that it did not receive data from a process on the other side of the trust boundary. Consider using logging or auditing to record the source, time, and summary of the received data.',
    mitigation: 'Record delivery receipts / acknowledgements and keep signed audit logs of outbound transmissions.',
    when: [['target.type', 'eq', 'external'], ['flow.crossesBoundary', 'eq', true]],
  },
  {
    id: 'R03', scope: 'interaction', category: 'R', priority: 'Low', focus: 'target',
    title: 'Data Store {target.name} Denies {source.name} Potentially Writing Data',
    description: '{target.name} claims that it did not write data received from an entity on the other side of the trust boundary. Consider using logging or auditing to record the source, time, and summary of the received data.',
    mitigation: 'Enable data store audit logging (who wrote what and when) and forward it to a central, tamper-resistant log.',
    when: [['target.type', 'eq', 'store'], ['flow.crossesBoundary', 'eq', true]],
  },
  {
    id: 'R04', scope: 'interaction', category: 'R', priority: 'Medium', focus: 'target',
    title: 'Lower Trusted Subject Updates Logs in {target.name}',
    description: 'If a lower trusted subject such as {source.name} can update the log store {target.name}, it may be able to erase or forge evidence of its actions.',
    mitigation: 'Make logs append-only (WORM storage), separate log writers from readers, and sign or hash-chain log entries.',
    when: [{ any: [['target.props.storesLogs', 'eq', 'Yes'], ['target.subtype', 'eq', 'Log Store']] }],
  },

  /* ---------------------------------------------- Information disclosure */
  {
    id: 'I01', scope: 'interaction', category: 'I', priority: 'High', focus: 'flow',
    title: 'Data Flow Sniffing on {flow.name}',
    description: 'Data flowing across "{flow.name}" may be sniffed by an attacker. Depending on what type of data an attacker can read, it may be used to attack other parts of the system or simply be a disclosure of information leading to compliance violations. Consider encrypting the data flow.',
    mitigation: 'Encrypt the channel with TLS 1.2+ (HSTS for web), or encrypt the payload end-to-end. Disable legacy protocols and weak cipher suites.',
    when: [['flow.crossesBoundary', 'eq', true], ['flow.props.encrypted', 'ne', 'Yes']],
  },
  {
    id: 'I02', scope: 'interaction', category: 'I', priority: 'Medium', focus: 'source',
    title: 'Weak Access Control for a Resource: {source.name}',
    description: 'Improper data protection of {source.name} can allow an attacker to read information not intended for disclosure. Review authorization settings.',
    mitigation: 'Apply least-privilege, fine-grained access control on the data store; use separate identities per consumer; deny by default.',
    when: [['source.type', 'eq', 'store'], ['source.props.accessControl', 'ne', 'Fine-grained']],
  },
  {
    id: 'I03', scope: 'interaction', category: 'I', priority: 'High', focus: 'flow',
    title: 'Credentials Exposed on {flow.name}',
    description: '"{flow.name}" carries credentials or tokens but is not declared as encrypted. Captured credentials allow an attacker to impersonate {source.name}.',
    mitigation: 'Only transmit credentials over encrypted, authenticated channels. Prefer short-lived, audience-restricted tokens over long-lived secrets.',
    when: [['flow.props.carriesCredentials', 'eq', 'Yes'], ['flow.props.encrypted', 'ne', 'Yes']],
  },
  {
    id: 'I04', scope: 'interaction', category: 'I', priority: 'Medium', focus: 'flow',
    title: 'Sensitive Data Sent to External Entity {target.name}',
    description: 'Sensitive data carried by "{flow.name}" leaves your control when it reaches {target.name}. Over-sharing may violate privacy or compliance requirements.',
    mitigation: 'Minimise the data shared, tokenise or pseudonymise where possible, and ensure data-processing agreements cover the recipient.',
    when: [['target.type', 'eq', 'external'], ['flow.props.carriesSensitiveData', 'eq', 'Yes']],
  },
  {
    id: 'I05', scope: 'interaction', category: 'I', priority: 'Low', focus: 'target', dedupeKey: 'target',
    title: 'Information Disclosure Through Error Messages of {target.name}',
    description: '{target.name} may return verbose error messages, stack traces or version banners to {source.name}, helping an attacker map the system.',
    mitigation: 'Return generic error messages to callers, log details server-side, and remove version banners and debug endpoints in production.',
    when: [['source.type', 'eq', 'external'], ['target.type', 'eq', 'process'], ['target.props.internetFacing', 'ne', 'No']],
  },

  /* --------------------------------------------------- Denial of service */
  {
    id: 'D01', scope: 'interaction', category: 'D', priority: 'Medium', focus: 'target', dedupeKey: 'target',
    title: 'Potential Process Crash or Stop for {target.name}',
    description: '{target.name} crashes, halts, stops or runs slowly; in all cases violating an availability metric.',
    mitigation: 'Bound input sizes and processing time, handle errors defensively, run multiple instances behind health checks, and auto-restart failed processes.',
    when: [['target.type', 'eq', 'process'], ['flow.crossesBoundary', 'eq', true]],
  },
  {
    id: 'D02', scope: 'interaction', category: 'D', priority: 'Medium', focus: 'flow',
    title: 'Data Flow {flow.name} Is Potentially Interrupted',
    description: 'An external agent interrupts data flowing across a trust boundary ({flow.boundaries}) in either direction.',
    mitigation: 'Design for retries with back-off, queues for asynchronous work, redundant network paths and DDoS protection at the edge.',
    when: [['flow.crossesBoundary', 'eq', true]],
  },
  {
    id: 'D03', scope: 'interaction', category: 'D', priority: 'Medium', focus: 'flow',
    title: 'Data Store {target.name} Inaccessible from {source.name}',
    description: 'An external agent prevents access to a data store ({source.name} → {target.name}) on the other side of the trust boundary.',
    mitigation: 'Use replicated / highly-available storage, connection pooling with timeouts, and graceful degradation when the store is unavailable.',
    when: [['flow.crossesBoundary', 'eq', true], { any: [['source.type', 'eq', 'store'], ['target.type', 'eq', 'store']] }],
  },
  {
    id: 'D04', scope: 'interaction', category: 'D', priority: 'Low', focus: 'flow',
    title: 'Potential Excessive Resource Consumption for {source.name} or {target.name}',
    description: 'Does {source.name} or {target.name} take explicit steps to control resource consumption? Resource consumption attacks can be hard to deal with, and there are times that it makes sense to let the OS do the job. Be careful that your resource requests don\'t deadlock, and that they do time out.',
    mitigation: 'Apply quotas, pagination, query timeouts and connection limits; monitor resource usage and alert on anomalies.',
    when: [['source.type', 'eq', 'process'], ['target.type', 'eq', 'store']],
  },
  {
    id: 'D05', scope: 'interaction', category: 'D', priority: 'Medium', focus: 'target',
    title: 'Missing Rate Limiting on {target.name}',
    description: '{source.name} can send an unbounded number of requests to {target.name} over "{flow.name}", enabling brute force and resource exhaustion attacks.',
    mitigation: 'Rate-limit and throttle per client / IP / token, add CAPTCHA or proof-of-work on sensitive endpoints, and use an API gateway or WAF.',
    when: [['source.type', 'eq', 'external'], ['target.type', 'eq', 'process'], ['flow.props.rateLimited', 'ne', 'Yes']],
  },

  /* ---------------------------------------------- Elevation of privilege */
  {
    id: 'E01', scope: 'interaction', category: 'E', priority: 'Medium', focus: 'target',
    title: 'Elevation Using Impersonation',
    description: '{target.name} may be able to impersonate the context of {source.name} in order to gain additional privilege.',
    mitigation: 'Avoid impersonation where possible; when required, constrain delegation, scope tokens to the minimum audience and permissions, and audit its use.',
    when: [['target.type', 'eq', 'process'], ['source.type', 'in', ['process', 'external']], ['flow.crossesBoundary', 'eq', true]],
  },
  {
    id: 'E02', scope: 'interaction', category: 'E', priority: 'High', focus: 'target', dedupeKey: 'target',
    title: '{target.name} May be Subject to Elevation of Privilege Using Remote Code Execution',
    description: '{source.name} may be able to remotely execute code for {target.name}.',
    mitigation: 'Keep dependencies patched, avoid dynamic code evaluation, run with least privilege in an isolated sandbox/container, and use memory-safe languages where possible.',
    when: [['target.type', 'eq', 'process'], ['flow.crossesBoundary', 'eq', true], { any: [['target.props.internetFacing', 'eq', 'Yes'], ['target.props.validatesInput', 'ne', 'Yes']] }],
  },
  {
    id: 'E04', scope: 'interaction', category: 'E', priority: 'Medium', focus: 'target',
    title: 'Cross Site Request Forgery against {target.name}',
    description: 'Cross-site request forgery (CSRF or XSRF) is a type of attack in which an attacker forces a user\'s browser to make a forged request to a vulnerable site by exploiting an existing trust relationship between the browser and {target.name}.',
    mitigation: 'Use anti-forgery tokens, SameSite=Lax/Strict cookies, and verify Origin / Referer headers on state-changing requests.',
    when: [['target.subtype', 'in', ['Web Application', 'Web API / Service']], ['source.type', 'eq', 'external'], ['flow.props.authentication', 'eq', 'Cookie / Session']],
  },
  {
    id: 'E05', scope: 'interaction', category: 'E', priority: 'High', focus: 'target',
    title: 'Unsafe Deserialization in {target.name}',
    description: '{target.name} receives serialized objects from {source.name} over a binary / RPC channel. Deserializing untrusted data can lead to remote code execution.',
    mitigation: 'Do not deserialize untrusted data into arbitrary types; use data-only formats (JSON with schemas), type allow-lists and signed payloads.',
    when: [['target.type', 'eq', 'process'], ['flow.subtype', 'in', ['Binary / Custom', 'RPC / DCOM']]],
  },
  {
    id: 'E06', scope: 'interaction', category: 'E', priority: 'High', focus: 'target',
    title: 'Missing Authorization in {target.name}',
    description: '{target.name} may not verify that {source.name} is authorized to perform the requested operation (broken access control / IDOR).',
    mitigation: 'Enforce authorization server-side for every request and object, deny by default, and centralise the policy (RBAC / ABAC).',
    when: [['source.type', 'eq', 'external'], ['target.type', 'eq', 'process'], ['target.props.authorizesRequests', 'ne', 'Yes']],
  },

  /* ------------------------------------------------- AI agents & MCP */
  {
    id: 'M01', scope: 'interaction', category: 'T', priority: 'High', focus: 'source',
    title: 'Tool Poisoning / Indirect Prompt Injection from {source.name}',
    description: 'Tool descriptions or tool results returned by the MCP server {source.name} may contain hidden instructions that manipulate the model in {target.name} into leaking data or invoking other tools on the attacker\'s behalf.',
    mitigation: 'Only connect to allow-listed MCP servers, pin and review tool definitions (detect changes / "rug pulls"), treat tool output as untrusted data, and require human confirmation for sensitive actions.',
    when: [['source.subtype', 'eq', 'MCP Server']],
  },
  {
    id: 'M02', scope: 'interaction', category: 'E', priority: 'High', focus: 'target',
    title: 'Excessive Agency: Over-privileged Tools in {target.name}',
    description: 'The MCP server {target.name} exposes tools that act with broad credentials. A manipulated or malicious client ({source.name}) can invoke destructive or data-exfiltrating operations.',
    mitigation: 'Scope each tool to least privilege with per-user, short-lived credentials; separate read and write tools; require confirmation for destructive actions; log every tool call.',
    when: [['target.subtype', 'eq', 'MCP Server']],
  },
  {
    id: 'M03', scope: 'interaction', category: 'S', priority: 'High', focus: 'target',
    title: 'Token Passthrough / Confused Deputy at {target.name}',
    description: '{target.name} may accept tokens not issued for it or forward the client\'s token to downstream APIs, letting {source.name} act with privileges it was never granted.',
    mitigation: 'Follow the MCP authorization spec: validate token audience and issuer, never pass client tokens through, obtain separate downstream tokens, and obtain user consent per client.',
    when: [['target.subtype', 'eq', 'MCP Server']],
  },
  {
    id: 'M04', scope: 'interaction', category: 'I', priority: 'Medium', focus: 'flow',
    title: 'Sensitive Data Sent to LLM Provider {target.name}',
    description: 'Prompts and context sent by {source.name} to {target.name} may contain personal or confidential data that the provider could log, retain or use for training.',
    mitigation: 'Minimise and redact data before sending, use enterprise agreements with zero data retention, and classify which data may reach external models.',
    when: [['target.subtype', 'eq', 'LLM Provider API']],
  },

  /* ------------------------------------------------ Kafka / event streams */
  {
    id: 'K01', scope: 'interaction', category: 'S', priority: 'High', focus: 'flow', supersedes: ['S03', 'S07'],
    title: 'Unauthenticated Producer Writes to {target.name}',
    description: '"{flow.name}" does not declare client authentication, so any network peer could produce events to {target.name} while impersonating {source.name}.',
    mitigation: 'Require SASL (SCRAM / OAUTHBEARER) or mTLS client authentication and enforce per-topic ACLs for producers.',
    when: [['target.subtype', 'in', ['Kafka Topic / Event Log', 'Kafka Broker']], ['flow.props.authentication', 'in', ['Not Selected', 'None']]],
  },
  {
    id: 'K02', scope: 'interaction', category: 'T', priority: 'Medium', focus: 'target',
    title: 'Event Injection / Poisoned Messages in {target.name}',
    description: 'Malicious or malformed events written by {source.name} to {target.name} are trusted and processed by every downstream consumer.',
    mitigation: 'Validate events against a schema registry, sign sensitive events, route invalid messages to a dead-letter topic and make consumers idempotent.',
    when: [['target.subtype', 'in', ['Kafka Topic / Event Log', 'Kafka Broker']]],
  },

  /* ------------------------------------------------------------ WebSockets */
  {
    id: 'W01', scope: 'interaction', category: 'S', priority: 'High', focus: 'target',
    title: 'Cross-Site WebSocket Hijacking against {target.name}',
    description: 'Browsers attach cookies to WebSocket handshakes from any origin. If {target.name} authenticates "{flow.name}" with cookies but does not check the Origin header, a malicious site visited by the user can open a socket as that user and read or send messages.',
    mitigation: 'Validate the Origin header against an allow-list during the handshake, use SameSite cookies, and authenticate with a short-lived token (sent after connect or as a subprotocol) instead of relying on cookies alone.',
    when: [WS, ['target.type', 'eq', 'process'], ['flow.props.authentication', 'eq', 'Cookie / Session'], { any: [['source.type', 'eq', 'external'], ['source.subtype', 'in', ['Browser Client (SPA)', 'Web Application']]] }],
  },
  {
    id: 'W02', scope: 'interaction', category: 'I', priority: 'High', focus: 'flow', supersedes: ['I01'],
    title: 'Unencrypted WebSocket (ws://) on {flow.name}',
    description: '"{flow.name}" uses a WebSocket connection that is not declared as encrypted. Messages, session tokens and the handshake cookies can be read or modified by anyone on the network path.',
    mitigation: 'Use wss:// (TLS 1.2+) only, reject ws:// connections and mixed content, and enable HSTS on the host serving the socket.',
    when: [['flow.subtype', 'in', ['WebSocket', 'WebSocket (ws://)']], ['flow.props.encrypted', 'ne', 'Yes']],
  },
  {
    id: 'W03', scope: 'interaction', category: 'S', priority: 'High', focus: 'flow', supersedes: ['S03', 'S07'],
    title: 'Unauthenticated WebSocket Handshake to {target.name}',
    description: 'The upgrade request for "{flow.name}" does not declare an authentication mechanism, so anyone who can reach {target.name} may open a socket and subscribe to or publish messages.',
    mitigation: 'Authenticate during the handshake (token in a subprotocol / first message, or a validated session) and close connections that fail to authenticate within a short timeout.',
    when: [WS, ['flow.props.authentication', 'in', ['Not Selected', 'None']]],
  },
  {
    id: 'W04', scope: 'interaction', category: 'E', priority: 'Medium', focus: 'target',
    title: 'Stale Authorization on Long-Lived WebSocket to {target.name}',
    description: 'A socket from {source.name} can stay open for hours. If {target.name} only authorizes at connect time, revoked sessions, expired tokens or removed permissions keep working, and per-message actions (joining channels, subscribing to topics) may not be authorized at all.',
    mitigation: 'Authorize every message / subscription server-side, re-validate tokens periodically, enforce maximum connection lifetimes and disconnect sockets when a session is revoked.',
    when: [WS, ['target.type', 'eq', 'process'], ['target.props.authorizesRequests', 'ne', 'Yes']],
  },
  {
    id: 'W05', scope: 'interaction', category: 'T', priority: 'Medium', focus: 'target',
    title: 'Malicious WebSocket Message Injection into {target.name}',
    description: 'Messages over "{flow.name}" bypass the HTTP-layer defences (WAF rules, request validation middleware). Crafted frames from {source.name} may inject commands, tamper with shared state or trigger stored XSS when broadcast to other clients.',
    mitigation: 'Validate every message against a schema, treat client-supplied state as untrusted, encode data before broadcasting it to other clients, and enforce message size limits.',
    when: [WS, ['target.type', 'eq', 'process']],
  },
  {
    id: 'W06', scope: 'interaction', category: 'D', priority: 'Medium', focus: 'target',
    title: 'WebSocket Connection / Message Flooding of {target.name}',
    description: 'Each open socket holds memory and file descriptors on {target.name}. An attacker can open many idle connections or flood messages over "{flow.name}" to exhaust resources.',
    mitigation: 'Limit connections per user / IP, rate-limit messages, cap frame and message size, time out idle sockets, and apply back-pressure on slow consumers.',
    when: [WS, ['target.type', 'eq', 'process'], ['flow.props.rateLimited', 'ne', 'Yes']],
  },

  /* ------------------------------------------ Contact center / IVR / voice */
  {
    id: 'V01', scope: 'interaction', category: 'S', priority: 'High', focus: 'source',
    title: 'Caller ID Spoofing against {target.name}',
    description: 'Caller ID (ANI) presented by {source.name} is trivially spoofed. If {target.name} uses it to identify or authenticate callers, an attacker can impersonate customers.',
    mitigation: 'Never use ANI as an authenticator; use STIR/SHAKEN attestation as a signal only, and step up with OTP or app-based verification (voice biometrics only with liveness detection).',
    when: [['target.subtype', 'in', ['IVR System', 'Genesys Contact Center', 'Genesys Cloud (SaaS)']], ['source.type', 'eq', 'external']],
  },
  {
    id: 'V02', scope: 'interaction', category: 'I', priority: 'High', focus: 'flow',
    title: 'Sensitive Data Captured in Call Recordings / Transcripts',
    description: 'Card numbers, PINs or personal data carried by "{flow.name}" may end up in call recordings, transcripts or analytics in {target.name}.',
    mitigation: 'Use DTMF masking or pause-and-resume for payments (PCI DSS de-scoping), redact transcripts, encrypt recordings and enforce retention limits.',
    when: [['target.subtype', 'in', ['IVR System', 'Genesys Contact Center', 'Genesys Cloud (SaaS)', 'Call Recording Store']], ['flow.props.carriesSensitiveData', 'eq', 'Yes']],
  },
  {
    id: 'V03', scope: 'interaction', category: 'D', priority: 'Medium', focus: 'target',
    title: 'Telephony DoS / Toll Fraud on {target.name}',
    description: 'Automated calls from {source.name} can flood {target.name}, exhaust trunk capacity or abuse outbound dialing for toll fraud.',
    mitigation: 'Rate-limit per caller and number range, deploy a SIP firewall / fraud detection, restrict outbound destinations and monitor trunk utilisation.',
    when: [['target.subtype', 'in', ['IVR System', 'Genesys Contact Center']], ['source.type', 'eq', 'external']],
  },
  {
    id: 'V04', scope: 'interaction', category: 'S', priority: 'Medium', focus: 'target',
    title: 'Social Engineering of Contact-Center Agents via {target.name}',
    description: 'An attacker calling through {target.name} may convince human agents to reset credentials, change contact details or disclose data (account takeover).',
    mitigation: 'Enforce scripted verification with strong factors, avoid knowledge-based questions, require call-back or in-app approval for sensitive changes, and train agents.',
    when: [['target.subtype', 'in', ['Genesys Contact Center', 'Genesys Cloud (SaaS)']]],
  },

  /* ------------------------------------------- Orchestrators & Kubernetes */
  {
    id: 'O01', scope: 'interaction', category: 'T', priority: 'High', focus: 'target',
    title: 'Workflow / Task Injection into {target.name}',
    description: '{source.name} may submit or alter workflow definitions, jobs or agent plans in the orchestrator {target.name}, causing it to run attacker-controlled steps with the orchestrator\'s privileges.',
    mitigation: 'Authenticate and authorize every trigger, validate parameters, keep workflow definitions in signed / reviewed source control and disallow dynamic code in tasks.',
    when: [['target.subtype', 'eq', 'Orchestrator (Workflow / Agents)']],
  },

  /* ------------------------------------------- Penetration-testing threats */
  {
    id: 'P01', scope: 'interaction', category: 'I', priority: 'High', focus: 'flow', supersedes: ['I01', 'T02'],
    title: 'Cleartext Legacy Protocol ({flow.subtype}) on {flow.name}',
    description: '"{flow.name}" uses {flow.subtype} without declared encryption, exposing data and any transmitted credentials in cleartext. Any attacker with a foothold on the network path (including inside the perimeter) can sniff or modify it.',
    mitigation: 'Replace with the secure equivalent (SSH instead of Telnet, SFTP/FTPS instead of FTP/TFTP, HTTPS, LDAPS, SNMPv3 with privacy) and disable the legacy service.',
    when: [['flow.subtype', 'in', LEGACY], ['flow.props.encrypted', 'ne', 'Yes']],
  },
  {
    id: 'P02', scope: 'interaction', category: 'E', priority: 'High', focus: 'target',
    title: 'Remote Administration Exposed Across Trust Boundary ({flow.subtype} to {target.name})',
    description: '{flow.subtype} access to {target.name} crosses {flow.boundaries}. Exposed remote-admin services are prime targets for brute force, credential stuffing and pre-auth exploits.',
    mitigation: 'Reach admin interfaces only through a VPN or bastion with MFA, restrict source IPs, disable password authentication where possible and patch remote-access services promptly.',
    when: [['flow.subtype', 'in', REMOTE_ADMIN], ['flow.crossesBoundary', 'eq', true]],
  },
  {
    id: 'P03', scope: 'interaction', category: 'S', priority: 'High', focus: 'flow',
    title: 'NTLM Relay / Pass-the-Hash on {flow.name}',
    description: 'NTLM authentication over "{flow.name}" can be relayed to other services or replayed with captured hashes, letting an attacker authenticate to {target.name} as {source.name}.',
    mitigation: 'Disable NTLM where possible in favour of Kerberos, enforce SMB / LDAP signing and channel binding (EPA), and restrict NTLM with auditing first.',
    when: [['flow.subtype', 'eq', 'NTLM']],
  },
  {
    id: 'P04', scope: 'interaction', category: 'E', priority: 'High', focus: 'target',
    title: 'Directory Credential Attacks against {target.name}',
    description: '{target.name} is an Active Directory / LDAP directory. Attackers reaching it from {source.name} can attempt password spraying, Kerberoasting, AS-REP roasting, LDAP enumeration or DCSync to escalate to domain admin.',
    mitigation: 'Enforce strong passwords and MFA, use gMSAs with long random passwords for service accounts, require Kerberos pre-auth, tier admin accounts, and monitor for roasting / replication events.',
    when: [['target.subtype', 'in', ['Active Directory Domain Controller', 'Directory (LDAP / AD)']]],
  },
  {
    id: 'P05', scope: 'interaction', category: 'S', priority: 'High', focus: 'flow',
    title: 'SSO Token / Assertion Forgery or Replay on {flow.name}',
    description: 'If {target.name} does not strictly validate {flow.subtype} tokens (signature, algorithm, issuer, audience, expiry, nonce / InResponseTo), an attacker can forge, swap or replay them to log in as another user.',
    mitigation: 'Validate signatures with pinned keys and algorithms (no "none", no XML signature wrapping), check issuer / audience / expiry / nonce, use PKCE and exact redirect-URI matching.',
    when: [['flow.subtype', 'in', ['SAML', 'OAuth 2.0 / OIDC']]],
  },
  {
    id: 'P06', scope: 'interaction', category: 'S', priority: 'Medium', focus: 'flow',
    title: 'DNS Spoofing / Hijacking of {flow.name}',
    description: 'Plain DNS responses to {target.name} can be spoofed or poisoned, redirecting traffic to attacker-controlled hosts. Dangling DNS records also enable subdomain takeover.',
    mitigation: 'Use DNSSEC-validating resolvers or DNS over HTTPS / TLS, protect registrar accounts with MFA and registry lock, and remove dangling CNAME records.',
    when: [['flow.subtype', 'eq', 'DNS']],
  },
  {
    id: 'P07', scope: 'interaction', category: 'S', priority: 'High', focus: 'flow',
    title: 'Forged Webhook Callbacks to {target.name}',
    description: '{target.name} receives webhook callbacks from {source.name}. Without a verified signature anyone can POST fake events (e.g. "payment succeeded").',
    mitigation: 'Verify an HMAC / asymmetric signature on every callback with a timestamp to prevent replay, and re-fetch critical state from the provider API before acting.',
    when: [['flow.subtype', 'eq', 'Webhook Callback'], ['flow.props.integrity', 'ne', 'Yes']],
  },
  {
    id: 'P08', scope: 'interaction', category: 'D', priority: 'Medium', focus: 'target',
    title: 'GraphQL Introspection, Batching and Query-Depth Abuse on {target.name}',
    description: 'GraphQL endpoints often expose their full schema, allow deeply nested or aliased queries and batched mutations, enabling reconnaissance, brute force through batching and resource exhaustion.',
    mitigation: 'Disable introspection in production, enforce query depth / complexity limits and persisted queries, rate-limit per operation, and authorize at the resolver level.',
    when: [{ any: [['flow.subtype', 'eq', 'GraphQL'], ['target.subtype', 'eq', 'GraphQL API']] }, ['target.type', 'eq', 'process']],
  },
  {
    id: 'P09', scope: 'interaction', category: 'T', priority: 'High', focus: 'target',
    title: 'HTTP Request Smuggling / Header Spoofing via {source.name}',
    description: '{source.name} and {target.name} may parse HTTP differently (Content-Length vs Transfer-Encoding, HTTP/2 downgrades), allowing request smuggling. {target.name} may also trust spoofable headers such as X-Forwarded-For or X-Forwarded-Host.',
    mitigation: 'Normalise and reject ambiguous requests at the edge, use HTTP/2 end-to-end where possible, strip / overwrite forwarding headers at the first hop and only trust them from known proxies.',
    when: [['source.subtype', 'in', EDGE], ['target.type', 'eq', 'process']],
  },
  {
    id: 'P10', scope: 'interaction', category: 'I', priority: 'High', focus: 'target',
    title: 'Cloud Credential Theft from Instance Metadata ({target.name})',
    description: '{source.name} can reach the cloud instance metadata service. A server-side request forgery (SSRF) in {source.name} lets an attacker read temporary cloud credentials from it.',
    mitigation: 'Enforce IMDSv2 / metadata headers with hop limit 1, block metadata IPs from application egress, and give the workload the least cloud IAM privilege.',
    when: [['target.subtype', 'eq', 'Cloud Instance Metadata']],
  },
  {
    id: 'P11', scope: 'interaction', category: 'T', priority: 'High', focus: 'source',
    title: 'Malicious or Vulnerable Artifact from {source.name}',
    description: '{target.name} consumes code, images or packages from {source.name}. Typosquatting, dependency confusion, compromised maintainers or vulnerable versions can introduce attacker code.',
    mitigation: 'Pin versions and digests, verify signatures and provenance (Sigstore / SLSA), use a private proxy registry, scan SBOMs for vulnerabilities and block unknown sources.',
    when: [['source.subtype', 'in', ARTIFACT_SOURCES], ['target.type', 'eq', 'process']],
  },
  {
    id: 'P12', scope: 'interaction', category: 'S', priority: 'Medium', focus: 'flow',
    title: 'Email Spoofing / Phishing via {flow.name}',
    description: 'Email sent over "{flow.name}" can be spoofed to or from {target.name} if SPF, DKIM and DMARC are not enforced, enabling phishing and business-email compromise.',
    mitigation: 'Publish SPF and DKIM, enforce DMARC p=reject, use MTA-STS for TLS, and tag external mail for users.',
    when: [['flow.subtype', 'in', ['SMTP', 'Email (SMTP)']]],
  },
  {
    id: 'P13', scope: 'interaction', category: 'T', priority: 'High', focus: 'flow', supersedes: ['S07'],
    title: 'Unauthenticated Industrial Control Commands on {flow.name}',
    description: '{flow.subtype} has no built-in authentication. Anyone on the OT / field network can read values or write set-points and commands to {target.name}, with possible safety impact.',
    mitigation: 'Segment OT networks (IEC 62443 zones and conduits), allow-list masters, use secure protocol variants (DNP3 SA, OPC UA with security) and deploy OT-aware monitoring.',
    when: [{ any: [['flow.subtype', 'in', ['Modbus', 'DNP3', 'CAN Bus']], ['target.subtype', 'eq', 'PLC / Controller']] }, ['flow.props.authentication', 'in', ['Not Selected', 'None']]],
  },
  {
    id: 'P14', scope: 'interaction', category: 'I', priority: 'Medium', focus: 'flow',
    title: 'Wireless Eavesdropping, Pairing and Relay Attacks on {flow.name}',
    description: '{flow.subtype} traffic can be captured from a distance; weak pairing, downgrade or relay attacks may let an attacker read or inject data.',
    mitigation: 'Use modern secure pairing (BLE LE Secure Connections, WPA3-Enterprise), encrypt at the application layer and apply distance bounding / anti-relay where relevant.',
    when: [['flow.subtype', 'in', ['Bluetooth / BLE', 'NFC', 'Wi-Fi']]],
  },
  {
    id: 'P15', scope: 'interaction', category: 'T', priority: 'Medium', focus: 'flow',
    title: 'Malicious Removable Media into {target.name}',
    description: 'USB devices or physical media can deliver malware, keystroke-injection (BadUSB) or exfiltrate data from {target.name}.',
    mitigation: 'Disable or allow-list USB devices, scan media on a kiosk, enforce device control in EDR and encrypt removable media.',
    when: [['flow.subtype', 'eq', 'USB / Physical Media']],
  },
  {
    id: 'P16', scope: 'interaction', category: 'I', priority: 'High', focus: 'source',
    title: 'Data Exfiltration or Misuse by Insider {source.name}',
    description: '{source.name} holds legitimate access to {target.name} and may abuse it to copy, alter or delete data while blending in with normal activity.',
    mitigation: 'Least privilege and just-in-time access, DLP, user-behaviour analytics, separation of duties and tamper-proof audit logging.',
    when: [['source.subtype', 'in', ['Malicious Insider', 'Privileged Insider']]],
  },
  {
    id: 'P17', scope: 'interaction', category: 'D', priority: 'Medium', focus: 'target',
    title: 'Volumetric DDoS against {target.name}',
    description: '{target.name} is an internet-facing edge component. Volumetric or protocol-level floods from {source.name} can take the whole service offline.',
    mitigation: 'Use a DDoS protection service / scrubbing, anycast CDN, autoscaling with limits, SYN cookies and upstream rate limiting.',
    when: [['target.subtype', 'in', ['Load Balancer', 'CDN / Edge', 'Web Application Firewall', 'API Gateway', 'DNS Server']], ['source.type', 'eq', 'external']],
  },
  {
    id: 'P18', scope: 'interaction', category: 'R', priority: 'Medium', focus: 'flow',
    title: 'Log Forging or Suppression before Reaching {target.name}',
    description: 'Log events sent over "{flow.name}" are not integrity protected. An attacker can inject fake entries (log injection) or drop events to hide their tracks from {target.name}.',
    mitigation: 'Sanitise log input (CR/LF), ship logs over authenticated TLS, alert on gaps in log sources and store logs in immutable storage.',
    when: [{ any: [['target.subtype', 'eq', 'SIEM / Log Collector'], ['flow.subtype', 'eq', 'Syslog']] }, ['flow.props.integrity', 'ne', 'Yes']],
  },

  /* ------------------------------------------------ Element-level threats */
  {
    id: 'X01', scope: 'element', category: 'I', priority: 'High', focus: 'element',
    title: 'Sensitive Data Stored Unencrypted in {element.name}',
    description: '{element.name} stores credentials or sensitive data but is not declared as encrypted at rest. Theft of the media, backups or snapshots would expose it.',
    mitigation: 'Enable encryption at rest with managed keys; hash passwords with a slow KDF (Argon2id / bcrypt); keep secrets in a dedicated vault.',
    when: [['element.type', 'eq', 'store'], { any: [['element.props.storesCredentials', 'eq', 'Yes'], ['element.props.storesPII', 'eq', 'Yes']] }, ['element.props.encryptedAtRest', 'ne', 'Yes']],
  },
  {
    id: 'X02', scope: 'element', category: 'E', priority: 'Medium', focus: 'element',
    title: '{element.name} Runs With Elevated Privileges',
    description: '{element.name} runs as {element.props.runningAs}. Any vulnerability in it immediately grants the attacker these high privileges.',
    mitigation: 'Run with the least privilege necessary, drop capabilities, and isolate the process in a container, VM or sandbox.',
    when: [['element.type', 'eq', 'process'], ['element.props.runningAs', 'in', ['Kernel', 'System / root']]],
  },
  {
    id: 'X03', scope: 'element', category: 'I', priority: 'Medium', focus: 'element',
    title: 'Secrets Leakage from {element.name}',
    description: '{element.name} handles secrets or keys that may leak through logs, crash dumps, environment variables or source control.',
    mitigation: 'Load secrets at runtime from a vault, never log them, rotate regularly and scan repositories for leaked secrets.',
    when: [['element.type', 'eq', 'process'], ['element.props.handlesSecrets', 'eq', 'Yes']],
  },
  {
    id: 'X04', scope: 'element', category: 'D', priority: 'Low', focus: 'element',
    title: 'Data Loss in {element.name}',
    description: '{element.name} is not backed up. Ransomware, accidental deletion or corruption would cause permanent data loss.',
    mitigation: 'Take regular, tested, immutable (off-site) backups and define RPO / RTO targets.',
    when: [['element.type', 'eq', 'store'], ['element.props.backedUp', 'ne', 'Yes']],
  },
  {
    id: 'X05', scope: 'element', category: 'E', priority: 'Medium', focus: 'element',
    title: 'Memory Corruption in {element.name}',
    description: '{element.name} is written in unmanaged code; buffer overflows and use-after-free bugs can lead to code execution.',
    mitigation: 'Use memory-safe languages where possible, enable compiler hardening, fuzz input parsers and run static analysis.',
    when: [['element.type', 'eq', 'process'], ['element.props.codeType', 'eq', 'Unmanaged (C/C++)']],
  },
  {
    id: 'C01', scope: 'element', category: 'E', priority: 'High', focus: 'element',
    title: 'Container Escape from {element.name}',
    description: '{element.name} runs as a container. Running as root, privileged mode, host mounts or missing seccomp profiles let a compromised container break out to the node and the rest of the cluster.',
    mitigation: 'Run as non-root with a read-only root filesystem, drop Linux capabilities, apply seccomp/AppArmor, enforce the "restricted" Pod Security Standard and avoid hostPath / privileged pods.',
    when: [['element.subtype', 'in', ['Kubernetes Pod', 'Container / Pod']], ['element.props.runningAs', 'ne', 'Low privilege / sandboxed']],
  },
  {
    id: 'C02', scope: 'element', category: 'E', priority: 'High', focus: 'element',
    title: 'Kubernetes Control Plane Compromise via {element.name}',
    description: 'Access to the Kubernetes API server, etcd or over-permissive service accounts grants control over every workload and secret in the cluster.',
    mitigation: 'Keep the API server private, apply least-privilege RBAC, disable automounted service-account tokens, encrypt etcd secrets, enable audit logs and admission control.',
    when: [['element.subtype', 'eq', 'Kubernetes Control Plane']],
  },
  {
    id: 'C03', scope: 'element', category: 'E', priority: 'High', focus: 'element',
    title: 'High-Value Orchestration Target: {element.name}',
    description: '{element.name} dispatches work to many workers or agents and typically holds their credentials. Its compromise enables lateral movement to everything it orchestrates.',
    mitigation: 'Isolate the orchestrator, issue per-task scoped and short-lived credentials, sign workflow definitions and audit every dispatched action.',
    when: [['element.subtype', 'eq', 'Orchestrator (Workflow / Agents)']],
  },
  {
    id: 'P19', scope: 'element', category: 'E', priority: 'High', focus: 'element',
    title: 'Server-Side Request Forgery (SSRF) in {element.name}',
    description: '{element.name} is internet facing. If it fetches URLs or files supplied by users, attackers can make it call internal services, cloud metadata endpoints or admin interfaces.',
    mitigation: 'Allow-list outbound destinations, resolve and validate IPs (block private, link-local and metadata ranges), disable redirects and unused URL schemes, and isolate egress.',
    when: [['element.subtype', 'in', WEB_APPS], ['element.props.internetFacing', 'eq', 'Yes']],
  },
  {
    id: 'P20', scope: 'element', category: 'T', priority: 'High', focus: 'element',
    title: 'Poisoned Pipeline Execution in {element.name}',
    description: '{element.name} builds and deploys code with powerful credentials. Malicious pull requests, compromised actions / plugins or build scripts can steal secrets or push backdoored artifacts to production.',
    mitigation: 'Require review before pipelines run untrusted code, pin third-party actions by commit SHA, use OIDC short-lived deploy credentials, isolate runners per job and sign build outputs.',
    when: [['element.subtype', 'in', ['CI/CD Pipeline', 'Build Agent / Runner']]],
  },
  {
    id: 'P21', scope: 'element', category: 'I', priority: 'High', focus: 'element',
    title: 'Secrets Committed to {element.name}',
    description: 'API keys, passwords and private keys committed to {element.name} (including history and forks) are routinely harvested by attackers.',
    mitigation: 'Enable secret scanning and push protection, rotate any exposed secret immediately, and load secrets at runtime from a vault.',
    when: [['element.subtype', 'eq', 'Source Code Repository']],
  },
  {
    id: 'P22', scope: 'element', category: 'E', priority: 'High', focus: 'element',
    title: 'Compromise of Administrative Access Path {element.name}',
    description: '{element.name} concentrates privileged access. Compromising it (stolen credentials, unpatched software, session hijacking) gives an attacker administrative reach into everything behind it.',
    mitigation: 'Harden and patch, require phishing-resistant MFA, use just-in-time access, record admin sessions and alert on anomalous logins.',
    when: [['element.subtype', 'in', ['Bastion / Jump Host', 'Admin Console / Management Plane']]],
  },
  {
    id: 'P23', scope: 'element', category: 'I', priority: 'High', focus: 'element',
    title: 'Session Tokens in {element.name} Exposed to XSS',
    description: 'Tokens stored in {element.name} (localStorage / sessionStorage / IndexedDB) can be read by any script running in the page, so a single XSS leads to account takeover.',
    mitigation: 'Keep session tokens in HttpOnly, Secure, SameSite cookies, or use short-lived in-memory tokens with refresh via a backend-for-frontend.',
    when: [['element.subtype', 'eq', 'Browser Storage'], ['element.props.storesCredentials', 'eq', 'Yes']],
  },
  {
    id: 'P24', scope: 'element', category: 'I', priority: 'Medium', focus: 'element',
    title: 'Unprotected Data on Device Storage ({element.name})',
    description: 'Data in {element.name} can be extracted from lost, stolen, rooted or backed-up devices if it is not encrypted with platform keystores.',
    mitigation: 'Use the platform keystore / Keychain with hardware-backed keys, avoid storing secrets on the device, exclude sensitive files from backups and detect rooted devices.',
    when: [['element.subtype', 'eq', 'Mobile Device Storage'], ['element.props.encryptedAtRest', 'ne', 'Yes']],
  },
];

export function validateRules(rules) {
  if (!Array.isArray(rules) || !rules.length) throw new Error('Template must be a non-empty array of rules.');
  const ids = new Set();
  for (const r of rules) {
    if (!r || typeof r !== 'object' || Array.isArray(r)) throw new Error('Rule ?: every rule must be an object.');
    const fail = (message) => { throw new Error(`Rule ${r.id ?? '?'}: ${message}`); };
    for (const k of ['id', 'category', 'title', 'when']) if (!Object.hasOwn(r, k) || r[k] == null) fail(`missing "${k}".`);
    if (typeof r.id !== 'string' || !r.id.trim()) fail('id must be a non-empty string.');
    if (!['S', 'T', 'R', 'I', 'D', 'E'].includes(r.category)) fail('category must be one of S,T,R,I,D,E.');
    if (typeof r.title !== 'string') fail('title must be text.');
    for (const k of ['description', 'mitigation']) if (Object.hasOwn(r, k) && typeof r[k] !== 'string') fail(`${k} must be text.`);
    if (ids.has(r.id)) throw new Error(`Duplicate rule id ${r.id}.`);
    ids.add(r.id);
    for (const [field, values] of [
      ['scope', ['interaction', 'element']], ['priority', ['High', 'Medium', 'Low']],
      ['focus', ['source', 'target', 'flow', 'element']], ['dedupeKey', ['target', 'source', 'flow']],
    ]) if (Object.hasOwn(r, field) && !values.includes(r[field])) fail(`${field} must be one of ${values.join(', ')}.`);
    if (Object.hasOwn(r, 'supersedes') && (!Array.isArray(r.supersedes) || r.supersedes.some((id) => typeof id !== 'string' || !id.trim()))) fail('supersedes must be an array of rule IDs.');

    const path = (value) => {
      if (typeof value !== 'string' || !value || value.split('.').some((part) => !part)) fail(`invalid condition path ${JSON.stringify(value)}.`);
      const parts = value.split('.');
      if (parts.some((part) => ['__proto__', 'prototype', 'constructor'].includes(part))) fail(`unsafe path "${value}".`);
      if (!['source', 'target', 'flow', 'element'].includes(parts[0])) fail(`invalid path root in "${value}".`);
      if (r.scope === 'element' && parts[0] !== 'element') fail(`element-scope condition cannot reference "${value}".`);
    };
    const condition = (cond, depth = 0) => {
      if (depth > 64) fail('condition nesting exceeds 64 levels.');
      if (Array.isArray(cond)) {
        if (typeof cond[0] === 'string') {
          if (cond.length !== 3) fail('clauses must be [path, op, value].');
          const [p, op, value] = cond; path(p);
          if (!['eq', 'ne', 'in', 'nin', 'exists'].includes(op)) fail(`unsupported operator "${op}".`);
          if (['in', 'nin'].includes(op) && !Array.isArray(value)) fail(`operator "${op}" requires an array value.`);
          if (op === 'exists' && typeof value !== 'boolean') fail('operator "exists" requires a boolean value.');
        } else for (const child of cond) condition(child, depth + 1);
        return;
      }
      if (cond && typeof cond === 'object' && Object.keys(cond).length === 1) {
        if (Object.hasOwn(cond, 'any') && Array.isArray(cond.any)) {
          for (const child of cond.any) condition(child, depth + 1);
          return;
        }
        if (Object.hasOwn(cond, 'not')) { condition(cond.not, depth + 1); return; }
      }
      fail('malformed condition; expected [path, op, value], an AND array, {any:[...]}, or {not: condition}.');
    };
    condition(r.when);
  }
  for (const r of rules) for (const id of r.supersedes || []) {
    if (!ids.has(id)) throw new Error(`Rule ${r.id}: supersedes references unknown rule "${id}".`);
  }
  return rules;
}

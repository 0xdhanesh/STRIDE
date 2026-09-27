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
// }
//
// Paths: source.type, source.subtype, source.props.<key>, target.*, flow.subtype,
// flow.props.<key>, flow.crossesBoundary (boolean), element.*

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
    when: [['target.type', 'eq', 'process']],
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
    when: [['target.type', 'eq', 'store']],
  },
  {
    id: 'S05', scope: 'interaction', category: 'S', priority: 'Medium', focus: 'source',
    title: 'Spoofing of Source Data Store {source.name}',
    description: '{source.name} may be spoofed by an attacker and this may lead to incorrect data delivered to {target.name}. Consider using a standard authentication mechanism to identify the source data store.',
    mitigation: 'Authenticate the data store endpoint (TLS certificate validation, private endpoints) and verify integrity of data read from it.',
    when: [['source.type', 'eq', 'store']],
  },
  {
    id: 'S06', scope: 'interaction', category: 'S', priority: 'Medium', focus: 'target',
    title: 'Spoofing of the {target.name} External Destination Entity',
    description: '{target.name} may be spoofed by an attacker and this may lead to data being sent to the attacker\'s target instead of {target.name}. Consider using a standard authentication mechanism to identify the external entity.',
    mitigation: 'Verify the identity of the destination (TLS certificate validation, allow-listed endpoints, signed webhooks).',
    when: [['target.type', 'eq', 'external']],
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
    id: 'T01', scope: 'interaction', category: 'T', priority: 'High', focus: 'target',
    title: 'Potential Lack of Input Validation for {target.name}',
    description: 'Data flowing across {flow.name} may be tampered with by an attacker. This may lead to a denial of service attack against {target.name}, an elevation of privilege attack against {target.name} or an information disclosure by {target.name}. Failure to verify that input is as expected is a root cause of a very large number of exploitable issues. Consider all paths and the way they handle data.',
    mitigation: 'Validate all input with an allow-list approach (type, length, format, range) at the trust boundary. Use schema validation for structured payloads and reject rather than sanitize where possible.',
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
    when: [['target.type', 'eq', 'store'], ['target.subtype', 'in', ['Database', 'SQL Database', 'NoSQL Database', 'Vector Database']]],
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
    id: 'R01', scope: 'interaction', category: 'R', priority: 'Medium', focus: 'target',
    title: 'Potential Data Repudiation by {target.name}',
    description: '{target.name} claims that it did not receive data from a source outside the trust boundary. Consider using logging or auditing to record the source, time, and summary of the received data.',
    mitigation: 'Log security-relevant events (who, what, when, from where) to an append-only store; synchronise clocks; include correlation IDs.',
    when: [['target.type', 'eq', 'process'], ['target.props.logsSecurityEvents', 'ne', 'Yes']],
  },
  {
    id: 'R02', scope: 'interaction', category: 'R', priority: 'Low', focus: 'target',
    title: 'External Entity {target.name} Potentially Denies Receiving Data',
    description: '{target.name} claims that it did not receive data from a process on the other side of the trust boundary. Consider using logging or auditing to record the source, time, and summary of the received data.',
    mitigation: 'Record delivery receipts / acknowledgements and keep signed audit logs of outbound transmissions.',
    when: [['target.type', 'eq', 'external']],
  },
  {
    id: 'R03', scope: 'interaction', category: 'R', priority: 'Low', focus: 'target',
    title: 'Data Store {target.name} Denies {source.name} Potentially Writing Data',
    description: '{target.name} claims that it did not write data received from an entity on the other side of the trust boundary. Consider using logging or auditing to record the source, time, and summary of the received data.',
    mitigation: 'Enable data store audit logging (who wrote what and when) and forward it to a central, tamper-resistant log.',
    when: [['target.type', 'eq', 'store']],
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
    id: 'I05', scope: 'interaction', category: 'I', priority: 'Low', focus: 'target',
    title: 'Information Disclosure Through Error Messages of {target.name}',
    description: '{target.name} may return verbose error messages, stack traces or version banners to {source.name}, helping an attacker map the system.',
    mitigation: 'Return generic error messages to callers, log details server-side, and remove version banners and debug endpoints in production.',
    when: [['source.type', 'eq', 'external'], ['target.type', 'eq', 'process']],
  },

  /* --------------------------------------------------- Denial of service */
  {
    id: 'D01', scope: 'interaction', category: 'D', priority: 'Medium', focus: 'target',
    title: 'Potential Process Crash or Stop for {target.name}',
    description: '{target.name} crashes, halts, stops or runs slowly; in all cases violating an availability metric.',
    mitigation: 'Bound input sizes and processing time, handle errors defensively, run multiple instances behind health checks, and auto-restart failed processes.',
    when: [['target.type', 'eq', 'process']],
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
    title: 'Data Store Inaccessible',
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
    when: [['target.type', 'eq', 'process'], ['source.type', 'in', ['process', 'external']]],
  },
  {
    id: 'E02', scope: 'interaction', category: 'E', priority: 'High', focus: 'target',
    title: '{target.name} May be Subject to Elevation of Privilege Using Remote Code Execution',
    description: '{source.name} may be able to remotely execute code for {target.name}.',
    mitigation: 'Keep dependencies patched, avoid dynamic code evaluation, run with least privilege in an isolated sandbox/container, and use memory-safe languages where possible.',
    when: [['target.type', 'eq', 'process'], ['flow.crossesBoundary', 'eq', true]],
  },
  {
    id: 'E03', scope: 'interaction', category: 'E', priority: 'Medium', focus: 'target',
    title: 'Elevation by Changing the Execution Flow in {target.name}',
    description: 'An attacker may pass data into {target.name} in order to change the flow of program execution within {target.name} to the attacker\'s choosing.',
    mitigation: 'Validate input strictly, use safe parsers, compile with exploit mitigations (ASLR, DEP, CFG) and prefer memory-safe languages.',
    when: [['target.type', 'eq', 'process'], ['target.props.validatesInput', 'ne', 'Yes']],
  },
  {
    id: 'E04', scope: 'interaction', category: 'E', priority: 'Medium', focus: 'target',
    title: 'Cross Site Request Forgery against {target.name}',
    description: 'Cross-site request forgery (CSRF or XSRF) is a type of attack in which an attacker forces a user\'s browser to make a forged request to a vulnerable site by exploiting an existing trust relationship between the browser and {target.name}.',
    mitigation: 'Use anti-forgery tokens, SameSite=Lax/Strict cookies, and verify Origin / Referer headers on state-changing requests.',
    when: [['target.subtype', 'in', ['Web Application', 'Web API / Service']], ['source.type', 'eq', 'external']],
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
    id: 'K01', scope: 'interaction', category: 'S', priority: 'High', focus: 'flow',
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
    when: [WS, ['target.type', 'eq', 'process'], ['source.type', 'in', ['external', 'process']], { any: [['source.type', 'eq', 'external'], ['source.subtype', 'in', ['Browser Client (SPA)', 'Web Application']]] }],
  },
  {
    id: 'W02', scope: 'interaction', category: 'I', priority: 'High', focus: 'flow',
    title: 'Unencrypted WebSocket (ws://) on {flow.name}',
    description: '"{flow.name}" uses a WebSocket connection that is not declared as encrypted. Messages, session tokens and the handshake cookies can be read or modified by anyone on the network path.',
    mitigation: 'Use wss:// (TLS 1.2+) only, reject ws:// connections and mixed content, and enable HSTS on the host serving the socket.',
    when: [WS, ['flow.props.encrypted', 'ne', 'Yes']],
  },
  {
    id: 'W03', scope: 'interaction', category: 'S', priority: 'High', focus: 'flow',
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
    when: [['element.type', 'eq', 'store'], ['element.props.backedUp', 'eq', 'No']],
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
];

export function validateRules(rules) {
  if (!Array.isArray(rules) || !rules.length) throw new Error('Template must be a non-empty array of rules.');
  const ids = new Set();
  for (const r of rules) {
    if (!r || typeof r !== 'object') throw new Error('Every rule must be an object.');
    for (const k of ['id', 'category', 'title', 'when']) if (r[k] == null) throw new Error(`Rule ${r.id || '?'} is missing "${k}".`);
    if (!'STRIDE'.includes(r.category) || r.category.length !== 1) throw new Error(`Rule ${r.id}: category must be one of S,T,R,I,D,E.`);
    if (ids.has(r.id)) throw new Error(`Duplicate rule id ${r.id}.`);
    ids.add(r.id);
  }
  return rules;
}

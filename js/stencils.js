// Stencil catalogue: the DFD element kinds, their subtypes and security properties.
// Properties feed the STRIDE rule engine (see rules.js) exactly like the property
// sheet in Microsoft Threat Modeling Tool.

export const STRIDE = [
  { key: 'S', name: 'Spoofing', color: '#e03131', property: 'Authentication', desc: 'Pretending to be something or someone other than yourself.' },
  { key: 'T', name: 'Tampering', color: '#e8590c', property: 'Integrity', desc: 'Modifying data or code in transit, in memory or at rest.' },
  { key: 'R', name: 'Repudiation', color: '#9c36b5', property: 'Non-repudiation', desc: 'Claiming not to have performed an action.' },
  { key: 'I', name: 'Information Disclosure', color: '#1971c2', property: 'Confidentiality', desc: 'Exposing information to someone not authorised to see it.' },
  { key: 'D', name: 'Denial of Service', color: '#0c8599', property: 'Availability', desc: 'Denying or degrading service to users.' },
  { key: 'E', name: 'Elevation of Privilege', color: '#2f9e44', property: 'Authorization', desc: 'Gaining capabilities without proper authorisation.' },
];
export const STRIDE_BY_KEY = Object.fromEntries(STRIDE.map((s) => [s.key, s]));

export const STATES = ['Not Started', 'Needs Investigation', 'Not Applicable', 'Mitigated'];
export const OPEN_STATES = ['Not Started', 'Needs Investigation'];
export const PRIORITIES = ['High', 'Medium', 'Low'];

const YN = ['Not Selected', 'Yes', 'No'];

export const STENCILS = {
  process: {
    label: 'Process',
    hint: 'Code that runs: a service, app, function or component.',
    size: { w: 130, h: 130 },
    subtypes: [
      'Generic Process', 'Web Application', 'Web API / Service', 'Browser Client (SPA)', 'Mobile App',
      'Desktop / Thick Client', 'Microservice', 'Serverless Function', 'Background Worker', 'Container / Pod',
      'Kubernetes Pod', 'Kubernetes Control Plane', 'Orchestrator (Workflow / Agents)', 'MCP Server', 'AI Agent / LLM App',
      'IVR System', 'Genesys Contact Center', 'Kafka Broker', 'Virtual Machine', 'Identity Provider', 'API Gateway',
      'Message Broker', 'Multiple Processes',
    ],
    subtypeDefaults: { 'Kubernetes Pod': { isolation: 'Container' }, 'Container / Pod': { isolation: 'Container' } },
    props: [
      { key: 'codeType', label: 'Code type', options: ['Not Selected', 'Managed', 'Unmanaged (C/C++)', 'Interpreted / Script'] },
      { key: 'runningAs', label: 'Running as', options: ['Not Selected', 'Kernel', 'System / root', 'Standard user', 'Low privilege / sandboxed'] },
      { key: 'isolation', label: 'Isolation', options: ['Not Selected', 'None', 'Container', 'Virtual machine', 'Sandbox'] },
      { key: 'authenticatesCallers', label: 'Authenticates callers', options: YN },
      { key: 'authorizesRequests', label: 'Authorizes requests', options: YN },
      { key: 'validatesInput', label: 'Validates input', options: YN },
      { key: 'sanitizesOutput', label: 'Encodes / sanitizes output', options: YN },
      { key: 'logsSecurityEvents', label: 'Logs security events', options: YN },
      { key: 'handlesSecrets', label: 'Handles secrets / keys', options: YN },
      { key: 'internetFacing', label: 'Internet facing', options: YN },
    ],
  },
  external: {
    label: 'External Entity',
    hint: 'People or systems outside your control that interact with it.',
    size: { w: 160, h: 80 },
    subtypes: [
      'Generic External Entity', 'Human User', 'Administrator', 'Browser', 'Third-Party Service', 'Mobile Device',
      'IoT Device', 'Partner System', 'Cloud Provider Service', 'Phone Caller (PSTN)', 'Genesys Cloud (SaaS)',
      'MCP Client / AI Assistant', 'LLM Provider API', 'Attacker',
    ],
    props: [
      { key: 'authenticatesItself', label: 'Authenticates itself', options: YN },
      { key: 'trustLevel', label: 'Trust level', options: ['Not Selected', 'Untrusted', 'Partially trusted', 'Trusted'] },
    ],
  },
  store: {
    label: 'Data Store',
    hint: 'Where data rests: databases, files, caches, queues, secrets.',
    size: { w: 160, h: 70 },
    subtypes: [
      'Generic Data Store', 'Database', 'SQL Database', 'NoSQL Database', 'Kafka Topic / Event Log', 'File System',
      'Blob / Object Storage', 'Cache', 'Key Vault / Secret Store', 'Message Queue', 'Log Store', 'Call Recording Store',
      'Vector Database', 'Browser Storage', 'Configuration / Registry', 'Backup',
    ],
    subtypeDefaults: {
      'Log Store': { storesLogs: 'Yes' }, 'Kafka Topic / Event Log': { storesLogs: 'Yes' },
      'Key Vault / Secret Store': { storesCredentials: 'Yes' }, 'Call Recording Store': { storesPII: 'Yes' },
    },
    props: [
      { key: 'encryptedAtRest', label: 'Encrypted at rest', options: YN },
      { key: 'integrity', label: 'Integrity protected (signed)', options: YN },
      { key: 'accessControl', label: 'Access control', options: ['Not Selected', 'Fine-grained', 'Coarse', 'None'] },
      { key: 'storesCredentials', label: 'Stores credentials / secrets', options: YN },
      { key: 'storesPII', label: 'Stores PII / sensitive data', options: YN },
      { key: 'storesLogs', label: 'Stores log data', options: YN },
      { key: 'backedUp', label: 'Backed up', options: YN },
    ],
  },
  flow: {
    label: 'Data Flow',
    hint: 'Data moving between elements. Threats are generated per flow.',
    subtypes: [
      'Generic Data Flow', 'HTTP', 'HTTPS', 'gRPC', 'WebSocket', 'SQL / DB Protocol', 'Message (AMQP / MQTT / Kafka)',
      'Kafka Produce / Consume', 'MCP (JSON-RPC)', 'SIP / RTP (Voice)', 'File Transfer (SFTP / SMB)', 'IPC / Named Pipe',
      'RPC / DCOM', 'SSH', 'Email (SMTP)', 'Binary / Custom',
    ],
    subtypeDefaults: {
      HTTPS: { encrypted: 'Yes' }, SSH: { encrypted: 'Yes' }, HTTP: { encrypted: 'No' },
    },
    props: [
      { key: 'encrypted', label: 'Encrypted in transit', options: YN },
      { key: 'authentication', label: 'Authentication', options: ['Not Selected', 'None', 'Password', 'Token (OAuth / JWT)', 'mTLS / Certificate', 'API key', 'Kerberos / Windows'] },
      { key: 'integrity', label: 'Integrity protected', options: YN },
      { key: 'replayProtection', label: 'Replay protection', options: YN },
      { key: 'rateLimited', label: 'Rate limited', options: YN },
      { key: 'carriesCredentials', label: 'Carries credentials / tokens', options: YN },
      { key: 'carriesSensitiveData', label: 'Carries sensitive data', options: YN },
    ],
  },
  boundary: {
    label: 'Trust Boundary',
    hint: 'A zone where the level of trust changes (network, machine, process).',
    size: { w: 380, h: 280 },
    subtypes: [
      'Generic Trust Boundary', 'Internet Boundary', 'Machine Boundary', 'Corporate Network', 'DMZ', 'Cloud VPC / VNet',
      'Kubernetes Cluster', 'Kubernetes Namespace', 'Container Boundary', 'Sandbox', 'Browser Sandbox', 'Kernel / User Mode',
    ],
    props: [],
  },
  boundaryLine: {
    label: 'Trust Boundary (line)',
    hint: 'A curved boundary line; flows that cross it are boundary-crossing.',
    subtypes: ['Generic Trust Boundary', 'Internet Boundary', 'Machine Boundary', 'Corporate Network', 'DMZ', 'Kernel / User Mode'],
    props: [],
  },
  note: {
    label: 'Note',
    hint: 'Free-text annotation.',
    subtypes: [],
    props: [],
  },
};

export const DEFAULT_NAMES = {
  process: 'Process', external: 'External Entity', store: 'Data Store', flow: 'Data Flow',
  boundary: 'Trust Boundary', boundaryLine: 'Trust Boundary', note: 'Note',
};

export function defaultProps(type) {
  const out = {};
  for (const p of STENCILS[type]?.props || []) out[p.key] = p.options[0];
  return out;
}

export const STROKES = ['#1e1e1e', '#e03131', '#2f9e44', '#1971c2', '#f08c00', '#9c36b5'];
export const FILLS = [null, '#ffc9c9', '#b2f2bb', '#a5d8ff', '#ffec99', '#eebefa'];
export const BOUNDARY_COLOR = '#e03131';

// Symbol drawn inside a shape for a given subtype (see glyphs.js).
export const SUBTYPE_GLYPH = {
  'Web Application': 'browser', 'Browser Client (SPA)': 'browser', 'Mobile App': 'phone', 'Serverless Function': 'function',
  'Container / Pod': 'container', 'Kubernetes Pod': 'kubernetes', 'Kubernetes Control Plane': 'kubernetes',
  'Orchestrator (Workflow / Agents)': 'orchestrator', 'MCP Server': 'mcp', 'AI Agent / LLM App': 'agent',
  'IVR System': 'ivr', 'Genesys Contact Center': 'headset', 'Kafka Broker': 'eventlog', 'Virtual Machine': 'vm',
  'Identity Provider': 'idp', 'API Gateway': 'gateway', 'Message Broker': 'queue',
  'Human User': 'user', Administrator: 'user', Browser: 'browser', 'Mobile Device': 'phone', 'IoT Device': 'iot',
  'Cloud Provider Service': 'cloud', 'Third-Party Service': 'cloud', 'Phone Caller (PSTN)': 'ivr',
  'Genesys Cloud (SaaS)': 'headset', 'MCP Client / AI Assistant': 'agent', 'LLM Provider API': 'agent', Attacker: 'attacker',
  Database: 'database', 'SQL Database': 'database', 'NoSQL Database': 'database', 'Vector Database': 'database',
  'Kafka Topic / Event Log': 'eventlog', 'File System': 'file', 'Blob / Object Storage': 'cloud', Cache: 'cache',
  'Key Vault / Secret Store': 'key', 'Message Queue': 'queue', 'Log Store': 'log', 'Call Recording Store': 'headset',
  'Kubernetes Cluster': 'kubernetes', 'Kubernetes Namespace': 'kubernetes', 'Container Boundary': 'container',
  'Cloud VPC / VNet': 'cloud',
};

// Data-store subtypes drawn with a dedicated outline instead of the DFD "two lines".
export const SUBTYPE_SHAPE = {
  Database: 'cylinder', 'SQL Database': 'cylinder', 'NoSQL Database': 'cylinder', 'Vector Database': 'cylinder',
  'Kafka Topic / Event Log': 'log',
};

// Entries of the stencil library (toolbar "Library" button): type + subtype presets.
export const LIBRARY = [
  { group: 'Data', items: [['store', 'Database'], ['store', 'SQL Database'], ['store', 'Kafka Topic / Event Log'], ['store', 'Cache'], ['store', 'Key Vault / Secret Store'], ['store', 'Blob / Object Storage'], ['store', 'Vector Database'], ['store', 'Log Store']] },
  { group: 'Platform', items: [['process', 'Kubernetes Pod'], ['process', 'Container / Pod'], ['process', 'Kubernetes Control Plane'], ['process', 'Orchestrator (Workflow / Agents)'], ['process', 'Kafka Broker'], ['process', 'API Gateway'], ['process', 'Serverless Function'], ['boundary', 'Kubernetes Cluster']] },
  { group: 'AI & MCP', items: [['process', 'MCP Server'], ['external', 'MCP Client / AI Assistant'], ['process', 'AI Agent / LLM App'], ['external', 'LLM Provider API']] },
  { group: 'Contact center', items: [['process', 'IVR System'], ['process', 'Genesys Contact Center'], ['external', 'Genesys Cloud (SaaS)'], ['external', 'Phone Caller (PSTN)'], ['store', 'Call Recording Store']] },
  { group: 'Apps & people', items: [['process', 'Web Application'], ['process', 'Web API / Service'], ['process', 'Identity Provider'], ['external', 'Human User'], ['external', 'Browser'], ['external', 'Third-Party Service']] },
];

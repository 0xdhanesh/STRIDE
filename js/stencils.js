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
      'Generic Process', 'Web Application', 'Web API / Service', 'GraphQL API', 'Browser Client (SPA)', 'Mobile App',
      'Desktop / Thick Client', 'Browser Extension', 'Microservice', 'Serverless Function', 'Background Worker',
      'Scheduled Job / Cron', 'ETL / Data Pipeline', 'Container / Pod', 'Kubernetes Pod', 'Kubernetes Control Plane',
      'Service Mesh / Sidecar', 'Orchestrator (Workflow / Agents)', 'MCP Server', 'AI Agent / LLM App', 'ML Model Serving',
      'IVR System', 'Genesys Contact Center', 'Kafka Broker', 'WebSocket Server / Gateway', 'Message Broker',
      'API Gateway', 'Load Balancer', 'Reverse Proxy', 'CDN / Edge', 'Web Application Firewall', 'Network Firewall',
      'VPN Gateway', 'Bastion / Jump Host', 'DNS Server', 'Mail Server', 'File Transfer Server',
      'Identity Provider', 'Authentication Service', 'Authorization / Policy Engine', 'Active Directory Domain Controller',
      'Certificate Authority / PKI', 'Secrets Manager', 'Payment Service',
      'CI/CD Pipeline', 'Build Agent / Runner', 'SIEM / Log Collector', 'EDR / Security Agent', 'Vulnerability Scanner',
      'Admin Console / Management Plane', 'Virtual Machine', 'Mainframe / Legacy System', 'Kernel Driver / Service',
      'IoT Gateway', 'PLC / Controller', 'SCADA / HMI', 'Multiple Processes',
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
      'Generic External Entity', 'Human User', 'Anonymous User', 'Authenticated User', 'Administrator', 'Privileged Insider',
      'Browser', 'Third-Party Service', 'SaaS Application', 'Payment Gateway', 'OAuth / Social Login Provider',
      'Mobile Device', 'IoT Device', 'Partner System', 'Supplier / Vendor', 'Cloud Provider Service', 'Email Recipient',
      'Phone Caller (PSTN)', 'Genesys Cloud (SaaS)', 'MCP Client / AI Assistant', 'LLM Provider API',
      'Open-Source Dependency', 'External Attacker (Internet)', 'Malicious Insider', 'Compromised Supply Chain', 'Attacker',
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
      'Generic Data Store', 'Database', 'SQL Database', 'NoSQL Database', 'Vector Database', 'Data Warehouse / Lake',
      'Search Index', 'Time-Series Database', 'Kafka Topic / Event Log', 'File System', 'File Share (SMB / NFS)',
      'Blob / Object Storage', 'Cache', 'Session Store', 'Key Vault / Secret Store', 'HSM / Key Management',
      'Certificate Store', 'Directory (LDAP / AD)', 'Message Queue', 'Log Store', 'Audit Trail', 'Call Recording Store',
      'Source Code Repository', 'Container Registry', 'Package / Artifact Registry', 'ML Model / Training Data',
      'Email Mailbox', 'Ledger / Blockchain', 'Browser Storage', 'Mobile Device Storage', 'Configuration / Registry',
      'Cloud Instance Metadata', 'Backup',
    ],
    subtypeDefaults: {
      'Log Store': { storesLogs: 'Yes' }, 'Kafka Topic / Event Log': { storesLogs: 'Yes' },
      'Key Vault / Secret Store': { storesCredentials: 'Yes' }, 'Call Recording Store': { storesPII: 'Yes' },
      'HSM / Key Management': { storesCredentials: 'Yes' }, 'Directory (LDAP / AD)': { storesCredentials: 'Yes' },
      'Session Store': { storesCredentials: 'Yes' }, 'Audit Trail': { storesLogs: 'Yes' }, 'Certificate Store': { storesCredentials: 'Yes' },
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
      'Generic Data Flow', 'HTTP', 'HTTPS', 'REST / JSON', 'GraphQL', 'SOAP / XML', 'gRPC', 'WebSocket Secure (wss://)',
      'WebSocket (ws://)', 'WebSocket', 'Webhook Callback', 'SQL / DB Protocol', 'Message (AMQP / MQTT / Kafka)',
      'Kafka Produce / Consume', 'MCP (JSON-RPC)', 'SIP / RTP (Voice)', 'OAuth 2.0 / OIDC', 'SAML', 'Kerberos', 'NTLM',
      'LDAP', 'LDAPS', 'RADIUS', 'DNS', 'DNS over HTTPS / TLS', 'NTP', 'Syslog', 'SNMP', 'SMTP', 'Email (SMTP)',
      'File Transfer (SFTP / SMB)', 'SMB', 'NFS', 'FTP', 'FTPS', 'TFTP', 'SSH', 'Telnet', 'RDP', 'VNC',
      'IPC / Named Pipe', 'RPC / DCOM', 'WinRM / PowerShell Remoting', 'VPN / IPsec', 'Bluetooth / BLE', 'NFC', 'Wi-Fi',
      'USB / Physical Media', 'Modbus', 'DNP3', 'OPC UA', 'CAN Bus', 'Binary / Custom',
    ],
    subtypeDefaults: {
      HTTPS: { encrypted: 'Yes' }, SSH: { encrypted: 'Yes' }, HTTP: { encrypted: 'No' },
      'WebSocket Secure (wss://)': { encrypted: 'Yes' }, 'WebSocket (ws://)': { encrypted: 'No' },
      LDAPS: { encrypted: 'Yes' }, FTPS: { encrypted: 'Yes' }, 'DNS over HTTPS / TLS': { encrypted: 'Yes' }, 'VPN / IPsec': { encrypted: 'Yes' },
      'File Transfer (SFTP / SMB)': {}, Telnet: { encrypted: 'No', authentication: 'Password' }, FTP: { encrypted: 'No' }, TFTP: { encrypted: 'No', authentication: 'None' },
      LDAP: { encrypted: 'No' }, SNMP: { encrypted: 'No' }, DNS: { encrypted: 'No' }, Modbus: { encrypted: 'No', authentication: 'None' },
      DNP3: { encrypted: 'No' }, 'CAN Bus': { encrypted: 'No', authentication: 'None' }, 'OAuth 2.0 / OIDC': { authentication: 'Token (OAuth / JWT)' },
      Kerberos: { authentication: 'Kerberos / Windows' }, NTLM: { authentication: 'Kerberos / Windows' },
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
      'Generic Trust Boundary', 'Internet Boundary', 'Machine Boundary', 'Process Boundary', 'Corporate Network', 'DMZ',
      'Cloud VPC / VNet', 'Cloud Account / Subscription', 'Tenant Boundary', 'Kubernetes Cluster', 'Kubernetes Namespace',
      'Container Boundary', 'Sandbox', 'Browser Sandbox', 'Kernel / User Mode', 'Management Network', 'PCI Zone (CDE)',
      'Partner Network', 'Remote Access / VPN', 'Wireless Network', 'OT / ICS Network', 'Physical Boundary', 'Endpoint / Device',
    ],
    props: [],
  },
  boundaryLine: {
    label: 'Trust Boundary (line)',
    hint: 'A curved boundary line; flows that cross it are boundary-crossing.',
    subtypes: ['Generic Trust Boundary', 'Internet Boundary', 'Machine Boundary', 'Process Boundary', 'Corporate Network', 'DMZ', 'Management Network', 'PCI Zone (CDE)', 'OT / ICS Network', 'Wireless Network', 'Kernel / User Mode'],
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
  'IVR System': 'ivr', 'Genesys Contact Center': 'headset', 'Kafka Broker': 'eventlog', 'WebSocket Server / Gateway': 'websocket', 'Virtual Machine': 'vm',
  'Identity Provider': 'idp', 'API Gateway': 'gateway', 'Message Broker': 'queue',
  'Human User': 'user', Administrator: 'user', Browser: 'browser', 'Mobile Device': 'phone', 'IoT Device': 'iot',
  'Cloud Provider Service': 'cloud', 'Third-Party Service': 'cloud', 'Phone Caller (PSTN)': 'ivr',
  'Genesys Cloud (SaaS)': 'headset', 'MCP Client / AI Assistant': 'agent', 'LLM Provider API': 'agent', Attacker: 'attacker',
  Database: 'database', 'SQL Database': 'database', 'NoSQL Database': 'database', 'Vector Database': 'database',
  'Kafka Topic / Event Log': 'eventlog', 'File System': 'file', 'Blob / Object Storage': 'cloud', Cache: 'cache',
  'Key Vault / Secret Store': 'key', 'Message Queue': 'queue', 'Log Store': 'log', 'Call Recording Store': 'headset',
  'Kubernetes Cluster': 'kubernetes', 'Kubernetes Namespace': 'kubernetes', 'Container Boundary': 'container',
  'Cloud VPC / VNet': 'cloud',
  // Web, API & edge
  'Web API / Service': 'server', 'GraphQL API': 'graph', 'Desktop / Thick Client': 'vm', 'Browser Extension': 'puzzle',
  Microservice: 'mesh', 'Background Worker': 'cpu', 'Scheduled Job / Cron': 'clock', 'ETL / Data Pipeline': 'pipeline',
  'Service Mesh / Sidecar': 'mesh', 'ML Model Serving': 'brain', 'Load Balancer': 'loadbalancer', 'Reverse Proxy': 'proxy',
  'CDN / Edge': 'globe', 'Web Application Firewall': 'firewall', 'Network Firewall': 'firewall', 'VPN Gateway': 'vpn',
  'Bastion / Jump Host': 'terminal', 'DNS Server': 'globe', 'Mail Server': 'mail', 'File Transfer Server': 'file',
  // Identity & crypto
  'Authentication Service': 'lock', 'Authorization / Policy Engine': 'policy', 'Active Directory Domain Controller': 'directory',
  'Certificate Authority / PKI': 'cert', 'Secrets Manager': 'key', 'Payment Service': 'card',
  // DevOps & security operations
  'CI/CD Pipeline': 'pipeline', 'Build Agent / Runner': 'cpu', 'SIEM / Log Collector': 'eye', 'EDR / Security Agent': 'shield',
  'Vulnerability Scanner': 'radar', 'Admin Console / Management Plane': 'terminal', 'Mainframe / Legacy System': 'server',
  'Kernel Driver / Service': 'chip', 'IoT Gateway': 'iot', 'PLC / Controller': 'factory', 'SCADA / HMI': 'gauge',
  // External entities
  'Anonymous User': 'user', 'Authenticated User': 'user', 'Privileged Insider': 'insider', 'SaaS Application': 'cloud',
  'Payment Gateway': 'card', 'OAuth / Social Login Provider': 'idp', 'Supplier / Vendor': 'cloud', 'Email Recipient': 'mail',
  'Open-Source Dependency': 'registry', 'External Attacker (Internet)': 'attacker', 'Malicious Insider': 'insider',
  'Compromised Supply Chain': 'registry', 'Partner System': 'server',
  // Data stores
  'Data Warehouse / Lake': 'warehouse', 'Search Index': 'search', 'Time-Series Database': 'database',
  'File Share (SMB / NFS)': 'file', 'Session Store': 'cache', 'HSM / Key Management': 'chip', 'Certificate Store': 'cert',
  'Directory (LDAP / AD)': 'directory', 'Audit Trail': 'log', 'Source Code Repository': 'branch', 'Container Registry': 'registry',
  'Package / Artifact Registry': 'registry', 'ML Model / Training Data': 'brain', 'Email Mailbox': 'mail', 'Ledger / Blockchain': 'chain',
  'Browser Storage': 'browser', 'Mobile Device Storage': 'phone', 'Configuration / Registry': 'file', 'Cloud Instance Metadata': 'cloud', Backup: 'file',
  // Trust zones
  'Cloud Account / Subscription': 'cloud', 'Tenant Boundary': 'directory', 'Management Network': 'terminal', 'PCI Zone (CDE)': 'card',
  'Partner Network': 'server', 'Remote Access / VPN': 'vpn', 'Wireless Network': 'wifi', 'OT / ICS Network': 'factory',
  'Physical Boundary': 'lock', 'Endpoint / Device': 'vm', 'Internet Boundary': 'globe', DMZ: 'firewall',
};

// Data-store subtypes drawn with a dedicated outline instead of the DFD "two lines".
export const SUBTYPE_SHAPE = {
  Database: 'cylinder', 'SQL Database': 'cylinder', 'NoSQL Database': 'cylinder', 'Vector Database': 'cylinder',
  'Kafka Topic / Event Log': 'log', 'Data Warehouse / Lake': 'cylinder', 'Time-Series Database': 'cylinder',
};

// Entries of the stencil library (toolbar "Library" button): type + subtype presets.
export const LIBRARY = [
  { group: 'Data', items: [['store', 'Database'], ['store', 'SQL Database'], ['store', 'NoSQL Database'], ['store', 'Data Warehouse / Lake'], ['store', 'Kafka Topic / Event Log'], ['store', 'Cache'], ['store', 'Session Store'], ['store', 'Search Index'], ['store', 'Blob / Object Storage'], ['store', 'File Share (SMB / NFS)'], ['store', 'Vector Database'], ['store', 'Log Store'], ['store', 'Audit Trail'], ['store', 'Backup']] },
  { group: 'Network & edge', items: [['process', 'Load Balancer'], ['process', 'Reverse Proxy'], ['process', 'CDN / Edge'], ['process', 'Web Application Firewall'], ['process', 'Network Firewall'], ['process', 'API Gateway'], ['process', 'VPN Gateway'], ['process', 'Bastion / Jump Host'], ['process', 'DNS Server'], ['process', 'Mail Server'], ['process', 'File Transfer Server']] },
  { group: 'Identity & secrets', items: [['process', 'Identity Provider'], ['process', 'Authentication Service'], ['process', 'Authorization / Policy Engine'], ['process', 'Active Directory Domain Controller'], ['store', 'Directory (LDAP / AD)'], ['process', 'Certificate Authority / PKI'], ['process', 'Secrets Manager'], ['store', 'Key Vault / Secret Store'], ['store', 'HSM / Key Management'], ['external', 'OAuth / Social Login Provider']] },
  { group: 'Platform', items: [['process', 'Kubernetes Pod'], ['process', 'Container / Pod'], ['process', 'Kubernetes Control Plane'], ['process', 'Service Mesh / Sidecar'], ['process', 'Orchestrator (Workflow / Agents)'], ['process', 'Kafka Broker'], ['process', 'Serverless Function'], ['process', 'Scheduled Job / Cron'], ['process', 'Virtual Machine'], ['process', 'Mainframe / Legacy System'], ['store', 'Cloud Instance Metadata'], ['boundary', 'Kubernetes Cluster']] },
  { group: 'Apps & APIs', items: [['process', 'Web Application'], ['process', 'Web API / Service'], ['process', 'GraphQL API'], ['process', 'Microservice'], ['process', 'Browser Client (SPA)'], ['process', 'Mobile App'], ['process', 'Desktop / Thick Client'], ['process', 'Browser Extension'], ['process', 'Payment Service'], ['process', 'Admin Console / Management Plane']] },
  { group: 'Realtime', items: [['process', 'WebSocket Server / Gateway'], ['process', 'Message Broker'], ['store', 'Message Queue']] },
  { group: 'AI & MCP', items: [['process', 'MCP Server'], ['external', 'MCP Client / AI Assistant'], ['process', 'AI Agent / LLM App'], ['process', 'ML Model Serving'], ['store', 'ML Model / Training Data'], ['external', 'LLM Provider API']] },
  { group: 'DevOps & supply chain', items: [['process', 'CI/CD Pipeline'], ['process', 'Build Agent / Runner'], ['store', 'Source Code Repository'], ['store', 'Container Registry'], ['store', 'Package / Artifact Registry'], ['external', 'Open-Source Dependency'], ['external', 'Compromised Supply Chain']] },
  { group: 'Security operations', items: [['process', 'SIEM / Log Collector'], ['process', 'EDR / Security Agent'], ['process', 'Vulnerability Scanner']] },
  { group: 'Contact center', items: [['process', 'IVR System'], ['process', 'Genesys Contact Center'], ['external', 'Genesys Cloud (SaaS)'], ['external', 'Phone Caller (PSTN)'], ['store', 'Call Recording Store']] },
  { group: 'OT / IoT & endpoints', items: [['process', 'PLC / Controller'], ['process', 'SCADA / HMI'], ['process', 'IoT Gateway'], ['external', 'IoT Device'], ['process', 'Kernel Driver / Service'], ['store', 'Mobile Device Storage'], ['store', 'Browser Storage']] },
  { group: 'People & threat actors', items: [['external', 'Anonymous User'], ['external', 'Authenticated User'], ['external', 'Administrator'], ['external', 'Privileged Insider'], ['external', 'External Attacker (Internet)'], ['external', 'Malicious Insider'], ['external', 'Third-Party Service'], ['external', 'SaaS Application'], ['external', 'Payment Gateway'], ['external', 'Partner System']] },
  { group: 'Trust zones', items: [['boundary', 'Internet Boundary'], ['boundary', 'DMZ'], ['boundary', 'Corporate Network'], ['boundary', 'Management Network'], ['boundary', 'Cloud VPC / VNet'], ['boundary', 'Cloud Account / Subscription'], ['boundary', 'Tenant Boundary'], ['boundary', 'PCI Zone (CDE)'], ['boundary', 'OT / ICS Network'], ['boundary', 'Wireless Network'], ['boundary', 'Remote Access / VPN'], ['boundary', 'Physical Boundary']] },
];

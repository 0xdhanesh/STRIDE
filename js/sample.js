// A small but realistic example model shown from the welcome screen / menu.

import { defaultProps } from './stencils.js';

const node = (id, type, name, subtype, x, y, w, h, props = {}, extra = {}) =>
  ({ id, type, name, subtype, x, y, w, h, props: { ...defaultProps(type), ...props }, style: {}, outOfScope: false, outOfScopeReason: '', notes: '', ...extra });

const flow = (id, name, subtype, sourceId, targetId, props = {}, bend = 0) =>
  ({ id, type: 'flow', name, subtype, sourceId, targetId, x1: 0, y1: 0, x2: 0, y2: 0, bend, props: { ...defaultProps('flow'), ...props }, style: {}, outOfScope: false, outOfScopeReason: '', notes: '' });

export function sampleModel() {
  const now = new Date().toISOString();
  return {
    app: 'stride-threat-modeler', version: 1,
    meta: {
      title: 'Online Shop – Checkout', owner: 'Security Champion', reviewer: 'AppSec Team', contributors: 'Dev team',
      description: 'Customers browse products and place orders through a web front-end. Orders are processed by an API that stores them in a SQL database and charges customers through an external payment provider.',
      assumptions: 'The cloud provider\'s infrastructure is trusted.\nTLS terminates at the web front-end.',
      dependencies: 'Payment provider REST API\nManaged SQL database service',
      created: now, modified: now,
    },
    diagrams: [{
      id: 'd_sample', name: 'Checkout flow',
      elements: [
        node('b_cloud', 'boundary', 'Cloud VNet', 'Cloud VPC / VNet', 300, 120, 780, 470),
        node('e_customer', 'external', 'Customer', 'Human User', 40, 235, 160, 80, { authenticatesItself: 'Yes', trustLevel: 'Untrusted' }),
        node('p_web', 'process', 'Web Frontend', 'Web Application', 360, 210, 130, 130, { validatesInput: 'Yes', logsSecurityEvents: 'Yes', internetFacing: 'Yes', codeType: 'Managed' }, { style: { fill: '#a5d8ff' } }),
        node('p_api', 'process', 'Orders API', 'Web API / Service', 620, 210, 130, 130, { codeType: 'Managed', handlesSecrets: 'Yes' }, { style: { fill: '#b2f2bb' } }),
        node('s_db', 'store', 'Orders DB', 'SQL Database', 880, 225, 140, 100, { storesPII: 'Yes', encryptedAtRest: 'Yes', backedUp: 'Yes' }),
        node('s_logs', 'store', 'Audit Logs', 'Log Store', 605, 460, 160, 70, { storesLogs: 'Yes' }),
        node('e_psp', 'external', 'Payment Provider', 'Third-Party Service', 600, -60, 170, 80, { trustLevel: 'Partially trusted' }),
        flow('f_1', 'Checkout request', 'HTTPS', 'e_customer', 'p_web', { encrypted: 'Yes', authentication: 'Password', carriesCredentials: 'Yes' }, 30),
        flow('f_2', 'Order page', 'HTTPS', 'p_web', 'e_customer', { encrypted: 'Yes' }, 30),
        flow('f_3', 'Create order', 'HTTPS', 'p_web', 'p_api', { encrypted: 'Yes', authentication: 'Token (OAuth / JWT)' }),
        flow('f_4', 'SQL query', 'SQL / DB Protocol', 'p_api', 's_db', {}, 22),
        flow('f_5', 'Order rows', 'SQL / DB Protocol', 's_db', 'p_api', {}, 22),
        flow('f_6', 'Audit events', 'Generic Data Flow', 'p_api', 's_logs'),
        flow('f_7', 'Charge card', 'HTTPS', 'p_api', 'e_psp', { encrypted: 'Yes', authentication: 'API key', carriesSensitiveData: 'Yes' }),
        { id: 'n_1', type: 'note', name: 'Sample model – double-click anything to rename,\nswitch to Analysis (top right) to see STRIDE threats.', x: 40, y: -40, w: 470, h: 47, props: {}, style: { stroke: '#868e96' }, notes: '' },
      ],
    }],
    threats: {}, nextThreatId: 1, template: null,
  };
}

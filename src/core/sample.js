// A small example model: an online shop with a browser, web app, API, database and payment provider.

import { DEFAULT_TEMPLATE } from '../templates/default.js';
import { addElement, createModel } from './model.js';
import { generateThreats } from './engine.js';

export function createSampleModel(template = DEFAULT_TEMPLATE) {
  const m = createModel({ template, name: 'Example: online shop' });
  m.meta.owner = 'Product security';
  m.meta.description = 'Customers browse and order through a web storefront. Orders are stored in SQL and paid through an external payment provider.';
  m.meta.assumptions = 'The cloud provider secures the infrastructure. TLS terminates at the storefront.';
  const d = m.diagrams[0].id;
  m.diagrams[0].name = 'Storefront';
  const add = (spec) => addElement(m, d, spec);
  const customer = add({ type: 'SE.EI.TMCore.User', name: 'Customer', x: 40, y: 200 });
  const web = add({ type: 'SE.P.TMCore.WebApp', name: 'Storefront', x: 360, y: 190, w: 150, h: 100, props: { hasInputSanitizers: 'Yes' } });
  const api = add({ type: 'SE.P.TMCore.WebSvc', name: 'Orders API', x: 640, y: 190, w: 150, h: 100, props: { implementsAuthenticationScheme: 'Yes' } });
  const db = add({ type: 'SE.DS.TMCore.SQL', name: 'Orders DB', x: 650, y: 420 });
  const logs = add({ type: 'GE.DS', name: 'Audit log', x: 380, y: 420, props: { storesLogData: 'Yes' } });
  const pay = add({ type: 'SE.EI.TMCore.WebSvc', name: 'Payment provider', x: 960, y: 205 });
  add({ type: 'SE.DF.TMCore.HTTPS', name: 'Browse & order', source: customer.id, target: web.id, props: { Cookies: 'Yes' } });
  add({ type: 'SE.DF.TMCore.HTTPS', name: 'Pages', source: web.id, target: customer.id });
  add({ type: 'GE.DF', name: 'Order JSON', source: web.id, target: api.id, props: { JSON: 'Yes' } });
  add({ type: 'GE.DF', name: 'SQL queries', source: api.id, target: db.id });
  add({ type: 'GE.DF', name: 'Order rows', source: db.id, target: api.id });
  add({ type: 'GE.DF', name: 'Audit events', source: api.id, target: logs.id });
  add({ type: 'SE.DF.TMCore.HTTPS', name: 'Charge card', source: api.id, target: pay.id });
  add({ type: 'SE.TB.L.TMCore.Internet', name: 'Internet boundary', x0: 260, y0: 110, x1: 250, y1: 380, bend: -12 });
  add({ type: 'SE.TB.B.TMCore.CorpNet', name: 'Backend network', x: 330, y: 150, w: 520, h: 400 });
  add({ type: 'GE.A', name: 'Payment data never touches our servers', x: 880, y: 330, w: 220, h: 54 });
  generateThreats(m);
  return m;
}

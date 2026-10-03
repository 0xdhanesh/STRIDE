// Native browser DOM checks, no framework or dependencies. Visit
// /tests/security.html using the app's existing static server.
import { store, normalizeModel } from '../js/store.js';
import { sampleModel } from '../js/sample.js';
import { syncThreats, threatList } from '../js/engine.js';
import { validateRules } from '../js/rules.js';
import { initThreatPanel } from '../js/panels.js';
import { buildReport } from '../js/io.js';

const check = (condition, message) => { if (!condition) throw new Error(message); };
const result = document.querySelector('#result');
try {
  const payload = '<img src=x onerror=alert(1)>', model = normalizeModel(sampleModel());
  model.diagrams[0].elements.find((e) => e.type === 'external').name = payload;
  model.template = validateRules([{ id: 'BROWSER', category: 'T', dedupeKey: 'target',
    title: '{source.name}', description: '</textarea>{source.name}<script>alert(1)</script>',
    mitigation: '<svg onload=alert(1)>{source.name}', when: [['source.type', 'eq', 'external']],
  }]);
  syncThreats(model); store.model = model;
  const threat = threatList(model).find((t) => t.title === payload);
  store.ui.diagramId = model.diagrams[0].id; store.ui.analysis = true; store.ui.activeThreat = threat.key;
  let alerts = 0; window.alert = () => { alerts++; };
  initThreatPanel({}).render();
  const panel = document.querySelector('#threats');
  check(!panel.querySelector('img, script, [onerror], [onload], [onfocus]'), 'Active attacker markup in threat panel');
  check(panel.querySelector('.t-title').textContent === payload, 'Title must be literal text');
  check(panel.querySelector('[data-tf="description"]').value === threat.description, 'Description changed');
  check(panel.querySelector('.hint').textContent.includes(threat.mitigationHint), 'Mitigation changed');
  check(panel.querySelector('textarea[disabled]').value.includes(payload), 'Contributing flow label changed');
  const report = new DOMParser().parseFromString(buildReport(model), 'text/html');
  check(!report.querySelector('img, script, [onerror], [onload], [onfocus]'), 'Active attacker markup in report');
  check(report.body.textContent.includes(payload), 'Report must preserve the literal name');
  check(alerts === 0, 'An injected event handler executed');
  result.textContent = 'PASS: malicious names and template text stay literal in the panel and report DOMs.';
} catch (error) {
  result.textContent = `FAIL: ${error.message}`;
  throw error;
}

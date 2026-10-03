import { importTM7, readModelFile, serializeModel } from '../js/io.js';

const check = (ok, message) => { if (!ok) throw new Error(message); };
const sample = '<ThreatModel xmlns="urn:tm7-test" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><DrawingSurfaceList><DrawingSurfaceModel><Guid>d</Guid><Borders><entry><Key>p</Key><Value><Guid>p</Guid><GenericTypeId>GE.P</GenericTypeId><TypeId>SE.P.TMCore.WebApp</TypeId><Properties><p><DisplayName>Name</DisplayName><Value>&lt;img src=x onerror=alert(1)&gt;</Value></p><p><DisplayName>Validates Input</DisplayName><SelectedIndex>1</SelectedIndex><Value><string>No</string><string>Yes</string></Value></p></Properties><Width>100</Width><Height>100</Height></Value></entry><entry><Key>unknown</Key><Value><GenericTypeId>Vendor.Shape</GenericTypeId></Value></entry></Borders></DrawingSurfaceModel></DrawingSurfaceList></ThreatModel>';
try {
  const m = importTM7(sample), [p, unknown] = m.diagrams[0].elements;
  check(p.subtype === 'Web Application' && p.props.validatesInput === 'Yes', 'Native property/stencil mapping failed');
  check(p.name === '<img src=x onerror=alert(1)>', 'Original text was lost');
  check(unknown.type === 'note' && m.importWarnings.some((w) => w.code === 'unmapped-stencil'), 'Unknown shape must be preserved and flagged');
  const copy = await readModelFile({ name: 'native.stride', text: async () => serializeModel(m) });
  check(JSON.stringify(copy) === JSON.stringify(m), 'Save/reopen changed imported content');
  check(copy.tm7.sourceXML === sample, 'Original source missing');
  for (const bad of ['<ThreatModel>', '<!DOCTYPE ThreatModel SYSTEM "https://example.test/evil"><ThreatModel/>']) {
    let rejected = false; try { importTM7(bad); } catch { rejected = true; }
    check(rejected, 'Invalid/unsafe XML was accepted');
  }
  document.querySelector('#result').textContent = 'PASS: native XML mapping, warnings, source preservation, save/reopen, and invalid XML checks.';
} catch (error) {
  document.querySelector('#result').textContent = `FAIL: ${error.message}`;
  throw error;
}
document.querySelector('#file').addEventListener('change', async (event) => {
  const file = event.target.files[0]; if (!file) return;
  try {
    const model = await readModelFile(file);
    document.querySelector('#summary').textContent = JSON.stringify({ note: model.importNote, diagrams: model.diagrams, threats: model.threats, warnings: model.importWarnings }, null, 2);
  } catch (error) { document.querySelector('#summary').textContent = error.message; }
});

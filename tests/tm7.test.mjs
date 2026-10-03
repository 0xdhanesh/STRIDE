import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { TestDOMParser } from './xml-dom.mjs';
import { importTM7, readModelFile, serializeModel, buildReport } from '../js/io.js';
import { mapTM7Stencil } from '../js/tm7.js';
import { STENCILS } from '../js/stencils.js';
import { syncThreats, validate } from '../js/engine.js';
import { createReport, buildMarkdown } from '../js/reports.js';
import { buildPDF } from '../js/pdf-report.js';
import { Store, store } from '../js/store.js';
import { initPropsPanel } from '../js/panels.js';

globalThis.DOMParser = TestDOMParser;
const fixture = await readFile(new URL('./fixture.tm7', import.meta.url), 'utf8');
const xml = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const prop = (name, value) => `<p><DisplayName>${xml(name)}</DisplayName><Value>${xml(value)}</Value></p>`;
const option = (name, selected, values) => `<p><DisplayName>${xml(name)}</DisplayName><SelectedIndex>${selected}</SelectedIndex><Value>${values.map((v) => `<string>${xml(v)}</string>`).join('')}</Value></p>`;
const entry = (id, generic, type, props = '', extra = '') => `<entry><Key>${id}</Key><Value><Guid>${id}</Guid><GenericTypeId>${generic}</GenericTypeId><TypeId>${type}</TypeId><Properties>${prop('Name', id)}${props}</Properties>${extra}</Value></entry>`;
const bounds = '<Left>400</Left><Top>50</Top><Width>150</Width><Height>100</Height>';
const flow = (id, source, target, props = '', extra = '') => entry(id, 'GE.DF', 'SE.DF.TMCore.HTTPS', props, `<SourceGuid>${source}</SourceGuid><TargetGuid>${target}</TargetGuid><SourceX>10</SourceX><SourceY>20</SourceY><TargetX>500</TargetX><TargetY>20</TargetY>${extra}`);
const diagram = (id, borders, lines = '') => `<DrawingSurfaceModel><Guid>${id}</Guid><Header>${id}</Header><Borders>${borders}</Borders><Lines>${lines}</Lines></DrawingSurfaceModel>`;
const document = (diagrams, threats = '', extra = '') => `<ThreatModel xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns:z="http://schemas.microsoft.com/2003/10/Serialization/"><DrawingSurfaceList>${diagrams}</DrawingSurfaceList><ThreatInstances>${threats}</ThreatInstances>${extra}</ThreatModel>`;
const threat = (id, properties = '', extra = '') => `<entry><Key>${id}</Key><Value><DrawingSurfaceGuid>d</DrawingSurfaceGuid><FlowGuid>f</FlowGuid><TargetGuid>target</TargetGuid><State>Mitigated</State><Priority>High</Priority><Properties>${prop('Title', id)}${prop('UserThreatCategory', 'Tampering')}${properties}</Properties>${extra}</Value></entry>`;
const pair = (targetProps = '', flowProps = '') => diagram('d', entry('source', 'GE.EI', 'SE.EI.User') + entry('target', 'GE.P', 'SE.P.WebApp', targetProps, bounds), flow('f', 'source', 'target', flowProps));

test('existing namespaced TM7 fixture imports geometry, HTTPS and reviewed threat intact', async () => {
  const m = await readModelFile({ name: 'portal.tm7', text: async () => fixture });
  assert.equal(m.meta.title, 'Portal TM'); assert.equal(m.meta.owner, 'Alice');
  assert.equal(m.diagrams.length, 1); assert.equal(m.diagrams[0].elements.length, 4);
  const [user, app, boundary, line] = m.diagrams[0].elements;
  assert.equal(user.subtype, 'Human User'); assert.equal(app.subtype, 'Web Application');
  assert.deepEqual([app.x, app.y, app.w, app.h], [400, 100, 100, 100]);
  assert.equal(boundary.type, 'boundary');
  assert.equal(line.sourceId, user.id); assert.equal(line.targetId, app.id);
  assert.equal(line.subtype, 'HTTPS'); assert.equal(line.props.encrypted, 'Yes'); assert.equal(line.bend, -15);
  assert.equal(m.importWarnings.length, 0);
  const t = Object.values(m.threats)[0];
  assert.equal(t.status, 'mitigated'); assert.equal(t.justification, 'We use Azure AD with MFA.');
  assert.equal(t.description, 'Browser User may be spoofed.'); assert.equal(t.auto, false);
  assert.equal(m.tm7.sourceXML, fixture);
  const before = structuredClone(t); syncThreats(m); assert.deepEqual(m.threats[t.key], before);
});

test('local TM7 opening decodes UTF-8 and Windows UTF-16 in either byte order', async () => {
  const unicode = fixture.replace('Portal TM', 'Portal Ω');
  const little = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(unicode, 'utf16le')]);
  const big = Buffer.from(little); big.swap16();
  for (const bytes of [Buffer.from(unicode, 'utf8'), little, big, little.subarray(2), big.subarray(2)]) {
    const m = await readModelFile({ name: 'portal.tm7', arrayBuffer: async () => bytes });
    assert.equal(m.meta.title, 'Portal Ω'); assert.equal(m.tm7.sourceXML, unicode);
  }
  await assert.rejects(readModelFile({ name: 'bad.tm7', arrayBuffer: async () => Uint8Array.of(0xff, 0) }), /Could not decode/);
});

test('all catalogue stencil names and selected TMT aliases map without fuzzy guessing', () => {
  const generics = { process: 'GE.P', external: 'GE.EI', store: 'GE.DS', flow: 'GE.DF', boundary: 'GE.TB.B', boundaryLine: 'GE.TB.L' };
  for (const [type, generic] of Object.entries(generics)) for (const subtype of STENCILS[type].subtypes) {
    const mapped = mapTM7Stencil(generic, '', subtype, '', 'Borders');
    assert.equal(mapped.type, type); assert.equal(mapped.subtype, subtype); assert.equal(mapped.mapping, 'exact');
  }
  assert.equal(mapTM7Stencil('GE.P', 'SE.P.TMCore.WebApp', '', '', 'Borders').subtype, 'Web Application');
  assert.equal(mapTM7Stencil('GE.DS', '', 'SQL Server', '', 'Borders').subtype, 'SQL Database');
  const unknown = mapTM7Stencil('GE.P', '', 'Web Magical Appliance', '', 'Borders');
  assert.equal(unknown.subtype, 'Generic Process'); assert.equal(unknown.mapping, 'unmapped');
});

test('maps security properties and enum selections; explicit values override stencil defaults', () => {
  const m = importTM7(document(pair(prop('Validates Input', 'true') + option('Running As', 1, ['Not Selected', 'System']), prop('Encrypted', 'No') + option('Authentication', 1, ['None', 'Cookie / Session']))));
  const [, target, line] = m.diagrams[0].elements;
  assert.equal(target.props.validatesInput, 'Yes'); assert.equal(target.props.runningAs, 'System / root');
  assert.equal(line.props.encrypted, 'No'); assert.equal(line.props.authentication, 'Cookie / Session');
  assert.equal(m.importWarnings.length, 0);
});

test('unknown types, properties and invalid option values are retained and flagged', () => {
  const props = prop('Encrypted', 'Quantum') + option('Authentication', -1, ['Yes', 'No']) + prop('__proto__', 'keep me') + prop('Custom Security Knob', 'enabled');
  const input = document(diagram('d', entry('unknown', 'Custom.Node', 'Vendor.Shape', prop('Custom Field', 'Original'), bounds) + entry('known', 'GE.P', 'Vendor.UnmappedWebThing', '', bounds), flow('f', 'unknown', 'known', props)));
  const m = importTM7(input), [unknown, known, line] = m.diagrams[0].elements;
  assert.equal(unknown.type, 'note'); assert.equal(known.type, 'process'); assert.equal(known.subtype, 'Generic Process');
  assert.equal(line.sourceId, null); assert.equal(line.targetId, 'known');
  assert.equal(line.props.encrypted, 'Not Selected'); assert.equal(line.props.authentication, 'Not Selected');
  assert.ok(line.tm7.properties.some((p) => p.name === '__proto__' && p.value === 'keep me'));
  for (const code of ['unmapped-stencil', 'unmapped-property', 'unmapped-value', 'unmapped-endpoint']) assert.ok(m.importWarnings.some((w) => w.code === code), code);
  assert.equal(m.tm7.sourceXML, input);
  assert.ok(validate(m).some((w) => w.code === 'unmapped-stencil' && w.elementId === 'unknown'));
});

test('missing and duplicate IDs keep every element without guessing ambiguous endpoints', () => {
  const m = importTM7(document(diagram('d', entry('same', 'GE.P', '') + entry('same', 'GE.P', '') + entry('', 'GE.EI', ''), flow('f', 'same', 'missing'))));
  const elements = m.diagrams[0].elements;
  assert.equal(elements.length, 4); assert.equal(new Set(elements.map((e) => e.id)).size, 4);
  const line = elements.at(-1); assert.equal(line.sourceId, null); assert.equal(line.targetId, null);
  assert.deepEqual([line.x1, line.y1, line.x2, line.y2], [10, 20, 500, 20]);
  assert.equal(line.bend, 0, 'missing handle must not bend toward origin');
  assert.equal(m.importWarnings.filter((w) => w.code === 'unmapped-endpoint').length, 2);
});

test('duplicate IDs across diagrams are remapped with references kept within each diagram', () => {
  const input = document(pair() + pair().replace('<Guid>d</Guid>', '<Guid>second</Guid>'));
  const m = importTM7(input), all = m.diagrams.flatMap((d) => [d.id, ...d.elements.map((e) => e.id)]);
  assert.equal(new Set(all).size, all.length);
  for (const d of m.diagrams) {
    const [source, target, line] = d.elements;
    assert.equal(line.sourceId, source.id); assert.equal(line.targetId, target.id);
  }
});

test('ambiguous security properties remain unset, notes/scope survive, and bad geometry is flagged', () => {
  const props = prop('Validates Input', 'Yes') + prop('Input Validation', 'No') + prop('Notes', 'Line one\nLine two') + prop('Out Of Scope', 'true') + prop('Reason For Out Of Scope', 'Vendor-managed');
  const m = importTM7(document(pair(props).replace('<Width>150</Width>', '<Width>Infinity</Width>')));
  const target = m.diagrams[0].elements[1];
  assert.equal(target.props.validatesInput, 'Not Selected'); assert.equal(target.w, 130);
  assert.equal(target.notes, 'Line one\nLine two'); assert.equal(target.outOfScope, true);
  assert.equal(target.outOfScopeReason, 'Vendor-managed');
  assert.ok(m.importWarnings.some((w) => w.code === 'invalid-geometry'));
  assert.ok(m.importWarnings.some((w) => w.code === 'unmapped-value'));
});

test('standalone notes and curved boundary lines survive import', () => {
  const border = entry('annotation', 'GE.A', 'Annotation', prop('Annotation', 'Keep this note'), bounds);
  const line = entry('trust', 'GE.TB.L', 'SE.TB.L.TrustLine', '', '<SourceX>0</SourceX><SourceY>0</SourceY><TargetX>100</TargetX><TargetY>0</TargetY><HandleX>50</HandleX><HandleY>40</HandleY>');
  const m = importTM7(document(diagram('d', border, line)));
  const [note, boundary] = m.diagrams[0].elements;
  assert.equal(note.type, 'note'); assert.ok(note.tm7.properties.some((p) => p.value === 'Keep this note'));
  assert.equal(boundary.type, 'boundaryLine'); assert.equal(boundary.bend, 20);
  assert.ok(STENCILS.boundaryLine.subtypes.includes(boundary.subtype));
});

test('GUID casing and dictionary keys resolve; nil GUIDs keep unconnected coordinates', () => {
  const input = fixture.replace('<SourceGuid>11111111-0000-0000-0000-000000000001</SourceGuid>', '<SourceGuid>{11111111-0000-0000-0000-000000000001}</SourceGuid>');
  const m = importTM7(input), d = m.diagrams[0]; assert.equal(d.elements[3].sourceId, d.elements[0].id);
  const byKey = importTM7(document(pair().replace('<Guid>source</Guid>', '')));
  assert.equal(byKey.diagrams[0].elements[2].sourceId, 'source');
  const nil = importTM7(document(pair().replace('<SourceGuid>source</SourceGuid>', '<SourceGuid>00000000-0000-0000-0000-000000000000</SourceGuid>')));
  assert.equal(nil.diagrams[0].elements[2].sourceId, null);
});

test('imported threats preserve review fields; unmapped categories/states/references remain visible', () => {
  const props = prop('Mitigation', 'mTLS applied') + prop('Owner', 'Payments') + prop('Notes', 'Evidence 42') + prop('StateInformation', 'Reviewed');
  const input = document(pair(), threat('one', props) + threat('two', prop('State', 'NotApplicable')) + threat('odd', prop('State', 'VendorState') + prop('ExtraReview', 'retain')).replace('<FlowGuid>f</FlowGuid>', '<FlowGuid>missing</FlowGuid>').replace('<Value>Tampering</Value>', '<Value>VendorCategory</Value>'));
  const m = importTM7(input), [one, two, odd] = Object.values(m.threats);
  assert.equal(one.owner, 'Payments'); assert.equal(one.mitigation, 'mTLS applied'); assert.equal(one.notes, 'Evidence 42');
  assert.equal(one.status, 'mitigated'); assert.equal(two.status, 'not-applicable');
  assert.equal(odd.status, 'open'); assert.equal(odd.orphan, true); assert.equal(odd.tm7.originalState, 'VendorState');
  assert.equal(odd.category, 'S'); assert.equal(odd.tm7.originalCategory, 'VendorCategory');
  assert.ok(m.importWarnings.some((w) => w.code === 'unmapped-category'));
  assert.ok(m.importWarnings.some((w) => w.threatIds?.includes(odd.id)));
});

test('DTD, external entities, malformed XML and wrong roots fail before replacing current work', () => {
  const store = new Store({ autosave: { save() {} } }); const before = structuredClone(store.model);
  for (const input of ['<!DOCTYPE ThreatModel SYSTEM "https://example.test/evil"><ThreatModel/>', '<!DOCTYPE ThreatModel [<!ENTITY x SYSTEM "file:///private">]><ThreatModel>&x;</ThreatModel>', '<ThreatModel>', '<svg/>', '<ThreatModel/>']) {
    assert.throws(() => store.replaceModel(importTM7(input)));
    assert.deepEqual(store.model, before);
  }
});

test('XML serialization references resolve locally; unresolved or cyclic references fail', () => {
  const original = fixture.replace('<b:DisplayName>Name</b:DisplayName><b:Name/><b:Value xmlns:c="http://www.w3.org/2001/XMLSchema" i:type="c:string">Browser User</b:Value>', '<b:DisplayName>Name</b:DisplayName><b:Name/><b:Value z:Id="name-value">Browser User</b:Value>');
  const shared = original.replace('<b:Value xmlns:c="http://www.w3.org/2001/XMLSchema" i:type="c:string">Portal</b:Value>', '<b:Value z:Ref="name-value"/>');
  assert.equal(importTM7(shared).diagrams[0].elements[1].name, 'Browser User');
  assert.throws(() => importTM7(shared.replace('z:Ref="name-value"', 'z:Ref="missing"')), /unresolved or cyclic/);
  assert.throws(() => importTM7(original.replace('z:Id="name-value"', 'z:Id="name-value" z:Ref="name-value"')), /cyclic/);
});

test('import, save, reopen and exports retain original source, warnings and threat reviews offline', async () => {
  const input = document(pair(prop('Custom review field', '<img src=x onerror=alert(1)>')), threat('review', prop('Notes', 'Evidence 42')));
  let calls = 0; const denied = () => { calls++; throw new Error('Network forbidden'); };
  const previous = [globalThis.fetch, globalThis.XMLHttpRequest, globalThis.WebSocket, globalThis.EventSource];
  [globalThis.fetch, globalThis.XMLHttpRequest, globalThis.WebSocket, globalThis.EventSource] = [denied, denied, denied, denied];
  try {
    const m = importTM7(input);
    const reopened = await readModelFile({ name: 'model.stride', text: async () => serializeModel(m) });
    assert.deepEqual(reopened, m);
    const bundle = createReport(reopened), html = buildReport(reopened), md = buildMarkdown(bundle);
    assert.equal(bundle.model.tm7.sourceXML, input);
    assert.ok(bundle.report.validation.some((w) => w.code === 'unmapped-property'));
    assert.doesNotMatch(html, /<img\b|<script\b/); assert.doesNotMatch(md, /<img\b|<script\b/);
    assert.ok(md.includes('Custom review field')); assert.ok(html.includes('Custom review field'));
    const bytes = await buildPDF(bundle); assert.equal(new TextDecoder().decode(bytes.slice(0, 5)), '%PDF-');
    assert.equal(calls, 0);
  } finally { [globalThis.fetch, globalThis.XMLHttpRequest, globalThis.WebSocket, globalThis.EventSource] = previous; }
});

test('unmapped content is visible and escaped in the properties panel', () => {
  const m = importTM7(document(pair(prop('<img src=x onerror=alert(1)>', '<script>bad()</script>'))));
  const previous = { document: globalThis.document, innerWidth: globalThis.innerWidth, model: store.model, ui: store.ui, listeners: new Set(store.listeners) };
  const root = { innerHTML: '', addEventListener() {}, querySelectorAll: () => [] };
  globalThis.document = { querySelector: () => root }; globalThis.innerWidth = 1200;
  try {
    store.model = m; store.ui = { ...store.ui, diagramId: m.diagrams[0].id, selection: new Set(['target']), analysis: false };
    initPropsPanel({}).render();
    assert.ok(root.innerHTML.includes('review needed'));
    assert.ok(root.innerHTML.includes('&lt;img src=x onerror=alert(1)&gt;'));
    assert.ok(root.innerHTML.includes('&lt;script&gt;bad()&lt;/script&gt;'));
    assert.doesNotMatch(root.innerHTML, /<img\b|<script\b/);
  } finally {
    globalThis.document = previous.document; globalThis.innerWidth = previous.innerWidth;
    store.model = previous.model; store.ui = previous.ui; store.listeners = previous.listeners;
  }
});

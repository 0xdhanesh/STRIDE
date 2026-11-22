import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KnowledgeBase, Tb7Error, parseTb7, parseTemplateText, parseXml, validateRule } from '../src/core/index.js';

const generic = (id, name, rep, attrs = '') => `
    <ElementType><Name>${name}</Name><ID>${id}</ID><Description /><ParentElement /><Hidden>false</Hidden><Representation>${rep}</Representation>
      <Attributes>${attrs}</Attributes></ElementType>`;

const FIXTURE = `<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE KnowledgeBase [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<KnowledgeBase xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <Manifest name="Mini &amp; Test" id="mini-1" version="1.2.3" author="tests" />
  <ThreatMetaData><PropertiesMetaData>
    <ThreatMetaDatum><Name>Priority</Name><Label>Priority</Label><HideFromUI>false</HideFromUI><Values><Value>High</Value><Value>Medium</Value><Value>Low</Value></Values></ThreatMetaDatum>
    <ThreatMetaDatum><Name>Owner</Name><Label>Team owner</Label><HideFromUI>false</HideFromUI><Values><Value /></Values></ThreatMetaDatum>
  </PropertiesMetaData></ThreatMetaData>
  <GenericElements>
    ${generic('GE.P', 'Generic Process', 'Ellipse', `<Attribute><Name>codeType</Name><DisplayName>Code Type</DisplayName><Mode>Dynamic</Mode><Type>List</Type><Inheritance>Virtual</Inheritance><AttributeValues><Value>Not Selected</Value><Value>Managed</Value></AttributeValues></Attribute>`)}
    ${generic('GE.EI', 'Generic External Interactor', 'Rectangle')}
    ${generic('GE.DS', 'Generic Data Store', 'ParallelLines')}
    ${generic('GE.DF', 'Generic Data Flow', 'Line')}
    ${generic('GE.TB.L', 'Generic Trust Line Boundary', 'LineBoundary')}
    ${generic('GE.TB.B', 'Generic Trust Border Boundary', 'BorderBoundary')}
    ${generic('GE.A', 'Free Text Annotation', 'Annotation')}
  </GenericElements>
  <StandardElements>
    <ElementType><Name>Web &lt;App&gt;</Name><ID>SE.P.X.Web</ID><ParentElement>GE.P</ParentElement><Hidden>false</Hidden><Representation>Inherited</Representation>
      <Attributes><Attribute><Name>codeType</Name><DisplayName>Code Type</DisplayName><Mode>Static</Mode><Inheritance>Virtual</Inheritance><AttributeValues><Value>Managed</Value></AttributeValues></Attribute></Attributes>
    </ElementType>
  </StandardElements>
  <ThreatCategories><ThreatCategory><Name>Spoofing</Name><Id>S</Id><ShortDescription>Spoof</ShortDescription><LongDescription /></ThreatCategory></ThreatCategories>
  <ThreatTypes>
    <ThreatType><GenerationFilters><Include>source is 'ROOT'</Include><Exclude /></GenerationFilters><Id>SU</Id><ShortTitle>Spoofing (v3)</ShortTitle><Category>S</Category><Description>legacy</Description></ThreatType>
    <ThreatType><GenerationFilters><Include>target is 'GE.P' and target.codeType is 'Managed'</Include><Exclude><![CDATA[source is 'GE.EI' & source is 'GE.EI']]></Exclude></GenerationFilters>
      <Id>X1</Id><ShortTitle>Thing on {target.Name}</ShortTitle><Category>S</Category><Description>base</Description>
      <PropertiesMetaData>
        <ThreatMetaDatum><Name>UserThreatDescription</Name><Values><Value>Detailed &amp; specific</Value></Values></ThreatMetaDatum>
        <ThreatMetaDatum><Name>Priority</Name><Values><Value xsi:nil="true" /><Value>Low</Value></Values></ThreatMetaDatum>
        <ThreatMetaDatum><Name>Owner</Name><Values><Value>AppSec</Value></Values></ThreatMetaDatum>
      </PropertiesMetaData>
    </ThreatType>
  </ThreatTypes>
</KnowledgeBase>`;

test('parses a .tb7 template', () => {
  const t = parseTb7(FIXTURE);
  assert.equal(t.manifest.name, 'Mini & Test');
  assert.equal(t.manifest.version, '1.2.3');
  const web = t.elements.find((e) => e.id === 'SE.P.X.Web');
  assert.equal(web.name, 'Web <App>');
  assert.equal(web.parent, 'GE.P');
  assert.equal(web.attributes[0].mode, 'static');
  const kb = new KnowledgeBase(t);
  assert.equal(kb.attribute('SE.P.X.Web', 'codeType').values[0], 'Managed');
  const x1 = t.threatTypes.find((x) => x.id === 'X1');
  assert.equal(x1.description, 'Detailed & specific');
  assert.equal(x1.priority, 'Low');
  assert.equal(x1.properties.Owner, 'AppSec');
  assert.equal(x1.exclude, "source is 'GE.EI' & source is 'GE.EI'");
  assert.equal(t.threatTypes.find((x) => x.id === 'SU').legacy, true);
  assert.equal(validateRule(x1.include, kb).ok, true);
  assert.deepEqual(kb.customThreatProperties().map((p) => p.name), ['Owner']);
});

test('DOCTYPE entities are never expanded (XXE safe)', () => {
  const doc = parseXml('<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>');
  assert.equal(doc.text, '&x;');
});

test('rejects non-template XML and malformed XML', () => {
  assert.throws(() => parseTb7('<Other/>'), Tb7Error);
  assert.throws(() => parseTb7('<KnowledgeBase><GenericElements></KnowledgeBase>'), /Not a valid/);
  assert.throws(() => parseTb7('<KnowledgeBase></KnowledgeBase>'), /missing generic elements/);
});

test('parseTemplateText accepts tb7, template JSON and model JSON', () => {
  const t = parseTb7(FIXTURE);
  assert.equal(parseTemplateText(FIXTURE).manifest.id, 'mini-1');
  assert.equal(parseTemplateText(JSON.stringify(t)).manifest.id, 'mini-1');
  assert.equal(parseTemplateText(JSON.stringify({ format: 'stride-model', template: t })).manifest.id, 'mini-1');
});

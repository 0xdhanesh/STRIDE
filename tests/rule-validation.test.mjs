import test from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_RULES, validateRules } from '../js/rules.js';
import { normalizeModel, newModel } from '../js/store.js';

const base = () => ({ id: 'UNTRUSTED', category: 'T', title: 'Custom {target.name}', when: [['target.type', 'eq', 'process']] });
test('built-in and legacy templates validate without adding new default fields', () => {
  assert.equal(validateRules(DEFAULT_RULES), DEFAULT_RULES);
  const template = [base()], before = structuredClone(template);
  assert.equal(validateRules(template), template); assert.deepEqual(template, before);
  const m = newModel(); m.template = template; assert.deepEqual(normalizeModel(m).template, before);
  assert.doesNotThrow(() => validateRules([{ ...base(), when: [
    ['source.name', 'exists', true], { any: [['target.props.x', 'nin', ['Yes']], { not: ['flow.subtype', 'eq', 'HTTP'] }] },
  ] }]));
});

const invalid = [
  ['scope', { scope: 'network' }], ['priority', { priority: 'Critical' }], ['focus', { focus: 'window' }],
  ['dedupeKey', { dedupeKey: 'diagram' }], ['scope', { scope: null }], ['title', { title: {} }],
  ['supersedes', { supersedes: 'T01' }], ['supersedes', { supersedes: [null] }], ['unknown rule', { supersedes: ['MISSING'] }],
  ['unsafe path', { when: ['source.__proto__.x', 'eq', true] }],
  ['unsafe path', { when: ['source.props.constructor.name', 'eq', 'Object'] }],
  ['unsafe path', { when: { any: [{ not: ['target.prototype.x', 'exists', true] }] } }],
  ['path root', { when: ['window.location', 'exists', true] }],
  ['invalid condition path', { when: ['target..name', 'eq', 'x'] }],
  ['element-scope', { scope: 'element', when: ['source.name', 'eq', 'x'] }],
  ['element-scope', { scope: 'element', when: { any: [['target.name', 'eq', 'x']] } }],
  ['element-scope', { scope: 'element', when: { not: ['flow.subtype', 'eq', 'x'] } }],
  ['unsupported operator', { when: ['source.name', 'matches', '.*'] }],
  ['clauses must', { when: ['source.name', 'eq'] }], ['clauses must', { when: ['source.name', 'eq', 'x', 'extra'] }],
  ['array value', { when: ['source.type', 'in', 'external'] }], ['array value', { when: ['target.type', 'nin', null] }],
  ['boolean value', { when: ['source.name', 'exists', 'Yes'] }],
  ['malformed condition', { when: { any: ['source.name', 'eq', 'x'] } }],
  ['malformed condition', { when: { not: null } }], ['malformed condition', { when: [true] }],
  ['malformed condition', { when: { any: [], not: [] } }], ['malformed condition', { when: { all: [] } }],
  ['malformed condition', { when: 'source.type' }], ['malformed condition', { when: {} }],
  ['missing', { when: null }], ['category', { category: 'STRIDE' }],
];
for (const [message, patch] of invalid) test(`reject ${JSON.stringify(patch)} with rule ID`, () => {
  const template = [{ ...base(), ...patch }];
  const rejects = (e) => e.message.includes('UNTRUSTED') && e.message.includes(message);
  assert.throws(() => validateRules(template), rejects);
  const m = newModel(); m.template = template;
  assert.throws(() => normalizeModel(m), rejects);
});

test('duplicate IDs, missing required fields, invalid IDs and deep conditions are rejected', () => {
  assert.throws(() => validateRules([base(), base()]), /Duplicate rule id UNTRUSTED/);
  for (const field of ['id', 'category', 'title', 'when']) {
    const r = base(); delete r[field]; assert.throws(() => validateRules([r]), /missing/);
  }
  for (const id of ['', 123, {}]) assert.throws(() => validateRules([{ ...base(), id }]), /id must be/);
  let when = []; for (let i = 0; i < 70; i++) when = { not: when };
  assert.throws(() => validateRules([{ ...base(), when }]), /UNTRUSTED.*nesting/);
});

test('supersedes permits forward references, empty lists and valid dedupe values', () => {
  for (const dedupeKey of ['flow', 'target', 'source']) {
    assert.doesNotThrow(() => validateRules([{ ...base(), dedupeKey, supersedes: ['SECOND'] }, { ...base(), id: 'SECOND', supersedes: [] }]));
  }
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_TEMPLATE, KnowledgeBase, RuleEvalError, compileRule, evaluate, expandTemplate, normalizeTemplate, parseRule, validateRule } from '../src/core/index.js';

const kb = new KnowledgeBase(normalizeTemplate(DEFAULT_TEMPLATE));

function subj(typeId, props = {}) {
  const map = new Map(Object.entries({ Name: 'X', ...props }).map(([k, v]) => [k.toUpperCase(), v]));
  return { chain: kb.chain(typeId), props: map };
}
function ctx({ source = 'GE.P', flow = 'GE.DF', target = 'GE.P', sp = {}, fp = {}, tp = {}, crossed = [] } = {}) {
  return {
    subjects: { source: subj(source, sp), flow: subj(flow, fp), target: subj(target, tp) },
    crosses: (t) => crossed.some((c) => kb.isDerived(c, t)),
    isBoundaryType: (t) => kb.boundaryTypeIds().includes(t),
  };
}
const run = (expr, c) => evaluate(parseRule(expr), c);

test('type tests match the whole type chain (subtype aware)', () => {
  assert.equal(run("target is 'GE.DS'", ctx({ target: 'SE.DS.TMCore.SQL' })), true);
  assert.equal(run("target is 'SE.DS.TMCore.SQL'", ctx({ target: 'SE.DS.TMCore.SQL' })), true);
  assert.equal(run("target is 'SE.DS.TMCore.SQL'", ctx({ target: 'GE.DS' })), false);
  assert.equal(run("source is 'ROOT'", ctx()), true);
});

test('property tests are case-insensitive on names and exact on values', () => {
  const c = ctx({ fp: { providesConfidentiality: 'Yes' } });
  assert.equal(run("flow.providesconfidentiality is 'Yes'", c), true);
  assert.equal(run("flow.[providesConfidentiality] is 'Yes'", c), true);
  assert.equal(run("flow.providesConfidentiality is 'yes'", c), false);
});

test('crosses is subtype aware and only valid after flow', () => {
  assert.equal(run("flow crosses 'GE.TB.B'", ctx({ crossed: ['SE.TB.B.TMCore.CorpNet'] })), true);
  assert.equal(run("flow crosses 'SE.TB.B.TMCore.Sandbox'", ctx({ crossed: ['SE.TB.B.TMCore.CorpNet'] })), false);
  assert.throws(() => parseRule("source crosses 'GE.TB.B'"), /not valid after 'source'/);
  assert.throws(() => run("flow crosses 'GE.P'", ctx()), RuleEvalError);
});

test('and/or precedence and short-circuit (missing properties guarded by type tests)', () => {
  // `and` binds tighter than `or`.
  assert.equal(run("source is 'GE.EI' and target is 'GE.EI' or flow is 'GE.DF'", ctx()), true);
  // codeType does not exist on a data store; short-circuit avoids the error.
  assert.equal(run("target is 'GE.P' and target.codeType is 'Unmanaged'", ctx({ target: 'GE.DS' })), false);
  assert.throws(() => run("target.codeType is 'Unmanaged'", ctx({ target: 'GE.DS' })), /does not exist/);
});

test('not applies to single rules only, no double negation', () => {
  assert.equal(run("not source is 'GE.EI'", ctx()), true);
  assert.throws(() => parseRule("not (source is 'GE.P')"), /only applies to rules/);
  assert.throws(() => parseRule("not not source is 'GE.P'"), /Double negation/);
});

test('syntax errors are specific', () => {
  const cases = [
    ["source is 'GE.P' and", /must be followed by an expression/],
    ["(source is 'GE.P'", /Expected \)/],
    ["source is 'GE.P')", /Unmatched \)/],
    ['()', /Empty \(\)/],
    ["source is GE.P", /single quotes/],
    ["source is 'GE.P' target is 'GE.P'", /logical operator/],
    ["process is 'GE.P'", /must start with either 'source', 'target', or 'flow'/],
    ["source . codeType is 'x'", /Spaces are not allowed/],
    ["source is 'GE.P", /No matching '/],
  ];
  for (const [expr, re] of cases) assert.throws(() => parseRule(expr), re, expr);
});

test('typographic quotes and dashes are normalized', () => {
  assert.equal(run('source is ‘GE.P’', ctx()), true);
});

test('empty expressions compile to null and never match', () => {
  assert.equal(compileRule('').ast, null);
  assert.equal(evaluate(null, ctx()), false);
});

test('validateRule reports unknown types and non-boundary crosses', () => {
  assert.equal(validateRule("source is 'GE.P'", kb).ok, true);
  assert.match(validateRule("source is 'NOPE'", kb).warnings[0], /Unknown element type/);
  assert.equal(validateRule("flow crosses 'GE.P'", kb).ok, false);
  assert.match(validateRule("flow.madeUp is 'x'", kb).warnings[0], /not defined/);
});

test('every rule in the default template is valid', () => {
  for (const t of kb.threatTypes) {
    for (const key of ['include', 'exclude']) {
      const r = validateRule(t[key], kb);
      assert.ok(r.ok, `${t.id} ${key}: ${r.errors.join('; ')}`);
      assert.deepEqual(r.warnings, [], `${t.id} ${key}`);
    }
  }
});

test('expandTemplate fills placeholders and leaves unknown ones', () => {
  const c = ctx({ sp: { Name: 'Browser' }, tp: { Name: 'API', codeType: 'Managed' } });
  assert.equal(expandTemplate('{source.Name} → {target.Name} ({target.[codeType]}) {flow.nope} {x}', c.subjects), 'Browser → API (Managed) {flow.nope} {x}');
});

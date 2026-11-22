// MTMT-compatible threat generation rule language (GenerationFilters Include/Exclude).
//
//   expr    := and { "or" and }
//   and     := unary { "and" unary }
//   unary   := "(" expr ")" | "not" rule | rule
//   rule    := subject "is" 'TypeId'
//            | subject "." ( Prop | "[" Prop Name "]" ) "is" 'Value'
//            | "flow" "crosses" 'BoundaryTypeId'
//   subject := "source" | "target" | "flow"
//
// Semantics match the Microsoft Threat Modeling Tool:
//   * `X is 'T'` is true when T appears anywhere in X's type chain (subtype aware).
//   * Property names are case-insensitive; values compare as exact strings
//     against the selected list text.
//   * `flow crosses 'B'` is geometric and matches any boundary derived from B.
//   * `not` applies to a single rule only; double negation is rejected.
//   * and/or short-circuit; a property missing on the subject is an evaluation error.

const SUBJECTS = new Set(['source', 'target', 'flow']);
const KEYWORDS = new Set(['and', 'or', 'not', 'is', 'crosses']);

export class RuleSyntaxError extends Error {
  constructor(message, position) {
    super(message);
    this.name = 'RuleSyntaxError';
    this.position = position;
  }
}

export class RuleEvalError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RuleEvalError';
  }
}

/** Replace typographic characters that sneak in from documents (MTMT does the same). */
export function normalizeRuleText(text) {
  return String(text ?? '')
    .replace(/[‘’‚′]/g, "'")
    .replace(/[“”„]/g, '"')
    .replace(/[–—]/g, '-')
    .replace(/[   ]/g, ' ')
    .replace(/…/g, '...');
}

function tokenize(input) {
  const s = normalizeRuleText(input);
  const tokens = [];
  let i = 0;
  while (i < s.length) {
    const ch = s[i];
    if (/\s/.test(ch)) {
      i++;
      continue;
    }
    if (ch === '(' || ch === ')' || ch === '.') {
      tokens.push({ t: ch, pos: i });
      i++;
      continue;
    }
    if (ch === "'") {
      const end = s.indexOf("'", i + 1);
      if (end === -1) throw new RuleSyntaxError(`No matching ' found. The starting delimiter is at position ${i + 1}. Add a closing ' to the value.`, i);
      tokens.push({ t: 'str', v: s.slice(i + 1, end), pos: i });
      i = end + 1;
      continue;
    }
    if (ch === '[') {
      const end = s.indexOf(']', i + 1);
      if (end === -1) throw new RuleSyntaxError(`No matching ] found. The starting delimiter is at position ${i + 1}. Add a ] after the property name.`, i);
      tokens.push({ t: 'bracket', v: s.slice(i + 1, end).trim(), pos: i });
      i = end + 1;
      continue;
    }
    if (ch === ']') throw new RuleSyntaxError(`Unmatched ] found at position ${i + 1}. Remove the ] or place a [ at the start of the property name.`, i);
    const m = /^[A-Za-z0-9_\-:]+/.exec(s.slice(i));
    if (m) {
      tokens.push({ t: 'word', v: m[0], lv: m[0].toLowerCase(), pos: i });
      i += m[0].length;
      continue;
    }
    throw new RuleSyntaxError(`Unexpected character '${ch}' at position ${i + 1}.`, i);
  }
  return tokens;
}

class Parser {
  constructor(tokens) {
    this.tokens = tokens;
    this.i = 0;
  }
  peek(o = 0) {
    return this.tokens[this.i + o];
  }
  next() {
    return this.tokens[this.i++];
  }
  isWord(tok, w) {
    return tok && tok.t === 'word' && tok.lv === w;
  }
  at(tok) {
    return tok ? `position ${tok.pos + 1}` : 'the end of the expression';
  }

  parse() {
    if (this.tokens.length === 0) return null;
    const expr = this.parseOr();
    const rest = this.peek();
    if (rest) {
      if (rest.t === ')') throw new RuleSyntaxError(`Unmatched ) found at ${this.at(rest)}. Remove the ) or insert a matching (.`, rest.pos);
      throw new RuleSyntaxError(
        `Expressions must be separated by a logical operator 'and' or 'or'. Found unexpected text '${tokText(rest)}' at ${this.at(rest)}. Add a logical operator.`,
        rest.pos,
      );
    }
    return expr;
  }

  parseOr() {
    let left = this.parseAnd();
    while (this.isWord(this.peek(), 'or')) {
      const op = this.next();
      if (!this.peek() || this.peek().t === ')') {
        throw new RuleSyntaxError(`Logical operators 'and' and 'or' must be followed by an expression. A trailing 'or' was found at ${this.at(op)}.`, op.pos);
      }
      left = { type: 'or', left, right: this.parseAnd() };
    }
    return left;
  }

  parseAnd() {
    let left = this.parseUnary();
    while (this.isWord(this.peek(), 'and')) {
      const op = this.next();
      if (!this.peek() || this.peek().t === ')') {
        throw new RuleSyntaxError(`Logical operators 'and' and 'or' must be followed by an expression. A trailing 'and' was found at ${this.at(op)}.`, op.pos);
      }
      left = { type: 'and', left, right: this.parseUnary() };
    }
    return left;
  }

  parseUnary() {
    const tok = this.peek();
    if (!tok) throw new RuleSyntaxError("Incomplete expression. Expected a rule starting with 'source', 'target', or 'flow'.", undefined);
    if (tok.t === '(') {
      this.next();
      const after = this.peek();
      if (after && after.t === ')') throw new RuleSyntaxError(`Empty () found at ${this.at(tok)}. Parenthesis must contain an expression.`, tok.pos);
      if (!after) throw new RuleSyntaxError(`Parenthesis must be followed by an expression. A trailing '(' was found at ${this.at(tok)}.`, tok.pos);
      const expr = this.parseOr();
      const close = this.next();
      if (!close || close.t !== ')') throw new RuleSyntaxError(`Expected ). Matching ( was found at ${this.at(tok)}. Add a ).`, tok.pos);
      return expr;
    }
    if (tok.t === ')') throw new RuleSyntaxError(`Unmatched ) found at ${this.at(tok)}. Remove the ) or insert a matching (.`, tok.pos);
    if (this.isWord(tok, 'not')) {
      this.next();
      const after = this.peek();
      if (!after) throw new RuleSyntaxError("Found a 'not' at the end of the expression. A 'not' must be followed by a rule.", tok.pos);
      if (this.isWord(after, 'not')) throw new RuleSyntaxError(`Found the 'not' operator twice at ${this.at(tok)}. Double negation is not supported.`, tok.pos);
      if (after.t === '(') {
        throw new RuleSyntaxError(
          `Found the 'not' operator followed by ( at ${this.at(tok)}. The 'not' operator only applies to rules, not to parenthesized expressions.`,
          tok.pos,
        );
      }
      if (after.t === ')') throw new RuleSyntaxError(`Mismatched ) found after the 'not' operator at ${this.at(after)}.`, after.pos);
      return { type: 'not', rule: this.parseRule() };
    }
    return this.parseRule();
  }

  parseRule() {
    const subj = this.next();
    if (!subj || subj.t !== 'word' || !SUBJECTS.has(subj.lv)) {
      throw new RuleSyntaxError(`A rule must start with either 'source', 'target', or 'flow'. Found '${tokText(subj)}' at ${this.at(subj)}.`, subj?.pos);
    }
    const subject = subj.lv;
    const op = this.next();
    if (!op) {
      throw new RuleSyntaxError(
        `Incomplete expression. Expected one of: ${subject} is 'type', ${subject}.property is 'value'${subject === 'flow' ? ", or flow crosses 'boundary'" : ''}.`,
        subj.pos,
      );
    }
    if (this.isWord(op, 'is')) {
      return { type: 'is', subject, value: this.expectString(op, `Expected an element type in single quotes after '${subject} is'.`) };
    }
    if (this.isWord(op, 'crosses')) {
      if (subject !== 'flow') throw new RuleSyntaxError(`'crosses' is not valid after 'source' or 'target'. Change '${subject}' to 'flow'.`, op.pos);
      return { type: 'crosses', subject, value: this.expectString(op, "Expected a boundary type in single quotes after 'flow crosses'.") };
    }
    if (op.t === '.') {
      const propTok = this.next();
      if (!propTok) throw new RuleSyntaxError(`Incomplete expression. Expected ${subject}.property is 'value'. Found '${subject}.' with no property name.`, op.pos);
      if (propTok.pos !== op.pos + 1 || op.pos !== subj.pos + subj.v.length) {
        throw new RuleSyntaxError(`Spaces are not allowed before or after the dot in '${subject}.'. Remove the spaces around the dot.`, op.pos);
      }
      let prop;
      if (propTok.t === 'bracket') prop = propTok.v;
      else if (propTok.t === 'word' && !KEYWORDS.has(propTok.lv)) prop = propTok.v;
      else throw new RuleSyntaxError(`Expected a property name after '${subject}.'. Found '${tokText(propTok)}'.`, propTok.pos);
      if (!prop) throw new RuleSyntaxError(`Expected a property name inside [ ] after '${subject}.'.`, propTok.pos);
      const isTok = this.next();
      if (!this.isWord(isTok, 'is')) {
        throw new RuleSyntaxError(`Expected ${subject}.${prop} is 'value'. Found '${tokText(isTok)}' at ${this.at(isTok)}. Add the word 'is' and a value.`, isTok?.pos ?? propTok.pos);
      }
      return { type: 'prop', subject, prop, value: this.expectString(isTok, `Property values must be enclosed in single quotes after '${subject}.${prop} is'.`) };
    }
    throw new RuleSyntaxError(
      `Expected 'is', '.'${subject === 'flow' ? ", or 'crosses'" : ''} after '${subject}'. Found '${tokText(op)}' at ${this.at(op)}.`,
      op.pos,
    );
  }

  expectString(after, message) {
    const tok = this.next();
    if (!tok) throw new RuleSyntaxError(`${message} Found nothing.`, after.pos);
    if (tok.t !== 'str') throw new RuleSyntaxError(`${message} Found '${tokText(tok)}' at ${this.at(tok)}.`, tok.pos);
    return tok.v;
  }
}

function tokText(tok) {
  if (!tok) return '';
  if (tok.t === 'str') return `'${tok.v}'`;
  if (tok.t === 'bracket') return `[${tok.v}]`;
  return tok.v ?? tok.t;
}

/** Parse a rule expression into an AST (null for an empty expression). */
export function parseRule(text) {
  return new Parser(tokenize(text)).parse();
}

const compileCache = new Map();

/** Cached parse; returns { ast } or { error }. */
export function compileRule(text) {
  const key = String(text ?? '');
  let entry = compileCache.get(key);
  if (!entry) {
    try {
      entry = { ast: parseRule(key) };
    } catch (e) {
      entry = { error: e };
    }
    if (compileCache.size > 5000) compileCache.clear();
    compileCache.set(key, entry);
  }
  return entry;
}

/**
 * Evaluate an AST.
 * ctx.subjects: { source, flow, target } each { chain: string[], props: Map<UPPERNAME,string> }
 * ctx.crosses(typeId): boolean
 * ctx.isBoundaryType(typeId): boolean (optional, for validation of the operand)
 */
export function evaluate(ast, ctx) {
  if (!ast) return false;
  switch (ast.type) {
    case 'and':
      return evaluate(ast.left, ctx) && evaluate(ast.right, ctx);
    case 'or':
      return evaluate(ast.left, ctx) || evaluate(ast.right, ctx);
    case 'not':
      return !evaluate(ast.rule, ctx);
    case 'is': {
      const subj = ctx.subjects[ast.subject];
      if (!subj) throw new RuleEvalError(`The subject '${ast.subject}' is not available.`);
      return subj.chain.includes(ast.value);
    }
    case 'prop': {
      const subj = ctx.subjects[ast.subject];
      if (!subj) throw new RuleEvalError(`The subject '${ast.subject}' is not available.`);
      const key = ast.prop.toUpperCase();
      if (!subj.props.has(key)) throw new RuleEvalError(`The identifier '${ast.subject}.${ast.prop}' does not exist on this element.`);
      return subj.props.get(key) === ast.value;
    }
    case 'crosses': {
      if (ctx.isBoundaryType && !ctx.isBoundaryType(ast.value)) {
        throw new RuleEvalError(`The operand of 'crosses' must be a trust boundary type; '${ast.value}' is not.`);
      }
      return !!ctx.crosses(ast.value);
    }
    default:
      throw new RuleEvalError(`Unknown rule node '${ast.type}'.`);
  }
}

/** Collect every leaf rule in an AST. */
export function ruleLeaves(ast, out = []) {
  if (!ast) return out;
  if (ast.type === 'and' || ast.type === 'or') {
    ruleLeaves(ast.left, out);
    ruleLeaves(ast.right, out);
  } else if (ast.type === 'not') ruleLeaves(ast.rule, out);
  else out.push(ast);
  return out;
}

/**
 * Validate a rule against a knowledge base.
 * Returns { ok, errors: string[], warnings: string[] }.
 */
export function validateRule(text, kb) {
  const result = { ok: true, errors: [], warnings: [] };
  const { ast, error } = compileRule(text);
  if (error) {
    result.ok = false;
    result.errors.push(error.message);
    return result;
  }
  if (!kb || !ast) return result;
  const boundaries = new Set(kb.boundaryTypeIds());
  const attrNames = kb.allAttributeNames();
  const builtins = new Set(['NAME', 'OUT OF SCOPE', 'REASON FOR OUT OF SCOPE', 'DATAFLOW ORDER']);
  for (const leaf of ruleLeaves(ast)) {
    if (leaf.type === 'is') {
      if (leaf.value !== 'ROOT' && !kb.element(leaf.value)) result.warnings.push(`Unknown element type '${leaf.value}' in '${leaf.subject} is'.`);
    } else if (leaf.type === 'crosses') {
      if (!boundaries.has(leaf.value)) {
        result.ok = false;
        result.errors.push(`'flow crosses' requires a trust boundary type; '${leaf.value}' is not one.`);
      }
    } else if (leaf.type === 'prop') {
      const key = leaf.prop.toUpperCase();
      if (!attrNames.has(key) && !builtins.has(key)) result.warnings.push(`Property '${leaf.prop}' is not defined by any element in this template.`);
    }
  }
  return result;
}

/**
 * Expand `{source.Name}`, `{flow.providesIntegrity}`, `{target.[Code Type]}` style
 * placeholders. Unknown placeholders are left untouched (MTMT behaviour).
 */
export function expandTemplate(text, subjects) {
  if (!text) return '';
  return String(text).replace(/\{([^{}]{1,300})\}/g, (match, inner) => {
    const dot = inner.indexOf('.');
    if (dot < 0) return match;
    const subj = subjects[inner.slice(0, dot).trim().toLowerCase()];
    if (!subj) return match;
    let prop = inner.slice(dot + 1).trim();
    if (prop.startsWith('[') && prop.endsWith(']')) prop = prop.slice(1, -1).trim();
    const key = prop.toUpperCase();
    return subj.props.has(key) ? subj.props.get(key) : match;
  });
}

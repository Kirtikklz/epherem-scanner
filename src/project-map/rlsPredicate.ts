export type Ternary = 'true' | 'false' | 'unknown';

export type RlsCaller = 'anonymous' | 'authenticated';

export interface PredicateVerdict {
  value: Ternary;
  readable: boolean;
}

const MAX_EXPRESSION = 4000;
const MAX_DEPTH = 40;

export function stripSqlComments(expression: string): string {
  let out = '';
  let index = 0;
  while (index < expression.length) {
    const char = expression[index];
    if (char === "'") {
      const end = findStringEnd(expression, index);
      out += expression.slice(index, end);
      index = end;
      continue;
    }
    if (char === '-' && expression[index + 1] === '-') {
      const newline = expression.indexOf('\n', index);
      index = newline === -1 ? expression.length : newline;
      out += ' ';
      continue;
    }
    if (char === '/' && expression[index + 1] === '*') {
      const close = expression.indexOf('*/', index + 2);
      index = close === -1 ? expression.length : close + 2;
      out += ' ';
      continue;
    }
    out += char;
    index += 1;
  }
  return out;
}

function findStringEnd(text: string, start: number): number {
  for (let index = start + 1; index < text.length; index += 1) {
    if (text[index] !== "'") continue;
    if (text[index + 1] === "'") {
      index += 1;
      continue;
    }
    return index + 1;
  }
  return text.length;
}

export function evaluatePredicate(expression: string, caller: RlsCaller): PredicateVerdict {
  const text = stripSqlComments(expression).trim();
  if (text.length === 0 || text.length > MAX_EXPRESSION) return { value: 'unknown', readable: false };
  if (!parensBalanced(text)) return { value: 'unknown', readable: false };
  return { value: evaluateExpression(text, caller, 0), readable: true };
}

function parensBalanced(text: string): boolean {
  let depth = 0;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (char === "'") {
      index = findStringEnd(text, index) - 1;
      continue;
    }
    if (char === '(') depth += 1;
    else if (char === ')') {
      depth -= 1;
      if (depth < 0) return false;
    }
  }
  return depth === 0;
}

function evaluateExpression(text: string, caller: RlsCaller, depth: number): Ternary {
  if (depth > MAX_DEPTH) return 'unknown';

  const orParts = splitTopLevel(text, 'OR');
  if (orParts.length > 1) {
    const values = orParts.map((part) => evaluateExpression(part, caller, depth + 1));
    if (values.includes('true')) return 'true';
    return values.every((value) => value === 'false') ? 'false' : 'unknown';
  }

  const andParts = splitTopLevel(text, 'AND');
  if (andParts.length > 1) {
    const values = andParts.map((part) => evaluateExpression(part, caller, depth + 1));
    if (values.includes('false')) return 'false';
    return values.every((value) => value === 'true') ? 'true' : 'unknown';
  }

  const trimmed = text.trim();
  const negated = /^NOT\s+([\s\S]+)$/i.exec(trimmed);
  if (negated !== null) return negate(evaluateExpression(negated[1] ?? '', caller, depth + 1));

  const inner = unwrapParentheses(trimmed);
  if (inner !== undefined) return evaluateExpression(inner, caller, depth + 1);

  return evaluateAtom(trimmed, caller);
}

function negate(value: Ternary): Ternary {
  if (value === 'true') return 'false';
  if (value === 'false') return 'true';
  return 'unknown';
}

function splitTopLevel(text: string, keyword: 'OR' | 'AND'): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (char === "'") {
      index = findStringEnd(text, index) - 1;
      continue;
    }
    if (char === '(') {
      depth += 1;
      continue;
    }
    if (char === ')') {
      depth -= 1;
      continue;
    }
    if (depth !== 0) continue;
    if (!isKeywordAt(text, index, keyword)) continue;
    parts.push(text.slice(start, index));
    index += keyword.length - 1;
    start = index + 1;
  }
  if (parts.length === 0) return [text];
  parts.push(text.slice(start));
  return parts;
}

function isKeywordAt(text: string, index: number, keyword: string): boolean {
  if (text.slice(index, index + keyword.length).toUpperCase() !== keyword) return false;
  const before = text[index - 1];
  const after = text[index + keyword.length];
  const isWord = (char: string | undefined): boolean => char !== undefined && /[\w$]/.test(char);
  return !isWord(before) && !isWord(after);
}

function unwrapParentheses(text: string): string | undefined {
  if (!text.startsWith('(') || !text.endsWith(')')) return undefined;
  let depth = 0;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (char === "'") {
      index = findStringEnd(text, index) - 1;
      continue;
    }
    if (char === '(') depth += 1;
    else if (char === ')') {
      depth -= 1;
      if (depth === 0 && index !== text.length - 1) return undefined;
    }
  }
  const inner = text.slice(1, -1).trim();
  return /^SELECT\b/i.test(inner) ? undefined : inner;
}

const AUTH_UID = /(?:\(\s*select\s+)?\bauth\s*\.\s*uid\s*\(\s*\)/i;
const AUTH_JWT = /(?:\(\s*select\s+)?\bauth\s*\.\s*jwt\s*\(\s*\)/i;
const AUTH_ROLE = /(?:\(\s*select\s+)?\bauth\s*\.\s*role\s*\(\s*\)/i;
const JWT_ROLE_SETTING = /current_setting\s*\(\s*'request\.jwt\.claim\.role'/i;

function evaluateAtom(atom: string, caller: RlsCaller): Ternary {
  const text = atom.trim().replace(/\s+/g, ' ');
  if (text.length === 0) return 'unknown';

  if (/^TRUE$/i.test(text)) return 'true';
  if (/^FALSE$/i.test(text)) return 'false';

  const isNull = /^([\s\S]+?)\s+IS\s+(NOT\s+)?NULL$/i.exec(text);
  if (isNull !== null) {
    const subject = (isNull[1] ?? '').trim();
    const wantsNotNull = isNull[2] !== undefined;
    const nullity = subjectIsNull(subject, caller);
    if (nullity === undefined) return 'unknown';
    return (wantsNotNull ? !nullity : nullity) ? 'true' : 'false';
  }

  const comparison = splitComparison(text);
  if (comparison !== undefined) {
    const { left, right, negatedComparison } = comparison;
    const leftRole = isRoleReference(left);
    const rightRole = isRoleReference(right);
    const leftLiteral = stringLiteral(left);
    const rightLiteral = stringLiteral(right);
    if (leftRole && rightLiteral !== undefined) {
      return roleComparison(rightLiteral, caller, negatedComparison);
    }
    if (rightRole && leftLiteral !== undefined) {
      return roleComparison(leftLiteral, caller, negatedComparison);
    }
    if (leftLiteral !== undefined && rightLiteral !== undefined) {
      const equal = leftLiteral === rightLiteral;
      return (negatedComparison ? !equal : equal) ? 'true' : 'false';
    }
  }

  const inList = /^([\s\S]+?)\s+(NOT\s+)?IN\s*\(([^()]*)\)$/i.exec(text);
  if (inList !== null && isRoleReference((inList[1] ?? '').trim())) {
    const values = (inList[3] ?? '')
      .split(',')
      .map((value) => stringLiteral(value.trim()))
      .filter((value): value is string => value !== undefined);
    if (values.length > 0) {
      const present = values.includes(roleOf(caller));
      const wantsAbsent = inList[2] !== undefined;
      return (wantsAbsent ? !present : present) ? 'true' : 'false';
    }
  }

  return 'unknown';
}

function roleOf(caller: RlsCaller): string {
  return caller === 'anonymous' ? 'anon' : 'authenticated';
}

function roleComparison(literal: string, caller: RlsCaller, negated: boolean): Ternary {
  const equal = literal.toLowerCase() === roleOf(caller);
  return (negated ? !equal : equal) ? 'true' : 'false';
}

function subjectIsNull(subject: string, caller: RlsCaller): boolean | undefined {
  const bare = stripValueParens(subject);
  if (AUTH_UID.test(bare) && isBareAuthCall(bare, AUTH_UID)) return caller === 'anonymous';
  if (AUTH_JWT.test(bare) && isBareAuthCall(bare, AUTH_JWT)) return caller === 'anonymous';
  if (isRoleReference(bare)) return false;
  return undefined;
}

function isBareAuthCall(text: string, pattern: RegExp): boolean {
  const match = pattern.exec(text);
  if (match === null) return false;
  const rest = text.slice(0, match.index) + text.slice(match.index + match[0].length);
  return rest.replace(/[\s()]/g, '').length === 0;
}

function isRoleReference(text: string): boolean {
  const bare = stripValueParens(text);
  if (JWT_ROLE_SETTING.test(bare)) return true;
  if (!AUTH_ROLE.test(bare)) return false;
  return isBareAuthCall(bare, AUTH_ROLE);
}

function stripValueParens(text: string): string {
  let out = text.trim();
  for (let round = 0; round < 4; round += 1) {
    const next = out
      .replace(/::\s*[\w."]+\s*$/i, '')
      .replace(/^\(\s*select\s+([\s\S]+)\)$/i, '$1')
      .replace(/^\(([\s\S]+)\)$/, '$1')
      .trim();
    if (next === out) break;
    out = next;
  }
  return out;
}

function stringLiteral(text: string): string | undefined {
  const bare = stripValueParens(text);
  const match = /^'((?:[^']|'')*)'$/.exec(bare);
  return match === null ? undefined : (match[1] ?? '').replace(/''/g, "'");
}

function splitComparison(
  text: string,
): { left: string; right: string; negatedComparison: boolean } | undefined {
  let depth = 0;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (char === "'") {
      index = findStringEnd(text, index) - 1;
      continue;
    }
    if (char === '(') depth += 1;
    else if (char === ')') depth -= 1;
    if (depth !== 0) continue;
    const two = text.slice(index, index + 2);
    if (two === '<>' || two === '!=') {
      return {
        left: text.slice(0, index),
        right: text.slice(index + 2),
        negatedComparison: true,
      };
    }
    if (char !== '=') continue;
    const before = text[index - 1];
    if (before === '<' || before === '>' || before === '!' || before === '=') continue;
    if (text[index + 1] === '=') continue;
    return { left: text.slice(0, index), right: text.slice(index + 1), negatedComparison: false };
  }
  return undefined;
}

export function bindsOnEveryBranch(
  expression: string,
  bindsLeaf: (leaf: string) => boolean,
): boolean {
  const text = stripSqlComments(expression).trim();
  if (text.length === 0 || text.length > MAX_EXPRESSION) return false;
  if (!parensBalanced(text)) return false;
  return walkBinding(text, bindsLeaf, 0);
}

function walkBinding(text: string, bindsLeaf: (leaf: string) => boolean, depth: number): boolean {
  if (depth > MAX_DEPTH) return false;

  const orParts = splitTopLevel(text, 'OR');
  if (orParts.length > 1) return orParts.every((part) => walkBinding(part, bindsLeaf, depth + 1));

  const andParts = splitTopLevel(text, 'AND');
  if (andParts.length > 1) return andParts.some((part) => walkBinding(part, bindsLeaf, depth + 1));

  const trimmed = text.trim();
  if (/^NOT\s+[\s\S]+$/i.test(trimmed)) return false;

  const inner = unwrapParentheses(trimmed);
  if (inner !== undefined) return walkBinding(inner, bindsLeaf, depth + 1);

  return bindsLeaf(trimmed);
}

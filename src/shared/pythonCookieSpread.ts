import { defsNamed, maskedLines } from './pythonScope.js';

export interface CookieSpread {
  supplied: string;
  unresolved: boolean;
}

function topLevelParts(args: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = '';
  for (let i = 0; i < args.length; i += 1) {
    const c = args[i]!;
    if (c === '"' || c === "'") {
      const quote = args.startsWith(c.repeat(3), i) ? c.repeat(3) : c;
      let j = i + quote.length;
      while (j < args.length && !args.startsWith(quote, j)) j += args[j] === '\\' ? 2 : 1;
      current += args.slice(i, j + quote.length);
      i = j + quote.length - 1;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    if (c === ',' && depth === 0) { parts.push(current); current = ''; continue; }
    current += c;
  }
  parts.push(current);
  return parts.map((p) => p.trim()).filter((p) => p !== '');
}

function dictText(expression: string): string | undefined {
  const text = expression.trim();
  if (/^\{[\s\S]*\}$/.test(text)) return text;
  if (/^dict\s*\([\s\S]*\)$/.test(text)) return text;
  return undefined;
}

function helperDicts(content: string, name: string): string | undefined {
  const masked = maskedLines(content);
  const raw = content.split('\n');
  const defs = defsNamed(masked, name);
  if (defs.length !== 1) return undefined;
  const scope = defs[0]!;
  const texts: string[] = [];
  for (let l = scope.defLine + 1; l <= scope.endLine; l += 1) {
    const m = /^(\s*)return\b/.exec(masked[l - 1] ?? '');
    if (m === null) continue;
    let text = (raw[l - 1] ?? '').slice(m[0].length);
    let depth = 0;
    for (let k = l; ; k += 1) {
      const line = k === l ? (masked[k - 1] ?? '').slice(m[0].length) : (masked[k - 1] ?? '');
      for (const c of line) {
        if (c === '(' || c === '[' || c === '{') depth += 1;
        else if (c === ')' || c === ']' || c === '}') depth -= 1;
      }
      if (depth <= 0 || k >= scope.endLine) break;
      text += `\n${raw[k] ?? ''}`;
    }
    const dict = dictText(text);
    if (dict === undefined) return undefined;
    texts.push(dict);
  }
  return texts.length > 0 ? texts.join('\n') : undefined;
}

function spreadText(content: string, expression: string): string | undefined {
  const text = expression.trim();
  const direct = dictText(text);
  if (direct !== undefined) return direct;
  const call = /^([A-Za-z_]\w*)\s*\([\s\S]*\)$/.exec(text);
  if (call !== null) return helperDicts(content, call[1]!);
  if (!/^[A-Za-z_]\w*$/.test(text)) return undefined;
  const masked = maskedLines(content).join('\n');
  const assign = new RegExp(String.raw`^([ \t]*)${text}[ \t]*(?::[^=\n]+)?=(?!=)`, 'gm');
  const found = [...masked.matchAll(assign)];
  if (found.length !== 1) return undefined;
  if (new RegExp(String.raw`\bdef\s+\w+\s*\([^)]*(?<![\w.])${text}\b|\bfor\s+[^\n]*\b${text}\b[^\n]*\bin\b|\bas\s+${text}\b|(?<![\w.])${text}\s*\[[^\]]*\]\s*=(?!=)|(?<![\w.])${text}\s*\.\s*(?:update|setdefault|pop)\s*\(|\b${text}\s*\|=`).test(masked)) return undefined;
  const start = found[0]!.index + found[0]![0].length;
  let depth = 0;
  let end = start;
  for (; end < content.length; end += 1) {
    const c = masked[end];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (c === '\n' && depth <= 0) break;
  }
  const value = content.slice(start, end).trim();
  return dictText(value) ?? (/^[A-Za-z_]\w*\s*\([\s\S]*\)$/.test(value) ? spreadText(content, value) : undefined);
}

export function pythonCookieSpread(content: string, args: string): CookieSpread | undefined {
  const spreads = topLevelParts(args).filter((part) => part.startsWith('**')).map((part) => part.slice(2));
  if (spreads.length === 0) return undefined;
  const supplied: string[] = [];
  let unresolved = false;
  for (const spread of spreads) {
    const text = spreadText(content, spread);
    if (text === undefined) unresolved = true;
    else supplied.push(text);
  }
  return { supplied: supplied.join('\n'), unresolved };
}

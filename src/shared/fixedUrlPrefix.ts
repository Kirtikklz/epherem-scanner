// A literal scheme://host prefix fixes the destination; only path/query vary.
export const FIXED_HOST_LITERAL = /^\s*[`'"]\s*(?:https?:)?\/\/[a-z0-9.-]+(?:[:/?#'"`]|\s|$)/i;

// Deployment config reads: process.env, import.meta.env, Deno.env.get.
export const CONFIG_READ = String.raw`(?:process\.env\s*(?:\.\s*[A-Za-z_$][\w$]*|\[\s*['"][^'"]*['"]\s*\])|import\.meta\.env\s*\.\s*[A-Za-z_$][\w$]*|Deno\.env\.get\s*\(\s*['"][^'"]*['"]\s*\))`;

// Host comes from deployment config, not from the request.
export const CONFIG_HOST_HEAD = new RegExp(
  String.raw`^\s*(?:` +
    String.raw`[` + '`' + String.raw`'"]\s*\$\{\s*` + CONFIG_READ + String.raw`\s*\}\s*(?=[/?#'"` + '`' + String.raw`]|$)` +
    '|' +
    CONFIG_READ + String.raw`\s*(?=[,)\s]|$)` +
    ')',
);

export const BASE_CONST_DEF =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]+)?=\s*([^;]{0,240}?['"`]https?:\/\/[a-z0-9.-][^;]{0,240})/gi;

export const ENV_BASE_CONST_DEF = new RegExp(
  String.raw`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]+)?=\s*(` + CONFIG_READ + String.raw`[^;\n]{0,160})`,
  'g',
);

export function leadingLiteralSegment(expression: string): string | undefined {
  const match = /^\s*(['"`])((?:[^'"`\\$]|\\.|\$(?!\{))*)/.exec(expression.trim());
  if (match === null) return undefined;
  return match[2] ?? '';
}

export function valueAlternatives(expression: string): string[] {
  const parts: string[] = [];
  let current = '';
  let depth = 0;
  let quote: string | undefined;
  let templateDepth = 0;
  for (let i = 0; i < expression.length; i += 1) {
    const ch = expression[i] ?? '';
    const previous = expression[i - 1];
    if (quote !== undefined) {
      current += ch;
      if (ch === quote && previous !== '\\') {
        if (quote === '`' && templateDepth > 0) {  } else quote = undefined;
      } else if (quote === '`' && ch === '{' && previous === '$') templateDepth += 1;
      else if (quote === '`' && ch === '}' && templateDepth > 0) templateDepth -= 1;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; current += ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') depth += 1;
    if (ch === ')' || ch === ']' || ch === '}') depth -= 1;
    if (depth === 0) {
      if (ch === '?' && expression[i + 1] !== '?' && expression[i - 1] !== '?') { parts.push(current); current = ''; continue; }
      if (ch === ':' && expression[i + 1] !== ':') { parts.push(current); current = ''; continue; }
      if (ch === '|' && expression[i + 1] === '|') { parts.push(current); current = ''; i += 1; continue; }
      if (ch === '?' && expression[i + 1] === '?') { parts.push(current); current = ''; i += 1; continue; }
    }
    current += ch;
  }
  parts.push(current);
  const alternatives = parts.map((part) => part.trim()).filter((part) => part !== '');
  if (alternatives.length > 1 && /(?<!\?)\?(?!\?)/.test(expression)) alternatives.shift();
  return alternatives;
}

export function isSafeRelativeLiteral(value: string): boolean {
  if (!value.startsWith('/')) return false;
  if (value.startsWith('//')) return false;
  if (value.startsWith('/\\') || value.startsWith('/%2f') || value.startsWith('/%5c')) return false;
  if (/^\/[a-z][a-z0-9+.-]*:/i.test(value)) return false;
  return true;
}

export function hasRelativePathHead(argText: string): boolean {
  const head = leadingLiteralSegment(argText);
  return head !== undefined && head !== '' && isSafeRelativeLiteral(head);
}

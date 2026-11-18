export function stripComments(content: string): string {
  let out = '';
  let i = 0;
  let quote: string | undefined;
  while (i < content.length) {
    const ch = content[i];
    if (quote !== undefined) {
      out += ch;
      if (ch === '\\' && i + 1 < content.length) {
        out += content[i + 1];
        i += 2;
        continue;
      }
      if (ch === quote) quote = undefined;
      i += 1;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      out += ch;
      i += 1;
      continue;
    }
    if (ch === '/' && content[i + 1] === '/') {
      while (i < content.length && content[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '/' && content[i + 1] === '*') {
      i += 2;
      while (i < content.length && !(content[i] === '*' && content[i + 1] === '/')) {
        if (content[i] === '\n') out += '\n';
        i += 1;
      }
      i += 2;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

export function isInsideComment(content: string, index: number): boolean {
  const lineStart = content.lastIndexOf('\n', index - 1) + 1;
  const before = content.slice(lineStart, index);
  if (/\/\//.test(stripStringsRough(before))) return true;
  const lastOpen = content.lastIndexOf('/*', index);
  if (lastOpen === -1) return false;
  const lastClose = content.lastIndexOf('*/', index);
  return lastClose < lastOpen;
}

function stripStringsRough(line: string): string {
  return line.replace(/'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`/g, '""');
}

export function splitTopLevelArguments(argText: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote: string | undefined;
  let start = 0;
  for (let i = 0; i < argText.length; i += 1) {
    const ch = argText[i];
    if (quote !== undefined) {
      if (ch === '\\') i += 1;
      else if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') depth += 1;
    else if (ch === ')' || ch === ']' || ch === '}') depth -= 1;
    else if (ch === ',' && depth === 0) {
      parts.push(argText.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(argText.slice(start));
  return parts;
}

export function lineOfIndex(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i += 1) {
    if (content[i] === '\n') line += 1;
  }
  return line;
}

export function sourceLineAt(content: string, line: number): string {
  let current = 1;
  let start = 0;
  while (current < line) {
    const next = content.indexOf('\n', start);
    if (next === -1) return '';
    start = next + 1;
    current += 1;
  }
  const end = content.indexOf('\n', start);
  return (end === -1 ? content.slice(start) : content.slice(start, end)).trim();
}

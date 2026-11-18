const MAX_SPAN = 4000;

export interface Region {
  start: number;
  end: number;
  name: string;
}

export function insideRegion(regions: readonly Region[], index: number): Region | undefined {
  return regions.find((region) => index >= region.start && index < region.end);
}

export function payloadRegions(content: string, emitter: RegExp): Region[] {
  const regions: Region[] = [];
  for (const match of matchAll(content, emitter)) {
    const open = match.index + match[0].length;
    const end = closingOffset(content, open, '(', ')');
    if (end === undefined) continue;
    regions.push({ start: open, end, name: '' });
  }
  return regions;
}

const JSX_OPENING_TAG = /<([A-Z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*)(?=[\s/>])/g;

export function jsxElementRegions(content: string): Region[] {
  const regions: Region[] = [];
  for (const match of matchAll(content, JSX_OPENING_TAG)) {
    const start = match.index + match[0].length;
    const end = openingTagEnd(content, start);
    if (end === undefined) continue;
    regions.push({ start, end, name: match[1] ?? '' });
  }
  return regions;
}

function matchAll(content: string, pattern: RegExp): RegExpExecArray[] {
  if (!pattern.global) throw new Error(`emittedValue requires a global regex, got: ${pattern}`);
  const found: RegExpExecArray[] = [];
  pattern.lastIndex = 0;
  let match = pattern.exec(content);
  while (match !== null) {
    found.push(match);
    if (match.index === pattern.lastIndex) pattern.lastIndex += 1;
    match = pattern.exec(content);
  }
  pattern.lastIndex = 0;
  return found;
}

function closingOffset(content: string, from: number, open: string, close: string): number | undefined {
  let depth = 1;
  const limit = Math.min(content.length, from + MAX_SPAN);
  let at = from;
  while (at < limit) {
    const character = content[at];
    if (character === '"' || character === "'" || character === '`') {
      const after = skipQuoted(content, at, character, limit);
      if (after === undefined) return undefined;
      at = after;
      continue;
    }
    if (character === open) depth += 1;
    else if (character === close) {
      depth -= 1;
      if (depth === 0) return at;
    }
    at += 1;
  }
  return undefined;
}

function openingTagEnd(content: string, from: number): number | undefined {
  let depth = 0;
  const limit = Math.min(content.length, from + MAX_SPAN);
  let at = from;
  while (at < limit) {
    const character = content[at];
    if (character === '"' || character === "'" || character === '`') {
      const after = skipQuoted(content, at, character, limit);
      if (after === undefined) return undefined;
      at = after;
      continue;
    }
    if (character === '{') depth += 1;
    else if (character === '}') depth -= 1;
    else if (character === '>' && depth === 0) return at;
    at += 1;
  }
  return undefined;
}

function skipQuoted(content: string, at: number, quote: string, limit: number): number | undefined {
  let cursor = at + 1;
  while (cursor < limit) {
    if (content[cursor] === '\\') {
      cursor += 2;
      continue;
    }
    if (content[cursor] === quote) return cursor + 1;
    cursor += 1;
  }
  return undefined;
}

export function balancedEnd(content: string, from: number, open: string, close: string): number | undefined {
  return closingOffset(content, from, open, close);
}

import { isPythonTestModule } from '../input/fileFilters.js';

const MAX_PYTHON_ARGUMENT_CHARS = 4000;

export function pythonCallArguments(content: string, open: number): string | undefined {
  let depth = 0;
  const limit = Math.min(content.length, open + MAX_PYTHON_ARGUMENT_CHARS);
  for (let i = open; i < limit; i += 1) {
    const c = content[i];
    if (c === '"' || c === "'") {
      const quote = content.startsWith(c.repeat(3), i) ? c.repeat(3) : c;
      let j = i + quote.length;
      while (j < limit && !content.startsWith(quote, j)) j += content[j] === '\\' ? 2 : 1;
      i = j + quote.length - 1;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') {
      depth -= 1;
      if (depth === 0) return c === ')' ? content.slice(open + 1, i) : undefined;
    }
  }
  return undefined;
}

const NON_PRODUCTION_CLASS = /^(?:Dev|Devel|Development|Local|Test|Testing)(?:Config|Configuration|Settings|Conf)?$/;

const NON_PRODUCTION_MODULE =
  /^(?:(?:settings|config)[_.-](?:dev|devel|development|local|test|testing)|(?:dev|devel|development|local|test|testing)[_.-](?:settings|config)|local_settings)$/i;
const NON_PRODUCTION_LEAF = /^(?:dev|devel|development|local|test|tests|testing)$/i;
const SETTINGS_PACKAGE = /^(?:settings|config|configs|conf)$/i;

const TEST_SETTINGS_CALL = /\b(?:override_settings|modify_settings)\s*\(/g;

function moduleIsNonProduction(filePath: string): boolean {
  const parts = filePath.replace(/\\/g, '/').split('/').filter((part) => part !== '');
  const file = parts[parts.length - 1] ?? '';
  if (!file.endsWith('.py')) return false;
  const leaf = file.slice(0, -3);
  const parent = parts[parts.length - 2] ?? '';
  if (NON_PRODUCTION_MODULE.test(leaf) || isPythonTestModule(file)) return true;
  if (NON_PRODUCTION_LEAF.test(leaf) && SETTINGS_PACKAGE.test(parent)) return true;
  return false;
}

function enclosingClassName(content: string, index: number): string | undefined {
  const lineStart = content.lastIndexOf('\n', index - 1) + 1;
  const ownIndent = /^[ \t]*/.exec(content.slice(lineStart))?.[0].length ?? 0;
  if (ownIndent === 0) return undefined;
  let cursor = lineStart - 1;
  while (cursor > 0) {
    const start = content.lastIndexOf('\n', cursor - 1) + 1;
    const line = content.slice(start, cursor);
    cursor = start - 1;
    if (line.trim() === '' || /^\s*#/.test(line)) continue;
    const indent = /^[ \t]*/.exec(line)?.[0].length ?? 0;
    if (indent >= ownIndent) continue;
    return /^\s*class\s+([A-Za-z_]\w*)/.exec(line)?.[1];
  }
  return undefined;
}

function insideTestSettingsCall(content: string, index: number): boolean {
  for (const match of content.matchAll(TEST_SETTINGS_CALL)) {
    if (match.index > index) break;
    const open = match.index + match[0].length - 1;
    const args = pythonCallArguments(content, open);
    if (args !== undefined && index > open && index <= open + args.length) return true;
  }
  return false;
}

export function isPythonNonProductionSetting(filePath: string, content: string, index: number): boolean {
  if (moduleIsNonProduction(filePath)) return true;
  const className = enclosingClassName(content, index);
  if (className !== undefined && NON_PRODUCTION_CLASS.test(className)) return true;
  return insideTestSettingsCall(content, index);
}

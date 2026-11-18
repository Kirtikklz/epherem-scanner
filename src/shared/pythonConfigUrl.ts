import { FIXED_HOST_LITERAL } from './fixedUrlPrefix.js';
import { pythonCallArguments } from './pythonFlow.js';
import { maskPython } from './pythonGuards.js';

const MAX_DEPTH = 3;
const ENV_READ = /^os\s*\.\s*(?:environ\s*(?:\[[^\]\n]+\]|\.\s*get\s*\([^()\n]*\))|getenv\s*\([^()\n]*\))$/;
const SETTINGS_READ = /^settings\s*\.\s*[A-Za-z_]\w*$/;
const SETTINGS_GETATTR = /^getattr\s*\(\s*settings\s*,\s*(['"])[A-Za-z_]\w*\1\s*(?:,\s*(?:None|(['"])[^'"\n]*\2))?\s*\)$/;
const DJANGO_SETTINGS_IMPORT = /^\s*from\s+django\.conf\s+import\s+(?:\(?\s*)?(?:[^\n]*,\s*)?settings\b(?!\s+as\b)/m;
const STRIP_CALL = /^(.+?)\s*\.\s*(?:rstrip|strip|lstrip)\s*\(\s*(?:(['"])[^'"\n]*\2)?\s*\)$/;
const STR_CALL = /^str\s*\(\s*(.+)\s*\)$/;
const OR_LITERAL = /^(.+?)\s+or\s+([rubf]{0,2}(['"])[^'"\n]*\3)$/i;
const SEPARATOR_START = /^[rubRUB]{0,2}(['"])[/?#]/;

function djangoSettingsProven(masked: string): boolean {
  if (!DJANGO_SETTINGS_IMPORT.test(masked)) return false;
  const other = /^\s*settings\s*(?::[^=\n]+)?=(?!=)|\bas\s+settings\b|\bfor\s+settings\b|\bdef\s+\w+\s*\([^)]*\bsettings\b|\bimport\s+[^\n]*\bsettings\b/gm;
  let binds = 0;
  for (const match of masked.matchAll(other)) {
    const lineStart = masked.lastIndexOf('\n', match.index) + 1;
    const line = masked.slice(lineStart, masked.indexOf('\n', match.index) === -1 ? undefined : masked.indexOf('\n', match.index));
    if (/^\s*from\s+django\.conf\s+import\b/.test(line)) continue;
    binds += 1;
  }
  return binds === 0;
}

interface Reader { raw: string; masked: string; settings: boolean }

function escape(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function assignments(reader: Reader, name: string): string[] | undefined {
  const target = escape(name).replace(/\\\./g, String.raw`\s*\.\s*`);
  const bare = !name.includes('.');
  const otherBinding = bare
    ? new RegExp(String.raw`\bfor\s+(?:[^\n]*[\s,(])?${target}\b[^\n]*\bin\b|\bas\s+${target}\b|\bdef\s+\w+\s*\([^)]*(?<![\w.])${target}\b|(?<![\w.])${target}\s*(?:\+|-|\*|\/|%|\||&|\^|<<|>>|\/\/|\*\*)=|\bimport\b[^\n]*(?<![\w.])${target}\b|\bglobal\s+[^\n]*\b${target}\b|\b${target}\s*:=`)
    : new RegExp(String.raw`(?<![\w.])${target}\s*(?:\+|-|\*|\/|%|\||&|\^|<<|>>|\/\/|\*\*)=|\bsetattr\s*\(\s*self\b`);
  if (otherBinding.test(reader.masked)) return undefined;
  const assign = new RegExp(String.raw`^[ \t]*${target}[ \t]*(?::[^=\n]+)?=(?!=)[ \t]*([^\n]+)$`, 'gm');
  const out: string[] = [];
  for (const match of reader.masked.matchAll(assign)) {
    const start = match.index + match[0].length - match[1]!.length;
    out.push(reader.raw.slice(start, start + match[1]!.length).trim());
  }
  const unpack = new RegExp(String.raw`^[ \t]*[^\n=]*,[ \t]*${target}[ \t]*=(?!=)|^[ \t]*${target}[ \t]*,[^\n=]*=(?!=)|=[ \t]*${target}[ \t]*=(?!=)`, 'm');
  if (unpack.test(reader.masked)) return undefined;
  return out;
}

function configuredValue(reader: Reader, expression: string, depth: number): boolean {
  const text = expression.trim();
  if (text === '' || depth > MAX_DEPTH) return false;
  if (ENV_READ.test(text)) return true;
  if (reader.settings && (SETTINGS_READ.test(text) || SETTINGS_GETATTR.test(text))) return true;
  if (FIXED_HOST_LITERAL.test(text.replace(/^[rubfRUBF]{1,2}(?=['"])/, ''))) return true;
  const stripped = STRIP_CALL.exec(text) ?? STR_CALL.exec(text);
  if (stripped !== null) return configuredValue(reader, stripped[1]!, depth + 1);
  const fallback = OR_LITERAL.exec(text);
  if (fallback !== null) {
    return configuredValue(reader, fallback[1]!, depth + 1) && configuredValue(reader, fallback[2]!, depth + 1);
  }
  const name = /^(?:self\s*\.\s*)?[A-Za-z_]\w*$/.test(text) ? text.replace(/\s+/g, '') : undefined;
  if (name === undefined || name === 'settings' || name === 'self') return false;
  const rhs = assignments(reader, name);
  return rhs !== undefined && rhs.length > 0 && rhs.every((value) => configuredValue(reader, value, depth + 1));
}

function headConfigured(reader: Reader, url: string, depth: number): boolean {
  const text = url.trim();
  if (configuredValue(reader, text, depth)) return true;
  const fString = /^[rR]?[fF][rR]?(['"]{1,3})\{([^{}:!]+)\}([\s\S]*)$/.exec(text);
  if (fString !== null) {
    const after = fString[3]!;
    if (!/^[/?#]/.test(after) && !after.startsWith(fString[1]!)) return false;
    return configuredValue(reader, fString[2]!, depth);
  }
  const plus = /^([^+]+?)\s*\+\s*([\s\S]+)$/.exec(text);
  if (plus !== null && SEPARATOR_START.test(plus[2]!.trim())) return configuredValue(reader, plus[1]!, depth);
  if (/^[A-Za-z_]\w*$/.test(text) && depth < MAX_DEPTH) {
    const rhs = assignments(reader, text);
    return rhs !== undefined && rhs.length > 0 && rhs.every((value) => headConfigured(reader, value, depth + 1));
  }
  return false;
}

export function pythonUrlHostConfigured(content: string, sinkIndex: number, isMethodLiteral: (text: string) => boolean): boolean {
  const open = content.indexOf('(', sinkIndex);
  if (open === -1) return false;
  const args = pythonCallArguments(content, open);
  const url = args.find((a) => a.keyword === 'url')
    ?? args.find((a) => a.keyword === undefined && !isMethodLiteral(content.slice(a.start, a.end)));
  if (url === undefined) return false;
  const masked = maskPython(content);
  const reader: Reader = { raw: content, masked, settings: djangoSettingsProven(masked) };
  return headConfigured(reader, content.slice(url.start, url.end), 0);
}

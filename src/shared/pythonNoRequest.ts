import { isPythonTestModule } from '../input/fileFilters.js';
import type { FileMapEntry, RuleContext } from './types.js';
import { maskPython } from './pythonGuards.js';

const COMMAND_PATH = /(?:^|\/)management\/commands\/([A-Za-z]\w*)\.py$/;
const COMMAND_CLASS = /^class\s+Command\s*\(([^)]*)\)\s*:/m;

function commandName(filePath: string): string | undefined {
  return COMMAND_PATH.exec(filePath.replace(/\\/g, '/'))?.[1];
}

const IMPORT_STATEMENT = /^[ \t]*(?:from[ \t]+[\w.]+[ \t]+import[ \t]+(?:\([^)]*\)|[^\n]*)|import[ \t]+[^\n]*)/gm;
const testOnlyCache = new WeakMap<object, Map<string, boolean>>();

function testOnly(context: RuleContext, entry: FileMapEntry): boolean {
  if (!isPythonTestModule(entry.path)) return false;
  let cache = testOnlyCache.get(context.fileMap);
  if (cache === undefined) { cache = new Map(); testOnlyCache.set(context.fileMap, cache); }
  const known = cache.get(entry.path);
  if (known !== undefined) return known;
  const stem = /([^/\\]+)\.py$/.exec(entry.path)![1]!;
  const names = new RegExp(String.raw`\b${stem}\b`);
  const only = !context.fileMap.entries.some((other) => other.extension === '.py' && other.path !== entry.path
    && !isPythonTestModule(other.path) && (other.content ?? '').includes(stem)
    && [...maskPython(other.content ?? '').matchAll(IMPORT_STATEMENT)].some((statement) => names.test(statement[0])));
  cache.set(entry.path, only);
  return only;
}

const namelessCache = new WeakMap<object, boolean>();
function namelessCallCommand(context: RuleContext): boolean {
  const known = namelessCache.get(context.fileMap);
  if (known !== undefined) return known;
  const nameless = context.fileMap.entries.some((other) => other.extension === '.py' && commandName(other.path) === undefined
    && (other.content ?? '').includes('call_command') && !testOnly(context, other)
    && /\bcall_command\s*\(\s*(?![rRbBuU]{0,2}['"])/.test(maskPython(other.content ?? '')));
  namelessCache.set(context.fileMap, nameless);
  return nameless;
}

export function isUnreachedDjangoCommand(context: RuleContext, entry: FileMapEntry): boolean {
  const name = commandName(entry.path);
  if (name === undefined) return false;
  const bases = COMMAND_CLASS.exec(maskPython(entry.content))?.[1];
  if (bases === undefined || !bases.split(',').some((base) => /Command\s*$/.test(base.trim()))) return false;
  const imported = new RegExp(String.raw`\bmanagement\s*\.\s*commands\s*\.\s*${name}\b|\bmanagement\s*\.\s*commands\s+import\s+(?:[^\n]*[\s,(])?${name}\b`);
  const called = new RegExp(String.raw`\bcall_command\s*\(\s*(?:[rbu]?)(['"])${name}\1`);
  if (namelessCallCommand(context)) return false;
  for (const other of context.fileMap.entries) {
    if (other.extension !== '.py' || other.path === entry.path) continue;
    if (commandName(other.path) !== undefined || testOnly(context, other)) continue;
    const text = other.content ?? '';
    if (!text.includes(name)) continue;
    if (imported.test(text) || called.test(text)) return false;
  }
  return true;
}

export function pythonFileNoRequestRuns(context: RuleContext, entry: FileMapEntry): boolean {
  if (entry.extension !== '.py') return false;
  return isPythonTestModule(entry.path) || isUnreachedDjangoCommand(context, entry);
}

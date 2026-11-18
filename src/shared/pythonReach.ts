import type { RuleContext } from './types.js';
import { pythonHandlerSpan, pythonRouteGuard } from './pythonGuards.js';
import { enclosingDef, indentOf, maskedLines, scopeOfDef, type PyScope } from './pythonScope.js';

interface Reach { reachable: Set<string>; complete: boolean }

const DEF_LINE = /^(\s*)(?:async\s+)?def\s+(\w+)\s*\(/;
const REGISTERS = /\b(?:add_url_rule|add_api_route|add_route|add_websocket_route|register\w*|connect|subscribe|on|route|view_func|handler|callback|signal|schedule\w*)\b\s*[(=]/;
const keyOf = (path: string, line: number): string => `${path}:${line}`;

const cache = new WeakMap<object, Reach>();

function computeReach(context: RuleContext): Reach {
  const entries = context.fileMap.entries.filter((entry) => entry.extension === '.py');
  const routes = context.projectMap.apiRoutes.filter((route) => route.filePath.endsWith('.py'));
  const django = entries.some((entry) => /^\s*(?:from|import)\s+(?:django|rest_framework)\b/m.test(entry.content ?? ''));
  if (routes.length === 0 || django) return { reachable: new Set(), complete: false };

  const defs: { path: string; scope: PyScope; lines: string[] }[] = [];
  const byName = new Map<string, { path: string; scope: PyScope; lines: string[] }[]>();
  const roots = new Set<string>();
  const handlerDefs = new Map<string, boolean>();
  for (const route of routes) {
    const entry = entries.find((candidate) => candidate.path === route.filePath);
    const span = pythonHandlerSpan(context, route);
    if (entry === undefined || span === undefined) continue;
    const lines = maskedLines(entry.content ?? '');
    for (let l = span.startLine; l <= span.endLine; l += 1) {
      if (!DEF_LINE.test(lines[l - 1] ?? '')) continue;
      const admin = pythonRouteGuard(context, route)?.level === 'admin';
      const key = keyOf(entry.path, l);
      handlerDefs.set(key, (handlerDefs.get(key) ?? true) && admin);
      break;
    }
  }
  for (const entry of entries) {
    const lines = maskedLines(entry.content ?? '');
    const classIndents: { indent: number; based: boolean }[] = [];
    lines.forEach((text, i) => {
      if (text.trim() === '') return;
      const indent = indentOf(text);
      while (classIndents.length > 0 && classIndents.at(-1)!.indent >= indent) classIndents.pop();
      const cls = /^\s*class\s+\w+\s*(\(([^)]*)\))?\s*:/.exec(text);
      if (cls !== null) {
        const bases = (cls[2] ?? '').trim();
        classIndents.push({ indent, based: bases !== '' && bases !== 'object' });
        return;
      }
      const m = DEF_LINE.exec(text);
      if (m === null) return;
      const scope = scopeOfDef(lines, i + 1);
      if (scope === undefined) return;
      const def = { path: entry.path, scope, lines };
      defs.push(def);
      const list = byName.get(scope.name) ?? [];
      list.push(def);
      byName.set(scope.name, list);
      const key = keyOf(entry.path, i + 1);
      const handler = handlerDefs.get(key);
      if (handler === false) roots.add(key);
      if (handler === undefined) {
        let p = i - 1;
        while (p >= 0 && (lines[p] ?? '').trim() === '') p -= 1;
        if (/^\s*@/.test(lines[p] ?? '')) roots.add(key);
        if (classIndents.some((c) => c.based && c.indent < indent)) roots.add(key);
      }
    });
  }
  for (const entry of entries) {
    const lines = maskedLines(entry.content ?? '');
    for (const text of lines) {
      if (!REGISTERS.test(text)) continue;
      for (const word of text.matchAll(/\b([A-Za-z_]\w*)\b/g)) {
        for (const def of byName.get(word[1]!) ?? []) roots.add(keyOf(def.path, def.scope.defLine));
      }
    }
  }
  const reachable = new Set(roots);
  const queue = defs.filter((def) => roots.has(keyOf(def.path, def.scope.defLine)));
  while (queue.length > 0) {
    const def = queue.pop()!;
    const body = def.lines.slice(def.scope.defLine, def.scope.endLine).join('\n');
    for (const word of new Set([...body.matchAll(/\b([A-Za-z_]\w*)\b/g)].map((m) => m[1]!))) {
      for (const target of byName.get(word) ?? []) {
        const key = keyOf(target.path, target.scope.defLine);
        if (reachable.has(key)) continue;
        reachable.add(key);
        queue.push(target);
      }
    }
    for (const nested of defs) {
      if (nested.path !== def.path || nested.scope.defLine <= def.scope.defLine || nested.scope.endLine > def.scope.endLine) continue;
      const key = keyOf(nested.path, nested.scope.defLine);
      if (!reachable.has(key)) { reachable.add(key); queue.push(nested); }
    }
  }
  return { reachable, complete: true };
}

export function pythonUnreachableFromRequests(context: RuleContext, filePath: string, content: string, line: number): boolean {
  let reach = cache.get(context.fileMap);
  if (reach === undefined) { reach = computeReach(context); cache.set(context.fileMap, reach); }
  if (!reach.complete) return false;
  const lines = maskedLines(content);
  let scope = enclosingDef(lines, line);
  if (scope === undefined) return false;
  while (scope !== undefined) {
    if (reach.reachable.has(keyOf(filePath, scope.defLine))) return false;
    scope = scope.defLine > 1 ? enclosingDef(lines, scope.defLine) : undefined;
  }
  return true;
}

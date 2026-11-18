import type { ApiRoute, RuleContext } from './types.js';
import { pythonHandlerSpan } from './pythonGuards.js';
import { defsNamed, indentOf, maskedLines } from './pythonScope.js';

const STATIC_SENSITIVE = /login|signin|sign-in|auth(?!or(?:s|ed|ing|ship)?(?![a-z]))|password|forgot|otp|verify|register|signup|sign-up|token|checkout|payment/i;
const REFUSES_429 = /\b429\b|TOO_MANY_REQUESTS/;
const REFUSING_LINE = /\b(?:raise|return|abort|status_code|status)\b/;
const PATH_PARAMETER = /\{[^}]*\}|<[^>]*>/g;

export function pythonRouteIsSensitive(route: ApiRoute): boolean {
  if (pathIsSensitive(route.declaredPath ?? route.routePath)) return true;
  if (route.declaredPath === undefined) return false;
  const last = route.routePath.replace(PATH_PARAMETER, '').split('/').filter(Boolean).pop();
  return last !== undefined && STATIC_SENSITIVE.test(last);
}

function pathIsSensitive(routePath: string): boolean {
  const path = routePath.replace(PATH_PARAMETER, '');
  if (STATIC_SENSITIVE.test(path)) return true;
  const segments = path.split('/').filter(Boolean);
  return segments.some((segment, i) => /^sessions?$/i.test(segment)
    || (/^reset/i.test(segment) && (i === 0 || /auth|account|password|user|login/i.test(segments[i - 1]!))));
}

function bodyRefuses429(lines: string[], from: number, to: number): boolean {
  for (let l = from; l <= to; l += 1) {
    const text = lines[l - 1] ?? '';
    if (REFUSES_429.test(text) && REFUSING_LINE.test(text)) return true;
  }
  return false;
}

interface ProjectLimits { limiterNames: Set<string>; appWide: boolean }
const projectCache = new WeakMap<object, ProjectLimits>();

function projectLimits(context: RuleContext): ProjectLimits {
  const cached = projectCache.get(context.fileMap);
  if (cached !== undefined) return cached;
  const limiterNames = new Set<string>();
  let appWide = false;
  const entries = context.fileMap.entries.filter((entry) => entry.extension === '.py');
  for (const entry of entries) {
    const content = entry.content ?? '';
    const lines = maskedLines(content);
    const imports = /^\s*from\s+(?:flask_limiter|slowapi)(?:\.\w+)*\s+import\b[^\n]*\bLimiter\b/m.test(content);
    lines.forEach((text) => {
      const bound = /^\s*(\w+)\s*(?::[^=]+)?=\s*Limiter\s*\(/.exec(text);
      if (bound !== null && imports) limiterNames.add(bound[1]!);
    });
    if (imports) {
      const code = lines.join('\n');
      for (const m of code.matchAll(/\bLimiter\s*\(/g)) {
        const call = code.slice(m.index, m.index + 600);
        if (/default_limits\s*=\s*\[\s*[^\]\s]/.test(call)) appWide = true;
      }
    }
    for (const text of lines) {
      const middleware = /\.\s*add_middleware\s*\(\s*([A-Za-z_]\w*)/.exec(text);
      if (middleware === null) continue;
      for (const other of entries) {
        const otherLines = maskedLines(other.content ?? '');
        otherLines.forEach((line, i) => {
          if (!new RegExp(`^\\s*class\\s+${middleware[1]}\\b`).test(line)) return;
          const indent = indentOf(line);
          let end = i + 1;
          while (end < otherLines.length && ((otherLines[end] ?? '').trim() === '' || indentOf(otherLines[end] ?? '') > indent)) end += 1;
          if (bodyRefuses429(otherLines, i + 2, end)) appWide = true;
        });
      }
    }
  }
  const limits = { limiterNames, appWide };
  projectCache.set(context.fileMap, limits);
  return limits;
}

export function pythonRouteRateLimited(context: RuleContext, route: ApiRoute): boolean {
  const limits = projectLimits(context);
  if (limits.appWide) return true;
  const entry = context.fileMap.entries.find((candidate) => candidate.path === route.filePath);
  const span = pythonHandlerSpan(context, route);
  if (entry === undefined || span === undefined) return false;
  const lines = maskedLines(entry.content ?? '');
  let defLine = span.startLine;
  while (defLine <= span.endLine && !/^\s*(?:async\s+)?def\s/.test(lines[defLine - 1] ?? '')) defLine += 1;
  for (let l = span.startLine; l < defLine; l += 1) {
    const decorator = /^\s*@(\w+)\s*\.\s*(?:limit|shared_limit)\s*\(/.exec(lines[l - 1] ?? '');
    if (decorator !== null && limits.limiterNames.has(decorator[1]!)) return true;
  }
  if (bodyRefuses429(lines, defLine + 1, span.endLine)) return true;
  const body = lines.slice(defLine, span.endLine).join('\n');
  for (const call of new Set([...body.matchAll(/(?<![\w])(?:[A-Za-z_]\w*\s*\.\s*)*([A-Za-z_]\w*)\s*\(/g)].map((m) => m[1]!))) {
    for (const other of context.fileMap.entries) {
      if (other.extension !== '.py' || !(other.content ?? '').includes(`def ${call}`)) continue;
      const otherLines = maskedLines(other.content ?? '');
      for (const def of defsNamed(otherLines, call)) {
        if (bodyRefuses429(otherLines, def.defLine + 1, def.endLine)) return true;
      }
    }
  }
  return false;
}

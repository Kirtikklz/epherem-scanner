import { analyzeFileAst, astVerdict, confidenceWithProof, userTaintedLines } from '../../ast/astAnalysis.js';
import { crossFileAstHits } from '../../ast/crossFileTaint.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches, lineAt } from '../../shared/utils.js';
import { referencesUserInput, windowAround } from '../../shared/userInput.js';
import { analyzeTaint, usesUserInput } from '../../shared/taint.js';
import { routeHandlerScopeForLine } from '../../shared/handlerScope.js';
import {
  BASE_CONST_DEF,
  CONFIG_HOST_HEAD,
  ENV_BASE_CONST_DEF,
  FIXED_HOST_LITERAL,
  hasRelativePathHead,
} from '../../shared/fixedUrlPrefix.js';
import { isBrowserServiceWorker } from '../../shared/executionContext.js';
import { stripCommentsAndStrings } from '../../shared/source.js';
import { isPythonTestModule } from '../../input/fileFilters.js';
import { pythonUrlHostConfigured } from '../../shared/pythonConfigUrl.js';
import { pythonCallArguments, pythonCallBindings, pythonCheckActsBefore, pythonDependencyAliases, pythonIdentifiers, pythonMasked, pythonValueReaches } from '../../shared/pythonFlow.js';

const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);

const JS_FETCH_SINK =
  /(?<![.\w$])(?:fetch|nodeFetch|got(?:\.(?:get|post|put|patch|delete|head|stream))?|request|needle(?:\.(?:get|post|put|patch|delete|head))?|ky(?:\.(?:get|post|put|patch|delete))?|axios(?:\.(?:get|post|put|delete|request))?|superagent\.\w+|undici\.(?:fetch|request|stream)|https?\.get)\s*\(/g;
const PY_FETCH_SINK = /\b(?:requests\.(?:get|post|put|delete|head)|urllib\.request\.urlopen|httpx\.(?:get|post|Client))\s*\(/g;
const HOST_ALLOWLIST_GUARD = /(?:allowedHosts?|allowlist|trustedHosts?)\s*\.\s*(?:includes|has)\s*\([^)]*\.hostname|\.hostname\s*={2,3}\s*['"][a-z0-9.-]+['"]|['"][a-z0-9.-]+['"]\s*={2,3}\s*[^;]{0,80}\.hostname/i;
const PROTOCOL_GUARD = /\.protocol\s*={2,3}\s*['"]https?:['"]|\[\s*['"]http:['"]\s*,\s*['"]https:['"]\s*\]\s*\.includes\s*\([^)]*\.protocol/i;
const PRIVATE_IP_GUARD = /(?:127\.0\.0\.1|0\.0\.0\.0|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|localhost|::1|fc00:|fe80:|private|loopback|link-local|metadata)/i;

const HTTP_METHOD_LITERAL = /^['"`](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"`]$/i;

const CURSOR_PROPERTY = String.raw`(?:@odata\.nextLink|nextLink|nextPageUrl|nextPageToken|continuationToken|NextContinuationToken|next)`;

const RESPONSE_BODY_DEF = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]{0,200}?)?=\s*await\s+[\w$]+(?:\s*\.\s*[\w$]+)*?\s*\.\s*json\s*\(\s*\)/g;

const RESPONSE_BODY_DESTRUCTURE = /\b(?:const|let|var)\s*\{([^{}]{0,300})\}\s*(?::[^=\n]{0,200}?)?=\s*await\s+[\w$]+(?:\s*\.\s*[\w$]+)*?\s*\.\s*json\s*\(\s*\)/g;

const DESTRUCTURED_CURSOR_RENAMED = new RegExp(String.raw`['"]?(?:` + CURSOR_PROPERTY + String.raw`)['"]?\s*:\s*([A-Za-z_$][\w$]*)`, 'gi');

const DESTRUCTURED_CURSOR_SHORTHAND = new RegExp(String.raw`(?:^|,)\s*(` + CURSOR_PROPERTY + String.raw`)\s*(?=,|$)`, 'gi');

const CURSOR_READ = new RegExp(
  String.raw`^([A-Za-z_$][\w$]*)\.(?:links\.)?(?:` + CURSOR_PROPERTY + String.raw`)` +
    String.raw`(?:as[\w|<>\[\]'"$.,]{0,80})?` +
    String.raw`(?:(?:\?\?|\|\|)(?:null|undefined|''|""|` + '``' + String.raw`))?$`,
  'i',
);

const NULLISH_RHS = /^\s*(?:null|undefined)\s*$/;

function normalisePropertyAccess(text: string): string {
  return text
    .replace(/\s+/g, '')
    .replace(/\[\s*['"]([^'"\]]+)['"]\s*\]/g, '.$1')
    .replace(/\?\./g, '.')
    .replace(/\.{2,}/g, '.');
}

function cursorSourceObject(rhs: string): string | undefined {
  const match = normalisePropertyAccess(rhs).match(CURSOR_READ);
  return match?.[1];
}

function collectResponseBodyIdentifiers(content: string): ReadonlySet<string> {
  const bodies = new Set<string>();
  for (const match of content.matchAll(RESPONSE_BODY_DEF)) {
    const name = match[1];
    if (name === undefined || referencesUserInput(match[0])) continue;
    bodies.add(name);
  }
  return bodies;
}

function collectDestructuredCursors(content: string): ReadonlySet<string> {
  const names = new Set<string>();
  for (const match of content.matchAll(RESPONSE_BODY_DESTRUCTURE)) {
    const pattern = match[1];
    if (pattern === undefined || referencesUserInput(match[0])) continue;
    for (const renamed of pattern.matchAll(DESTRUCTURED_CURSOR_RENAMED)) {
      if (renamed[1] !== undefined) names.add(renamed[1]);
    }
    for (const shorthand of pattern.matchAll(DESTRUCTURED_CURSOR_SHORTHAND)) {
      if (shorthand[1] !== undefined) names.add(shorthand[1]);
    }
  }
  return names;
}

function assignmentsTo(content: string, name: string): string[] {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(
    String.raw`(?:\b(?:const|let|var)\s+${escaped}\s*(?::[^=;\n]{0,120})?|(?<![.\w$?])${escaped}\s*)=(?!=)([^;\n]{0,240})`,
    'g',
  );
  const found: string[] = [];
  for (const match of content.matchAll(pattern)) {
    if (match[1] !== undefined) found.push(match[1].trim());
  }
  return found;
}

function hasUnreadableAssignment(content: string, name: string): boolean {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const compound = new RegExp(String.raw`(?<![.\w$])${escaped}\s*(?:\+|-|\*|\/|%|\*\*|\|\||&&|\?\?|&|\||\^|<<|>>>?)=(?!=)`);
  const iteration = new RegExp(String.raw`\b(?:const|let|var)\s+${escaped}\s+(?:of|in)\b`);
  return compound.test(content) || iteration.test(content);
}

function collectFixedHostConstants(context: RuleContext): Map<string, ReadonlySet<string>> {
  const byFile = new Map<string, ReadonlySet<string>>();
  for (const entry of context.fileMap.entries) {
    const fixed = new Set<string>();
    for (const definition of [BASE_CONST_DEF, ENV_BASE_CONST_DEF]) {
      for (const match of entry.content.matchAll(definition)) {
        const name = match[1];
        const rhs = match[2] ?? '';
        if (name === undefined) continue;
        if (referencesUserInput(rhs)) continue;
        fixed.add(name);
      }
    }
    for (const name of creditedCursorIdentifiers(entry.content, fixed)) fixed.add(name);
    if (fixed.size > 0) byFile.set(entry.path, fixed);
  }
  return byFile;
}

function creditedCursorIdentifiers(content: string, fixedHostConstants: ReadonlySet<string>): string[] {
  const responseBodies = collectResponseBodyIdentifiers(content);
  const candidates = new Set<string>(collectDestructuredCursors(content));
  if (responseBodies.size > 0) {
    for (const body of responseBodies) {
      for (const match of content.matchAll(
        new RegExp(
          String.raw`(?:\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]{0,120})?|(?<![.\w$?])([A-Za-z_$][\w$]*)\s*)=(?!=)([^;\n]{0,240})`,
          'g',
        ),
      )) {
        const name = match[1] ?? match[2];
        const rhs = match[3];
        if (name === undefined || rhs === undefined) continue;
        if (cursorSourceObject(rhs) === body) candidates.add(name);
      }
    }
  }
  const credited: string[] = [];
  for (const name of candidates) {
    if (fixedHostConstants.has(name)) continue;
    if (hasUnreadableAssignment(content, name)) continue;
    const assignments = assignmentsTo(content, name);
    const allTrusted = assignments.every((rhs) => {
      const source = cursorSourceObject(rhs);
      if (source !== undefined && responseBodies.has(source)) return true;
      if (NULLISH_RHS.test(rhs)) return true;
      return hasFixedTrustedHost(rhs, fixedHostConstants);
    });
    if (allTrusted) credited.push(name);
  }
  return credited;
}

function hasStrongSsrfControls(scope: string): boolean {
  return HOST_ALLOWLIST_GUARD.test(scope) && (PROTOCOL_GUARD.test(scope) || PRIVATE_IP_GUARD.test(scope) || /new\s+URL\s*\(/.test(scope));
}

function hasDestructuringBinding(content: string, name: string): boolean {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(String.raw`\b(?:const|let|var)\s*[{[][^}\]]{0,200}\b${escaped}\b[^}\]]{0,200}[}\]]\s*=`).test(content);
}

function soleIdentifier(argText: string): string | undefined {
  const trimmed = argText.trim();
  const direct = /^([A-Za-z_$][\w$]*)$/.exec(trimmed);
  if (direct?.[1] !== undefined) return direct[1];
  const rendered = /^(?:String\s*\(\s*([A-Za-z_$][\w$]*)\s*\)|([A-Za-z_$][\w$]*)\s*\.\s*toString\s*\(\s*\))$/.exec(trimmed);
  return rendered?.[1] ?? rendered?.[2];
}

function urlConstructorArguments(argText: string): string[] | undefined {
  const trimmed = argText.trim();
  const match = /^new\s+URL\s*\(/.exec(trimmed);
  if (match === null) return undefined;
  return topLevelArguments(trimmed, match[0].length - 1);
}

function hasFixedTrustedHost(
  argText: string,
  fixedHostConstants: ReadonlySet<string> | undefined,
  content?: string,
  depth = 0,
): boolean {
  if (FIXED_HOST_LITERAL.test(argText)) return true;
  if (CONFIG_HOST_HEAD.test(argText)) return true;
  if (hasRelativePathHead(argText)) return true;
  if (depth < 3) {
    const constructed = urlConstructorArguments(argText);
    if (constructed !== undefined && constructed.length > 0) {
      const first = constructed[0] ?? '';
      const base = constructed[1];
      if (FIXED_HOST_LITERAL.test(first) || CONFIG_HOST_HEAD.test(first)) return true;
      if (base !== undefined) return hasFixedTrustedHost(base, fixedHostConstants, content, depth + 1);
      return hasFixedTrustedHost(first, fixedHostConstants, content, depth + 1);
    }
    const identifier = soleIdentifier(argText);
    if (identifier !== undefined && content !== undefined) {
      if (fixedHostConstants?.has(identifier) === true) return true;
      if (!hasDestructuringBinding(content, identifier) && !hasUnreadableAssignment(content, identifier)) {
        const assignments = assignmentsTo(content, identifier);
        if (assignments.length > 0 &&
            assignments.every((rhs) => hasFixedTrustedHost(rhs, fixedHostConstants, content, depth + 1))) {
          return true;
        }
      }
    }
  }
  if (fixedHostConstants === undefined) return false;
  const leading = argText.match(
    /^\s*[`'"]?\s*\$\{\s*([A-Za-z_$][\w$]*)\s*\}|^\s*([A-Za-z_$][\w$]*)\s*(?:\+|\.|\/|`)|^\s*([A-Za-z_$][\w$]*)\s*(?:[,)]|$)/,
  );
  const ident = leading?.[1] ?? leading?.[2] ?? leading?.[3];
  return ident !== undefined && fixedHostConstants.has(ident);
}

const PARAMETER_LIKE = /^[A-Za-z_$][\w$]*\s*(?::\s*[^=]{1,120})?(?:=\s*[^,]{1,80})?$/;

function precedingToken(content: string, index: number): string {
  let i = index - 1;
  while (i >= 0 && /\s/.test(content[i] ?? '')) i -= 1;
  if (i < 0) return '';
  if (!/[\w$]/.test(content[i] ?? '')) return content[i] ?? '';
  const end = i + 1;
  while (i >= 0 && /[\w$]/.test(content[i] ?? '')) i -= 1;
  return content.slice(i + 1, end);
}

function argumentListEnd(content: string, open: number): number {
  let depth = 0;
  let quote: string | undefined;
  const limit = Math.min(content.length, open + 600);
  for (let i = open; i < limit; i += 1) {
    const ch = content[i] ?? '';
    if (quote !== undefined) {
      if (ch === '\\') { i += 1; continue; }
      if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { depth += 1; continue; }
    if (ch === ')' || ch === ']' || ch === '}') {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

function isFollowedByFunctionBody(content: string, afterParen: number): boolean {
  if (afterParen === -1) return false;
  const tail = content.slice(afterParen, afterParen + 200);
  return /^\s*\{/.test(tail) || /^\s*:\s*[^{;=]{1,150}\{/.test(tail);
}

function isRequestHandlerDefinition(content: string, sinkIndex: number): boolean {
  const previous = precedingToken(content, sinkIndex);
  const open = content.indexOf('(', sinkIndex);
  if (open === -1) return false;
  const declarationKeyword = previous === 'async' || previous === 'function';
  const methodPosition = previous === '{' || previous === ',' || previous === ';' || previous === '}';
  if (!declarationKeyword && !methodPosition) return false;
  const args = topLevelArguments(content, sinkIndex);
  if (!args.every((arg) => PARAMETER_LIKE.test(arg.trim()))) return false;
  return isFollowedByFunctionBody(content, argumentListEnd(content, open));
}

function locallyBoundSinkNames(content: string): ReadonlySet<string> {
  const bound = new Set<string>();
  const candidates = ['fetch', 'nodeFetch', 'request', 'needle', 'ky', 'got', 'axios'];
  for (const name of candidates) {
    const declared = new RegExp(
      String.raw`\b(?:async\s+)?function\s+${name}\s*\(` +
        String.raw`|\b(?:const|let|var)\s+${name}\s*(?::[^=;\n]{0,120})?=\s*(?:async\s*)?(?:function\b|\([^)]{0,200}\)\s*(?::[^=>]{0,80})?=>|[A-Za-z_$][\w$]*\s*=>)`,
    );
    if (!declared.test(content)) continue;
    const imported = new RegExp(
      String.raw`\bimport\b[^;\n]{0,200}\b${name}\b[^;\n]{0,200}\bfrom\b` +
        String.raw`|\b(?:const|let|var)\s*\{[^}]{0,200}\b${name}\b[^}]{0,200}\}\s*=\s*require\s*\(` +
        String.raw`|\b(?:const|let|var)\s+${name}\s*=\s*require\s*\(`,
    );
    if (imported.test(content)) continue;
    bound.add(name);
  }
  return bound;
}

const PY_CLIENT_WITH = /\b(?:httpx|requests|aiohttp)\s*\.\s*(?:AsyncClient|Client|Session|ClientSession)\s*\([^()]*\)\s+as\s+([A-Za-z_]\w*)/g;
const PY_CLIENT_ASSIGN = /(?<![\w.])([A-Za-z_]\w*)\s*=\s*(?:httpx|requests|aiohttp)\s*\.\s*(?:AsyncClient|Client|Session|ClientSession)\s*\(/g;

function pythonClientSink(content: string): RegExp | undefined {
  const masked = pythonMasked(content);
  const names = new Set<string>();
  for (const pattern of [PY_CLIENT_WITH, PY_CLIENT_ASSIGN]) for (const m of masked.matchAll(pattern)) names.add(m[1]!);
  if (names.size === 0) return undefined;
  return new RegExp(String.raw`(?<![\w.])(?:${[...names].join('|')})\s*\.\s*(?:get|post|put|patch|delete|head|request|stream)\s*\(`, 'g');
}

function pythonUrlReaches(content: string, sinkIndex: number, aliases: ReadonlySet<string>): boolean {
  const open = content.indexOf('(', sinkIndex);
  if (open === -1) return false;
  const args = pythonCallArguments(content, open);
  const url = args.find((a) => a.keyword === 'url')
    ?? args.find((a) => a.keyword === undefined && !HTTP_METHOD_LITERAL.test(content.slice(a.start, a.end)));
  if (url === undefined || !pythonValueReaches(content, url.start, url.end, { head: true, aliases })) return false;
  return !pythonHostAllowListed(content, sinkIndex, content.slice(url.start, url.end));
}

function pythonHostAllowListed(content: string, sinkIndex: number, urlText: string): boolean {
  const urlNames = pythonIdentifiers(urlText);
  urlNames.delete('str');
  const parsed = pythonCallBindings(content, sinkIndex, /(?:urllib\s*\.\s*parse\s*\.\s*)?url(?:parse|split)/)
    .filter((b) => [...pythonIdentifiers(b.args)].some((n) => urlNames.has(n)))
    .map((b) => b.name);
  if (parsed.length === 0) return false;
  return pythonCheckActsBefore(content, sinkIndex, (condition) => parsed.some((n) =>
    new RegExp(String.raw`\b${n}\s*\.\s*(?:hostname|netloc)\b[^\n]*?\bnot\s+in\b|\b${n}\s*\.\s*(?:hostname|netloc)\s*!=`).test(condition)));
}

function sinkNameAt(content: string, sinkIndex: number): string | undefined {
  const match = /^[A-Za-z_$][\w$]*/.exec(content.slice(sinkIndex, sinkIndex + 40));
  return match?.[0];
}

function topLevelArguments(content: string, sinkIndex: number): string[] {
  const open = content.indexOf('(', sinkIndex);
  if (open === -1) return [];
  const args: string[] = [];
  let current = '';
  let depth = 0;
  let quote: string | undefined;
  const limit = Math.min(content.length, open + 600);
  const flush = (): void => {
    const trimmed = current.trim();
    if (trimmed !== '') args.push(trimmed);
    current = '';
  };
  for (let i = open; i < limit; i += 1) {
    const ch = content[i] ?? '';
    if (quote !== undefined) {
      current += ch;
      if (ch === '\\') {
        const next = content[i + 1];
        if (next !== undefined) { current += next; i += 1; }
        continue;
      }
      if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; current += ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') {
      depth += 1;
      if (!(depth === 1 && ch === '(')) current += ch;
      continue;
    }
    if (ch === ')' || ch === ']' || ch === '}') {
      depth -= 1;
      if (depth === 0) { flush(); return args; }
      current += ch;
      continue;
    }
    if (ch === ',' && depth === 1) { flush(); continue; }
    current += ch;
  }
  flush();
  return args;
}

function urlArgument(args: readonly string[]): string | undefined {
  for (const arg of args) {
    if (HTTP_METHOD_LITERAL.test(arg)) continue;
    return arg;
  }
  return undefined;
}

function lineStartIndex(content: string, line: number): number {
  let index = 0;
  for (let current = 1; current < line; current += 1) {
    const next = content.indexOf('\n', index);
    if (next === -1) return -1;
    index = next + 1;
  }
  return index;
}

function requestSinkIndexOnLine(content: string, line: number): number {
  const start = lineStartIndex(content, line);
  if (start === -1) return -1;
  const newline = content.indexOf('\n', start);
  const text = content.slice(start, newline === -1 ? content.length : newline);
  for (const pattern of [JS_FETCH_SINK, PY_FETCH_SINK]) {
    pattern.lastIndex = 0;
    const found = pattern.exec(text);
    pattern.lastIndex = 0;
    if (found !== null) return start + found.index;
  }
  return -1;
}

export const serverSideRequestForgery: ScanRule = {
  id: 'ssrf',
  title: 'Possible server-side request forgery (SSRF)',
  category: 'ssrf',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const fixedHostConstants = collectFixedHostConstants(context);
    for (const entry of context.fileMap.entries) {
      if (!CODE_EXTENSIONS.has(entry.extension)) continue;
      if (entry.extension === '.py' && isPythonTestModule(entry.path)) continue;
      const fixedHostsHere = fixedHostConstants.get(entry.path);
      const taint = analyzeTaint(entry.content);
      if (context.projectMap.publicClientUsage.includes(entry.path)) continue;
      if (isBrowserServiceWorker(entry)) continue;
      const ast = analyzeFileAst(entry.path, entry.content, entry.extension, crossFileAstHits(context.projectMap.crossFileTaint, entry.path));
      const codeOnly = stripCommentsAndStrings(entry.content);
      const locallyBound = locallyBoundSinkNames(entry.content);
      const seen = new Set<number>();
      const isPython = entry.extension === '.py';
      const clientSink = isPython ? pythonClientSink(entry.content) : undefined;
      for (const pattern of clientSink === undefined ? [JS_FETCH_SINK, PY_FETCH_SINK] : [JS_FETCH_SINK, PY_FETCH_SINK, clientSink]) {
        for (const match of findMatches(codeOnly, pattern)) {
          if (seen.has(match.line)) continue;
          if (isRequestHandlerDefinition(entry.content, match.index)) continue;
          const sinkName = sinkNameAt(entry.content, match.index);
          if (sinkName !== undefined && locallyBound.has(sinkName)) continue;
          const verdict = astVerdict(ast, 'request', match.line);
          if (verdict === 'suppress') continue;
          const scope = windowAround(entry.content, match.index, 360);
          const followed = isPython && pythonUrlReaches(entry.content, match.index, pythonDependencyAliases(context.fileMap.entries));
          const windowed = pattern !== clientSink && usesUserInput(scope, taint, match.index);
          if (verdict !== 'confirm' && !windowed && !followed) continue;
          if (isPython && verdict !== 'confirm' && !followed
            && pythonUrlHostConfigured(entry.content, match.index, (text) => HTTP_METHOD_LITERAL.test(text))) continue;
          if (hasStrongSsrfControls(scope)) continue;
          const urlArg = urlArgument(topLevelArguments(entry.content, match.index));
          if (urlArg === undefined) continue;
          if (hasFixedTrustedHost(urlArg, fixedHostsHere, entry.content)) continue;
          seen.add(match.line);
          findings.push(
            makeFinding({
              ruleId: this.id,
              title: this.title,
              severity: 'high',
              confidence: confidenceWithProof(verdict, 'medium'),
              filePath: entry.path,
              lineStart: match.line,
              evidence: lineAt(entry.content, match.line),
              userExplanation:
                'Your server fetches a web address that the user can control, with no restriction on where it can point. Attackers can aim it at internal systems or cloud metadata endpoints to steal credentials. Restrict outbound requests to an allowlist of trusted hosts.',
              technicalExplanation:
                `${entry.path}:${match.line} performs a server-side request to a user-influenced URL without host validation. Parse the URL, enforce an allowlist of schemes/hosts, and block private/link-local ranges (169.254.169.254, 10/8, 127/8, ::1).`,
              fixHint:
                'Validate the URL before fetching: allow only https, resolve the host and reject private/loopback/link-local IPs, and check it against an allowlist of expected domains. Consider a dedicated egress proxy.',
              category: this.category,
            }),
          );
        }
      }
      for (const [line] of userTaintedLines(ast, 'request')) {
        if (seen.has(line)) continue;
        if (hasStrongSsrfControls(routeHandlerScopeForLine(entry.content, line))) continue;
        const astSink = requestSinkIndexOnLine(entry.content, line);
        if (astSink !== -1) {
          if (isRequestHandlerDefinition(entry.content, astSink)) continue;
          const astArgs = topLevelArguments(entry.content, astSink);
          if (astArgs.length === 0) continue;
          const astUrlArg = urlArgument(astArgs);
          if (astUrlArg !== undefined && hasFixedTrustedHost(astUrlArg, fixedHostsHere, entry.content)) continue;
        }
        seen.add(line);
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'high',
            confidence: 'high',
            filePath: entry.path,
            lineStart: line,
            evidence: lineAt(entry.content, line),
            userExplanation:
              'Your server fetches a web address that the user can control, with no restriction on where it can point. Attackers can aim it at internal systems.',
            technicalExplanation:
              `${entry.path}:${line}: syntax-aware analysis traced request-derived data into an outbound request sink without URL validation in this file.`,
            fixHint:
              'Constrain the outbound request: allow only an allowlist of trusted hosts/schemes, resolve the host and block private, loopback, link-local, and cloud-metadata IP ranges, and do not follow redirects to untrusted hosts. Never fetch a raw user-supplied URL. Keep legitimate outbound calls working.',
            category: this.category,
          }),
        );
      }
    }
    return findings;
  },
};




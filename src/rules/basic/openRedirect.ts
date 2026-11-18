import { analyzeFileAst, astVerdict, confidenceWithProof, userTaintedLines } from '../../ast/astAnalysis.js';
import { crossFileAstHits } from '../../ast/crossFileTaint.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches, lineAt } from '../../shared/utils.js';
import { referencesUserInput, windowAround } from '../../shared/userInput.js';
import { analyzeTaint, classifyExpression } from '../../shared/taint.js';
import { routeHandlerScopeForLine } from '../../shared/handlerScope.js';
import {
  BASE_CONST_DEF,
  CONFIG_HOST_HEAD,
  ENV_BASE_CONST_DEF,
  FIXED_HOST_LITERAL,
  isSafeRelativeLiteral,
  leadingLiteralSegment,
  valueAlternatives,
} from '../../shared/fixedUrlPrefix.js';
import { entryFor, importedFrom, namedFunctionBody } from '../../shared/importedVerifier.js';
import { pythonCallArguments, pythonCheckActsBefore, pythonDependencyAliases, pythonHasBranches, pythonIdentifiers, pythonMasked, pythonRedirectStraightFromQuery, pythonUrlHeadFixed, pythonValueReaches } from '../../shared/pythonFlow.js';

const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);
const REDIRECT_SINK = /\b(?:res\.redirect|response\.redirect|reply\.redirect|NextResponse\.redirect|redirect)\s*\(/g;

const PY_REDIRECT_RESPONSE = /(?<![.\w$])(?:RedirectResponse|HttpResponseRedirect|HttpResponsePermanentRedirect)\s*\(/g;

function pythonDestinationChecked(content: string, openParen: number, destination: string): boolean {
  const names = [...pythonIdentifiers(destination)];
  return pythonCheckActsBefore(content, openParen, (condition) => names.some((n) =>
    new RegExp(String.raw`\b(?:url_has_allowed_host_and_scheme|is_safe_url)\s*\(\s*(?:url\s*=\s*)?${n}\b|^\s*${n}\s+not\s+in\s+[A-Za-z_]`).test(condition)), names);
}

function pythonRedirectTarget(content: string, openParen: number): { start: number; end: number } | undefined {
  const args = pythonCallArguments(content, openParen);
  return args.find((a) => a.keyword === 'url' || a.keyword === 'location' || a.keyword === 'redirect_to')
    ?? args.find((a) => a.keyword === undefined);
}

// startsWith('/') alone is not a guard: //evil.com passes it.
const ROBUST_REDIRECT_GUARD =
  /allowlist|allowedRedirects?|isSafeRedirect|safeRedirect|sanitizeRedirect|validateRedirect|['"`]\/\/['"`]|['"`]\\\\['"`]|URL\s*\([^)]*\)\s*\.\s*origin/i;

function argAt(content: string, openParenIndex: number, index: number): string {
  let depth = 0;
  let current = 0;
  let out = '';
  for (let i = openParenIndex; i < content.length && i < openParenIndex + 300; i += 1) {
    const ch = content[i] ?? '';
    if (ch === '(') { depth += 1; if (depth === 1) continue; }
    if (ch === ')') { depth -= 1; if (depth === 0) break; }
    if (ch === ',' && depth === 1) {
      if (current === index) break;
      current += 1;
      out = '';
      continue;
    }
    if (current === index) out += ch;
  }
  return out.trim();
}

const REDIRECT_STATUS_ARGUMENT = /^3\d\d$/;

// The destination is not always the first argument: redirect(302, url).
function redirectTarget(content: string, openParenIndex: number): string {
  const first = argAt(content, openParenIndex, 0);
  if (!REDIRECT_STATUS_ARGUMENT.test(first)) return first;
  const second = argAt(content, openParenIndex, 1);
  return second === '' ? first : second;
}

function fixedPrefixLocals(content: string): ReadonlySet<string> {
  const fixed = new Set<string>();
  const unreadable = new Map<string, boolean>();
  // Two passes cover one level of indirection and keep the loop bounded.
  for (let pass = 0; pass < 2; pass += 1) {
    for (const definition of [BASE_CONST_DEF, ENV_BASE_CONST_DEF, ANY_CONST_DEF]) {
      definition.lastIndex = 0;
      for (const match of content.matchAll(definition)) {
        const name = match[1];
        const rhs = match[2] ?? '';
        if (name === undefined || fixed.has(name)) continue;
        if (!hasFixedPrefix(rhs, fixed)) continue;
        if (valueAlternatives(rhs).some((alternative) => WHOLE_BARE_SLASH.test(alternative))) continue;
        let cannotRead = unreadable.get(name);
        if (cannotRead === undefined) { cannotRead = hasUnreadableAssignment(content, name); unreadable.set(name, cannotRead); }
        if (!cannotRead) fixed.add(name);
      }
    }
  }
  return fixed;
}

const ANY_CONST_DEF = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]+)?=\s*([^;]{0,240})/g;

function hasUnreadableAssignment(content: string, name: string): boolean {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const compound = new RegExp(String.raw`(?<![.\w$])${escaped}\s*(?:\+|-|\*|\/|%|\*\*|\|\||&&|\?\?|&|\||\^|<<|>>>?)=(?!=)`);
  const iteration = new RegExp(String.raw`\b(?:const|let|var)\s+${escaped}\s+(?:of|in)\b`);
  const reassigned = new RegExp(String.raw`(?<![.\w$])${escaped}\s*=(?!=)`, 'g');
  const definitions = new RegExp(String.raw`\b(?:const|let|var)\s+${escaped}\s*(?::[^=;]+)?=(?!=)`, 'g');
  const writes = (content.match(reassigned) ?? []).length;
  const bindings = (content.match(definitions) ?? []).length;
  return compound.test(content) || iteration.test(content) || writes > bindings;
}

const BARE_SLASH_HEAD = /^\/[\t\r\n]*$/;
const ENCODE_URI_CALL = /(?<![.\w$])encodeURI\s*\(/;
const WHOLE_BARE_SLASH = /^\s*(['"`])\/\1\s*$/;

function hasFixedPrefix(expression: string, locals: ReadonlySet<string>): boolean {
  const alternatives = valueAlternatives(expression);
  if (alternatives.length === 0) return false;
  return alternatives.every((alternative) => {
    if (FIXED_HOST_LITERAL.test(alternative)) return true;
    if (CONFIG_HOST_HEAD.test(alternative)) return true;
    const literalHead = leadingLiteralSegment(alternative);
    if (literalHead !== undefined && BARE_SLASH_HEAD.test(literalHead) && !WHOLE_BARE_SLASH.test(alternative)) return false;
    if (literalHead !== undefined && literalHead !== '' && isSafeRelativeLiteral(literalHead)) return true;
    const leading = /^\s*[`'"]?\s*\$\{\s*([A-Za-z_$][\w$]*)\s*\}\s*(?=[/?#'"`]|$)|^\s*([A-Za-z_$][\w$]*)\s*(?:\+|$)/.exec(alternative);
    const ident = leading?.[1] ?? leading?.[2];
    return ident !== undefined && locals.has(ident);
  });
}

function calleeName(expression: string): string | undefined {
  return /^\s*([A-Za-z_$][\w$]*)\s*\(/.exec(expression.trim())?.[1];
}

function helperReturnsFixedPrefix(context: RuleContext, filePath: string, name: string): boolean {
  const sources = [filePath];
  const imported = importedFrom(context, filePath, name);
  if (imported !== undefined) sources.push(imported);
  for (const source of sources) {
    const entry = entryFor(context, source);
    if (entry === undefined) continue;
    const body = namedFunctionBody(entry.content, name);
    if (body === undefined) continue;
    const returns = [...body.matchAll(/\breturn\b([^;\n]{0,240})/g)].map((match) => (match[1] ?? '').trim());
    if (returns.length === 0) continue;
    const locals = fixedPrefixLocals(body);
    return returns.every((value) => value !== '' && hasFixedPrefix(value, locals));
  }
  return false;
}

export const openRedirect: ScanRule = {
  id: 'open_redirect',
  title: 'Possible open redirect from user-controlled destination',
  category: 'open_redirect',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const entry of context.fileMap.entries) {
      if (!CODE_EXTENSIONS.has(entry.extension)) continue;
      const taint = analyzeTaint(entry.content);
      const fixedLocals = fixedPrefixLocals(entry.content);
      const ast = analyzeFileAst(entry.path, entry.content, entry.extension, crossFileAstHits(context.projectMap.crossFileTaint, entry.path));
      const seen = new Set<number>();

      const isPython = entry.extension === '.py';
      for (const match of [
        ...findMatches(entry.content, REDIRECT_SINK),
        ...(isPython ? findMatches(entry.content, PY_REDIRECT_RESPONSE).filter((m) => pythonMasked(entry.content).startsWith(m.matchText, m.index)) : []),
      ]) {
        if (seen.has(match.line)) continue;
        const astSaid = astVerdict(ast, 'redirect', match.line);
        const openParen = entry.content.indexOf('(', match.index);
        if (openParen === -1) continue;
        const target = isPython ? pythonRedirectTarget(entry.content, openParen) : undefined;
        const responseClass = isPython && /^\s*(?:RedirectResponse|HttpResponse(?:Permanent)?Redirect)\b/.test(entry.content.slice(match.index, openParen));
        if (responseClass && target === undefined) continue;
        const arg = responseClass ? entry.content.slice(target!.start, target!.end) : redirectTarget(entry.content, openParen);
        if (astSaid === 'suppress' && !ENCODE_URI_CALL.test(arg)) continue;
        const verdict = astSaid === 'suppress' ? 'none' : astSaid;

        const literal = /^\s*['"`]([^'"`]*)['"`]\s*$/.exec(arg);
        const newUrlLiteral = /^\s*new\s+URL\s*\(\s*['"`]([^'"`]*)['"`][^)]*\)\s*$/.exec(arg);
        if (literal !== null || newUrlLiteral !== null) {
          const value = (newUrlLiteral?.[1] ?? literal?.[1]) ?? '';
          if (isSafeRelativeLiteral(value)) continue;
          continue;
        }

        if (entry.extension === '.py' && /^\s*request\s*\.\s*(?:url|base_url)\s*$/.test(arg)) continue;
        const branches = isPython && pythonHasBranches(arg);
        if (!branches && hasFixedPrefix(arg, fixedLocals)) { seen.add(match.line); continue; }
        if (isPython && pythonUrlHeadFixed(arg)) { seen.add(match.line); continue; }
        const callee = calleeName(arg);
        if (!branches && callee !== undefined && helperReturnsFixedPrefix(context, entry.path, callee)) {
          seen.add(match.line);
          continue;
        }

        const kind = classifyExpression(arg, taint, match.index);
        const followed = target !== undefined && pythonValueReaches(entry.content, target.start, target.end, { head: true, aliases: pythonDependencyAliases(context.fileMap.entries) })
          && !pythonDestinationChecked(entry.content, openParen, arg);
        const userControlled = responseClass ? followed : (kind === 'user' || referencesUserInput(arg) || followed);
        if (verdict !== 'confirm' && !userControlled) continue;

        const scope = windowAround(entry.content, match.index, 260);
        if (ROBUST_REDIRECT_GUARD.test(scope)) continue;

        seen.add(match.line);
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'medium',
            confidence: target !== undefined && pythonRedirectStraightFromQuery(entry.content, target.start, target.end, { aliases: pythonDependencyAliases(context.fileMap.entries) })
              ? 'high'
              : confidenceWithProof(verdict, 'medium'),
            filePath: entry.path,
            lineStart: match.line,
            evidence: match.snippet,
            userExplanation:
              'This code sends users to a web address taken from their own request, without safely checking it. Attackers use this to make links that look like they go to your site but bounce visitors to a phishing page. Note that only checking it starts with "/" is not enough, because "//evil.com" also starts with "/".',
            technicalExplanation:
              `${entry.path}:${match.line} redirects to a user-controlled destination with no robust validation. A safe relative redirect must start with exactly one "/" (not "//" or "/\\") and contain no scheme; otherwise restrict to an allowlist or compare against the app's own origin.`,
            fixHint:
              'Validate the destination: allow only paths that start with a single "/" (reject "//" and "\\"), or resolve against your origin with new URL(dest, base) and confirm url.origin equals your origin, or match against an allowlist.',
            category: this.category,
          }),
        );
      }
      for (const [line] of userTaintedLines(ast, 'redirect')) {
        if (seen.has(line)) continue;
        const redirectCall = /\b(?:res\.redirect|response\.redirect|reply\.redirect|NextResponse\.redirect|redirect)\s*\(/.exec(lineAt(entry.content, line));
        if (redirectCall?.index !== undefined) {
          const lineStart = entry.content.split('\n').slice(0, line - 1).join('\n').length + (line > 1 ? 1 : 0);
          const openParen = entry.content.indexOf('(', lineStart + redirectCall.index);
          if (openParen !== -1) {
            const argument = redirectTarget(entry.content, openParen);
            const callee = calleeName(argument);
            if (hasFixedPrefix(argument, fixedLocals) ||
                (callee !== undefined && helperReturnsFixedPrefix(context, entry.path, callee))) {
              seen.add(line);
              continue;
            }
          }
        }
        if (ROBUST_REDIRECT_GUARD.test(routeHandlerScopeForLine(entry.content, line))) continue;
        seen.add(line);
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'medium',
            confidence: 'high',
            filePath: entry.path,
            lineStart: line,
            evidence: lineAt(entry.content, line),
            userExplanation:
              'This code sends users to a web address taken from their own request, without safely checking it. Attackers use this for convincing phishing links.',
            technicalExplanation:
              `${entry.path}:${line}: syntax-aware analysis traced request-derived data into a redirect destination with no robust validation in this file.`,
            fixHint:
              'Only redirect to a same-origin relative path (must start with a single "/", reject "//" and backslashes) or an allowlisted absolute URL; otherwise fall back to a safe default. Do not pass the raw user value to the redirect. Preserve valid in-app redirects.',
            category: this.category,
          }),
        );
      }
    }
    return findings;
  },
};

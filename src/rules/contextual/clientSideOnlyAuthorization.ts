import { directImportsOf, authSignalsInFile } from '../../project-map/buildProjectMap.js';
import { effectiveGuards } from '../../project-map/detectAuthSignals.js';
import { creditScopedEntries } from '../../shared/creditScope.js';
import { stripCommentsOnly, usesHashComments } from '../../shared/source.js';
import { findMatches, lineAt, lineNumberAt } from '../../shared/utils.js';
import {
  ACCESS_DENIED_CONSEQUENCE,
  BROWSER_STORAGE_READ,
  DOCUMENT_COOKIE_READ,
  IDENTITY_SETTER_CALL,
  SERVER_BACKED_IDENTITY,
  STRING_CONSTANT_DECLARATION,
  isIdentityBindingName,
  isIdentityStorageKey,
} from '../../shared/browserStoredIdentity.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, FileMapEntry, RuleContext, ScanRule } from '../../shared/types.js';

const GATE_WINDOW_LINES = 6;
const SEED_PROPAGATION_ROUNDS = 3;
const MAX_IMPORT_DEPTH = 6;

interface StorageRead {
  line: number;
  index: number;
  storage: string;
  key: string;
  snippet: string;
  tokens: string[];
}

interface IdentityOrigin {
  filePath: string;
  read: StorageRead;
  identityNames: string[];
  sinkSnippet: string;
  sinkLine: number;
}

interface AccessGate {
  line: number;
  token: string;
  snippet: string;
  denialLine: number;
  denialSnippet: string;
  origin: IdentityOrigin;
}

export const clientSideOnlyAuthorization: ScanRule = {
  id: 'client_side_only_authorization',
  title: 'Access control enforced only in the browser',
  category: 'authentication',
  kind: 'contextual',
  run(context: RuleContext): Finding[] {
    if (!projectLacksServerEnforcement(context)) return [];

    const clientFiles = new Set(context.projectMap.publicClientUsage);
    const entries = [...context.fileMap.entries].sort((a, b) => a.path.localeCompare(b.path));

    const origins = new Map<string, IdentityOrigin>();
    for (const entry of entries) {
      if (!clientFiles.has(entry.path)) continue;
      const origin = findIdentityOrigin(entry);
      if (origin === undefined) continue;
      if (hasServerBackedIdentity(context, entry.path, true)) continue;
      origins.set(entry.path, origin);
    }
    if (origins.size === 0) return [];

    const findings: Finding[] = [];
    for (const entry of entries) {
      if (!clientFiles.has(entry.path)) continue;
      if (hasServerBackedIdentity(context, entry.path, false)) continue;

      const source = stripCommentsOnly(entry.content, usesHashComments(entry.extension, entry.label));
      const tokens = identityTokensInScope(context, entry, source, origins);
      if (tokens.size === 0) continue;

      const gate = findAccessGate(entry, source, tokens);
      if (gate === undefined) continue;

      const origin = gate.origin;
      const sameFile = origin.filePath === entry.path;
      const originPhrase = sameFile
        ? `line ${origin.read.line} of this file`
        : `${origin.filePath}:${origin.read.line}`;

      findings.push(
        makeFinding({
          ruleId: this.id,
          title: this.title,
          severity: 'high',
          confidence: 'high',
          filePath: entry.path,
          lineStart: gate.line,
          lineEnd: gate.denialLine,
          evidence:
            `access gate on "${gate.token}" @ line ${gate.line}: ${gate.snippet}; ` +
            `denies access @ line ${gate.denialLine}: ${gate.denialSnippet}; ` +
            `"${gate.token}" is seeded from ${origin.read.storage} key "${origin.read.key}" at ` +
            `${originPhrase}: ${origin.read.snippet}; ` +
            `no server-side authentication anywhere in the project`,
          userExplanation:
            'This page decides whether to let someone in by checking a value stored in their own ' +
            `browser (${origin.read.storage}, under the key "${origin.read.key}"). Anyone visiting your ` +
            'site can open the browser\'s developer tools and write that value themselves — it takes ' +
            'one line and no special tools — and the application will then treat them as a signed-in ' +
            'user, with whatever name and role they typed in. Nothing we can see behind this check ' +
            'stops them: the uploaded code has no server-side login check, no protected middleware ' +
            'and no Supabase database access rules. Unless protection set up elsewhere (such as ' +
            'Firebase security rules or your hosting platform) steps in, the pages and the data open ' +
            'up too. In short, the login is not a lock; ' +
            'it is a sticker. Whether someone is signed in has to be decided by your server, from a ' +
            'signed session cookie or token it issued and verifies on every request.',
          technicalExplanation:
            `${entry.path}:${gate.line} gates rendering/navigation on "${gate.token}", and that value ` +
            `originates at ${originPhrase} from ${origin.read.storage}["${origin.read.key}"], reaching the ` +
            `identity state at line ${origin.sinkLine} (${origin.sinkSnippet}). Browser storage is ` +
            'written by the page and by anyone with a console, so the value is attacker-chosen and ' +
            'carries no signature the application checks. The gate is therefore satisfiable by ' +
            'fabrication. It is also the project\'s only access control: no file outside the client ' +
            'bundle contains a checked authentication guard, no middleware performs a checked ' +
            'protection, and no Supabase RLS policy is committed — so, unless protection outside the ' +
            'uploaded code (Firebase rules, hosting) applies, the API routes and the database behind ' +
            'this screen accept the same fabricated caller.',
          fixHint:
            'Move the decision to the server. Issue a session on successful login as an httpOnly, ' +
            'Secure, SameSite cookie (or a signed token), verify it server-side on every request — ' +
            'Next.js middleware, a server component/loader check, or a guard at the top of each API ' +
            `route — and derive the user from that verified session. Keep ${origin.read.storage} for ` +
            'presentation state only; a browser-held user object may drive what is rendered, but it ' +
            'must never be what decides access.',
          category: this.category,
          extraFixRequirements: [
            'Do not fix this by encrypting, signing-in-the-browser, or obfuscating the stored value — the browser holds any key it can use, so the value stays forgeable.',
            'Every API route and database policy behind this screen must independently reject an unauthenticated caller; the page gate is not a substitute and must not be the only change.',
          ],
        }),
      );
    }
    return findings;
  },
};

function projectLacksServerEnforcement(context: RuleContext): boolean {
  const vouching = new Set(creditScopedEntries(context).map((entry) => entry.path));
  const clientFiles = new Set(context.projectMap.publicClientUsage);

  for (const signal of effectiveGuards(context.projectMap.authSignals)) {
    if (!vouching.has(signal.filePath)) continue;
    if (clientFiles.has(signal.filePath)) continue;
    return false;
  }
  for (const policy of context.projectMap.supabaseRls.policies) {
    if (vouching.has(policy.filePath)) return false;
  }
  return true;
}

function findIdentityOrigin(entry: FileMapEntry): IdentityOrigin | undefined {
  const source = stripCommentsOnly(entry.content, usesHashComments(entry.extension, entry.label));
  const reads = collectIdentityStorageReads(source);
  if (reads.length === 0) return undefined;

  const seeded = propagateSeeds(source, reads);
  const identityNames: string[] = [];
  let sinkSnippet: string | undefined;
  let sinkLine = 0;

  for (const match of findMatches(source, IDENTITY_SETTER_CALL)) {
    const suffix = match.groups[0];
    const argument = match.groups[1] ?? '';
    if (suffix === undefined) continue;
    if (!seeded.some((token) => containsToken(argument, token))) continue;
    identityNames.push(lowerFirst(suffix));
    if (sinkSnippet === undefined) {
      sinkSnippet = match.snippet.trim().slice(0, 160);
      sinkLine = match.line;
    }
  }
  for (const match of findMatches(source, SIMPLE_DECLARATION)) {
    const name = match.groups[0];
    const initializer = match.groups[1] ?? '';
    if (name === undefined || !isIdentityBindingName(name)) continue;
    if (!seeded.some((token) => containsToken(initializer, token))) continue;
    identityNames.push(name);
    if (sinkSnippet === undefined) {
      sinkSnippet = match.snippet.trim().slice(0, 160);
      sinkLine = match.line;
    }
  }

  if (identityNames.length === 0 || sinkSnippet === undefined) return undefined;
  const read = reads[0] as StorageRead;
  return {
    filePath: entry.path,
    read,
    identityNames: [...new Set(identityNames)],
    sinkSnippet,
    sinkLine,
  };
}

function collectIdentityStorageReads(source: string): StorageRead[] {
  const constants = new Map<string, string>();
  for (const match of findMatches(source, STRING_CONSTANT_DECLARATION)) {
    const name = match.groups[0];
    const value = match.groups[2];
    if (name === undefined || value === undefined) continue;
    if (!constants.has(name)) constants.set(name, value);
  }

  const reads: StorageRead[] = [];
  for (const match of findMatches(source, BROWSER_STORAGE_READ)) {
    const storage = match.groups[0];
    const keyExpression = match.groups[1];
    if (storage === undefined || keyExpression === undefined) continue;
    const key = /^['"`]/.test(keyExpression)
      ? keyExpression.slice(1, -1)
      : constants.get(keyExpression);
    if (key === undefined || !isIdentityStorageKey(key)) continue;
    const declared = declaredNamesOnLine(source, match.index);
    reads.push({
      line: match.line,
      index: match.index,
      storage,
      key,
      snippet: match.snippet.trim().slice(0, 160),
      tokens: declared.length > 0 ? declared : [match.matchText],
    });
  }

  for (const match of findMatches(source, DOCUMENT_COOKIE_READ)) {
    const line = lineAt(source, match.line);
    if (/document\s*\.\s*cookie\s*=[^=]/.test(line)) continue;
    const named = [...line.matchAll(/['"`]([A-Za-z0-9_.\-]{1,60})['"`]/g)]
      .map((literal) => literal[1])
      .find((literal) => literal !== undefined && isIdentityStorageKey(literal));
    if (named === undefined) continue;
    const declared = declaredNamesOnLine(source, match.index);
    reads.push({
      line: match.line,
      index: match.index,
      storage: 'document.cookie',
      key: named,
      snippet: line.trim().slice(0, 160),
      tokens: declared.length > 0 ? declared : [match.matchText],
    });
  }

  reads.sort((a, b) => a.index - b.index);
  return reads;
}

function propagateSeeds(source: string, reads: StorageRead[]): string[] {
  const seeded = new Set<string>();
  for (const read of reads) for (const token of read.tokens) seeded.add(token);

  for (let round = 0; round < SEED_PROPAGATION_ROUNDS; round += 1) {
    let grew = false;
    const widen = (name: string): void => {
      if (seeded.has(name)) return;
      seeded.add(name);
      grew = true;
    };
    for (const match of findMatches(source, SIMPLE_DECLARATION)) {
      const name = match.groups[0];
      const initializer = match.groups[1] ?? '';
      if (name === undefined || seeded.has(name)) continue;
      if ([...seeded].some((token) => containsToken(initializer, token))) widen(name);
    }
    for (const match of findMatches(source, DESTRUCTURING_DECLARATION)) {
      const pattern = match.groups[0];
      const initializer = match.groups[1] ?? '';
      if (pattern === undefined) continue;
      if (![...seeded].some((token) => containsToken(initializer, token))) continue;
      for (const { binding } of destructuredBindings(pattern)) widen(binding);
    }
    if (!grew) break;
  }
  return [...seeded];
}

function identityTokensInScope(
  context: RuleContext,
  entry: FileMapEntry,
  source: string,
  origins: ReadonlyMap<string, IdentityOrigin>,
): Map<string, IdentityOrigin> {
  const tokens = new Map<string, IdentityOrigin>();

  const own = origins.get(entry.path);
  if (own !== undefined) for (const name of own.identityNames) tokens.set(name, own);

  const fileImports = context.projectMap.imports.find((imports) => imports.filePath === entry.path);
  const accessors = new Map<string, IdentityOrigin>();
  for (const importRef of fileImports?.imports ?? []) {
    const resolved = importRef.resolvedPath;
    if (resolved === undefined) continue;
    const origin = origins.get(resolved);
    if (origin === undefined) continue;
    for (const binding of importRef.bindings ?? []) accessors.set(binding, origin);
  }
  if (accessors.size > 0) {
    for (const match of findMatches(source, CALL_DECLARATION)) {
      const pattern = match.groups[0];
      const callee = match.groups[1];
      if (pattern === undefined || callee === undefined) continue;
      const origin = accessors.get(callee);
      if (origin === undefined) continue;
      if (pattern.startsWith('{')) {
        for (const { key, binding } of destructuredBindings(pattern)) {
          if (isIdentityBindingName(key)) tokens.set(binding, origin);
        }
      } else if (isIdentityBindingName(pattern)) {
        tokens.set(pattern, origin);
      }
    }
  }
  return tokens;
}

function findAccessGate(
  entry: FileMapEntry,
  source: string,
  tokens: ReadonlyMap<string, IdentityOrigin>,
): AccessGate | undefined {
  const lines = source.split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] as string;
    const condition = conditionText(line);
    if (condition === undefined) continue;
    for (const [token, origin] of tokens) {
      if (!absenceOf(token).test(condition)) continue;
      const end = Math.min(lines.length, index + GATE_WINDOW_LINES);
      for (let cursor = index; cursor < end; cursor += 1) {
        const candidate = lines[cursor] as string;
        if (!ACCESS_DENIED_CONSEQUENCE.test(candidate)) continue;
        return {
          line: index + 1,
          token,
          snippet: lineAt(entry.content, index + 1).trim().slice(0, 160),
          denialLine: cursor + 1,
          denialSnippet: lineAt(entry.content, cursor + 1).trim().slice(0, 160),
          origin,
        };
      }
    }
  }
  return undefined;
}

function conditionText(line: string): string | undefined {
  const conditional = /\bif\s*\(([\s\S]*)$/.exec(line);
  if (conditional?.[1] !== undefined) return conditional[1];
  const ternary = /^([^?\n]*)\?/.exec(line);
  if (ternary?.[1] !== undefined && /[!=]/.test(ternary[1])) return ternary[1];
  return undefined;
}

function absenceOf(token: string): RegExp {
  return new RegExp(
    `(?:^|[^\\w$])!\\s*${token}(?![\\w$])|(?<![\\w$])${token}\\s*(?:===?\\s*(?:null|undefined|false)\\b|!==?\\s*true\\b)`,
  );
}

function hasServerBackedIdentity(
  context: RuleContext,
  filePath: string,
  followImports: boolean,
): boolean {
  const entriesByPath = new Map(context.fileMap.entries.map((entry) => [entry.path, entry]));
  const check = (path: string): boolean => {
    if (authSignalsInFile(context.projectMap, path).some((signal) => signal.protective)) return true;
    const entry = entriesByPath.get(path);
    if (entry === undefined) return false;
    const source = stripCommentsOnly(entry.content, usesHashComments(entry.extension, entry.label));
    return SERVER_BACKED_IDENTITY.test(source);
  };

  if (check(filePath)) return true;
  if (!followImports) return false;

  const visited = new Set<string>([filePath]);
  let frontier = directImportsOf(context.projectMap, filePath);
  for (let depth = 0; depth < MAX_IMPORT_DEPTH && frontier.length > 0; depth += 1) {
    const next: string[] = [];
    for (const imported of frontier) {
      if (visited.has(imported)) continue;
      visited.add(imported);
      if (check(imported)) return true;
      next.push(...directImportsOf(context.projectMap, imported));
    }
    frontier = next;
  }
  return false;
}

const SIMPLE_DECLARATION = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^\n;]{0,200})/g;
const DESTRUCTURING_DECLARATION = /\b(?:const|let|var)\s+(\{[^{}]{0,400}\})\s*=\s*([^\n;]{0,200})/g;
const CALL_DECLARATION =
  /\b(?:const|let|var)\s+(\{[^{}]{0,400}\}|[A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?([A-Za-z_$][\w$]*)\s*\(/g;

function destructuredBindings(pattern: string): { key: string; binding: string }[] {
  const inner = pattern.replace(/^\{/, '').replace(/\}$/, '');
  const result: { key: string; binding: string }[] = [];
  for (const part of inner.split(',')) {
    const trimmed = part.trim();
    if (trimmed === '') continue;
    const renamed = /^([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*)/.exec(trimmed);
    if (renamed?.[1] !== undefined && renamed[2] !== undefined) {
      result.push({ key: renamed[1], binding: renamed[2] });
      continue;
    }
    const plain = /^([A-Za-z_$][\w$]*)/.exec(trimmed);
    if (plain?.[1] !== undefined) result.push({ key: plain[1], binding: plain[1] });
  }
  return result;
}

function declaredNamesOnLine(source: string, index: number): string[] {
  const line = lineAt(source, lineNumberAt(source, index));
  const simple = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/.exec(line);
  if (simple?.[1] !== undefined) return [simple[1]];
  const destructured = /\b(?:const|let|var)\s+(\{[^{}]{0,400}\})\s*=/.exec(line);
  if (destructured?.[1] !== undefined) {
    return destructuredBindings(destructured[1]).map((pair) => pair.binding);
  }
  return [];
}

function containsToken(haystack: string, token: string): boolean {
  if (/^[A-Za-z_$][\w$]*$/.test(token)) {
    return new RegExp(`(?<![\\w$])${token}(?![\\w$])`).test(haystack);
  }
  return haystack.includes(token);
}

function lowerFirst(value: string): string {
  return value.charAt(0).toLowerCase() + value.slice(1);
}

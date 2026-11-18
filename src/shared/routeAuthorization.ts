import type { GuardLookup } from './types.js';

const ROUTE_REGISTRATION = /\b(?:app|router)\.(?:get|post|put|delete|patch|all)\s*\(/;
const ADMIN_NAME = /\b(?:require_?admin|adminOnly|requireAdmin|isAdmin|assertAdmin|ensureAdmin|verifyAdmin|adminGuard|requireRole|requirePermission|hasRole)\b/i;
const AUTH_NAME = /\b(?:get_current_user|getCurrentUser|requireAuth|authenticate|isAuthenticated|verifyToken|verifyJwt|jwtAuth|authMiddleware|requireUser|requireSession)\b/i;
const ADMIN_WORD =
  /(?:\b|(?<=[A-Za-z0-9_$]))(?:[Aa]dministrators?|ADMINISTRATORS?|[Ss]uper[Aa]dmins?|SUPERADMINS?|[Ss]uper[Uu]sers?|SUPERUSERS?|[Aa]dmins?|ADMINS?)(?![a-z])/g;

const ROLE_WORD =
  /\b(?:roles?|claims?|permissions?|scopes?|privileges?|is_admin|isAdmin|user_?type|account_?type|user_?role)\b/gi;

const ROLE_LITERAL_TEST =
  /\b(?:roles?|claims?|permissions?|scopes?|privileges?|user_?type|account_?type|user_?role)\b[^;{}\n]{0,48}?(?:[!=]==?|\.includes\s*\(|\.has\s*\(|\.indexOf\s*\(|\.some\s*\()\s*['"`][^'"`\n]{1,48}['"`]/;

const ROLE_ADMIN_PROXIMITY = 160;

function matchOffsets(text: string, pattern: RegExp): number[] {
  const offsets: number[] = [];
  for (const match of text.matchAll(pattern)) if (match.index !== undefined) offsets.push(match.index);
  return offsets;
}

function looksLikeRoleCheck(text: string): boolean {
  const roles = matchOffsets(text, ROLE_WORD);
  if (roles.length > 0) {
    const admins = matchOffsets(text, ADMIN_WORD);
    if (roles.some((role) => admins.some((admin) => Math.abs(admin - role) <= ROLE_ADMIN_PROXIMITY))) return true;
  }
  return ROLE_LITERAL_TEST.test(text);
}
const DENY_PATH = /\b(?:throw\b|return\b|redirect\s*\(|notFound\s*\(|NextResponse\.redirect\s*\(|Response\.json\s*\([^)]*status\s*:\s*40[13]|\.status\s*\(\s*40[13]\s*\)|res\.sendStatus\s*\(\s*40[13]\s*\)|abort\s*\(\s*40[13]\s*\))/i;

function lineStarts(content: string): number[] {
  const starts = [0];
  for (let i = 0; i < content.length; i += 1) if (content.charCodeAt(i) === 10) starts.push(i + 1);
  return starts;
}

function balancedFrom(content: string, start: number, max = 6_000): string {
  let depth = 0;
  let quote: string | undefined;
  let escaped = false;
  let sawOpen = false;
  for (let i = start; i < content.length && i < start + max; i += 1) {
    const ch = content[i] ?? '';
    if (quote !== undefined) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '(' || ch === '{' || ch === '[') { depth += 1; sawOpen = true; }
    else if (ch === ')' || ch === '}' || ch === ']') {
      depth -= 1;
      if (sawOpen && depth <= 0) return content.slice(start, i + 1);
    }
  }
  return content.slice(start, Math.min(content.length, start + max));
}

export function routeRegistrationAroundLine(content: string, line: number): string | undefined {
  const starts = lineStarts(content);
  const lineIndex = Math.max(0, line - 1);
  for (let startLine = lineIndex; startLine >= 0 && startLine >= lineIndex - 140; startLine -= 1) {
    const start = starts[startLine] ?? 0;
    const prefix = content.slice(start, Math.min(content.length, start + 160));
    if (!ROUTE_REGISTRATION.test(prefix)) continue;
    const text = balancedFrom(content, start);
    const lineOffset = starts[lineIndex] ?? 0;
    if (lineOffset >= start && lineOffset <= start + text.length) return text;
  }
  return undefined;
}

function functionBody(content: string, name: string): string | undefined {
  const escaped = name.replace(/[$]/g, '\\$&');
  const patterns = [
    new RegExp(`function\\s+${escaped}\\s*\\([^)]*\\)\\s*\\{`, 'i'),
    new RegExp(`(?:const|let|var)\\s+${escaped}\\s*=\\s*(?:async\\s*)?(?:\\([^)]*\\)|[A-Za-z_$][\\w$]*)\\s*=>\\s*\\{`, 'i'),
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(content);
    if (match?.index === undefined) continue;
    const open = content.indexOf('{', match.index);
    if (open !== -1) return balancedFrom(content, open, 4_000);
  }
  return undefined;
}

function importedSources(context: GuardLookup, filePath: string): string[] {
  const imports = context.projectMap.imports.find((entry) => entry.filePath === filePath);
  if (imports === undefined) return [];
  return imports.imports
    .map((ref) => ref.resolvedPath)
    .filter((path): path is string => path !== undefined);
}

export function isStrongAdminText(text: string): boolean {
  return looksLikeRoleCheck(text) && DENY_PATH.test(text);
}

function adminHelperNames(text: string): string[] {
  const names = new Set<string>();
  for (const match of text.matchAll(/\b([A-Za-z_$][\w$]*)\b/g)) {
    const name = match[1];
    if (name !== undefined && ADMIN_NAME.test(name)) names.add(name);
  }
  return [...names];
}

export function hasSuggestiveAdminGuard(text: string): boolean {
  return ADMIN_NAME.test(text);
}

export function hasSuggestiveAuthGuard(text: string): boolean {
  return AUTH_NAME.test(text) || ADMIN_NAME.test(text);
}

export function resolvesToStrongAdminHelper(context: GuardLookup, filePath: string, text: string): boolean {
  const names = adminHelperNames(text);
  if (names.length === 0) return false;
  const sourceFiles = [filePath, ...importedSources(context, filePath)];
  for (const name of names) {
    for (const path of sourceFiles) {
      const imported = context.fileMap.entries.find((candidate) => candidate.path === path);
      const body = imported === undefined ? undefined : functionBody(imported.content, name);
      if (body !== undefined && isStrongAdminText(body)) return true;
    }
  }
  return false;
}

export function hasStrongAdminAuthorization(context: GuardLookup, filePath: string, line: number, nearbyText?: string): boolean {
  const entry = context.fileMap.entries.find((candidate) => candidate.path === filePath);
  const source = entry?.content ?? '';
  const starts = source === '' ? [0] : lineStarts(source);
  const registration = nearbyText ?? (source === '' ? '' : routeRegistrationAroundLine(source, line) ?? '');
  const lineStart = starts[Math.max(0, line - 1)] ?? 0;
  const handlerWindow = source === '' ? '' : source.slice(Math.max(0, lineStart - 1_500), Math.min(source.length, starts[line + 120] ?? source.length));
  if (isStrongAdminText(registration) || (nearbyText === undefined && isStrongAdminText(handlerWindow))) return true;
  const nameScope = nearbyText === undefined ? `${registration}\n${handlerWindow}` : registration;
  return resolvesToStrongAdminHelper(context, filePath, nameScope);
}

const HANDLER_WINDOW_LINES = 120;

export function fileRoutedHandlerText(content: string, line: number, endLine?: number): string {
  if (content === '') return '';
  const starts = lineStarts(content);
  const from = starts[Math.max(0, line - 1)] ?? 0;
  const stopLine = Math.min(endLine ?? Number.MAX_SAFE_INTEGER, line + HANDLER_WINDOW_LINES);
  const to = starts[Math.max(0, stopLine - 1)] ?? content.length;
  return content.slice(from, Math.max(from, to));
}

export function hasStrongAdminAuthorizationInHandler(
  context: GuardLookup,
  filePath: string,
  line: number,
  endLine?: number,
): boolean {
  const entry = context.fileMap.entries.find((candidate) => candidate.path === filePath);
  const handler = fileRoutedHandlerText(entry?.content ?? '', line, endLine);
  if (handler === '') return false;
  if (isStrongAdminText(handler)) return true;
  return resolvesToStrongAdminHelper(context, filePath, handler);
}

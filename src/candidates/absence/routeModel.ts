import type { FileMap, ProjectMap } from '../../shared/types.js';
import { isInsideComment, splitTopLevelArguments } from '../textUtils.js';
import { resolveLocalImport } from '../../project-map/resolveImports.js';
import { isInlineHandlerText, matchClose, resolveHandler, type HandlerLocation } from './handlerResolution.js';
import { spanText } from './handlerEvidence.js';
import { resolvesToRejection } from '../../shared/handlerGuardCall.js';
import {
  hasValidatorChain,
  rejectsOnValidationResult,
  resolveMiddleware,
  type ControlState,
} from '../../shared/middlewareGuard.js';

export type { HandlerLocation } from './handlerResolution.js';

export interface AbsenceRoute {
  method: string;
  relPath: string;
  fullPath: string;
  filePath: string;
  line: number;
  endLine: number;
  spanResolved: boolean;
  middlewares: string[];
  handlerToken?: string;
  handler?: HandlerLocation;
  protectedByAuth: boolean;
  authProofFile?: string;
  pathResolution: 'mounted' | 'relative';
  controls: RouteControls;
}

const unresolvedControl: RouteControl = { state: 'unresolved' };

export interface RouteControl {
  state: ControlState;
  provenBy?: string;
}

export interface RouteControls {
  auth: RouteControl;
  validation: RouteControl;
  rateLimit: RouteControl;
  signature: RouteControl;
  admin: RouteControl;
}

export type { ControlState } from '../../shared/middlewareGuard.js';

const METHODS = '(?:get|post|put|delete|patch|all)';
const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'ALL']);
export const MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

const JS_TS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

const AUTH_NAME =
  /^(?:protect|requireAuth|requireUser|requireLogin|ensureAuth\w*|ensureAuthenticated|isAuth\w*|isAuthenticated|isLoggedIn\w*|loggedIn|registrationAuth|authenticate\w*|authGuard|authMiddleware|auth|verifyToken|verifyAuth|checkAuth|checkToken|jwt\w*|passport|withAuth|adminOnly|requireAdmin|isAdmin)$/i;

const AUTH_METHOD =
  /^(?:isAuthenticated|authenticate|protect|requireAuth\w*|requireUser|requireLogin|ensureAuth\w*|ensureAuthenticated|isAuth\w*|isLoggedIn\w*|loggedIn|registrationAuth|authGuard|authMiddleware|verifyToken|verifyAuth|checkAuth|checkToken|adminOnly|requireAdmin|isAdmin|authorize|requireScopes?)$/i;

const MAX_ALIAS_HOPS = 3;

interface RawRoute {
  method: string;
  relPath: string;
  filePath: string;
  line: number;
  endLine: number;
  middlewares: string[];
  middlewareTexts: string[];
  handlerToken?: string;
  spanResolved: boolean;
  handlerInline: boolean;
}

interface Mount {
  filePath: string;
  prefix: string;
  routerVar?: string;
  requireSpec?: string;
  middlewares: string[];
  middlewareTexts: string[];
}

function importBindingMap(projectMap: ProjectMap, filePath: string): Map<string, string> {
  const map = new Map<string, string>();
  const fi = projectMap.imports.find((f) => f.filePath === filePath);
  if (fi === undefined) return map;
  for (const ref of fi.imports) {
    if (ref.resolvedPath === undefined) continue;
    for (const b of ref.bindings ?? []) map.set(b, ref.resolvedPath);
  }
  return map;
}

function authGuardFiles(projectMap: ProjectMap): Set<string> {
  const set = new Set<string>();
  for (const s of projectMap.authSignals) {
    if (s.protective && s.checked) set.add(s.filePath);
  }
  return set;
}

function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i += 1) if (content[i] === '\n') line += 1;
  return line;
}

function parenAt(content: string, from: number): number {
  const limit = Math.min(content.length, from + 40);
  for (let i = from; i < limit; i += 1) {
    if (content[i] === '(') return i;
    if (content[i] === ';' || content[i] === '\n') break;
  }
  return -1;
}

const MAX_ARGS_CHARS = 60_000;

export function argsAt(content: string, openParen: number): { text: string; end: number } | undefined {
  const end = matchClose(content, openParen, MAX_ARGS_CHARS);
  if (end === -1) return undefined;
  return { text: content.slice(openParen + 1, end), end };
}

const STRING_ARG = /^\s*['"`]([^'"`]*)['"`]\s*$/;

const OPTIONAL_AUTH = /^\s*[A-Za-z_$][\w$]*\s*\(\s*\{[^}]*\boptional\b\s*:\s*(?!false\b)/i;

function tokenOf(arg: string): string | undefined {
  if (OPTIONAL_AUTH.test(arg)) return 'optionalAuth';
  const m = /^\s*([A-Za-z_$][\w$.]*)/.exec(arg);
  if (m === null) return undefined;
  return m[1];
}

const ALIAS_RE =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(new\s+)?([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*([;,\n)(]|$)/g;

function parseAliases(content: string): Map<string, string> {
  const aliases = new Map<string, string>();
  for (let m = ALIAS_RE.exec(content); m !== null; m = ALIAS_RE.exec(content)) {
    if (isInsideComment(content, m.index)) continue;
    const name = m[1] ?? '';
    const isNew = m[2] !== undefined;
    const expr = (m[3] ?? '').replace(/\s+/g, '');
    const terminator = m[4] ?? '';
    if (terminator === '(' && !isNew) continue;
    if (expr === 'require') continue;
    if (name === expr) continue;
    aliases.set(name, expr);
  }
  return aliases;
}

function parseFile(
  filePath: string,
  content: string,
): {
  routes: RawRoute[];
  routerUse: string[];
  routerUseTexts: string[];
  mounts: Mount[];
  aliases: Map<string, string>;
  unreadableUse: boolean;
  unreadableMount: boolean;
} {
  const routes: RawRoute[] = [];
  const routerUse: string[] = [];
  const routerUseTexts: string[] = [];
  const mounts: Mount[] = [];
  const aliases = parseAliases(content);
  let unreadableUse = false;
  let unreadableMount = false;

  const useRe = /\brouter\s*\.\s*use\s*\(/g;
  for (let m = useRe.exec(content); m !== null; m = useRe.exec(content)) {
    if (isInsideComment(content, m.index)) continue;
    const open = m.index + m[0].length - 1;
    const span = argsAt(content, open);
    if (span === undefined) {
      unreadableUse = true;
      continue;
    }
    const { text } = span;
    const args = splitTopLevelArguments(text);
    if (args.length === 0) continue;
    if (STRING_ARG.test(args[0] ?? '')) continue;
    for (const a of args) {
      routerUseTexts.push(a);
      const t = tokenOf(a);
      if (t !== undefined) routerUse.push(t);
    }
  }

  const inlineRe = new RegExp(`\\b(app|router)\\s*\\.\\s*(${METHODS})\\s*\\(`, 'g');
  for (let m = inlineRe.exec(content); m !== null; m = inlineRe.exec(content)) {
    if (isInsideComment(content, m.index)) continue;
    const open = m.index + m[0].length - 1;
    const span = argsAt(content, open);
    const line = lineOf(content, m.index);
    const method = (m[2] ?? '').toUpperCase();
    if (span === undefined) {
      const headSm = STRING_ARG.exec(splitTopLevelArguments(content.slice(open + 1, open + 400))[0] ?? '');
      if (headSm === null) continue;
      routes.push({
        method,
        relPath: headSm[1] ?? '/',
        filePath,
        line,
        endLine: line,
        middlewares: [],
        middlewareTexts: [],
        spanResolved: false,
        handlerInline: false,
      });
      continue;
    }
    const { text, end } = span;
    const args = splitTopLevelArguments(text);
    const first = args[0] ?? '';
    const sm = STRING_ARG.exec(first);
    if (sm === null) continue;
    const middlewareTexts = args.slice(1, -1);
    const middlewares = middlewareTexts.map(tokenOf).filter((t): t is string => t !== undefined);
    const lastArg = args.length >= 2 ? args[args.length - 1] ?? '' : undefined;
    const handlerToken = lastArg !== undefined ? tokenOf(lastArg) : undefined;
    routes.push({
      method,
      relPath: sm[1] ?? '/',
      filePath,
      line,
      endLine: lineOf(content, end),
      middlewares,
      middlewareTexts,
      spanResolved: true,
      ...(handlerToken !== undefined ? { handlerToken } : {}),
      handlerInline: lastArg !== undefined && isInlineHandlerText(lastArg),
    });
  }

  const routeRe = /\b(?:app|router)\s*\.\s*route\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g;
  for (let m = routeRe.exec(content); m !== null; m = routeRe.exec(content)) {
    if (isInsideComment(content, m.index)) continue;
    const relPath = m[1] ?? '/';
    let cursor = m.index + m[0].length;
    const chainMethodRe = new RegExp(`^\\s*\\.\\s*(${METHODS})\\s*\\(`);
    for (let guard = 0; guard < 20; guard += 1) {
      const rest = content.slice(cursor, cursor + 4000);
      const cm = chainMethodRe.exec(rest);
      if (cm === null) break;
      const openRel = cm.index + cm[0].length - 1;
      const open = cursor + openRel;
      const span = argsAt(content, open);
      const method = (cm[1] ?? '').toUpperCase();
      if (span === undefined) {
        routes.push({
          method,
          relPath,
          filePath,
          line: lineOf(content, open),
          endLine: lineOf(content, open),
          middlewares: [],
          middlewareTexts: [],
          spanResolved: false,
          handlerInline: false,
        });
        break;
      }
      const { text, end } = span;
      const args = splitTopLevelArguments(text);
      const middlewareTexts = args.slice(0, -1);
      const middlewares = middlewareTexts.map(tokenOf).filter((t): t is string => t !== undefined);
      const lastArg = args.length >= 1 ? args[args.length - 1] ?? '' : undefined;
      const handlerToken = lastArg !== undefined ? tokenOf(lastArg) : undefined;
      routes.push({
        method,
        relPath,
        filePath,
        line: lineOf(content, open),
        endLine: lineOf(content, end),
        middlewares,
        middlewareTexts,
        spanResolved: true,
        ...(handlerToken !== undefined ? { handlerToken } : {}),
        handlerInline: lastArg !== undefined && isInlineHandlerText(lastArg),
      });
      cursor = end + 1;
    }
  }

  const mountRe = /\bapp\s*\.\s*use\s*\(/g;
  for (let m = mountRe.exec(content); m !== null; m = mountRe.exec(content)) {
    if (isInsideComment(content, m.index)) continue;
    const open = m.index + m[0].length - 1;
    const span = argsAt(content, open);
    if (span === undefined) {
      unreadableMount = true;
      continue;
    }
    const { text } = span;
    const args = splitTopLevelArguments(text);
    if (args.length === 0) continue;
    let prefix = '/';
    let rest = args;
    const sm = STRING_ARG.exec(args[0] ?? '');
    if (sm !== null) {
      prefix = sm[1] ?? '/';
      rest = args.slice(1);
    }
    const lastArg = (rest[rest.length - 1] ?? '').trim();
    const mwTexts = rest.slice(0, -1);
    const mws = mwTexts.map(tokenOf).filter((t): t is string => t !== undefined);
    const req = /^require\(\s*['"]([^'"]+)['"]\s*\)$/.exec(lastArg);
    if (req !== null) {
      mounts.push({ filePath, prefix, requireSpec: req[1] ?? '', middlewares: mws, middlewareTexts: mwTexts });
    } else if (/^[A-Za-z_$][\w$]*$/.test(lastArg)) {
      mounts.push({ filePath, prefix, routerVar: lastArg, middlewares: mws, middlewareTexts: mwTexts });
    }
  }

  return { routes, routerUse, routerUseTexts, mounts, aliases, unreadableUse, unreadableMount };
}

export function expandAlias(token: string, aliases: ReadonlyMap<string, string>): string {
  let current = token;
  for (let hop = 0; hop < MAX_ALIAS_HOPS; hop += 1) {
    const parts = current.split('.');
    const head = parts[0] ?? '';
    const target = aliases.get(head);
    if (target === undefined || target === head) return current;
    current = [target, ...parts.slice(1)].join('.');
  }
  return current;
}

function joinPath(prefix: string, rel: string): string {
  const a = prefix.replace(/\/+$/, '');
  const b = rel.startsWith('/') ? rel : `/${rel}`;
  const joined = `${a}${b}`.replace(/\/{2,}/g, '/');
  return joined === '' ? '/' : joined;
}

export function buildAbsenceRouteModel(fileMap: FileMap, projectMap: ProjectMap): AbsenceRoute[] {
  const guardFiles = authGuardFiles(projectMap);
  const perFile = new Map<
    string,
    {
      routes: RawRoute[];
      routerUse: string[];
      routerUseTexts: string[];
      aliases: Map<string, string>;
      unreadableUse: boolean;
    }
  >();
  const allMounts: Mount[] = [];
  let mountGraphIncomplete = false;

  for (const entry of fileMap.entries) {
    if (!JS_TS.has(entry.extension)) continue;
    if (!/\b(?:app|router)\s*\.\s*(?:get|post|put|delete|patch|all|use|route)\s*\(/.test(entry.content)) continue;
    let parsed;
    try {
      parsed = parseFile(entry.path, entry.content);
    } catch {
      continue;
    }
    perFile.set(entry.path, {
      routes: parsed.routes,
      routerUse: parsed.routerUse,
      routerUseTexts: parsed.routerUseTexts,
      aliases: parsed.aliases,
      unreadableUse: parsed.unreadableUse,
    });
    if (parsed.unreadableMount) mountGraphIncomplete = true;
    allMounts.push(...parsed.mounts);
  }
  const aliasesOf = (filePath: string): ReadonlyMap<string, string> => perFile.get(filePath)?.aliases ?? new Map();

  const filePaths = new Set(fileMap.entries.map((e) => e.path));
  const mountsByTarget = new Map<string, Mount[]>();
  for (const mount of allMounts) {
    let target: string | undefined;
    if (mount.requireSpec !== undefined) {
      target = resolveLocalImport(mount.filePath, mount.requireSpec, filePaths);
    } else if (mount.routerVar !== undefined) {
      target = importBindingMap(projectMap, mount.filePath).get(mount.routerVar);
    }
    if (target === undefined) continue;
    const list = mountsByTarget.get(target) ?? [];
    list.push(mount);
    mountsByTarget.set(target, list);
  }

  const isAuthProof = (
    tokens: string[],
    bindings: Map<string, string>,
    aliases: ReadonlyMap<string, string>,
  ): string | undefined => {
    for (const raw of tokens) {
      const t = expandAlias(raw, aliases);
      const parts = t.split('.');
      const obj = parts[0] ?? '';
      const method = parts.length > 1 ? parts[parts.length - 1] ?? '' : undefined;
      if (/^passport$/i.test(obj) && (method === undefined || /^authenticate$/i.test(method))) {
        return 'passport';
      }
      if (method !== undefined) {
        if (AUTH_METHOD.test(method)) {
          const resolved = bindings.get(obj);
          if (resolved !== undefined && guardFiles.has(resolved)) return resolved;
        }
        continue;
      }
      if (AUTH_NAME.test(obj)) {
        const resolved = bindings.get(obj);
        if (resolved !== undefined && guardFiles.has(resolved)) return resolved;
      }
    }
    return undefined;
  };

  const contentIndex = new Map(fileMap.entries.map((entry) => [entry.path, entry.content]));
  const contentOf = (path: string): string | undefined => contentIndex.get(path);

  const out: AbsenceRoute[] = [];
  for (const [filePath, { routes, routerUse, routerUseTexts, aliases, unreadableUse }] of perFile) {
    const bindings = importBindingMap(projectMap, filePath);
    const mounts = mountsByTarget.get(filePath) ?? [];
    for (const route of routes) {
      if (!HTTP_METHODS.has(route.method)) continue;
      if (!route.spanResolved) {
        out.push({
          method: route.method,
          relPath: route.relPath,
          fullPath: route.relPath,
          filePath,
          line: route.line,
          endLine: route.endLine,
          spanResolved: false,
          middlewares: [],
          protectedByAuth: false,
          pathResolution: 'relative',
          controls: {
            auth: unresolvedControl,
            validation: unresolvedControl,
            rateLimit: unresolvedControl,
            signature: unresolvedControl,
            admin: unresolvedControl,
          },
        });
        continue;
      }
      const mountMws = mounts.flatMap((mnt) => mnt.middlewares);
      const applicable = [...route.middlewares, ...routerUse, ...mountMws];
      const forProof = route.handlerToken !== undefined ? [...applicable, route.handlerToken] : applicable;
      let proof = isAuthProof(forProof, bindings, aliases);
      if (proof === undefined) {
        for (const mnt of mounts) {
          const p = isAuthProof(mnt.middlewares, importBindingMap(projectMap, mnt.filePath), aliasesOf(mnt.filePath));
          if (p !== undefined) {
            proof = p;
            break;
          }
        }
      }
      const applicableMiddleware: { token: string; ownerFile: string }[] = [
        ...route.middlewares.map((token) => ({ token, ownerFile: filePath })),
        ...routerUse.map((token) => ({ token, ownerFile: filePath })),
        ...mounts.flatMap((mnt) => mnt.middlewares.map((token) => ({ token, ownerFile: mnt.filePath }))),
      ];
      const applicableTexts = [
        ...route.middlewareTexts,
        ...routerUseTexts,
        ...mounts.flatMap((mnt) => mnt.middlewareTexts),
      ];

      const found = { auth: false, admin: false, rateLimit: false, signature: false, validation: false };
      const provenBy: Partial<Record<keyof typeof found, string>> = {};
      let anyUnresolved = unreadableUse;
      for (const { token, ownerFile } of applicableMiddleware) {
        const expanded = expandAlias(token, aliasesOf(ownerFile));
        if (/^passport$/i.test(expanded.split('.')[0] ?? '')) {
          if (!found.auth) provenBy.auth = 'passport';
          found.auth = true;
          continue;
        }
        const resolved = resolveMiddleware(
          expanded,
          ownerFile,
          ownerFile === filePath ? bindings : importBindingMap(projectMap, ownerFile),
          contentOf,
        );
        if (resolved === undefined) {
          anyUnresolved = true;
          continue;
        }
        for (const key of ['auth', 'admin', 'rateLimit', 'signature', 'validation'] as const) {
          if (!resolved.effects[key]) continue;
          if (!found[key]) provenBy[key] = resolved.filePath;
          found[key] = true;
        }
      }

      if (proof !== undefined && !found.auth) {
        found.auth = true;
        provenBy.auth = proof;
      }
      const state = (key: keyof typeof found): RouteControl =>
        found[key]
          ? { state: 'proven', ...(provenBy[key] !== undefined ? { provenBy: provenBy[key] as string } : {}) }
          : { state: anyUnresolved ? 'unresolved' : 'absent' };

      const mount = mounts[0];
      const fullPath = mount !== undefined ? joinPath(mount.prefix, route.relPath) : route.relPath;
      if (mount === undefined && mountGraphIncomplete) anyUnresolved = true;
      const handler = resolveHandler({
        token: route.handlerToken !== undefined ? expandAlias(route.handlerToken, aliases) : undefined,
        inline: route.handlerInline,
        filePath,
        line: route.line,
        endLine: route.endLine,
        bindings,
        contentOf,
      });

      if (!found.auth && handler !== undefined) {
        const handlerContent = contentOf(handler.filePath);
        if (handlerContent !== undefined) {
          const handlerText = spanText(handlerContent, handler.line, handler.endLine);
          if (resolvesToRejection({ fileMap, projectMap }, handler.filePath, handlerText)) {
            found.auth = true;
            provenBy.auth = handler.filePath;
          }
        }
      }

      const authProven = found.auth;
      const authProvenBy = provenBy.auth;

      const validationState = (): RouteControl => {
        const chained = applicableTexts.some((text) => hasValidatorChain(text));
        if (!chained && !found.validation) return { state: anyUnresolved ? 'unresolved' : 'absent' };
        if (handler === undefined) return { state: 'unresolved' };
        const handlerContent = contentOf(handler.filePath);
        if (handlerContent === undefined) return { state: 'unresolved' };
        const handlerText = spanText(handlerContent, handler.line, handler.endLine);
        if (!rejectsOnValidationResult(handlerText)) {
          return { state: anyUnresolved ? 'unresolved' : 'absent' };
        }
        return { state: 'proven', ...(provenBy.validation !== undefined ? { provenBy: provenBy.validation } : {}) };
      };

      out.push({
        method: route.method,
        relPath: route.relPath,
        fullPath,
        filePath,
        line: route.line,
        endLine: route.endLine,
        spanResolved: true,
        middlewares: applicable,
        ...(route.handlerToken !== undefined ? { handlerToken: route.handlerToken } : {}),
        ...(handler !== undefined ? { handler } : {}),
        protectedByAuth: authProven,
        ...(authProvenBy !== undefined ? { authProofFile: authProvenBy } : {}),
        pathResolution: mount !== undefined ? 'mounted' : 'relative',
        controls: {
          auth: state('auth'),
          admin: state('admin'),
          rateLimit: state('rateLimit'),
          signature: state('signature'),
          validation: validationState(),
        },
      });
    }
  }

  out.sort(
    (a, b) => a.filePath.localeCompare(b.filePath) || a.line - b.line || a.method.localeCompare(b.method),
  );
  return out;
}

import { MAX_AST_FILE_BYTES, type AstAnalysisGaps } from '../ast/astAnalysis.js';
import { crossFileFlowChecks } from '../ast/crossFileTaint.js';
import { ROUTE_CALL_GRAPH_LIMITS, UNRESOLVED_HANDLER_REASON, type CallWalkFailure } from '../project-map/buildRouteSecurity.js';
import { CappedNames, quotedListWithRemainder } from './cappedNames.js';
import type { ApiRouteFramework, LinksNotFollowed, RouteSecurityProfile } from './types.js';

const PYTHON_ROUTE_FRAMEWORKS: ReadonlySet<ApiRouteFramework> = new Set(['fastapi', 'flask', 'django']);

const files = (n: number): string => `${n} file${n === 1 ? '' : 's'}`;
const was = (n: number): string => (n === 1 ? 'was' : 'were');
const thoseFiles = (n: number): string => (n === 1 ? 'that file' : 'those files');

export function astGapWarnings(gaps: AstAnalysisGaps | undefined): string[] {
  if (gaps === undefined) return [];
  const checks = crossFileFlowChecks();
  const out: string[] = [];
  const say = (names: CappedNames, sentence: (n: number) => string): void => {
    if (names.total > 0) out.push(`${sentence(names.total)}: ${quotedListWithRemainder(names)}.`);
  };
  say(
    gaps['node-budget'],
    (n) =>
      `${files(n)} ${was(n)} only partly analysed for data flow (${n === 1 ? 'it exceeds' : 'they exceed'} the ` +
      `per-file analysis size), so in ${thoseFiles(n)} the ${checks} checks rest partly or wholly on pattern matching`,
  );
  say(
    gaps['too-large'],
    (n) =>
      `${files(n)} ${was(n)} not analysed for data flow because ${n === 1 ? 'it is' : 'they are'} larger than ` +
      `the analysis accepts (over ${MAX_AST_FILE_BYTES.toLocaleString('en-US')} characters), so in ${thoseFiles(n)} ` +
      `the ${checks} checks rest on pattern matching alone`,
  );
  say(
    gaps['scan-budget'],
    (n) =>
      `${files(n)} ${was(n)} analysed for data flow only partly or not at all, because this scan's total ` +
      `data-flow analysis budget ran out, so in ${thoseFiles(n)} the ${checks} checks rest partly or wholly on ` +
      'pattern matching',
  );
  return out;
}

export function linkWarnings(links: LinksNotFollowed | undefined): string[] {
  if (links === undefined || links.total === 0) return [];
  const n = links.total;
  const s = n === 1 ? '' : 's';
  return [
    `${n} linked file${s} or folder${s} ${was(n)} not followed (links can point outside the project, so Epherem ` +
      `never follows them). ${n === 1 ? 'Its' : 'Their'} contents were not scanned: ${quotedListWithRemainder(links)}.`,
  ];
}

function inWords(items: readonly string[]): string {
  return items.length <= 1 ? (items[0] ?? '') : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}

export function routeProtectionGapWarnings(
  profiles: readonly RouteSecurityProfile[],
  callWalkFailures: readonly CallWalkFailure[],
  isScannable: (filePath: string) => boolean,
): string[] {
  const out: string[] = [];

  const stopped = new CappedNames();
  const limitsHit = new Set<string>();
  for (const profile of profiles) {
    if (!isScannable(profile.filePath)) continue;
    const hit = ROUTE_CALL_GRAPH_LIMITS.filter((limit) => profile.analysisReasons.includes(limit.reason));
    if (hit.length === 0) continue;
    for (const limit of hit) limitsHit.add(limit.reason);
    stopped.add(`${profile.method} ${profile.routePath} at "${profile.filePath}:${profile.line}"`);
  }
  if (stopped.total > 0) {
    const n = stopped.total;
    const because = ROUTE_CALL_GRAPH_LIMITS.filter((limit) => limitsHit.has(limit.reason)).map((limit) => limit.words);
    const unnamed = stopped.unnamed;
    out.push(
      `Route protection analysis stopped early on ${n} route${n === 1 ? '' : 's'} because ${inWords(because)}, ` +
        `so on ${n === 1 ? 'that route' : 'those routes'} a login, permission, input-validation, rate-limit or CSRF ` +
        'check that was not found in the code followed was marked unknown rather than missing, and this scan does ' +
        `not say whether ${n === 1 ? 'the route is' : 'they are'} protected: ${stopped.named.join(', ')}` +
        `${unnamed > 0 ? `… and ${unnamed} more` : ''}.`,
    );
  }

  const failed = new CappedNames();
  for (const failure of callWalkFailures) {
    if (isScannable(failure.filePath)) failed.add(`${failure.filePath}:${failure.line}`);
  }
  if (failed.total > 0) {
    const n = failed.total;
    out.push(
      `Route protection analysis could not follow the calls made inside ${n} function${n === 1 ? '' : 's'}, so on ` +
        `a route that reaches ${n === 1 ? 'it' : 'one of them'}, a login, permission or other check made in a ` +
        `function ${n === 1 ? 'it calls' : 'they call'} was not seen and may be reported as missing: ` +
        `${quotedListWithRemainder(failed)}.`,
    );
  }

  const python = new CappedNames();
  const unlocated = new CappedNames();
  for (const profile of profiles) {
    if (!isScannable(profile.filePath) || !profile.analysisReasons.includes(UNRESOLVED_HANDLER_REASON)) continue;
    const label = `${profile.method} ${profile.routePath} at "${profile.filePath}:${profile.line}"`;
    const route = `${profile.filePath}\0${profile.line}\0${profile.method}`;
    if (PYTHON_ROUTE_FRAMEWORKS.has(profile.framework)) python.add(label, route);
    else if (!ROUTE_CALL_GRAPH_LIMITS.some((limit) => profile.analysisReasons.includes(limit.reason))) {
      unlocated.add(label, route);
    }
  }
  if (python.total > 0) {
    const n = python.total;
    out.push(
      `Route protection analysis reads JavaScript and TypeScript handlers only, so it did not follow the code of ` +
        `${n} Python route${n === 1 ? '' : 's'}, and a missing login, permission, input-validation, rate-limit or ` +
        `CSRF check on ${n === 1 ? 'it' : 'them'} can go unreported; only checks that match Python code by pattern ` +
        `examined ${n === 1 ? 'it' : 'them'}: ${routeList(python)}.`,
    );
  }
  if (unlocated.total > 0) {
    const n = unlocated.total;
    out.push(
      `The handler code of ${n} route${n === 1 ? '' : 's'} could not be located, so route protection analysis did ` +
        'not follow it, and a missing login, permission, input-validation, rate-limit or CSRF check on ' +
        `${n === 1 ? 'it' : 'them'} can go unreported: ${routeList(unlocated)}.`,
    );
  }
  return out;
}

function routeList(routes: CappedNames): string {
  return `${routes.named.join(', ')}${routes.unnamed > 0 ? `… and ${routes.unnamed} more` : ''}`;
}

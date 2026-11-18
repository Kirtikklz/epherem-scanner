import { buildAbsenceRouteModel, type AbsenceRoute, type RouteControls } from '../candidates/absence/routeModel.js';
import type { RuleContext } from './types.js';

export type { RouteControls, RouteControl, ControlState } from '../candidates/absence/routeModel.js';

export type ControlKind = keyof RouteControls;

const modelCache = new WeakMap<RuleContext, Map<string, AbsenceRoute[]>>();

function routesByFile(context: RuleContext): Map<string, AbsenceRoute[]> {
  let cached = modelCache.get(context);
  if (cached !== undefined) return cached;
  cached = new Map();
  let routes: AbsenceRoute[];
  try {
    routes = buildAbsenceRouteModel(context.fileMap, context.projectMap);
  } catch {
    routes = [];
  }
  for (const route of routes) {
    const list = cached.get(route.filePath) ?? [];
    list.push(route);
    cached.set(route.filePath, list);
  }
  modelCache.set(context, cached);
  return cached;
}

function routeAt(context: RuleContext, filePath: string, line: number): AbsenceRoute | undefined {
  const routes = routesByFile(context).get(filePath);
  if (routes === undefined) return undefined;
  let best: AbsenceRoute | undefined;
  for (const route of routes) {
    if (line < route.line || line > route.endLine) continue;
    if (best === undefined || route.endLine - route.line < best.endLine - best.line) best = route;
  }
  return best;
}

export function routeControlsAt(context: RuleContext, filePath: string, line: number): RouteControls | undefined {
  return routeAt(context, filePath, line)?.controls;
}

export function routeMiddlewareAt(
  context: RuleContext,
  filePath: string,
  line: number,
): readonly string[] | undefined {
  const route = routeAt(context, filePath, line);
  if (route === undefined) return undefined;
  if (!route.spanResolved) return undefined;
  return route.middlewares;
}

export function unreadRoutes(context: RuleContext): AbsenceRoute[] {
  return absenceRoutesFor(context)
    .filter((route) => !route.spanResolved)
    .sort((a, b) => a.filePath.localeCompare(b.filePath) || a.line - b.line);
}

export function absenceRoutesFor(context: RuleContext): AbsenceRoute[] {
  const out: AbsenceRoute[] = [];
  for (const routes of routesByFile(context).values()) out.push(...routes);
  return out;
}

export function routeControlProven(
  context: RuleContext,
  filePath: string,
  line: number,
  control: ControlKind,
): boolean {
  return routeControlsAt(context, filePath, line)?.[control].state === 'proven';
}

export function routeControlProvenBy(
  context: RuleContext,
  filePath: string,
  line: number,
  control: ControlKind,
): string | undefined {
  const found = routeControlsAt(context, filePath, line)?.[control];
  return found?.state === 'proven' ? found.provenBy : undefined;
}

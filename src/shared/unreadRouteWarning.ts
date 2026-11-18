import { isScannablePath } from '../rules/index.js';
import { unreadRoutes } from './routeControlModel.js';
import type { RuleContext } from './types.js';

const MAX_UNREAD_ROUTES_NAMED = 5;

export function unreadRouteWarnings(context: RuleContext): string[] {
  const prefix = context.projectMap.scannerRootPrefix;
  const unread = unreadRoutes(context).filter((route) => isScannablePath(route.filePath, prefix));
  if (unread.length === 0) return [];

  const named = unread.slice(0, MAX_UNREAD_ROUTES_NAMED);
  const unnamed = unread.length - named.length;
  const list = named.map((route) => `${route.method} ${route.fullPath} at "${route.filePath}:${route.line}"`).join(', ');

  const count =
    unread.length === 1
      ? '1 route registration could not be read, so no middleware, handler or protection applied to it was resolved'
      : `${unread.length} route registrations could not be read, so no middleware, handler or protection applied to them was resolved`;
  const partial =
    unnamed === 0
      ? ''
      : ` This list is partial: only the first ${named.length} are named below, and ${unnamed} further ` +
        `route${unnamed === 1 ? '' : 's'} could not be read and ${unnamed === 1 ? 'is' : 'are'} not named here.`;

  return [
    `${count}.${partial} ${named.length === 1 ? 'The route is' : 'The named routes are'}: ${list}. ` +
      'A finding on one of these routes means the scanner could not read the route, not that the route is ' +
      'unguarded; every other route in the scan is unaffected.',
  ];
}

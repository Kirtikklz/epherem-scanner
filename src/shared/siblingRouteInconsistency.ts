import { enclosingFunctionScopeRange } from './handlerScope.js';
import { lineNumberAt } from './utils.js';
import type { ProjectMap, RouteSecurityProfile } from './types.js';

const MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export const MAX_NAMED_SIBLINGS = 3;

export interface SiblingInconsistency {
  groupPath: string;
  siblingRoutePaths: string[];
}

export function siblingGroupOf(routePath: string): string {
  const segments = String(routePath ?? '').split('/').filter((segment) => segment !== '');
  return '/' + segments.slice(0, -1).join('/');
}

function directoryOf(filePath: string): string {
  const cut = filePath.lastIndexOf('/');
  return cut === -1 ? '' : filePath.slice(0, cut);
}

function shareDirectoryPrefix(left: string, right: string): boolean {
  const a = directoryOf(left).split('/').filter((segment) => segment !== '');
  const b = directoryOf(right).split('/').filter((segment) => segment !== '');
  return a.length > 0 && b.length > 0 && a[0] === b[0];
}

function owningProfiles(
  profiles: readonly RouteSecurityProfile[],
  content: string,
  index: number,
): RouteSecurityProfile[] {
  const range = enclosingFunctionScopeRange(content, index);
  const startLine = lineNumberAt(content, range.start);
  const endLine = lineNumberAt(content, Math.max(range.start, range.end - 1));
  return profiles.filter((profile) => profile.line >= startLine && profile.line <= endLine);
}

export function siblingInconsistency(
  projectMap: ProjectMap,
  filePath: string,
  content: string,
  index: number,
): SiblingInconsistency | undefined {
  const profiles = projectMap.routeSecurityProfiles ?? [];
  if (profiles.length === 0) return undefined;

  const owning = owningProfiles(
    profiles.filter((profile) => profile.filePath === filePath),
    content,
    index,
  );
  if (owning.length === 0) return undefined;

  const flaggedIsForgettable = owning.every(
    (profile) =>
      profile.analysisStatus === 'complete' &&
      profile.authentication.status === 'absent' &&
      MUTATION_METHODS.has(profile.method),
  );
  if (!flaggedIsForgettable) return undefined;

  const groupPaths = new Set(owning.map((profile) => siblingGroupOf(profile.routePath)));
  if (groupPaths.size !== 1) return undefined;
  const groupPath = [...groupPaths][0] as string;

  const ownRoutePaths = new Set(owning.map((profile) => profile.routePath));
  const frameworks = new Set(owning.map((profile) => profile.framework));
  const siblings = profiles.filter(
    (profile) =>
      siblingGroupOf(profile.routePath) === groupPath &&
      !ownRoutePaths.has(profile.routePath) &&
      profile.filePath !== filePath,
  );
  if (siblings.length === 0) return undefined;

  const byRoutePath = new Map<string, RouteSecurityProfile[]>();
  for (const sibling of siblings) {
    const list = byRoutePath.get(sibling.routePath) ?? [];
    list.push(sibling);
    byRoutePath.set(sibling.routePath, list);
  }

  const allProtected = [...byRoutePath.values()].every((list) =>
    list.every(
      (profile) =>
        profile.authentication.status === 'present' &&
        profile.analysisStatus === 'complete' &&
        frameworks.has(profile.framework) &&
        shareDirectoryPrefix(profile.filePath, filePath),
    ),
  );
  if (!allProtected) return undefined;

  const siblingRoutePaths = [...byRoutePath.keys()].sort();
  if (siblingRoutePaths.length < 2) return undefined;

  return { groupPath, siblingRoutePaths };
}

export function describeSiblings(siblingRoutePaths: readonly string[]): string {
  const named = siblingRoutePaths.slice(0, MAX_NAMED_SIBLINGS);
  const remaining = siblingRoutePaths.length - named.length;
  return remaining > 0 ? `${named.join(', ')} and ${remaining} more` : named.join(', ');
}

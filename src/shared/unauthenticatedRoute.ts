import { enclosingFunctionScopeRange } from './handlerScope.js';
import { lineNumberAt } from './utils.js';
import type { ProjectMap, RouteSecurityProfile } from './types.js';

const MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

const MUTATION_DB_KINDS = new Set(['insert', 'update', 'delete', 'upsert', 'write', 'raw_sql']);

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

export function isUnauthenticatedMutationRoute(
  projectMap: ProjectMap,
  filePath: string,
  content: string,
  index: number,
): boolean {
  const inFile = (projectMap.routeSecurityProfiles ?? []).filter(
    (profile) => profile.filePath === filePath,
  );
  if (inFile.length === 0) return false;

  const owning = owningProfiles(inFile, content, index);
  if (owning.length === 0) return false;

  return owning.every(
    (profile) =>
      profile.analysisStatus === 'complete' &&
      profile.authentication.status === 'absent' &&
      profile.authorization.status !== 'present' &&
      MUTATION_METHODS.has(profile.method) &&
      profile.databaseOperations.some((operation) => MUTATION_DB_KINDS.has(operation.kind)),
  );
}

export const MUTATION_DB_KINDS_FOR_TEST: ReadonlySet<string> = MUTATION_DB_KINDS;

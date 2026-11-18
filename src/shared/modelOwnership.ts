import { normaliseModelKey } from '../project-map/detectSchemaModels.js';
import type { ProjectMap } from './types.js';

export function modelHasNoOwner(projectMap: ProjectMap, modelName: string | undefined): boolean {
  if (modelName === undefined) return false;
  const schemaModels = projectMap.schemaModels;
  if (schemaModels === undefined || schemaModels.sourcesParsed === 0) return false;
  const key = normaliseModelKey(modelName);
  if (key === '') return false;
  const canonical = schemaModels.aliases[key] ?? key;
  const model = schemaModels.models.find((candidate) => candidate.key === canonical);
  if (model === undefined) return false;
  return !model.hasOwnerLink;
}

export function modelFromReceiver(receiver: string): string | undefined {
  const trimmed = receiver.trim();
  if (trimmed === '') return undefined;
  const fromTable = /\.\s*from\s*\(\s*['"`]([^'"`]+)['"`]\s*\)\s*$/.exec(trimmed);
  if (fromTable?.[1] !== undefined) return fromTable[1];
  if (!/^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*$/.test(trimmed)) return undefined;
  const segments = trimmed.split('.').map((segment) => segment.trim()).filter((segment) => segment !== '');
  const last = segments[segments.length - 1];
  if (last === undefined) return undefined;
  if (segments.length === 1 && /^(?:db|prisma|client|supabase|sql|knex|conn|connection|pool|store)$/i.test(last)) {
    return undefined;
  }
  return last;
}

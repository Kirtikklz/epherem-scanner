import type { FileMap, PreparedInput } from '../shared/types.js';
import { classifyFile } from './classifyFile.js';

export function buildFileMap(prepared: PreparedInput): FileMap {
  return {
    rootPath: prepared.rootPath,
    entries: prepared.files.map(classifyFile),
    skipped: prepared.skipped,
    skippedCount: prepared.skippedCount,
    ...(prepared.skippedByReason !== undefined ? { skippedByReason: prepared.skippedByReason } : {}),
    warnings: prepared.warnings,
  };
}

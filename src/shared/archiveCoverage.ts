import type { ArchiveIgnoredExtensionCounts } from './languages.js';

export interface ArchiveIgnoredCarry {
  files: number;
  byExtension: ArchiveIgnoredExtensionCounts;
  byReason?: Readonly<Record<string, number>>;
  nestedArchive?: string;
}

export function emptyArchiveIgnoredCarry(): ArchiveIgnoredCarry {
  return { files: 0, byExtension: {} };
}

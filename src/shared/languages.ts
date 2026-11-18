import type { FileMap } from './types.js';
import { extensionOf } from './utils.js';

export type AnalysedLanguage = 'javascript' | 'typescript' | 'python' | 'sql';

export const COMPONENT_EXTENSIONS: ReadonlySet<string> = new Set(['.astro', '.svelte', '.vue']);

const EXTENSION_LANGUAGE: Record<string, string> = {
  '.ts': 'typescript', '.tsx': 'typescript', '.mts': 'typescript', '.cts': 'typescript',
  '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  ...Object.fromEntries([...COMPONENT_EXTENSIONS].map((extension) => [extension, 'typescript'])),
  '.py': 'python',
  '.sql': 'sql',
  '.rb': 'ruby', '.go': 'go', '.php': 'php', '.java': 'java', '.rs': 'rust',
  '.cs': 'csharp', '.kt': 'kotlin', '.swift': 'swift', '.scala': 'scala',
  '.c': 'c', '.h': 'c', '.cpp': 'cpp', '.cc': 'cpp', '.hpp': 'cpp',
  '.ex': 'elixir', '.exs': 'elixir', '.dart': 'dart', '.lua': 'lua', '.pl': 'perl',
};

const ANALYSED: ReadonlySet<string> = new Set(['javascript', 'typescript', 'python', 'sql']);

export function unanalysedLanguageOf(extension: string): string | undefined {
  const language = EXTENSION_LANGUAGE[extension];
  return language !== undefined && !ANALYSED.has(language) ? language : undefined;
}

export const DECLARATIVE_LANGUAGES: ReadonlySet<string> = new Set(['config', 'sql']);

export const SOURCE_MAPPED_EXTENSIONS: ReadonlySet<string> = new Set(Object.keys(EXTENSION_LANGUAGE));

const DIRECTORY_SKIP_REASONS: ReadonlySet<string> = new Set([
  'ignored_directory',
  'directory_unreadable',
  'max_depth_exceeded',
]);

const NOT_PROJECT_FILE_SKIP_REASONS: ReadonlySet<string> = new Set(['os_metadata']);

export const ANALYSIS_METHOD_BY_LANGUAGE: Readonly<Record<AnalysedLanguage, string>> = {
  typescript: 'ast+regex',
  javascript: 'ast+regex',
  python: 'parsed_with_pattern_fallback',
  sql: 'regex_only',
};

export interface DetectedLanguages {
  detected: string[];
  analysed: string[];
  unsupported: string[];
  fileCountByLanguage: Readonly<Record<string, number>>;
  unreadExtensions: Readonly<Record<string, number>>;
  unreadLanguages: string[];
  skippedFilesSeen: number;
  skippedFilesTotal: number;
}

export type ArchiveIgnoredExtensionCounts = Readonly<Record<string, number>>;

export function detectLanguages(
  fileMap: FileMap,
  archiveIgnoredExtensions: ArchiveIgnoredExtensionCounts = {},
): DetectedLanguages {
  const fileCountByLanguage: Record<string, number> = {};
  const count = (extension: string, files = 1): void => {
    const language = EXTENSION_LANGUAGE[extension];
    if (language === undefined) return;
    fileCountByLanguage[language] = (fileCountByLanguage[language] ?? 0) + files;
  };
  const readLanguages = new Set<string>();
  for (const entry of fileMap.entries) {
    count(entry.extension);
    const language = EXTENSION_LANGUAGE[entry.extension];
    if (language !== undefined) readLanguages.add(language);
  }
  const unreadExtensions: Record<string, number> = {};
  const recordUnread = (extension: string, files: number): void => {
    const language = EXTENSION_LANGUAGE[extension];
    if (language === undefined || !ANALYSED.has(language)) return;
    unreadExtensions[extension] = (unreadExtensions[extension] ?? 0) + files;
  };
  for (const skip of fileMap.skipped) {
    if (NOT_PROJECT_FILE_SKIP_REASONS.has(skip.reason)) continue;
    const extension = extensionOf(skip.path);
    count(extension);
    if (DIRECTORY_SKIP_REASONS.has(skip.reason)) continue;
    recordUnread(extension, 1);
  }
  for (const [extension, files] of Object.entries(archiveIgnoredExtensions)) {
    if (!Number.isSafeInteger(files) || files <= 0) continue;
    count(extension, files);
    recordUnread(extension, files);
  }
  const detected = Object.keys(fileCountByLanguage).sort((a, b) => a.localeCompare(b));
  const unreadLanguages = [
    ...new Set(
      Object.keys(unreadExtensions)
        .map((extension) => EXTENSION_LANGUAGE[extension])
        .filter((language): language is string => language !== undefined),
    ),
  ].sort((a, b) => a.localeCompare(b));
  return {
    detected,
    analysed: detected.filter((language) => ANALYSED.has(language) && readLanguages.has(language)),
    unsupported: detected.filter((language) => !ANALYSED.has(language)),
    unreadExtensions,
    unreadLanguages,
    fileCountByLanguage,
    skippedFilesSeen: fileMap.skipped.length,
    skippedFilesTotal: fileMap.skippedCount,
  };
}

export function detectedCodeLanguages(fileMap: FileMap): Set<'javascript' | 'typescript' | 'python'> {
  const { detected } = detectLanguages(fileMap);
  const code = new Set<'javascript' | 'typescript' | 'python'>();
  for (const language of detected) {
    if (language === 'javascript' || language === 'typescript' || language === 'python') code.add(language);
  }
  return code;
}

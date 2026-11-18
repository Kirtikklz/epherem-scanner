import path from 'node:path';
import type { SkippedFile } from '../shared/types.js';
import { extensionOf } from '../shared/utils.js';
import { COMPONENT_EXTENSIONS, unanalysedLanguageOf } from '../shared/languages.js';

export const EMPTY_INPUT_LEAD = 'Epherem found no JavaScript, TypeScript or Python code in this project, so nothing was scanned.';

export const NESTED_ARCHIVE_EXTENSIONS: ReadonlySet<string> = new Set(['.zip', '.rar', '.7z', '.tar', '.gz', '.tgz']);

export interface RefusedBeforeWalk {
  nestedArchive?: string;
  byExtension: Readonly<Record<string, number>>;
}

const LANGUAGE_NAMES: Readonly<Record<string, string>> = {
  ruby: 'Ruby', go: 'Go', php: 'PHP', java: 'Java', rust: 'Rust', csharp: 'C#', kotlin: 'Kotlin',
  swift: 'Swift', scala: 'Scala', c: 'C', cpp: 'C++', elixir: 'Elixir', dart: 'Dart', lua: 'Lua', perl: 'Perl',
};

function sayable(filePath: string): string {
  const name = path.posix.basename(String(filePath).replace(/\\/g, '/')).replace(/[\u0000-\u001f\u007f"“”]/g, '').trim();
  return name.length > 60 ? `${name.slice(0, 59)}…` : name;
}

function list(counts: Map<string, number>): string {
  const names = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([name]) => name);
  return names.length <= 1 ? (names[0] ?? '') : `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

const READ_CODE = /^\.(?:[cm]?[jt]sx?|py)$/;

function nestedArchiveName(skipped: readonly SkippedFile[], refusedBeforeWalk: RefusedBeforeWalk): string {
  const nested = skipped.find((s) => s.reason === 'ignored_extension' && NESTED_ARCHIVE_EXTENSIONS.has(extensionOf(s.path)))?.path
    ?? refusedBeforeWalk.nestedArchive;
  return nested === undefined ? '' : sayable(nested);
}

function otherCode(skipped: readonly SkippedFile[], refusedBeforeWalk: RefusedBeforeWalk): Map<string, number> {
  const other = new Map<string, number>();
  const note = (extension: string, files: number): void => {
    const language = unanalysedLanguageOf(extension);
    const name = language !== undefined ? (LANGUAGE_NAMES[language] ?? language) : COMPONENT_EXTENSIONS.has(extension) ? `${extension} files` : undefined;
    if (name !== undefined) other.set(name, (other.get(name) ?? 0) + files);
  };
  for (const s of skipped) if (s.reason === 'not_useful') note(extensionOf(s.path), 1);
  for (const [extension, files] of Object.entries(refusedBeforeWalk.byExtension)) {
    if (Number.isSafeInteger(files) && files > 0) note(extension, files);
  }
  return other;
}

export function isReadCodePath(filePath: string): boolean {
  return READ_CODE.test(extensionOf(filePath));
}

function whatWasThere(
  skipped: readonly SkippedFile[],
  maxFileSizeBytes: number,
  refusedBeforeWalk: RefusedBeforeWalk,
  read: 'none' | 'few',
): string {
  const nested = nestedArchiveName(skipped, refusedBeforeWalk);
  if (nested !== '') {
    return `${read === 'none' ? 'Its' : 'More of its'} code may be inside “${nested}”, and Epherem doesn’t open an archive inside a project. Unzip it, then scan the files themselves.`;
  }
  const other = otherCode(skipped, refusedBeforeWalk);
  if (other.size > 0) {
    return `The ${read === 'none' ? '' : 'rest of the '}code here is ${otherLanguages(other)}, which Epherem doesn’t read yet.`;
  }
  const mb = Math.round(maxFileSizeBytes / 1_000_000);
  const unread = skipped.find((s) => (s.reason === 'too_large' || s.reason === 'minified') && READ_CODE.test(extensionOf(s.path)));
  if (unread !== undefined) {
    return read === 'none'
      ? `The only code here is “${sayable(unread.path)}”, which is minified or larger than ${mb} MB, so Epherem doesn’t read it. Scan the source code it was built from.`
      : `“${sayable(unread.path)}” is minified or larger than ${mb} MB, so Epherem didn’t read it.`;
  }
  if (Object.entries(refusedBeforeWalk.byExtension).some(([extension, files]) => READ_CODE.test(extension) && Number.isSafeInteger(files) && files > 0)) {
    return read === 'none'
      ? `The only code here is minified or larger than ${mb} MB, so Epherem doesn’t read it. Scan the source code it was built from.`
      : `Some of its code is minified or larger than ${mb} MB, so Epherem didn’t read it.`;
  }
  return read === 'none' ? 'Scan the folder that holds your app’s source code.' : '';
}

export function emptyInputMessage(
  skipped: readonly SkippedFile[],
  maxFileSizeBytes: number,
  refusedBeforeWalk: RefusedBeforeWalk = { byExtension: {} },
): string {
  return `${EMPTY_INPUT_LEAD} ${whatWasThere(skipped, maxFileSizeBytes, refusedBeforeWalk, 'none')}`;
}

export const FEW_CODE_FILES = 3;
export const FEW_CODE_LEAD = 'Epherem read only ';
export const NO_CODE_IN_REPORT_LEAD = 'Epherem found no JavaScript, TypeScript or Python code in this project, so only its other files were checked.';

export interface FewCodeFiles {
  codeFilesRead: number;
  message: string;
}

function quotedList(names: readonly string[]): string {
  const quoted = names.map((name) => `“${name}”`);
  return quoted.length <= 1 ? (quoted[0] ?? '') : `${quoted.slice(0, -1).join(', ')} and ${quoted[quoted.length - 1]}`;
}

export function fewCodeFilesNote(
  readPaths: readonly string[],
  skipped: readonly SkippedFile[],
  maxFileSizeBytes: number,
  refusedBeforeWalk: RefusedBeforeWalk = { byExtension: {} },
): FewCodeFiles | undefined {
  const code = readPaths.filter(isReadCodePath);
  if (code.length > FEW_CODE_FILES) return undefined;
  if (code.length === 0) {
    return { codeFilesRead: 0, message: `${NO_CODE_IN_REPORT_LEAD} ${whatWasThere(skipped, maxFileSizeBytes, refusedBeforeWalk, 'none')}` };
  }
  const names = code.map(sayable);
  const which = names.every((name) => name !== '') ? `: ${quotedList(names)}` : '';
  const lead = `${FEW_CODE_LEAD}${code.length} code file${code.length === 1 ? '' : 's'} in this project${which}.`;
  const rest = whatWasThere(skipped, maxFileSizeBytes, refusedBeforeWalk, 'few');
  return { codeFilesRead: code.length, message: rest === '' ? lead : `${lead} ${rest}` };
}

export type ScanFitReason = 'few_code_files' | 'other_language' | 'no_recognised_setup' | 'no_package_list';
export const SCAN_FIT_REASONS: readonly ScanFitReason[] = ['few_code_files', 'other_language', 'no_recognised_setup', 'no_package_list'];
export const NO_RECOGNISED_SETUP_SENTENCE = 'Epherem didn’t recognise what this app is built with.';
export const NO_PACKAGE_LIST_SENTENCE = 'Epherem found no package.json, requirements.txt or other package list it reads in this project, so your app’s libraries weren’t checked.';
export const OTHER_LANGUAGE_LEAD = 'Most of the code in this project is ';

export interface ScanFit {
  reasons: ScanFitReason[];
  codeFilesRead?: number;
  lead?: string;
  also: string[];
}

export interface ScanFitInput {
  readPaths: readonly string[];
  skipped: readonly SkippedFile[];
  maxFileSizeBytes: number;
  refusedBeforeWalk?: RefusedBeforeWalk;
  stacks: readonly string[];
  packageListRead: boolean;
}

function otherLanguages(other: Map<string, number>): string {
  if (other.size <= 3) return list(other);
  const names = [...other.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([name]) => name);
  return `${names.slice(0, 3).join(', ')} and other languages`;
}

export function scanFitNote(input: ScanFitInput): ScanFit {
  const refused = input.refusedBeforeWalk ?? { byExtension: {} };
  const few = fewCodeFilesNote(input.readPaths, input.skipped, input.maxFileSizeBytes, refused);
  const other = otherCode(input.skipped, refused);
  const otherFiles = [...other.values()].reduce((sum, files) => sum + files, 0);
  const sentences = new Map<ScanFitReason, string>();
  if (few !== undefined) sentences.set('few_code_files', few.message);
  if (otherFiles > input.readPaths.filter(isReadCodePath).length) {
    sentences.set('other_language', `${OTHER_LANGUAGE_LEAD}${otherLanguages(other)}, which Epherem doesn’t read yet.`);
  }
  if (input.stacks.length === 0) sentences.set('no_recognised_setup', NO_RECOGNISED_SETUP_SENTENCE);
  if (!input.packageListRead) sentences.set('no_package_list', NO_PACKAGE_LIST_SENTENCE);
  const reasons = SCAN_FIT_REASONS.filter((reason) => sentences.has(reason));
  const first = reasons[0];
  if (first === undefined) return { reasons: [], also: [] };
  const leadSaysLanguage = first === 'few_code_files' && nestedArchiveName(input.skipped, refused) === '' && other.size > 0;
  return {
    reasons,
    ...(few !== undefined ? { codeFilesRead: few.codeFilesRead } : {}),
    lead: sentences.get(first) ?? '',
    also: reasons.slice(1).filter((reason) => !(reason === 'other_language' && leadSaysLanguage)).map((reason) => sentences.get(reason) ?? ''),
  };
}

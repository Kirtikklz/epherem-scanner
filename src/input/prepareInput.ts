import { promises as fs, constants as fsConstants } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { ScannerError } from '../shared/errors.js';
import type { InputLimits, PreparedFile, PreparedInput, SkippedFile } from '../shared/types.js';
import { resolveInputLimits } from '../shared/config.js';
import { extensionOf, toPosixPath } from '../shared/utils.js';
import { isIgnoredDirectory, isIngestedLockfile, looksBinary, preOpenSkipReason } from './fileFilters.js';
import { exceedsNestingDepth } from './nestingDepth.js';
import { isPythonRequirementsPath } from '../shared/pythonRequirementFiles.js';
import { CappedNames } from '../shared/cappedNames.js';
import { emptyInputMessage, type RefusedBeforeWalk } from './emptyInputMessage.js';

export interface PrepareInputOptions {
  limits?: Partial<InputLimits>;
  onlyPaths?: ReadonlySet<string>;
  refusedBeforeWalk?: RefusedBeforeWalk;
  onFileName?: (relativePath: string) => void;
}

interface WalkState {
  rootPath: string;
  limits: InputLimits;
  onlyPaths: ReadonlySet<string> | null;
  files: PreparedFile[];
  skipped: SkippedFile[];
  skippedCount: number;
  skippedByReason: Partial<Record<SkippedFile['reason'], number>>;
  warnings: string[];
  totalContentBytes: number;
  visitedEntries: number;
  directoriesVisited: number;
  deepNestingNamed: number;
  deepNestingTotal: number;
  links: CappedNames;
  onFileName: ((relativePath: string) => void) | undefined;
  startedAt: number;
  truncated: boolean;
}

// Only files handed to a recursive parser are depth-checked.
const PARSED_EXTENSIONS: ReadonlySet<string> = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts',
]);

const MAX_NAMED_DEEP_NESTING_WARNINGS = 5;

// Never follow a symlink at the final path component (0 where unsupported).
const O_NOFOLLOW = (fsConstants.O_NOFOLLOW as number | undefined) ?? 0;
// Files are read in bounded chunks, never past the size cap.
const READ_CHUNK_BYTES = 65_536;

// Read-only walk: project files are opened for reading, never written.
export async function prepareInput(
  inputPath: string,
  options: PrepareInputOptions = {},
): Promise<PreparedInput> {
  const rootPath = path.resolve(inputPath);
  const stat = await fs.stat(rootPath).catch(() => null);
  if (stat === null) {
    throw new ScannerError(`Input path does not exist: ${inputPath}`, 'INPUT_NOT_FOUND');
  }
  if (!stat.isDirectory()) {
    throw new ScannerError(
      'prepareInput expects an extracted project directory. Archives (.zip) must be extracted by the upload system first.',
      'INPUT_NOT_A_DIRECTORY',
    );
  }

  const state: WalkState = {
    rootPath,
    limits: resolveInputLimits(options.limits),
    onlyPaths: options.onlyPaths ?? null,
    files: [],
    skipped: [],
    skippedCount: 0,
    skippedByReason: {},
    warnings: [],
    totalContentBytes: 0,
    visitedEntries: 0,
    directoriesVisited: 0,
    deepNestingNamed: 0,
    deepNestingTotal: 0,
    links: new CappedNames(),
    onFileName: options.onFileName,
    startedAt: Date.now(),
    truncated: false,
  };
  await walkDirectory(state, rootPath, 0);

  const deepNestingUnnamed = state.deepNestingTotal - state.deepNestingNamed;
  if (deepNestingUnnamed > 0) {
    state.warnings.push(
      `…and ${deepNestingUnnamed} more file${deepNestingUnnamed === 1 ? '' : 's'} nest${deepNestingUnnamed === 1 ? 's' : ''} ` +
        `brackets more than ${state.limits.maxSourceNestingDepth} levels deep, so ` +
        `${deepNestingUnnamed === 1 ? 'it was' : 'they were'} not analysed either.`,
    );
  }

  if (state.files.length === 0) {
    // Empty because a limit stopped the walk, not because nothing was there.
    if (state.truncated) {
      throw new ScannerError(
        'Epherem stopped reading this project before it reached any file it could analyse, ' +
          'because a scan limit was hit first. This is not a statement about the project: ' +
          'no file in it was read, and none was found to be unsupported. Scanning again, or ' +
          'scanning a smaller part of the project, may complete.',
        'INPUT_TRUNCATED_BEFORE_ANY_FILE',
      );
    }
    throw new ScannerError(emptyInputMessage(state.skipped, state.limits.maxFileSizeBytes, options.refusedBeforeWalk), 'INPUT_EMPTY');
  }

  state.files.sort((a, b) => a.path.localeCompare(b.path));
  state.skipped.sort((a, b) => a.path.localeCompare(b.path));
  return {
    rootPath,
    files: state.files,
    ...(state.links.total > 0 ? { linksNotFollowed: { named: [...state.links.named], total: state.links.total } } : {}),
    skipped: state.skipped,
    skippedCount: state.skippedCount,
    skippedByReason: { ...state.skippedByReason },
    warnings: state.warnings,
  };
}

function recordSkip(state: WalkState, skipped: SkippedFile): void {
  state.skippedCount += 1;
  state.skippedByReason[skipped.reason] = (state.skippedByReason[skipped.reason] ?? 0) + 1;
  if (state.skipped.length < state.limits.maxSkippedDetails) {
    state.skipped.push(skipped);
  } else if (state.skipped.length === state.limits.maxSkippedDetails) {
    addWarningOnce(
      state,
      `Skipped-file detail list capped at ${state.limits.maxSkippedDetails}; ` +
        'further skipped files are counted but not listed individually.',
    );
  }
}

// Links are never followed out of the project; each one is reported.
async function noteLinkNotFollowed(
  state: WalkState,
  absolutePath: string,
  name: string,
  relativePath: string,
): Promise<void> {
  if (state.onlyPaths !== null && !state.onlyPaths.has(relativePath)) return;
  if (isIgnoredDirectory(name)) return;
  const target = await fs.readlink(absolutePath).catch(() => undefined);
  if (target !== undefined) {
    const resolved = path.resolve(path.dirname(absolutePath), target);
    const inProject = path.relative(state.rootPath, resolved);
    if (inProject === '' || (!inProject.startsWith('..') && !path.isAbsolute(inProject))) return;
    if (isIgnoredDirectory(path.basename(resolved))) return;
  }
  state.links.add(relativePath);
}

function globalLimitReached(state: WalkState): boolean {
  if (state.truncated) return true;
  if (state.visitedEntries >= state.limits.maxVisitedEntries) {
    markTruncated(state, '', `visited-entry limit (${state.limits.maxVisitedEntries})`);
    return true;
  }
  if (state.directoriesVisited >= state.limits.maxDirectories) {
    markTruncated(state, '', `directory limit (${state.limits.maxDirectories})`);
    return true;
  }
  if (Date.now() - state.startedAt > state.limits.maxScanDurationMs) {
    markTruncated(state, '', `scan duration limit (${state.limits.maxScanDurationMs} ms)`);
    return true;
  }
  return false;
}

async function walkDirectory(state: WalkState, currentPath: string, depth: number): Promise<void> {
  if (globalLimitReached(state)) return;
  if (depth > state.limits.maxDirectoryDepth) {
    const relativePath = toPosixPath(path.relative(state.rootPath, currentPath));
    recordSkip(state, { path: relativePath, reason: 'max_depth_exceeded' });
    addWarningOnce(
      state,
      `Directory depth limit (${state.limits.maxDirectoryDepth}) exceeded; some directories were not scanned.`,
    );
    return;
  }

  state.directoriesVisited += 1;

  let entries;
  try {
    entries = await fs.readdir(currentPath, { withFileTypes: true });
  } catch {
    const relativePath = toPosixPath(path.relative(state.rootPath, currentPath)) || '.';
    recordSkip(state, { path: relativePath, reason: 'directory_unreadable' });
    addWarningOnce(
      state,
      'One or more directories could not be read and were skipped; results may be incomplete.',
    );
    return;
  }
  entries.sort((a, b) => a.name.localeCompare(b.name));

  for (const entry of entries) {
    if (globalLimitReached(state)) return;
    state.visitedEntries += 1;
    const absolutePath = path.join(currentPath, entry.name);
    const relativePath = toPosixPath(path.relative(state.rootPath, absolutePath));

    if (entry.isSymbolicLink()) {
      await noteLinkNotFollowed(state, absolutePath, entry.name, relativePath);
      continue;
    }
    if (entry.isDirectory()) {
      if (isIgnoredDirectory(entry.name)) {
        recordSkip(state, { path: relativePath, reason: 'ignored_directory' });
      } else {
        await walkDirectory(state, absolutePath, depth + 1);
      }
      continue;
    }
    if (!entry.isFile()) continue;

    if (state.onlyPaths !== null && !state.onlyPaths.has(relativePath)) continue;
    state.onFileName?.(relativePath);

    const extension = extensionOf(entry.name);
    const skipReason = isPythonRequirementsPath(relativePath) ? undefined : preOpenSkipReason(entry.name, extension);
    if (skipReason !== undefined) {
      recordSkip(state, { path: relativePath, reason: skipReason });
      continue;
    }

    if (state.files.length >= state.limits.maxTotalFiles) {
      markTruncated(state, relativePath, `file count limit (${state.limits.maxTotalFiles})`);
      return;
    }

    await loadBoundedFile(state, absolutePath, relativePath, entry.name, extension);
    if (state.truncated) return;
  }
}

async function loadBoundedFile(
  state: WalkState,
  absolutePath: string,
  relativePath: string,
  fileName: string,
  extension: string,
): Promise<void> {
  const perFileCap = isIngestedLockfile(fileName)
    ? state.limits.maxLockfileSizeBytes
    : state.limits.maxFileSizeBytes;

  let handle: FileHandle;
  try {
    handle = await fs.open(absolutePath, fsConstants.O_RDONLY | O_NOFOLLOW);
  } catch {
    recordSkip(state, { path: relativePath, reason: 'unreadable' });
    return;
  }

  try {
    const st = await handle.stat();
    if (!st.isFile()) {
      recordSkip(state, { path: relativePath, reason: 'unreadable' });
      return;
    }

    const rel = path.relative(state.rootPath, absolutePath);
    if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
      recordSkip(state, { path: relativePath, reason: 'unreadable' });
      return;
    }

    const limit = perFileCap + 1;
    const chunks: Buffer[] = [];
    let bytesRead = 0;
    for (;;) {
      const want = Math.min(READ_CHUNK_BYTES, limit - bytesRead);
      if (want <= 0) break;
      const chunk = Buffer.allocUnsafe(want);
      const { bytesRead: n } = await handle.read(chunk, 0, want, bytesRead);
      if (n <= 0) break;
      chunks.push(n === want ? chunk : chunk.subarray(0, n));
      bytesRead += n;
      if (n < want) break;
    }
    const buffer = Buffer.concat(chunks, bytesRead);

    if (bytesRead > perFileCap) {
      recordSkip(state, { path: relativePath, reason: 'too_large' });
      return;
    }
    if (looksBinary(buffer)) {
      recordSkip(state, { path: relativePath, reason: 'binary' });
      return;
    }
    const content = buffer.toString('utf8');
    if (PARSED_EXTENSIONS.has(extension) && exceedsNestingDepth(content, state.limits.maxSourceNestingDepth)) {
      recordSkip(state, { path: relativePath, reason: 'nesting_too_deep' });
      state.deepNestingTotal += 1;
      if (state.deepNestingNamed < MAX_NAMED_DEEP_NESTING_WARNINGS) {
        state.deepNestingNamed += 1;
        addWarningOnce(
          state,
          `"${relativePath}" nests brackets more than ${state.limits.maxSourceNestingDepth} levels deep, ` +
            'which this scanner cannot parse safely, so that one file was not analysed. ' +
            'Everything else in the project was scanned normally.',
        );
      }
      return;
    }
    if (state.totalContentBytes + bytesRead > state.limits.maxTotalContentBytes) {
      markTruncated(state, relativePath, `total content limit (${state.limits.maxTotalContentBytes} bytes)`);
      return;
    }

    state.totalContentBytes += bytesRead;
    state.files.push({
      path: relativePath,
      absolutePath,
      extension,
      size: bytesRead,
      content,
    });
  } catch {
    recordSkip(state, { path: relativePath, reason: 'unreadable' });
  } finally {
    await handle.close().catch(() => undefined);
  }
}

function markTruncated(state: WalkState, relativePath: string, limitDescription: string): void {
  state.truncated = true;
  if (relativePath.length > 0) {
    recordSkip(state, { path: relativePath, reason: 'scan_limit_reached' });
  }
  addWarningOnce(
    state,
    `Scan truncated: ${limitDescription} reached. Remaining files were not scanned; results are incomplete.`,
  );
}

function addWarningOnce(state: WalkState, warning: string): void {
  if (!state.warnings.includes(warning)) state.warnings.push(warning);
}

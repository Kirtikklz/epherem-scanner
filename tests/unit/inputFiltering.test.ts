import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  isEligibleArchiveFile,
  isIgnoredDirectory,
  isIngestedLockfile,
  isSkippedLockfile,
  looksBinary,
  preContentSkipReason,
} from '../../src/input/fileFilters.js';
import { prepareInput } from '../../src/input/prepareInput.js';
import { DEFAULT_INPUT_LIMITS } from '../../src/shared/constants.js';
import { ScannerError } from '../../src/shared/errors.js';

const limits = DEFAULT_INPUT_LIMITS;

describe('file filters', () => {
  it('ignores junk directories', () => {
    for (const name of [
      'node_modules', '.git', '.svn', '.hg', 'dist', 'build', 'coverage', '.next', '.nuxt',
      '.output', 'out', 'target', 'vendor', '__pycache__', '.venv', 'venv', '.cache', 'tmp', 'temp',
    ]) {
      expect(isIgnoredDirectory(name)).toBe(true);
    }
    expect(isIgnoredDirectory('src')).toBe(false);
  });

  it('uses the same filters when deciding which archive files count toward the scan limit', () => {
    expect(isEligibleArchiveFile('src/app.ts', 100, limits)).toBe(true);
    expect(isEligibleArchiveFile('node_modules/pkg/index.ts', 100, limits)).toBe(false);
    expect(isEligibleArchiveFile('frontend/.next/server/app.js', 100, limits)).toBe(false);
    expect(isEligibleArchiveFile('target/generated.js', 100, limits)).toBe(false);
    expect(isEligibleArchiveFile('src/bundle.min.js', 100, limits)).toBe(false);
    expect(isEligibleArchiveFile('src/image.png', 100, limits)).toBe(false);
    expect(isEligibleArchiveFile('src/oversized.ts', limits.maxFileSizeBytes + 1, limits)).toBe(false);
  });

  it('ingests JS + Python lockfiles but skips other ecosystems', () => {
    expect(isIngestedLockfile('package-lock.json')).toBe(true);
    expect(isIngestedLockfile('yarn.lock')).toBe(true);
    expect(isIngestedLockfile('pnpm-lock.yaml')).toBe(true);
    expect(isIngestedLockfile('poetry.lock')).toBe(true);
    expect(isIngestedLockfile('bun.lock')).toBe(true);
    expect(isIngestedLockfile('bun.lockb')).toBe(false);
    expect(isSkippedLockfile('bun.lockb')).toBe(true);
    expect(isSkippedLockfile('cargo.lock')).toBe(true);
    expect(isSkippedLockfile('composer.lock')).toBe(true);
    expect(preContentSkipReason('package-lock.json', '.json', 2_000_000, limits)).toBeUndefined();
    expect(preContentSkipReason('poetry.lock', '.lock', 100, limits)).toBeUndefined();
    expect(preContentSkipReason('cargo.lock', '.lock', 100, limits)).toBe('lockfile');
  });

  it('skips media, oversized, and non-useful files before reading content', () => {
    expect(preContentSkipReason('logo.png', '.png', 100, limits)).toBe('ignored_extension');
    expect(preContentSkipReason('video.mp4', '.mp4', 100, limits)).toBe('ignored_extension');
    expect(preContentSkipReason('font.woff2', '.woff2', 100, limits)).toBe('ignored_extension');
    expect(preContentSkipReason('big.ts', '.ts', 5_000_000, limits)).toBe('too_large');
    expect(preContentSkipReason('package-lock.json', '.json', 20_000_000, limits)).toBe('too_large');
    expect(preContentSkipReason('bundle.min.js', '.js', 100, limits)).toBe('minified');
    expect(preContentSkipReason('notes.docx', '.docx', 100, limits)).toBe('not_useful');
    expect(preContentSkipReason('app.ts', '.ts', 100, limits)).toBeUndefined();
    expect(preContentSkipReason('.env', '', 100, limits)).toBeUndefined();
    expect(preContentSkipReason('firestore.rules', '.rules', 100, limits)).toBeUndefined();
  });

  it('detects binary buffers', () => {
    expect(looksBinary(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01]))).toBe(true);
    expect(looksBinary(Buffer.from('const a = 1;'))).toBe(false);
  });
});

describe('prepareInput', () => {
  let projectDir: string;

  beforeAll(async () => {
    projectDir = await mkdtemp(path.join(tmpdir(), 'epherem-scanner-'));
    await mkdir(path.join(projectDir, 'node_modules', 'lib'), { recursive: true });
    await mkdir(path.join(projectDir, 'src'), { recursive: true });
    await writeFile(path.join(projectDir, 'node_modules', 'lib', 'index.js'), 'module.exports = 1;');
    await writeFile(path.join(projectDir, 'src', 'app.ts'), 'export const answer = 42;');
    await writeFile(path.join(projectDir, 'package-lock.json'), '{"lockfileVersion":3,"packages":{}}');
    await writeFile(path.join(projectDir, 'poetry.lock'), '[[package]]');
    await writeFile(path.join(projectDir, 'image.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00]));
    await writeFile(path.join(projectDir, 'huge.ts'), 'x'.repeat(1_100_000));
    await writeFile(path.join(projectDir, 'binary.json'), Buffer.from([0x7b, 0x00, 0x7d]));
  });

  afterAll(async () => {
    await rm(projectDir, { recursive: true, force: true });
  });

  it('keeps useful files (including JS + Python lockfiles) and skips junk with reasons', async () => {
    const prepared = await prepareInput(projectDir);
    expect(prepared.files.map((file) => file.path)).toEqual(['package-lock.json', 'poetry.lock', 'src/app.ts']);
    expect(prepared.warnings).toEqual([]);

    const reasons = new Map(prepared.skipped.map((skipped) => [skipped.path, skipped.reason]));
    expect(reasons.get('node_modules')).toBe('ignored_directory');
    expect(reasons.has('poetry.lock')).toBe(false);
    expect(reasons.get('image.png')).toBe('ignored_extension');
    expect(reasons.get('huge.ts')).toBe('too_large');
    expect(reasons.get('binary.json')).toBe('binary');
    expect(prepared.skippedCount).toBeGreaterThanOrEqual(prepared.skipped.length);
  });

  it('never modifies the user files', async () => {
    await prepareInput(projectDir);
    const content = await readFile(path.join(projectDir, 'src', 'app.ts'), 'utf8');
    expect(content).toBe('export const answer = 42;');
  });

  it('enforces the total file count limit with a warning', async () => {
    const prepared = await prepareInput(projectDir, { limits: { maxTotalFiles: 1 } });
    expect(prepared.files).toHaveLength(1);
    expect(prepared.warnings.some((warning) => warning.includes('file count limit'))).toBe(true);
    expect(prepared.skipped.some((skipped) => skipped.reason === 'scan_limit_reached')).toBe(true);
  });

  it('enforces the total content byte limit with a warning', async () => {
    const prepared = await prepareInput(projectDir, { limits: { maxTotalContentBytes: 40 } });
    expect(prepared.files.length).toBeGreaterThan(0);
    expect(prepared.warnings.some((warning) => warning.includes('total content limit'))).toBe(true);
    expect(prepared.skipped.some((skipped) => skipped.reason === 'scan_limit_reached')).toBe(true);
  });

  it('never sends files from excluded directories to scanner rules or the eligible-file count', async () => {
    const excludedDir = await mkdtemp(path.join(tmpdir(), 'epherem-excluded-'));
    const ignored = [
      'node_modules', '.git', '.svn', '.hg', 'dist', 'build', 'coverage', '.next', '.nuxt',
      '.output', 'out', 'target', 'vendor', '__pycache__', '.venv', 'venv', '.cache', 'tmp', 'temp',
    ];
    try {
      await mkdir(path.join(excludedDir, 'src'), { recursive: true });
      await writeFile(path.join(excludedDir, 'src', 'app.ts'), 'export const safe = true;');
      for (const directory of ignored) {
        await mkdir(path.join(excludedDir, directory), { recursive: true });
        await writeFile(
          path.join(excludedDir, directory, 'ignored.ts'),
          ('const password = "AK' + 'IAIOSFODNN7EXAMPLE"; eval(userInput);'),
        );
      }
      const prepared = await prepareInput(excludedDir, { limits: { maxTotalFiles: 1 } });
      expect(prepared.files.map((file) => file.path)).toEqual(['src/app.ts']);
      expect(prepared.warnings.some((warning) => warning.includes('file count limit'))).toBe(false);
      expect(prepared.files.every((file) => !ignored.some((directory) => file.path.includes(`${directory}/`)))).toBe(true);
    } finally {
      await rm(excludedDir, { recursive: true, force: true });
    }
  });

  it('enforces the directory count limit against traversal-bomb inputs', async () => {
    const wideDir = await mkdtemp(path.join(tmpdir(), 'epherem-wide-'));
    try {
      await writeFile(path.join(wideDir, 'a_top.ts'), 'export const top = true;');
      for (let i = 0; i < 6; i += 1) {
        await mkdir(path.join(wideDir, `d${i}`), { recursive: true });
        await writeFile(path.join(wideDir, `d${i}`, 'x.ts'), 'export const x = true;');
      }
      const prepared = await prepareInput(wideDir, { limits: { maxDirectories: 2 } });
      expect(prepared.files.length).toBeGreaterThan(0);
      expect(prepared.warnings.some((warning) => warning.includes('directory limit'))).toBe(true);
    } finally {
      await rm(wideDir, { recursive: true, force: true });
    }
  });

  it('enforces the directory depth limit with a warning', async () => {
    const deepDir = await mkdtemp(path.join(tmpdir(), 'epherem-deep-'));
    try {
      let current = deepDir;
      for (let level = 0; level < 5; level += 1) {
        current = path.join(current, `level${level}`);
      }
      await mkdir(current, { recursive: true });
      await writeFile(path.join(current, 'deep.ts'), 'export const deep = true;');
      await writeFile(path.join(deepDir, 'top.ts'), 'export const top = true;');

      const prepared = await prepareInput(deepDir, { limits: { maxDirectoryDepth: 2 } });
      expect(prepared.files.map((file) => file.path)).toEqual(['top.ts']);
      expect(prepared.skipped.some((skipped) => skipped.reason === 'max_depth_exceeded')).toBe(true);
      expect(prepared.warnings.some((warning) => warning.includes('depth limit'))).toBe(true);
    } finally {
      await rm(deepDir, { recursive: true, force: true });
    }
  });

  it('rejects archives and missing paths', async () => {
    const zipPath = path.join(projectDir, 'upload.zip');
    await writeFile(zipPath, 'not really a zip');
    await expect(prepareInput(zipPath)).rejects.toThrow(ScannerError);
    await expect(prepareInput(path.join(projectDir, 'does-not-exist'))).rejects.toThrow(ScannerError);
  });
});

describe('a retained lockfile is not read into the content budget', () => {
  let shrinkwrapDir: string;

  beforeAll(async () => {
    shrinkwrapDir = await mkdtemp(path.join(tmpdir(), 'epherem-shrinkwrap-'));
    await writeFile(path.join(shrinkwrapDir, 'index.ts'), 'export const app = 1;');
    const filler = '{"version":"1.0.0","resolved":"https://registry.npmjs.org/x/-/x-1.0.0.tgz"},';
    const body = `{"lockfileVersion":3,"packages":[${filler.repeat(20_000)}{}]}`;
    expect(body.length).toBeGreaterThan(limits.maxFileSizeBytes);
    expect(body.length).toBeLessThan(limits.maxLockfileSizeBytes);
    await writeFile(path.join(shrinkwrapDir, 'npm-shrinkwrap.json'), body);
  });

  afterAll(async () => {
    await rm(shrinkwrapDir, { recursive: true, force: true });
  });

  it('skips an oversized shrinkwrap as too_large, so the unparsed-format declaration can still fire', async () => {
    const prepared = await prepareInput(shrinkwrapDir);
    const reasons = new Map(prepared.skipped.map((skipped) => [skipped.path, skipped.reason]));
    expect(reasons.get('npm-shrinkwrap.json')).toBe('too_large');
    expect(prepared.files.map((file) => file.path)).not.toContain('npm-shrinkwrap.json');
  });

  it('holds none of its bytes: the read cap keys on INGESTED, not on RETAINED', async () => {
    const prepared = await prepareInput(shrinkwrapDir);
    const held = prepared.files.reduce((total, file) => total + file.size, 0);
    expect(
      held,
      'an oversized shrinkwrap was read into the file map, so a JSON file no parser reads is ' +
        `consuming the ${limits.maxTotalContentBytes}-byte content budget — the read cap has been made ` +
        'to follow RETAINED_LOCKFILE_NAMES instead of INGESTED_LOCKFILE_NAMES',
    ).toBeLessThan(limits.maxFileSizeBytes);
  });
});

describe('bun.lock reaches the collector as an ENTRY, not as a skipped path', () => {
  let bunDir: string;

  beforeAll(async () => {
    bunDir = await mkdtemp(path.join(tmpdir(), 'epherem-bun-'));
    await writeFile(path.join(bunDir, 'index.ts'), 'export const app = 1;');
    await writeFile(
      path.join(bunDir, 'bun.lock'),
      '{\n  // bun writes JSONC\n  "packages": {\n    "lodash": ["lodash@4.17.21", "", {}, "sha512-x"],\n  },\n}\n',
    );
    await writeFile(path.join(bunDir, 'bun.lockb'), Buffer.from([0x62, 0x00, 0x75, 0x6e]));
  });

  afterAll(async () => {
    await rm(bunDir, { recursive: true, force: true });
  });

  it('reads the text lockfile into the file map with its bytes', async () => {
    const prepared = await prepareInput(bunDir);
    const bun = prepared.files.find((file) => file.path === 'bun.lock');
    expect(
      bun,
      'bun.lock is not a fileMap entry, so the dispatch in collectDependenciesWithDiagnostics ' +
        'never sees it and its parser can never run — the RETAINED→INGESTED move has been reverted',
    ).toBeDefined();
    expect(bun?.content).toContain('lodash@4.17.21');
  });

  it('still refuses the BINARY lockfile, which has no parser', async () => {
    const prepared = await prepareInput(bunDir);
    expect(prepared.files.map((file) => file.path)).not.toContain('bun.lockb');
    const reasons = new Map(prepared.skipped.map((skipped) => [skipped.path, skipped.reason]));
    expect(reasons.get('bun.lockb')).toBe('lockfile');
  });

  it('reads it up to the LOCKFILE cap, the tier it now belongs to', () => {
    expect(preContentSkipReason('bun.lock', '.lock', 2_000_000, limits)).toBeUndefined();
    expect(preContentSkipReason('bun.lock', '.lock', limits.maxLockfileSizeBytes + 1, limits)).toBe('too_large');
  });
});

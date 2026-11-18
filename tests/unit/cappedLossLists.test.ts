import { describe, expect, it } from 'vitest';
import { analyzeCrossFileTaint } from '../../src/ast/crossFileTaint.js';
import { buildRouteSecurityProfiles } from '../../src/project-map/buildRouteSecurity.js';
import { andMoreFiles, CappedNames, MAX_FILES_NAMED, quotedListWithRemainder } from '../../src/shared/cappedNames.js';
import type { FileMap, FileMapEntry, ProjectMap } from '../../src/shared/types.js';

function entry(path: string, content: string): FileMapEntry {
  return {
    path,
    extension: path.slice(path.lastIndexOf('.')),
    label: 'unknown_useful',
    size: content.length,
    isLikelyConfig: false,
    isLikelyApiRoute: false,
    isLikelyAuthRelated: false,
    isLikelyDatabaseRelated: false,
    isLikelyMiddleware: false,
    usesEnvVariables: false,
    technologyHints: [],
    content,
  };
}

function unreadable(path: string): FileMapEntry {
  const base = entry(path, '');
  Object.defineProperty(base, 'content', {
    enumerable: true,
    get: () => {
      throw new RangeError('Maximum call stack size exceeded');
    },
  });
  return base;
}

const unreadableFiles = (count: number): FileMapEntry[] =>
  Array.from({ length: count }, (_, index) => unreadable(`src/lost-${String(index).padStart(2, '0')}.ts`));

function fileMap(entries: FileMapEntry[]): FileMap {
  return { rootPath: '/project', entries, skipped: [], skippedCount: 0, warnings: [] };
}

const EMPTY_PROJECT = { apiRoutes: [], imports: [] } as unknown as ProjectMap;

const crossFileLines = (warnings: string[]): string[] => warnings.filter((w) => /cross-file data flow/.test(w));
const routeLines = (warnings: string[]): string[] => warnings.filter((w) => /route protection/.test(w));

describe('CappedNames: name a few, count the rest', () => {
  it('names the first five distinct names and counts every distinct name', () => {
    const names = new CappedNames();
    for (const name of ['a', 'b', 'a', 'c', 'd', 'e', 'f', 'b', 'g', 'g']) names.add(name);
    expect(names.named).toEqual(['a', 'b', 'c', 'd', 'e']);
    expect(names.total).toBe(7);
    expect(names.unnamed).toBe(2);
  });

  it('add() says true only when it NAMED the name', () => {
    const names = new CappedNames(1);
    expect(names.add('a')).toBe(true);
    expect(names.add('a')).toBe(false);
    expect(names.add('b')).toBe(false);
    expect(names.unnamed).toBe(1);
  });

  it('the further line is absent at zero, singular at one, plural above', () => {
    expect(andMoreFiles(0, 'route protection')).toBeUndefined();
    expect(andMoreFiles(1, 'route protection')).toBe('…and 1 more file could not be analysed for route protection.');
    expect(andMoreFiles(12, 'cross-file data flow')).toBe(
      '…and 12 more files could not be analysed for cross-file data flow.',
    );
  });

  it('an in-sentence list carries its remainder', () => {
    const names = new CappedNames(2);
    for (const name of ['x.ts', 'y.ts', 'z.ts']) names.add(name);
    expect(quotedListWithRemainder(names)).toBe('"x.ts", "y.ts"… and 1 more');
  });
});

describe('cross-file data flow: the sixth unreadable file onwards is counted', () => {
  it('five files: five named lines and nothing further — the cap did not bite', () => {
    const map = fileMap(unreadableFiles(MAX_FILES_NAMED));
    analyzeCrossFileTaint(map, []);
    expect(crossFileLines(map.warnings)).toHaveLength(5);
    expect(map.warnings.some((w) => w.startsWith('…and'))).toBe(false);
  });

  it('six files: five named, then exactly "…and 1 more file"', () => {
    const map = fileMap(unreadableFiles(6));
    analyzeCrossFileTaint(map, []);
    const lines = crossFileLines(map.warnings);
    expect(lines).toHaveLength(6);
    expect(lines.slice(0, 5).every((line) => /^"src\/lost-0[0-4]\.ts" could not be analysed/.test(line))).toBe(true);
    expect(lines[5]).toBe('…and 1 more file could not be analysed for cross-file data flow.');
  });

  it('eleven files: five named, then exactly "…and 6 more files", and no sixth name anywhere', () => {
    const map = fileMap(unreadableFiles(11));
    analyzeCrossFileTaint(map, []);
    expect(map.warnings.at(-1)).toBe('…and 6 more files could not be analysed for cross-file data flow.');
    expect(map.warnings.join('\n')).not.toContain('lost-05');
  });

  it('a scan the function limit truncates AFTER its lost files still says how many more', () => {
    const tooManyFunctions = Array.from({ length: 5_001 }, (_, index) => `export function f${index}() {}`).join('\n');
    const map = fileMap([...unreadableFiles(7), entry('src/zz-many.ts', tooManyFunctions)]);
    const result = analyzeCrossFileTaint(map, []);
    expect(result.status).toBe('truncated');
    expect(map.warnings).toContain('…and 2 more files could not be analysed for cross-file data flow.');
  });
});

describe('route protection: the sixth unreadable file onwards is counted', () => {
  it('five files: five named lines and nothing further', () => {
    const map = fileMap(unreadableFiles(MAX_FILES_NAMED));
    buildRouteSecurityProfiles(map, EMPTY_PROJECT);
    expect(routeLines(map.warnings)).toHaveLength(5);
    expect(map.warnings.some((w) => w.startsWith('…and'))).toBe(false);
  });

  it('six files: five named, then exactly "…and 1 more file"', () => {
    const map = fileMap(unreadableFiles(6));
    buildRouteSecurityProfiles(map, EMPTY_PROJECT);
    const lines = routeLines(map.warnings);
    expect(lines).toHaveLength(6);
    expect(lines[5]).toBe('…and 1 more file could not be analysed for route protection.');
  });

  it('twelve files: five named, then exactly "…and 7 more files"', () => {
    const map = fileMap(unreadableFiles(12));
    buildRouteSecurityProfiles(map, EMPTY_PROJECT);
    expect(routeLines(map.warnings)).toHaveLength(6);
    expect(map.warnings.at(-1)).toBe('…and 7 more files could not be analysed for route protection.');
  });
});

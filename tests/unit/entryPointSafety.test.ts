import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { MockDependencyVulnerabilityScanner } from '../../src/dependency-audit/dependencyAudit.js';
import { prepareInput } from '../../src/input/prepareInput.js';
import { scanProject } from '../../src/scanProject.js';
import { DEFAULT_INPUT_LIMITS } from '../../src/shared/constants.js';
import type { ScanReport } from '../../src/shared/types.js';

const objectNesting = (depth: number): string =>
  `const deep = ${'{ a: '.repeat(depth)}1${' }'.repeat(depth)};\n`;
const callNesting = (depth: number): string =>
  `const deep = ${'f('.repeat(depth)}1${')'.repeat(depth)};\n`;

const VULNERABLE_ROUTE = `import { db } from '../../../lib/db';

export async function GET(request) {
  const id = request.nextUrl.searchParams.get('id');
  return db.query('SELECT * FROM users WHERE id = ' + id);
}
`;

async function project(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), 'epherem-entry-'));
  for (const [relative, content] of Object.entries(files)) {
    const full = path.join(root, relative);
    await mkdir(path.dirname(full), { recursive: true });
    await writeFile(full, content, 'utf8');
  }
  return root;
}
const cleanup = (dir: string): Promise<void> => rm(dir, { recursive: true, force: true });

const scan = (root: string): Promise<ScanReport> =>
  scanProject(root, { dependencyScanner: new MockDependencyVulnerabilityScanner() });

const findingPaths = (report: ScanReport): string[] =>
  [...new Set(report.findings.map((finding) => finding.filePath))].sort();

const warningsNaming = (report: ScanReport, fileName: string): string[] =>
  report.warnings.filter((warning) => warning.includes(fileName));

const withoutPath = (warning: string, fileName: string): string =>
  warning.split(fileName).join('<file>');

const warningsNamingAnyOf = (report: ScanReport, fileNames: string[]): string[] =>
  report.warnings.filter((warning) => fileNames.some((fileName) => warning.includes(fileName)));

const SOURCE_NESTING_BOUND = DEFAULT_INPUT_LIMITS.maxSourceNestingDepth;

const CAUSE_CLAIMS = [/nest/i, /deep/i, /bracket/i, /pars/i, /stack/i, /recursi/i, /overflow/i, /syntax/i];

const BASE_FILES: Record<string, string> = {
  'package.json': JSON.stringify({ name: 'deep-nesting-fixture', dependencies: { next: '14.0.0' } }),
  'app/api/users/route.ts': VULNERABLE_ROUTE,
};

describe('one unreadable file cannot end a scan', () => {
  it('a project with no such file is completely unaffected', async () => {
    const root = await project(BASE_FILES);
    try {
      const report = await scan(root);
      expect(report.findings.length).toBeGreaterThan(0);
      expect(findingPaths(report)).toContain('app/api/users/route.ts');
      expect(report.coverage.filesSkipped).toBe(0);

      expect(warningsNamingAnyOf(report, Object.keys(BASE_FILES))).toEqual([]);
    } finally {
      await cleanup(root);
    }
  });

  for (const [shape, fileName, source] of [
    ['object nesting', 'deep.ts', objectNesting(1000)],
    ['call nesting', 'deep.js', callNesting(1000)],
  ] as const) {
    it(`${shape}: the report still arrives and still covers every other file`, async () => {
      const root = await project({ ...BASE_FILES, [fileName]: source });
      try {
        const report = await scan(root);

        expect(report.scanId).toMatch(/^scan_/);

        expect(findingPaths(report)).toContain('app/api/users/route.ts');

        expect(report.coverage.filesSkipped).toBeGreaterThanOrEqual(1);
        expect(findingPaths(report)).not.toContain(fileName);

        const named = warningsNaming(report, fileName);
        const bound = new RegExp(String(SOURCE_NESTING_BOUND));
        const inputWarning = named.find((warning) => bound.test(warning));
        expect(inputWarning).toBeDefined();
        expect(inputWarning).toMatch(/nest/i);

        expect(named).toHaveLength(1);
      } finally {
        await cleanup(root);
      }
    });
  }

  it('names the file with a stated reason in the skip list', async () => {
    const root = await project({ ...BASE_FILES, 'deep.ts': objectNesting(1000) });
    try {
      const prepared = await prepareInput(root);
      expect(prepared.skipped).toContainEqual({ path: 'deep.ts', reason: 'nesting_too_deep' });
      expect(prepared.files.map((file) => file.path)).not.toContain('deep.ts');
    } finally {
      await cleanup(root);
    }
  });

  it('the deep file changes nothing about the findings of the others', async () => {
    const clean = await project(BASE_FILES);
    const withDeep = await project({ ...BASE_FILES, 'deep.ts': objectNesting(1000) });
    try {
      const before = await scan(clean);
      const after = await scan(withDeep);
      const strip = (report: ScanReport): string =>
        JSON.stringify(report.findings.map((finding) => [finding.ruleId, finding.filePath, finding.lineStart, finding.lineEnd]));
      expect(strip(after)).toEqual(strip(before));
    } finally {
      await Promise.all([cleanup(clean), cleanup(withDeep)]);
    }
  });
});

describe('the adversarial inputs, through scanProject', () => {
  it('survives the deterministic fuzz inputs and still reports', async () => {
    let seed = 0x5eed1234;
    const next = (): number => (seed = (seed * 1664525 + 1013904223) >>> 0);
    const alphabet = '{}[]()`${};,.?/\\"\'abcdefghijklmnopqrstuvwxyz0123456789\0\n';
    const files: Record<string, string> = { ...BASE_FILES };
    for (let caseIndex = 0; caseIndex < 250; caseIndex += 1) {
      let source = '';
      const length = next() % 2048;
      for (let index = 0; index < length; index += 1) source += alphabet[next() % alphabet.length];
      files[`fuzz/case-${caseIndex}.tsx`] = source;
    }
    const root = await project(files);
    try {
      const report = await scan(root);
      expect(report.scanId).toMatch(/^scan_/);
      expect(findingPaths(report)).toContain('app/api/users/route.ts');
    } finally {
      await cleanup(root);
    }
  }, 120_000);

  for (const [doorName, fileName, source, lostThing] of [
    ['route call-graph walk', 'chain.js', `const b = ${'1+'.repeat(200_000)}1;\n`, /route protection/i],
    ['cross-file taint walk', 'markup.tsx', `const j = ${'<a>'.repeat(8_000)}x${'</a>'.repeat(8_000)};\n`, /cross-file data flow/i],
  ] as const) {
    it(`the ${doorName} contains it, names the file, and claims no cause`, async () => {
      const root = await project({ ...BASE_FILES, [fileName]: source });
      try {
        const report = await scan(root);
        expect(report.scanId).toMatch(/^scan_/);
        expect(findingPaths(report)).toContain('app/api/users/route.ts');

        const named = warningsNaming(report, fileName);
        expect(named.length).toBeGreaterThan(0);

        expect(named.some((warning) => lostThing.test(warning))).toBe(true);

        for (const warning of named) {
          const body = withoutPath(warning, fileName);
          for (const claim of CAUSE_CLAIMS) expect(body).not.toMatch(claim);
        }
      } finally {
        await cleanup(root);
      }
    }, 120_000);
  }

  it('the cross-file summary walk contains it, names the file once, and claims no cause', async () => {
    const fileName = 'chain-in-function.js';
    const source = `export function deep(a) {\n  return a${'+1'.repeat(200_000)};\n}\n`;
    const clean = await project(BASE_FILES);
    const root = await project({ ...BASE_FILES, [fileName]: source });
    try {
      const report = await scan(root);
      expect(report.scanId).toMatch(/^scan_/);

      expect(findingPaths(report)).toContain('app/api/users/route.ts');
      const strip = (value: ScanReport): string =>
        JSON.stringify(value.findings.map((f) => [f.ruleId, f.filePath, f.lineStart, f.lineEnd]));
      expect(strip(report)).toEqual(strip(await scan(clean)));

      const named = warningsNaming(report, fileName);
      expect(named.length).toBeGreaterThan(0);
      const crossFile = named.filter((warning) => /cross-file data flow/i.test(warning));

      expect(crossFile).toHaveLength(1);

      for (const warning of named) {
        const body = withoutPath(warning, fileName);
        for (const claim of CAUSE_CLAIMS) expect(body).not.toMatch(claim);
      }
    } finally {
      await Promise.all([cleanup(root), cleanup(clean)]);
    }
  }, 120_000);

  it('the syntax-aware walk door keeps every other rule running, and names the file', async () => {
    const fileName = 'chain-in-file.js';
    const source = `const b = ${'1+'.repeat(50_000)}1;\n`;
    const clean = await project(BASE_FILES);
    const root = await project({ ...BASE_FILES, [fileName]: source });
    try {
      const report = await scan(root);
      expect(report.scanId).toMatch(/^scan_/);

      expect(report.warnings.filter((warning) => /^Rule "/.test(warning))).toEqual([]);

      expect(report.ruleResults.find((entry) => entry.ruleId === 'sql_injection')?.status)
        .not.toBe('not_completed');

      expect(findingPaths(report)).toContain('app/api/users/route.ts');
      const strip = (value: ScanReport): string =>
        JSON.stringify(value.findings.map((f) => [f.ruleId, f.filePath, f.lineStart, f.lineEnd]));
      expect(strip(report)).toEqual(strip(await scan(clean)));

      const named = warningsNaming(report, fileName);
      expect(named.some((warning) => /rest on pattern matching alone/i.test(warning))).toBe(true);

      expect(named.filter((warning) => /rest on pattern matching alone/i.test(warning))).toHaveLength(1);

      for (const warning of named) {
        const body = withoutPath(warning, fileName);
        for (const claim of CAUSE_CLAIMS) expect(body).not.toMatch(claim);
      }
    } finally {
      await Promise.all([cleanup(root), cleanup(clean)]);
    }
  }, 120_000);

  it('a project with no such file gets no degraded-analysis warning', async () => {
    const root = await project(BASE_FILES);
    try {
      const report = await scan(root);
      expect(report.warnings.filter((warning) => /could not be analysed in full/i.test(warning))).toEqual([]);
      expect(report.warnings.filter((warning) => /pattern matching alone/i.test(warning))).toEqual([]);
      expect(findingPaths(report)).toContain('app/api/users/route.ts');
    } finally {
      await cleanup(root);
    }
  });

  it('survives degenerate shapes the fuzz inputs do not reach', async () => {
    const files: Record<string, string> = {
      ...BASE_FILES,
      'shapes/array.ts': `const a = ${'['.repeat(2000)}1${']'.repeat(2000)};\n`,
      'shapes/paren.js': `const p = ${'('.repeat(2000)}1${')'.repeat(2000)};\n`,
      'shapes/template.ts': `const t = ${'`${'.repeat(2000)}1${'}`'.repeat(2000)};\n`,
      'shapes/arrow.js': `const f = ${'() => '.repeat(2000)}1;\n`,
      'shapes/blocks.js': `function q() { ${'if (a) {'.repeat(2000)}b();${'}'.repeat(2000)} }\n`,
      'shapes/unterminated.ts': '{'.repeat(5000),
      'shapes/jsx.tsx': `const j = ${'<a>'.repeat(2000)}x${'</a>'.repeat(2000)};\n`,
      'shapes/nul.ts': 'export const a = 1;\0\0\0export const b = 2;\n',
      'shapes/binary-chain.js': `const b = ${'1+'.repeat(200_000)}1;\n`,
    };
    const root = await project(files);
    try {
      const report = await scan(root);
      expect(report.scanId).toMatch(/^scan_/);
      expect(findingPaths(report)).toContain('app/api/users/route.ts');
    } finally {
      await cleanup(root);
    }
  }, 120_000);
});

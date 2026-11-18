import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { MockDependencyVulnerabilityScanner } from '../../src/dependency-audit/dependencyAudit.js';
import { prepareInput } from '../../src/input/prepareInput.js';
import { scanProject } from '../../src/scanProject.js';
import { linkWarnings } from '../../src/shared/analysisGapWarnings.js';

const tmp = (prefix: string): Promise<string> => mkdtemp(path.join(tmpdir(), prefix));
const cleanup = (...dirs: string[]): Promise<void[]> =>
  Promise.all(dirs.map((dir) => rm(dir, { recursive: true, force: true })));

async function canCreateSymbolicLinks(): Promise<boolean> {
  const dir = await tmp('epherem-link-probe-');
  try {
    await writeFile(path.join(dir, 'target.txt'), 'probe');
    await symlink(path.join(dir, 'target.txt'), path.join(dir, 'link.txt'));
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EPERM') return false;
    throw error;
  } finally {
    await cleanup(dir);
  }
}

const SKIP_REASON = 'this host cannot create symbolic links (Windows without Developer Mode or elevation)';
const linksAvailable = await canCreateSymbolicLinks();
const describeLinks = linksAvailable ? describe : describe.skip;
if (!linksAvailable) console.warn(`linksNotFollowed.test.ts SKIPPED: ${SKIP_REASON}`);

const APP = 'export async function GET(req) { return Response.json({ ok: true }); }\n';

async function project(root: string, files: Record<string, string>): Promise<void> {
  for (const [relative, content] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(root, relative)), { recursive: true });
    await writeFile(path.join(root, relative), content, 'utf8');
  }
}

describe('the sentence', () => {
  it('nothing to say when there were no links', () => {
    expect(linkWarnings(undefined)).toEqual([]);
    expect(linkWarnings({ named: [], total: 0 })).toEqual([]);
  });

  it('says why a link is never followed, names five, and counts the rest', () => {
    expect(linkWarnings({ named: ['lib'], total: 1 })).toEqual([
      '1 linked file or folder was not followed (links can point outside the project, so Epherem never follows ' +
        'them). Its contents were not scanned: "lib".',
    ]);
    expect(linkWarnings({ named: ['a', 'b', 'c', 'd', 'e'], total: 8 })).toEqual([
      '8 linked files or folders were not followed (links can point outside the project, so Epherem never follows ' +
        'them). Their contents were not scanned: "a", "b", "c", "d", "e"… and 3 more.',
    ]);
  });
});

describeLinks('the walk records the links it did not follow', () => {
  it('a linked folder and a linked file are recorded, and neither is read', async () => {
    const root = await tmp('epherem-links-');
    const outside = await tmp('epherem-links-outside-');
    try {
      await project(root, { 'app/api/a/route.ts': APP });
      await project(outside, { 'shared/secret.ts': 'export const LEAK = "outside-root";\n', 'one.ts': 'export const ONE = 1;\n' });
      await symlink(path.join(outside, 'shared'), path.join(root, 'linked-dir'), 'dir');
      await symlink(path.join(outside, 'one.ts'), path.join(root, 'linked-file.ts'));

      const prepared = await prepareInput(root);
      expect(prepared.files.map((file) => file.path)).toEqual(['app/api/a/route.ts']);
      expect(prepared.linksNotFollowed).toEqual({ named: ['linked-dir', 'linked-file.ts'], total: 2 });
    } finally {
      await cleanup(root, outside);
    }
  });

  it('past five, the record names five and counts every one', async () => {
    const root = await tmp('epherem-links-many-');
    const outside = await tmp('epherem-links-many-target-');
    try {
      await project(root, { 'app/api/a/route.ts': APP });
      await project(outside, { 'shared/x.ts': 'export const X = 1;\n' });
      for (let index = 0; index < 8; index += 1) {
        await symlink(path.join(outside, 'shared'), path.join(root, `link-${index}`), 'dir');
      }
      const prepared = await prepareInput(root);
      expect(prepared.linksNotFollowed?.total).toBe(8);
      expect(prepared.linksNotFollowed?.named).toEqual(['link-0', 'link-1', 'link-2', 'link-3', 'link-4']);
    } finally {
      await cleanup(root, outside);
    }
  });

  it('a link named like an ignored directory, pointing at one, or pointing inside the project is left unsaid', async () => {
    const root = await tmp('epherem-links-ignored-');
    const store = await tmp('epherem-links-store-');
    try {
      await project(root, { 'app/api/a/route.ts': APP, 'real/x.ts': 'export const X = 1;\n' });
      await project(store, {
        'pnpm-store/pkg/index.js': 'module.exports = 1;\n',
        'node_modules/pkg/index.js': 'module.exports = 1;\n',
      });
      await mkdir(path.join(root, 'web'));
      await symlink(path.join(store, 'pnpm-store'), path.join(root, 'web', 'node_modules'), 'dir');
      await symlink(path.join(store, 'node_modules'), path.join(root, 'deps'), 'dir');
      await symlink(path.join(root, 'real'), path.join(root, 'alias'), 'dir');
      await symlink(path.join(store, 'pnpm-store'), path.join(root, 'lib'), 'dir');

      const prepared = await prepareInput(root);
      expect(prepared.linksNotFollowed).toEqual({ named: ['lib'], total: 1 });
    } finally {
      await cleanup(root, store);
    }
  });

  it('a changed-files scan records only the links it was asked about', async () => {
    const root = await tmp('epherem-links-scoped-');
    const outside = await tmp('epherem-links-scoped-target-');
    try {
      await project(root, { 'app/api/a/route.ts': APP });
      await project(outside, { 'x.ts': 'export const X = 1;\n' });
      await symlink(path.join(outside, 'x.ts'), path.join(root, 'asked.ts'));
      await symlink(path.join(outside, 'x.ts'), path.join(root, 'not-asked.ts'));
      const prepared = await prepareInput(root, { onlyPaths: new Set(['app/api/a/route.ts', 'asked.ts']) });
      expect(prepared.linksNotFollowed).toEqual({ named: ['asked.ts'], total: 1 });
    } finally {
      await cleanup(root, outside);
    }
  });
});

describeLinks('no count, status or scope input moves', () => {
  it('skippedCount, filesSkipped, filesSkippedInWalk, statuses and rule rows are identical with and without the links', async () => {
    const plain = await tmp('epherem-links-plain-');
    const linked = await tmp('epherem-links-linked-');
    const outside = await tmp('epherem-links-target-');
    try {
      const files = {
        'package.json': JSON.stringify({ name: 'links', dependencies: { next: '14.0.0' } }),
        'app/api/a/route.ts': APP,
        'README.md': '# links\n',
      };
      await project(plain, files);
      await project(linked, files);
      await project(outside, { 'lib/util.ts': 'export const U = 1;\n', 'evil.ts': 'export const E = 1;\n' });
      await symlink(path.join(outside, 'lib'), path.join(linked, 'lib'), 'dir');
      await symlink(path.join(outside, 'evil.ts'), path.join(linked, 'evil.ts'));

      expect((await prepareInput(linked)).skippedCount).toBe((await prepareInput(plain)).skippedCount);

      const scan = (root: string) => scanProject(root, { dependencyScanner: new MockDependencyVulnerabilityScanner() });
      const [before, after] = [await scan(plain), await scan(linked)];

      expect(after.coverage.filesSkippedInWalk).toBe(before.coverage.filesSkippedInWalk);
      expect(after.coverage.filesSkipped).toBe(before.coverage.filesSkipped);
      expect(after.coverage.filesAnalysed).toBe(before.coverage.filesAnalysed);
      expect(after.coverage.unreadExtensions).toEqual(before.coverage.unreadExtensions);
      expect(after.coverage.reasons).toEqual(before.coverage.reasons);
      expect(after.scanStatus).toBe(before.scanStatus);
      expect(after.codeScanStatus).toBe(before.codeScanStatus);
      expect(after.statusSummary).toEqual(before.statusSummary);
      expect(after.ruleResults).toEqual(before.ruleResults);
      expect(after.coverage.partiallyCoveredRules).toEqual(before.coverage.partiallyCoveredRules);

      expect(after.warnings.filter((w) => !before.warnings.includes(w))).toEqual([
        '2 linked files or folders were not followed (links can point outside the project, so Epherem never ' +
          'follows them). Their contents were not scanned: "evil.ts", "lib".',
      ]);
    } finally {
      await cleanup(plain, linked, outside);
    }
  }, 120_000);
});

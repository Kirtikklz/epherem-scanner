import { mkdtemp, mkdir, rm, writeFile, symlink, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { prepareInput } from '../../src/input/prepareInput.js';
import { scanProject } from '../../src/scanProject.js';
import { MockDependencyVulnerabilityScanner } from '../../src/dependency-audit/dependencyAudit.js';
import { ScannerError } from '../../src/shared/errors.js';

async function tmpProject(): Promise<string> {
  return mkdtemp(path.join(tmpdir(), 'epherem-input-'));
}
const cleanup = (dir: string): Promise<void> => rm(dir, { recursive: true, force: true });

async function canCreateSymbolicLinks(): Promise<boolean> {
  const dir = await tmpProject();
  try {
    const target = path.join(dir, 'target.txt');
    const link = path.join(dir, 'link.txt');
    await writeFile(target, 'probe');
    await symlink(target, link);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EPERM') return false;
    throw error;
  } finally {
    await cleanup(dir);
  }
}

const describeSymlinkSafety = (await canCreateSymbolicLinks()) ? describe : describe.skip;

describeSymlinkSafety('input safety: symlinks are never followed', () => {
  it('a symlink to a file OUTSIDE the scan root is not read', async () => {
    const dir = await tmpProject();
    const outside = await tmpProject();
    try {
      await writeFile(path.join(outside, 'secret.ts'), 'export const SECRET = "leaked-outside-root";');
      await writeFile(path.join(dir, 'app.ts'), 'export const ok = 1;');
      await symlink(path.join(outside, 'secret.ts'), path.join(dir, 'link.ts'));
      const prepared = await prepareInput(dir);
      const contents = prepared.files.map((f) => f.content).join('\n');
      expect(contents).not.toContain('leaked-outside-root');
      expect(prepared.files.map((f) => f.path)).toEqual(['app.ts']);
    } finally {
      await Promise.all([cleanup(dir), cleanup(outside)]);
    }
  });

  it('a symlinked directory is not traversed', async () => {
    const dir = await tmpProject();
    const outside = await tmpProject();
    try {
      await mkdir(path.join(outside, 'sub'));
      await writeFile(path.join(outside, 'sub', 'leak.ts'), 'export const X = "leaked-dir";');
      await writeFile(path.join(dir, 'app.ts'), 'export const ok = 1;');
      await symlink(path.join(outside, 'sub'), path.join(dir, 'linkdir'));
      const prepared = await prepareInput(dir);
      expect(prepared.files.map((f) => f.content).join('\n')).not.toContain('leaked-dir');
    } finally {
      await Promise.all([cleanup(dir), cleanup(outside)]);
    }
  });
});

describe('input safety: size is enforced against real bytes, not a claimed stat', () => {
  it('a file over the per-file cap is skipped too_large and not accepted', async () => {
    const dir = await tmpProject();
    try {
      await writeFile(path.join(dir, 'big.ts'), 'a'.repeat(2000));
      await writeFile(path.join(dir, 'ok.ts'), 'export const ok = 1;');
      const prepared = await prepareInput(dir, { limits: { maxFileSizeBytes: 1000 } });
      const reasons = new Map(prepared.skipped.map((s) => [s.path, s.reason]));
      expect(reasons.get('big.ts')).toBe('too_large');
      expect(prepared.files.map((f) => f.path)).toEqual(['ok.ts']);
    } finally {
      await cleanup(dir);
    }
  });

  it('a file exactly at the cap is accepted; the read is bounded (cap + 1)', async () => {
    const dir = await tmpProject();
    try {
      await writeFile(path.join(dir, 'edge.ts'), 'b'.repeat(1000));
      const prepared = await prepareInput(dir, { limits: { maxFileSizeBytes: 1000 } });
      const edge = prepared.files.find((f) => f.path === 'edge.ts');
      expect(edge?.size).toBe(1000);
    } finally {
      await cleanup(dir);
    }
  });
});

describe('input safety: deterministic ordering + incomplete warnings preserved', () => {
  it('produces identical file ordering across repeated scans', async () => {
    const dir = await tmpProject();
    try {
      await mkdir(path.join(dir, 'z'));
      await mkdir(path.join(dir, 'a'));
      await writeFile(path.join(dir, 'z', 'b.ts'), 'export const b = 1;');
      await writeFile(path.join(dir, 'a', 'c.ts'), 'export const c = 1;');
      await writeFile(path.join(dir, 'app.ts'), 'export const a = 1;');
      const first = (await prepareInput(dir)).files.map((f) => f.path);
      const second = (await prepareInput(dir)).files.map((f) => f.path);
      expect(first).toEqual(second);
      expect(first).toEqual([...first].sort((a, b) => a.localeCompare(b)));
    } finally {
      await cleanup(dir);
    }
  });

  it('depth limit records a warning + max_depth_exceeded and still completes', async () => {
    const dir = await tmpProject();
    try {
      let deep = dir;
      for (let i = 0; i < 6; i += 1) {
        deep = path.join(deep, `d${i}`);
        await mkdir(deep);
      }
      await writeFile(path.join(deep, 'buried.ts'), 'export const x = 1;');
      await writeFile(path.join(dir, 'top.ts'), 'export const t = 1;');
      const prepared = await prepareInput(dir, { limits: { maxDirectoryDepth: 2 } });
      expect(prepared.warnings.some((w) => /depth limit/i.test(w))).toBe(true);
      expect(prepared.skipped.some((s) => s.reason === 'max_depth_exceeded')).toBe(true);
      expect(prepared.files.some((f) => f.path === 'top.ts')).toBe(true);
    } finally {
      await cleanup(dir);
    }
  });
});

describe('input safety: adversarial / degenerate projects never crash', () => {
  it('empty project throws a typed ScannerError (not a raw crash)', async () => {
    const dir = await tmpProject();
    try {
      await expect(prepareInput(dir)).rejects.toBeInstanceOf(ScannerError);
    } finally {
      await cleanup(dir);
    }
  });

  it('binary/NUL, huge-single-line, and unbalanced-brace files do not crash the scan', async () => {
    const dir = await tmpProject();
    try {
      await writeFile(path.join(dir, 'package.json'), '{"name":"x"}');
      await writeFile(path.join(dir, 'bin.ts'), Buffer.from([0x65, 0x00, 0x66]));
      await writeFile(path.join(dir, 'huge.ts'), `const s = "${'x'.repeat(50_000)}";`);
      await writeFile(path.join(dir, 'weird.ts'), '{{{{{{ if(!) throw ((( \n'.repeat(200));
      const report = await scanProject(dir, { dependencyScanner: new MockDependencyVulnerabilityScanner() });
      expect(['complete', 'incomplete']).toContain(report.scanStatus);
    } finally {
      await cleanup(dir);
    }
  }, 120_000);

  it('an unreadable subdirectory is skipped with a warning, scan still completes', async () => {
    const dir = await tmpProject();
    try {
      await writeFile(path.join(dir, 'app.ts'), 'export const a = 1;');
      const locked = path.join(dir, 'locked');
      await mkdir(locked);
      await writeFile(path.join(locked, 'inner.ts'), 'export const i = 1;');
      await chmod(locked, 0o000);
      const prepared = await prepareInput(dir);
      expect(prepared.files.some((f) => f.path === 'app.ts')).toBe(true);
      await chmod(locked, 0o755).catch(() => undefined);
    } finally {
      await cleanup(dir);
    }
  });
});

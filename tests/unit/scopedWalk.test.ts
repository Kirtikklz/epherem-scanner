import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { prepareInput } from '../../src/input/prepareInput.js';

const temporaries: string[] = [];

afterEach(async () => {
  await Promise.all(temporaries.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function project(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'epherem-scoped-'));
  temporaries.push(dir);
  await mkdir(path.join(dir, 'src'), { recursive: true });
  await writeFile(path.join(dir, 'package.json'), '{"name":"p","dependencies":{}}');
  await writeFile(path.join(dir, 'src', 'changed.ts'), 'export const changed = 1;\n');
  await writeFile(path.join(dir, 'src', 'untouched.ts'), 'export const untouched = 2;\n');
  await writeFile(path.join(dir, 'src', 'also-untouched.ts'), 'export const other = 3;\n');
  await writeFile(path.join(dir, 'src', 'logo.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01]));
  return dir;
}

describe('a restricted walk judges the named paths and nothing else', () => {
  it('loads exactly the set it was given', async () => {
    const dir = await project();
    const prepared = await prepareInput(dir, {
      onlyPaths: new Set(['src/changed.ts', 'package.json']),
    });

    expect(prepared.files.map((file) => file.path)).toEqual(['package.json', 'src/changed.ts']);
  });

  it('reads the whole project when it is given no set at all', async () => {
    const dir = await project();
    const prepared = await prepareInput(dir, {});

    expect(prepared.files.map((file) => file.path)).toEqual([
      'package.json',
      'src/also-untouched.ts',
      'src/changed.ts',
      'src/untouched.ts',
    ]);
  });

  it('does not record a path outside the range as a file the scanner refused', async () => {
    const dir = await project();
    const restricted = await prepareInput(dir, { onlyPaths: new Set(['src/changed.ts']) });
    const whole = await prepareInput(dir, {});

    const skippedPaths = restricted.skipped.map((entry) => entry.path);
    expect(skippedPaths).not.toContain('src/untouched.ts');
    expect(skippedPaths).not.toContain('src/also-untouched.ts');
    expect(restricted.skippedCount).toBe(0);

    expect(whole.skipped.map((entry) => entry.path)).toEqual(['src/logo.png']);
  });

  it('finds nothing for a named path that is not there, and does not throw', async () => {
    const dir = await project();

    await expect(
      prepareInput(dir, { onlyPaths: new Set(['src/changed.ts', 'src/never-existed.ts']) }),
    ).resolves.toMatchObject({ files: [{ path: 'src/changed.ts' }] });
  });
});

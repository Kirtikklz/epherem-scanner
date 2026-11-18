import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { scanProject } from '../../src/scanProject.js';
import { hardcodedSecret } from '../../src/rules/basic/hardcodedSecret.js';
import { buildFindingId } from '../../src/shared/utils.js';
import { memoryContext } from './helpers.js';

async function makeProject(fileContent: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'epherem-ids-'));
  await mkdir(path.join(dir, 'src'), { recursive: true });
  await writeFile(path.join(dir, 'package.json'), '{"name":"x","dependencies":{"react":"18.0.0"}}');
  await writeFile(path.join(dir, 'src', 'app.ts'), fileContent);
  return dir;
}

describe('scan ids', () => {
  it('same content, same size: identical scanId; different content, same size: different scanId', async () => {
    const projectA = await makeProject('export const value = "AAAA";');
    const projectB = await makeProject('export const value = "BBBB";');
    const projectA2 = await makeProject('export const value = "AAAA";');
    try {
      const [reportA, reportB, reportA2] = await Promise.all([
        scanProject(projectA),
        scanProject(projectB),
        scanProject(projectA2),
      ]);
      expect(reportA.scanId).not.toBe(reportB.scanId);
      expect(reportA.scanId).toBe(reportA2.scanId);
    } finally {
      await Promise.all([projectA, projectB, projectA2].map((dir) => rm(dir, { recursive: true, force: true })));
    }
  });
});

describe('finding ids', () => {
  it('two different secrets on the same line produce two distinct findings', () => {
    const context = memoryContext([
      ['package.json', '{"name":"x"}'],
      [
        'src/keys.ts',
        `const keys = { stripe: 'sk${''}_live_FAKEAAAA1111BBBB2222', github: 'gh${''}p_FAKE0000000000000000000000000000' };\n`,
      ],
    ]);
    const findings = hardcodedSecret.run(context);
    const sameLine = findings.filter((finding) => finding.filePath === 'src/keys.ts' && finding.lineStart === 1);
    expect(sameLine.length).toBe(2);
    expect(new Set(sameLine.map((finding) => finding.id)).size).toBe(2);
  });

  it('id changes when evidence changes, stays stable otherwise', () => {
    const idA = buildFindingId('rule', 'file.ts', 3, 'evidence-a');
    const idB = buildFindingId('rule', 'file.ts', 3, 'evidence-b');
    const idA2 = buildFindingId('rule', 'file.ts', 3, 'evidence-a');
    expect(idA).not.toBe(idB);
    expect(idA).toBe(idA2);
  });
});

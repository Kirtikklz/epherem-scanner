import { cp, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { runCli, type CliIo } from '../../src/cli.js';
import { MockDependencyVulnerabilityScanner } from '../../src/dependency-audit/dependencyAudit.js';
import { scanProject } from '../../src/scanProject.js';
import type { Finding, ScanReport } from '../../src/shared/types.js';
import { fixturePath } from './helpers.js';

const NAME_RULES = ['private_key_or_credential_file', 'data_artefact_committed'] as const;

const temps: string[] = [];
afterAll(async () => {
  for (const dir of temps) await rm(dir, { recursive: true, force: true });
});
async function tempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  temps.push(dir);
  return dir;
}

const nameFindings = (report: ScanReport): Finding[] =>
  report.findings.filter((f) => (NAME_RULES as readonly string[]).includes(f.ruleId));
const placesOf = (report: ScanReport): string[][] =>
  nameFindings(report).map((f) => [f.ruleId, f.filePath ?? '', f.severity, f.confidence]).sort((a, b) => a[1]!.localeCompare(b[1]!));
const statusOf = (report: ScanReport): Record<string, string> =>
  Object.fromEntries(report.ruleResults.filter((r) => (NAME_RULES as readonly string[]).includes(r.ruleId)).map((r) => [r.ruleId, r.status]));

const FIXTURE_PLACES = [
  ['data_artefact_committed', 'data/app.sqlite', 'high', 'high'],
  ['data_artefact_committed', 'db/backup.sql', 'high', 'high'],
  ['private_key_or_credential_file', 'deploy/server.pem', 'critical', 'high'],
  ['private_key_or_credential_file', 'id_rsa', 'critical', 'high'],
  ['data_artefact_committed', 'infra/terraform.tfstate', 'high', 'high'],
];

describe('a folder scan that asks reads its own file names', () => {
  it('reports each key, database and state file by its name, and both checks have a result', async () => {
    const report = await scanProject(fixturePath('folder-name-checks'), { watchFolderNames: true, dependencyScanner: new MockDependencyVulnerabilityScanner() });
    expect(placesOf(report)).toEqual(FIXTURE_PLACES);
    expect(statusOf(report)).toEqual({ private_key_or_credential_file: 'failed', data_artefact_committed: 'failed' });
  });

  it('a .sql named like an export that holds no data is not reported; one that holds a dump is, as read', async () => {
    const report = await scanProject(fixturePath('folder-name-checks'), { watchFolderNames: true, dependencyScanner: new MockDependencyVulnerabilityScanner() });
    const paths = nameFindings(report).map((f) => f.filePath);
    expect(paths).not.toContain('db/views_export.sql');
    expect(nameFindings(report).find((f) => f.filePath === 'db/backup.sql')?.confidence).toBe('high');
  });

  it('says folder, not upload, and keeps the same adjudication exemption', async () => {
    const report = await scanProject(fixturePath('folder-name-checks'), { watchFolderNames: true, dependencyScanner: new MockDependencyVulnerabilityScanner() });
    for (const finding of nameFindings(report)) {
      expect(finding.userExplanation).toContain('in this project folder');
      expect(finding.userExplanation).not.toMatch(/upload/i);
      expect(finding.technicalExplanation).toContain('scanned folder');
      expect(finding.technicalExplanation).not.toMatch(/archive|upload/i);
      expect(finding.fixPrompt).not.toMatch(/archive entry|this upload/i);
      expect(finding.adjudication?.required).toBe(false);
      expect(finding.adjudication?.basis).toContain('scanned folder');
    }
  });

  it('without the option a folder scan is unchanged: no name findings, both checks not run', async () => {
    const report = await scanProject(fixturePath('folder-name-checks'), { dependencyScanner: new MockDependencyVulnerabilityScanner() });
    expect(nameFindings(report)).toEqual([]);
    expect(statusOf(report)).toEqual({ private_key_or_credential_file: 'not_completed', data_artefact_committed: 'not_completed' });
  });

  it('a folder with none of these files passes both checks', async () => {
    const report = await scanProject(fixturePath('clean-basic-project'), { watchFolderNames: true, dependencyScanner: new MockDependencyVulnerabilityScanner() });
    expect(nameFindings(report)).toEqual([]);
    expect(statusOf(report)).toEqual({ private_key_or_credential_file: 'passed', data_artefact_committed: 'passed' });
  });

  it('names under ignored folders are not read, and a file under one shared folder keeps its whole path', async () => {
    const project = path.join(await tempDir('epherem-folder-names-'), 'app');
    await cp(fixturePath('folder-name-checks'), path.join(project, 'app'), { recursive: true });
    await mkdir(path.join(project, 'app', 'node_modules', 'some-package'), { recursive: true });
    await writeFile(path.join(project, 'app', 'node_modules', 'some-package', 'test.pem'), 'Placeholder.\n');
    const report = await scanProject(project, { watchFolderNames: true, dependencyScanner: new MockDependencyVulnerabilityScanner() });
    expect(placesOf(report)).toEqual(FIXTURE_PLACES.map(([rule, file, sev, conf]) => [rule!, `app/${file}`, sev!, conf!]));
  });
});

describe('the command-line scanner asks', () => {
  it('its report carries both checks with a result, and neither is listed as not covering the project', async () => {
    const out: string[] = [];
    const err: string[] = [];
    const io: CliIo = { out: (t) => out.push(t), err: (t) => err.push(t), cwd: await tempDir('epherem-folder-cwd-'), color: false };
    expect(await runCli([fixturePath('folder-name-checks'), '--offline', '--json'], io)).toBe(0);
    const report = JSON.parse(out.join('')) as ScanReport;
    expect(placesOf(report)).toEqual(FIXTURE_PLACES);
    expect(statusOf(report)).toEqual({ private_key_or_credential_file: 'failed', data_artefact_committed: 'failed' });

    out.length = 0;
    expect(await runCli([fixturePath('folder-name-checks'), '--offline'], io)).toBe(0);
    const text = out.join('');
    expect(text).toContain('A key or password file is in your project');
    expect(text).toContain('A database copy or server file is in your project');
    expect(text).not.toContain('private_key_or_credential_file (none)');
    expect(text).not.toContain('data_artefact_committed (none)');
  });
});

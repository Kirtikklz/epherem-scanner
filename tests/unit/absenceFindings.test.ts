import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ABSENCE_RULES,
  ENABLED_ABSENCE_TAGS,
  absenceFindings,
  type AbsenceRuleTag,
} from '../../src/candidates/absence/absenceFindings.js';
import { MockDependencyVulnerabilityScanner } from '../../src/dependency-audit/dependencyAudit.js';
import { buildFileMap } from '../../src/file-map/buildFileMap.js';
import { prepareInput } from '../../src/input/prepareInput.js';
import { buildProjectMap } from '../../src/project-map/buildProjectMap.js';
import { RULE_CATALOG } from '../../src/rules/ruleCatalog.js';
import { ruleMetadata } from '../../src/rules/ruleRegistry.js';
import { scanProject } from '../../src/scanProject.js';
import { makeFinding } from '../../src/shared/findingFactory.js';
import { detectStack } from '../../src/stack-detection/detectStack.js';
import type { FileMap, Finding, ProjectMap, ScanReport } from '../../src/shared/types.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ABSENCE_RULES_SOURCE = path.resolve(HERE, '../../src/candidates/absence/rules.ts');

const FIXTURE: Record<string, string> = {
  'package.json': JSON.stringify({ name: 'notes-api', dependencies: { express: '^4.19.2' } }),
  'server.js': [
    "const express = require('express');",
    "const notesRouter = require('./routes/notes');",
    'const app = express();',
    'app.use(express.json());',
    "app.use('/api/notes', notesRouter);",
    'app.listen(3000);',
    '',
  ].join('\n'),
  'routes/notes.js': [
    "const express = require('express');",
    "const { createNote, removeNote } = require('../controllers/notes');",
    'const router = express.Router();',
    "router.post('/', createNote);",
    "router.delete('/:id', removeNote);",
    'module.exports = router;',
    '',
  ].join('\n'),
  'controllers/notes.js': [
    'const notes = [];',
    'function createNote(req, res) {',
    '  notes.push({ id: notes.length + 1, text: req.body.text });',
    '  res.status(201).json(notes[notes.length - 1]);',
    '}',
    'function removeNote(req, res) {',
    '  const index = notes.findIndex((note) => note.id === Number(req.params.id));',
    '  if (index >= 0) notes.splice(index, 1);',
    '  res.status(204).end();',
    '}',
    'module.exports = { createNote, removeNote };',
    '',
  ].join('\n'),
};

async function project(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), 'epherem-absence-'));
  for (const [relative, content] of Object.entries(files)) {
    const full = path.join(root, relative);
    await mkdir(path.dirname(full), { recursive: true });
    await writeFile(full, content, 'utf8');
  }
  return root;
}

const scan = (root: string, absenceTags?: ReadonlySet<string>): Promise<ScanReport> =>
  scanProject(root, {
    dependencyScanner: new MockDependencyVulnerabilityScanner(),
    ...(absenceTags !== undefined ? { absenceTags } : {}),
  });

async function maps(root: string): Promise<{ fileMap: FileMap; projectMap: ProjectMap }> {
  const fileMap = buildFileMap(await prepareInput(root, {}));
  const projectMap = buildProjectMap(fileMap, detectStack(fileMap));
  return { fileMap, projectMap };
}

const ONLY_AUTH = new Set(['api-mutation-without-auth']);
const isAbsenceAuth = (finding: Finding): boolean =>
  finding.ruleId === 'api_mutation_without_auth' && finding.detectionKind === 'absence';

describe('the absence bridge is wired into scanProject and carries the allowlist', () => {
  let root: string;
  beforeAll(async () => {
    root = await project(FIXTURE);
  });
  afterAll(() => rm(root, { recursive: true, force: true }));

  it('the production allowlist contains api-mutation-without-auth and missing-request-body-validation and NOTHING else', () => {
    expect([...ENABLED_ABSENCE_TAGS].sort()).toEqual(['api-mutation-without-auth', 'missing-request-body-validation']);
  });

  it('a DEFAULT scan of the fixture reports the unauthenticated DELETE and the unvalidated POST as absence findings (the public rules still cannot see these routes)', async () => {
    const report = await scan(root);
    const absence = report.findings.filter(isAbsenceAuth);
    expect(absence.map((finding) => finding.evidence).sort()).toEqual(['DELETE /api/notes/:id', 'POST /api/notes/']);
    for (const finding of absence) expect(finding.confidence).toBe('low');
    const body = report.findings.filter(
      (finding) => finding.ruleId === 'missing_request_body_validation' && finding.detectionKind === 'absence',
    );
    expect(body.map((finding) => finding.evidence)).toEqual(['POST /api/notes/']);
    expect(body[0]?.confidence).toBe('low');
  });

  it('GUARD: with api-mutation-without-auth enabled, the unauthenticated DELETE reaches the report', async () => {
    const report = await scan(root, ONLY_AUTH);
    const absence = report.findings.filter(isAbsenceAuth);
    const del = absence.find((finding) => finding.evidence === 'DELETE /api/notes/:id');
    expect(del, 'the DELETE route must surface as a finding').toBeDefined();
    expect(del?.filePath).toBe('routes/notes.js');
    expect(del?.lineStart).toBe(5);
    expect(del?.confidence).toBe('low');
    expect(del?.detectionMethod).toBe('heuristic');
    expect(del?.severity).toBe(ruleMetadata('api_mutation_without_auth')?.defaultSeverity);
    expect(del?.category).toBe('authentication');
    expect(del?.stableId).toBeDefined();
    expect(del?.adjudication).toBeUndefined();
    expect(absence.some((finding) => finding.evidence === 'POST /api/notes/')).toBe(true);
    expect(report.findingsByRule.some((row) => row.ruleId === 'api_mutation_without_auth')).toBe(true);
  });

  it('an enabled tag other than the one that fires adds nothing', async () => {
    const report = await scan(root, new Set(['missing-webhook-verification']));
    expect(report.findings.filter(isAbsenceAuth)).toEqual([]);
  });

  it('a tag the absence rules do not know is ignored, not an error', async () => {
    const report = await scan(root, new Set(['no-such-tag']));
    expect(report.findings.filter(isAbsenceAuth)).toEqual([]);
  });
});

describe('absenceFindings — the converter itself', () => {
  let root: string;
  let fileMap: FileMap;
  let projectMap: ProjectMap;
  beforeAll(async () => {
    root = await project(FIXTURE);
    ({ fileMap, projectMap } = await maps(root));
  });
  afterAll(() => rm(root, { recursive: true, force: true }));

  it('an empty allowlist returns nothing and no failures', () => {
    expect(absenceFindings({ fileMap, projectMap, enabledTags: new Set(), codeFindings: [] })).toEqual({
      findings: [],
      failures: [],
    });
  });

  it('DEDUP: a public finding at the same (ruleId, filePath, line) wins and the absence one is not emitted', () => {
    const fresh = absenceFindings({ fileMap, projectMap, enabledTags: ONLY_AUTH, codeFindings: [] });
    const del = fresh.findings.find((finding) => finding.evidence === 'DELETE /api/notes/:id');
    expect(del).toBeDefined();
    if (del === undefined) return;
    const publicFinding = makeFinding({
      ruleId: 'api_mutation_without_auth',
      title: 'public rule saw it first',
      severity: 'high',
      confidence: 'medium',
      detectionKind: 'absence',
      filePath: del.filePath,
      lineStart: del.lineStart,
      evidence: 'in-memory delete @ line 5',
      userExplanation: 'x',
      technicalExplanation: 'x',
      fixHint: 'x',
      category: 'authentication',
    });
    const deduped = absenceFindings({ fileMap, projectMap, enabledTags: ONLY_AUTH, codeFindings: [publicFinding] });
    expect(deduped.findings.some((finding) => finding.evidence === 'DELETE /api/notes/:id')).toBe(false);
    expect(deduped.findings.some((finding) => finding.evidence === 'POST /api/notes/')).toBe(true);
    const otherRule = { ...publicFinding, ruleId: 'missing_rate_limit' };
    expect(
      absenceFindings({ fileMap, projectMap, enabledTags: ONLY_AUTH, codeFindings: [otherRule] }).findings.some(
        (finding) => finding.evidence === 'DELETE /api/notes/:id',
      ),
    ).toBe(true);
  });

  it('the finding carries the CATALOG rule id, not the candidate tag', () => {
    const { findings } = absenceFindings({ fileMap, projectMap, enabledTags: ONLY_AUTH, codeFindings: [] });
    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      expect(finding.ruleId).toBe('api_mutation_without_auth');
      expect(finding.ruleId in RULE_CATALOG).toBe(true);
      expect(finding.detectionKind).toBe('absence');
    }
  });

  it('a hit on a non-production path is dropped, by the same exclusion every public rule uses', async () => {
    const testRoot = await project({
      'package.json': FIXTURE['package.json'] ?? '',
      'server.js': (FIXTURE['server.js'] ?? '').replace("'./routes/notes'", "'./__tests__/routes/notes'"),
      '__tests__/routes/notes.js': FIXTURE['routes/notes.js'] ?? '',
      'controllers/notes.js': FIXTURE['controllers/notes.js'] ?? '',
    });
    try {
      const m = await maps(testRoot);
      const { runAbsencePass } = await import('../../src/candidates/absence/index.js');
      const raw = runAbsencePass(m.fileMap, m.projectMap, () => undefined).hits;
      expect(raw.some((hit) => hit.filePath === '__tests__/routes/notes.js' && hit.ruleTag === 'api-mutation-without-auth')).toBe(true);
      const { findings } = absenceFindings({ ...m, enabledTags: ONLY_AUTH, codeFindings: [] });
      expect(findings.filter((finding) => finding.filePath.startsWith('__tests__/'))).toEqual([]);
    } finally {
      await rm(testRoot, { recursive: true, force: true });
    }
  });
});

describe('absenceFindings — every tag maps to a catalogued rule the registry agrees with', () => {
  it('every ruleId is in RULE_CATALOG, and category and severity come from the registry entry', () => {
    for (const tag of Object.keys(ABSENCE_RULES) as AbsenceRuleTag[]) {
      const spec = ABSENCE_RULES[tag];
      expect(spec.ruleId in RULE_CATALOG, `${tag} -> ${spec.ruleId}`).toBe(true);
      const metadata = ruleMetadata(spec.ruleId);
      expect(metadata, `${spec.ruleId} has a registry entry`).toBeDefined();
      expect(spec.category, `${tag}: category matches the registry`).toBe(metadata?.category);
    }
  });

  it('every ruleTag that rules.ts can emit has a mapping (a new absence rule cannot fall silently through)', async () => {
    const source = await readFile(ABSENCE_RULES_SOURCE, 'utf8');
    const emitted = new Set([...source.matchAll(/ruleTag:\s*'([a-z-]+)'/g)].map((match) => match[1]));
    expect(emitted.size).toBeGreaterThanOrEqual(7);
    expect([...emitted].sort()).toEqual(Object.keys(ABSENCE_RULES).sort());
  });
});

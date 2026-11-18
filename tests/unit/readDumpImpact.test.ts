import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { archiveEntryFindings, isSqlDumpReadAndFound } from '../../src/archive-findings/archiveEntryFindings.js';
import type { SqlDumpContent } from '../../src/archive-findings/sqlDumpContent.js';
import { emptySupabaseRlsInfo } from '../../src/project-map/detectRls.js';
import { buildRuleImpacts, withReadDumpImpact } from '../../src/report/buildFindingsByRule.js';
import { buildReport } from '../../src/report/buildReport.js';
import { validateScanReport } from '../../src/report/validateReport.js';
import { RULE_CATALOG } from '../../src/rules/ruleCatalog.js';
import { UNEXPECTED_CATEGORY_ORDER, type ArchiveWatchListCarry } from '../../src/shared/archiveObservations.js';
import { makeFinding } from '../../src/shared/findingFactory.js';
import type { Finding } from '../../src/shared/types.js';

const DUMP = 'data_artefact_committed';
const approved = JSON.parse(
  readFileSync(fileURLToPath(new URL('../fixtures/approved-impact-texts.json', import.meta.url)), 'utf8'),
) as Record<string, string>;

const APPROVED = approved[DUMP] as string;
const WHEN_READ =
  'A file whose name looks like a database copy or infrastructure-state file is travelling with the project, so anyone who receives the project receives that file too. ' +
  'Epherem read this file and found the marks of a database dump in it (a dump tool\'s header, COPY … FROM stdin, or many INSERT rows); if it holds real customer data or live credentials, those values would be disclosed along with the source code.';

function carryOf(paths: string[]): ArchiveWatchListCarry {
  return {
    groups: UNEXPECTED_CATEGORY_ORDER.map((category) => ({
      category,
      count: category === 'database_dumps' ? paths.length : 0,
      sample: { paths: category === 'database_dumps' ? paths : [], shortened: [] },
    })),
  };
}
const dumps = (paths: string[], read: Record<string, SqlDumpContent>): Finding[] =>
  archiveEntryFindings(carryOf(paths), (archivePath) => read[archivePath]).findings;

const emptyProjectMap = {
  apiRoutes: [], frontendComponents: [], authFiles: [], middlewareFiles: [], middlewareMatchers: [],
  databaseFiles: [], envFiles: [], configFiles: [], supabaseUsage: [], firebaseUsage: [],
  supabaseRls: emptySupabaseRlsInfo(), databaseCalls: [], imports: [],
  dangerousOperations: [], publicClientUsage: [], serverSideUsage: [], authSignals: [], envUsage: [],
};
const reportOf = (findings: Finding[]) =>
  buildReport({
    fileMap: { rootPath: '/', entries: [], skipped: [], skippedCount: 0, warnings: [] },
    detectedStack: { stacks: [] },
    projectMap: emptyProjectMap,
    findings,
  });
const xss = makeFinding({
  ruleId: 'xss', title: 'x', severity: 'high', confidence: 'high', filePath: 'src/a.ts', lineStart: 2,
  evidence: 'e', userExplanation: 'u', technicalExplanation: 't', fixHint: 'f', category: 'configuration',
});

describe('the two paragraphs', () => {
  it('CRUCIAL: the approved paragraph is unchanged, and the catalog\'s second one is the new text, word for word', () => {
    expect(RULE_CATALOG[DUMP].impact).toBe(APPROVED);
    expect(APPROVED).toContain('Epherem has not opened it to confirm what it contains');
    expect(RULE_CATALOG[DUMP].impactWhenRead).toBe(WHEN_READ);
  });

  it('the second keeps the approved first sentence and the approved last clause; only what Epherem did changes', () => {
    const firstSentence = APPROVED.slice(0, APPROVED.indexOf(' Epherem has not opened'));
    expect(WHEN_READ.startsWith(`${firstSentence} Epherem read this file`)).toBe(true);
    const tail = 'if it holds real customer data or live credentials, those values would be disclosed along with the source code.';
    expect(APPROVED.endsWith(tail)).toBe(true);
    expect(WHEN_READ.endsWith(tail)).toBe(true);
    expect(WHEN_READ).not.toContain('not opened');
  });

  it('no other rule has a second paragraph', () => {
    const withSecond = Object.entries(RULE_CATALOG)
      .filter(([, entry]) => 'impactWhenRead' in entry)
      .map(([id]) => id);
    expect(withSecond).toEqual([DUMP]);
  });
});

describe('which one a report carries', () => {
  it('CRUCIAL: a .sql the scan read and found a dump in: the second paragraph', () => {
    const findings = dumps(['db/nightly_export.sql'], { 'db/nightly_export.sql': 'holds_data' });
    expect(findings.map(isSqlDumpReadAndFound)).toEqual([true]);
    const report = reportOf(findings);
    expect(report.ruleImpacts?.[DUMP]).toBe(WHEN_READ);
    expect(validateScanReport(report).errors).toEqual([]);
  });

  it('CRUCIAL: a .sql the scan did not read keeps the approved paragraph: it really was not opened', () => {
    const findings = dumps(['db/nightly_export.sql'], {});
    expect(findings.map((finding) => finding.confidence)).toEqual(['medium']);
    expect(reportOf(findings).ruleImpacts?.[DUMP]).toBe(APPROVED);
  });

  it('CRUCIAL: a .sqlite, a .sqlite.bak or a .dump keeps the approved paragraph: named, not read', () => {
    for (const name of ['data/app.sqlite', 'data/db.sqlite.bak', 'nightly.dump']) {
      expect(reportOf(dumps([name], {})).ruleImpacts?.[DUMP], name).toBe(APPROVED);
    }
  });

  it('CRUCIAL: a check holding both kinds keeps the approved paragraph', () => {
    const findings = dumps(['db/nightly_export.sql', 'data/db.sqlite.bak'], { 'db/nightly_export.sql': 'holds_data' });
    expect(findings.map(isSqlDumpReadAndFound)).toEqual([true, false]);
    expect(reportOf(findings).ruleImpacts?.[DUMP]).toBe(APPROVED);
  });

  it('only this rule\'s paragraph can change; the others, and the map\'s order, are as buildRuleImpacts made them', () => {
    const report = reportOf([xss, ...dumps(['db/nightly_export.sql'], { 'db/nightly_export.sql': 'holds_data' })]);
    expect(Object.keys(report.ruleImpacts ?? {})).toEqual(report.findingsByRule.map((row) => row.ruleId));
    expect(report.ruleImpacts?.xss).toBe(approved.xss);
    const built = buildRuleImpacts(report.findingsByRule);
    expect(withReadDumpImpact(built, [xss])).toBe(built);
  });

  it('a finding of the rule with another path or confidence is not counted as read', () => {
    const base = { ruleId: DUMP, filePath: 'db/x.sql', confidence: 'high' as const };
    expect(isSqlDumpReadAndFound(base)).toBe(true);
    expect(isSqlDumpReadAndFound({ ...base, filePath: 'db/X.SQL' })).toBe(true);
    expect(isSqlDumpReadAndFound({ ...base, confidence: 'medium' })).toBe(false);
    expect(isSqlDumpReadAndFound({ ...base, filePath: 'db/x.sqlite' })).toBe(false);
    expect(isSqlDumpReadAndFound({ ...base, ruleId: 'private_key_or_credential_file' })).toBe(false);
  });
});

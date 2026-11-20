import { describe, expect, it } from 'vitest';
import { archiveEntryFindings } from '../../src/archive-findings/archiveEntryFindings.js';
import { detectLanguages } from '../../src/shared/languages.js';
import { buildRuleResults } from '../../src/report/buildRuleResults.js';
import { ARCHIVE_ENTRY_RULE_IDS, RULE_CATALOG } from '../../src/rules/ruleCatalog.js';
import { ruleMetadata } from '../../src/rules/ruleRegistry.js';
import { MAX_REPORTED_PATH_SAMPLE } from '../../src/upload/reportedPath.js';
import {
  UNEXPECTED_CATEGORY_ORDER,
  type ArchiveWatchListCarry,
  type UnexpectedFileCategoryId,
} from '../../src/shared/archiveObservations.js';
import type { DependencyAuditSummary, Finding } from '../../src/shared/types.js';
import { memoryContext } from './helpers.js';

function carryOf(
  hits: Partial<Record<UnexpectedFileCategoryId, { paths: string[]; shortened?: number[]; count?: number }>>,
  rootPrefix?: string,
): ArchiveWatchListCarry {
  return {
    ...(rootPrefix === undefined ? {} : { rootPrefix }),
    groups: UNEXPECTED_CATEGORY_ORDER.map((category) => {
      const hit = hits[category];
      return {
        category,
        count: hit?.count ?? hit?.paths.length ?? 0,
        sample: { paths: hit?.paths ?? [], shortened: hit?.shortened ?? [] },
      };
    }),
  };
}

function byRule(findings: readonly Finding[], ruleId: string): Finding[] {
  return findings.filter((finding) => finding.ruleId === ruleId);
}

describe('the exemption, asserted by VALUE', () => {
  const { findings } = archiveEntryFindings(
    carryOf({
      private_keys: { paths: ['deploy/server.pem', 'id_rsa'] },
      cloud_credentials: { paths: ['.aws/credentials'] },
      database_dumps: { paths: ['data/backup.sql', 'app.sqlite'] },
      infrastructure_state: { paths: ['infra/terraform.tfstate'] },
    }),
  );

  it('produces findings for both rules', () => {
    expect(byRule(findings, 'private_key_or_credential_file')).toHaveLength(3);
    expect(byRule(findings, 'data_artefact_committed')).toHaveLength(3);
  });

  it('EVERY finding declares `required: false` — the literal value, on every one', () => {
    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      expect(finding.adjudication, `no adjudication policy on ${finding.ruleId}`).toBeDefined();
      expect(finding.adjudication?.required).toBe(false);
      expect(finding.adjudication?.reason).toBe('archive_entry_name_observation');
      expect((finding.adjudication?.basis ?? '').length).toBeGreaterThan(0);
    }
  });

  it('the basis states what it does NOT claim, rather than borrowing the dependency measurement', () => {
    const basis = findings[0]?.adjudication?.basis ?? '';
    expect(basis).toContain('NOT CLAIMED');
    expect(basis).not.toContain('232');
  });
});

describe('the archive wrapper is re-attached to every path', () => {
  const ROOT = 'repo-a1b2c3';

  it('a finding names the file at the SAME path the rest of the report uses', () => {
    const { findings } = archiveEntryFindings(
      carryOf({ private_keys: { paths: ['deploy/server.pem'] } }, ROOT),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.filePath).toBe(`${ROOT}/deploy/server.pem`);
    expect(findings[0]?.evidence).toContain(`${ROOT}/deploy/server.pem`);
  });

  it('an archive with no single common root gets nothing invented for it', () => {
    const { findings } = archiveEntryFindings(carryOf({ private_keys: { paths: ['server.pem'] } }));
    expect(findings[0]?.filePath).toBe('server.pem');
  });

  it('the fix prompt names the same location as filePath', () => {
    const { findings } = archiveEntryFindings(
      carryOf({ infrastructure_state: { paths: ['infra/terraform.tfstate'] } }, ROOT),
    );
    expect(findings[0]?.fixPrompt).toContain(`${ROOT}/infra/terraform.tfstate:1`);
  });
});

describe('a shortened path names no file, so it produces no finding', () => {
  it('is skipped, and never becomes a filePath', () => {
    const { findings, warnings } = archiveEntryFindings(
      carryOf({ private_keys: { paths: ['short.pem', 'a-very-long-prefix/that-was-cut.p'], shortened: [1] } }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.filePath).toBe('short.pem');
    for (const finding of findings) {
      expect(finding.filePath).not.toContain('that-was-cut');
    }
    expect(warnings.join(' ')).toContain('too long to name in full');
  });

  it('a shortened path is still COUNTED, so the total does not shrink to match the list', () => {
    const { warnings } = archiveEntryFindings(
      carryOf({ database_dumps: { paths: ['ok.dump', 'cut.dum'], shortened: [1] } }),
    );
    expect(warnings.join(' ')).toContain('2 database or infrastructure-state file(s) were found');
    expect(warnings.join(' ')).toContain('names 1 of them');
  });
});

describe('the 50-path sample cap is declared, and the arithmetic closes', () => {
  const paths = Array.from({ length: MAX_REPORTED_PATH_SAMPLE }, (_, index) => `keys/k${index}.pem`);

  it('200 keys yield 50 findings and a warning that says 200', () => {
    const { findings, warnings } = archiveEntryFindings(
      carryOf({ private_keys: { paths, count: 200 } }),
    );
    expect(findings).toHaveLength(MAX_REPORTED_PATH_SAMPLE);
    const warning = warnings.join(' ');
    expect(warning).toContain('200 private key or credential file(s) were found');
    expect(warning).toContain('names 50 of them');
    expect(warning).toContain('150 beyond the 50 paths retained per category');
    expect(warning).toContain('FLOOR');
  });

  it('EVERY dropped file is accounted for by cause: named + beyondSample + alreadyProven + unnamed === matched', () => {
    const { findings, warnings } = archiveEntryFindings(
      carryOf({
        cloud_credentials: {
          count: 60,
          paths: [
            'firebase-adminsdk-aaa.json',
            'firebase-adminsdk-bbb.json',
            'cut-off-path',
            ...Array.from({ length: 47 }, (_, index) => `creds/aws${index}/credentials`),
          ],
          shortened: [2],
        },
      }),
    );
    expect(findings).toHaveLength(47);
    const warning = warnings.join(' ');
    expect(warning).toContain('60 private key or credential file(s) were found');
    expect(warning).toContain('names 47 of them');
    expect(warning).toContain('10 beyond the 50 paths retained per category');
    expect(warning).toContain('2 already reported by hardcoded_secret');
    expect(warning).toContain('1 whose path was too long to name in full');
    expect(47 + 10 + 2 + 1).toBe(60);
  });

  it('no shortfall means NO warning — a declaration that fires when nothing was dropped is its own wrong number', () => {
    const { findings, warnings } = archiveEntryFindings(
      carryOf({ private_keys: { paths: ['a.pem', 'b.key', 'c.p12'] } }),
    );
    expect(findings).toHaveLength(3);
    expect(warnings).toEqual([]);
    for (const finding of findings) {
      expect(finding.userExplanation).not.toContain('FLOOR');
    }
  });

  it('the shortfall rides on userExplanation, never on evidence, so identities do not churn', () => {
    const withGap = archiveEntryFindings(carryOf({ private_keys: { paths: ['a.pem'], count: 9 } }));
    const withoutGap = archiveEntryFindings(carryOf({ private_keys: { paths: ['a.pem'] } }));
    expect(withGap.findings[0]?.evidence).toBe(withoutGap.findings[0]?.evidence);
    expect(withGap.findings[0]?.userExplanation).not.toBe(withoutGap.findings[0]?.userExplanation);
  });
});

describe('the .json cloud credentials are left to hardcoded_secret', () => {
  it('a firebase-adminsdk json produces NO finding from this rule', () => {
    const { findings } = archiveEntryFindings(
      carryOf({ cloud_credentials: { paths: ['config/firebase-adminsdk-abc123.json'] } }),
    );
    expect(findings).toHaveLength(0);
  });

  it('.aws/credentials carries no .json and stays in this rule', () => {
    const { findings } = archiveEntryFindings(
      carryOf({ cloud_credentials: { paths: ['.aws/credentials'] } }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('private_key_or_credential_file');
  });

  it('the exclusion is on the cloud-credential category ONLY', () => {
    const { findings } = archiveEntryFindings(
      carryOf({ database_dumps: { paths: ['dump.db'] }, private_keys: { paths: ['weird.json.pem'] } }),
    );
    expect(findings).toHaveLength(2);
  });
});

describe('no archive means no findings, and never a pass', () => {
  it('an undefined carry produces nothing at all', () => {
    expect(archiveEntryFindings(undefined)).toEqual({ findings: [], warnings: [] });
  });

  it('an archive that matched nothing produces nothing, and no warning', () => {
    expect(archiveEntryFindings(carryOf({}))).toEqual({ findings: [], warnings: [] });
  });

  const audit: DependencyAuditSummary = {
    performed: false,
    incomplete: true,
    source: 'none',
    dependenciesCollected: 0,
    checked: 0,
    notChecked: [],
    vulnerabilities: [],
    diagnostics: [],
    note: 'not run',
  };
  const context = memoryContext([]);

  function statusOf(archiveObserved: boolean, findings: Finding[] = []): Map<string, string> {
    const results = buildRuleResults({
      findings,
      context,
      codeScanComplete: true,
      dependencyAudit: audit,
      dependencyAuditStatus: 'not_performed',
      archiveObserved,
      languages: detectLanguages(context.fileMap),
    });
    return new Map(results.map((result) => [result.ruleId, result.status]));
  }

  it('a scan with NO archive reports both rules not_completed, never passed', () => {
    const status = statusOf(false);
    for (const ruleId of ARCHIVE_ENTRY_RULE_IDS) {
      expect(status.get(ruleId), `${ruleId} on a directory scan`).toBe('not_completed');
    }
  });

  it('a scan WITH an archive and no hits reports passed — that is a real result', () => {
    const status = statusOf(true);
    for (const ruleId of ARCHIVE_ENTRY_RULE_IDS) {
      expect(status.get(ruleId), `${ruleId} on a clean archive`).toBe('passed');
    }
  });

  it('findings make it failed, whatever the archive flag says', () => {
    const { findings } = archiveEntryFindings(carryOf({ private_keys: { paths: ['id_rsa'] } }));
    expect(statusOf(true, findings).get('private_key_or_credential_file')).toBe('failed');
  });
});

describe('catalog, registry and emitted severity agree', () => {
  it('both ids are catalogued and declared as non-registry archive producers', () => {
    for (const ruleId of ARCHIVE_ENTRY_RULE_IDS) {
      expect(RULE_CATALOG).toHaveProperty(ruleId);
    }
    expect([...ARCHIVE_ENTRY_RULE_IDS].sort()).toEqual([
      'data_artefact_committed',
      'private_key_or_credential_file',
    ]);
  });

  it('THE REGRESSION 9254a43 GUARDS: defaultSeverity equals what the module actually emits', () => {
    const { findings } = archiveEntryFindings(
      carryOf({
        private_keys: { paths: ['id_rsa'] },
        database_dumps: { paths: ['app.sqlite'] },
      }),
    );
    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      const meta = ruleMetadata(finding.ruleId);
      expect(meta, `no registry metadata for ${finding.ruleId}`).toBeDefined();
      expect(meta?.defaultSeverity, `declared default disagrees with emitted severity for ${finding.ruleId}`).toBe(
        finding.severity,
      );
      expect(meta?.error).toBe(RULE_CATALOG[finding.ruleId as keyof typeof RULE_CATALOG].error);
    }
  });

  it('every finding is deterministic, not a heuristic absence signal', () => {
    const { findings } = archiveEntryFindings(carryOf({ private_keys: { paths: ['id_rsa'] } }));
    expect(findings[0]?.detectionKind).toBe('pattern');
    expect(findings[0]?.detectionMethod).toBe('deterministic');
    expect(findings[0]?.confidence).toBe('high');
  });
});

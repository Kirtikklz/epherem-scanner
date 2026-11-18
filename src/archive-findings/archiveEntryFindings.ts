import {
  type ArchiveWatchListCarry,
  type UnexpectedFileCategoryId,
  type UnexpectedFileGroupRecord,
} from '../shared/archiveObservations.js';
import { makeFinding } from '../shared/findingFactory.js';
import type { SqlDumpContent } from './sqlDumpContent.js';
import type {
  Finding,
  FindingAdjudicationPolicy,
  FindingCategory,
  Severity,
} from '../shared/types.js';

export type ArchiveEntryRuleId = 'private_key_or_credential_file' | 'data_artefact_committed';

const CATEGORY_RULE: Record<UnexpectedFileCategoryId, ArchiveEntryRuleId> = {
  private_keys: 'private_key_or_credential_file',
  cloud_credentials: 'private_key_or_credential_file',
  database_dumps: 'data_artefact_committed',
  infrastructure_state: 'data_artefact_committed',
};

const CATEGORY_LABEL: Record<UnexpectedFileCategoryId, string> = {
  private_keys: 'private key or certificate store',
  cloud_credentials: 'cloud service-account credential',
  database_dumps: 'database file or database dump',
  infrastructure_state: 'infrastructure state file',
};

interface ArchiveRuleSpec {
  ruleId: ArchiveEntryRuleId;
  title: string;
  severity: Severity;
  category: FindingCategory;
  plural: string;
  userExplanation: string;
  technicalExplanation: string;
  fixHint: string;
  extraFixRequirements: string[];
}

const RULES: Record<ArchiveEntryRuleId, ArchiveRuleSpec> = {
  private_key_or_credential_file: {
    ruleId: 'private_key_or_credential_file',
    title: 'File named like a private key or credential store committed with the project',
    severity: 'critical',
    category: 'secrets',
    plural: 'private key or credential file(s)',
    userExplanation:
      'A file whose name marks it as a private key or credential store is part of this upload. This finding is based on the file\'s name; some such files hold only a public certificate. Anyone who gets a copy of the project also gets the file, and if it holds a real key, a key that has been copied is a key that has to be replaced — deleting the file is not enough on its own.',
    technicalExplanation:
      'An archive entry name matched the private-key / cloud-credential watch-list. Key material and credentials must never be committed: if this file holds any, assume they are disclosed to everyone who has ever had a copy of the repository or the upload, including its history.',
    fixHint:
      'Revoke or rotate the key or credential FIRST, at the provider, so a copy already taken stops working. Then remove the file from the project and from version-control history, add its pattern to .gitignore, and load the replacement from an environment variable or a secrets manager.',
    extraFixRequirements: [
      'Rotate or revoke the credential at its provider BEFORE removing the file. Deleting a key that is already copied changes nothing about who can use it.',
      'Remove the file from version-control HISTORY, not only from the working tree; a deleted file is still readable in every earlier commit.',
      'Do not replace the file with an encrypted or base64-encoded copy of the same secret; the secret itself must change.',
    ],
  },
  data_artefact_committed: {
    ruleId: 'data_artefact_committed',
    title: 'Database dump or infrastructure state committed with the project',
    severity: 'high',
    category: 'data_exposure',
    plural: 'database or infrastructure-state file(s)',
    userExplanation:
      'A database file, a database dump, or an infrastructure state file is part of this upload. These usually hold real data or real infrastructure detail — customer records, password hashes, resource names, and sometimes credentials — and they are rarely meant to travel with the code.',
    technicalExplanation:
      'An archive entry name matched the database-dump / infrastructure-state watch-list. Dumps commonly contain production or production-like personal data; Terraform state files record resource identifiers and can contain credentials in plain text. Neither belongs in a source repository.',
    fixHint:
      'Remove the file from the project and from version-control history, and add its pattern to .gitignore. Keep dumps in a private store with access control, and move Terraform state to a remote backend with encryption and locking. If the file held real personal data or any credential, treat it as disclosed and act accordingly.',
    extraFixRequirements: [
      'Remove the file from version-control HISTORY, not only from the working tree.',
      'If the file contains personal data, treat its presence in a shared repository as a disclosure and follow whatever notification obligation applies; do not silently delete it.',
      'For Terraform state, migrate to a remote backend rather than committing a re-generated local state file.',
    ],
  },
};

const ARCHIVE_NAME_ADJUDICATION_POLICY: FindingAdjudicationPolicy = {
  required: false,
  reason: 'archive_entry_name_observation',
  basis:
    'This finding is an observation of a NAME in the uploaded archive table of contents, not an inference about code. ' +
    'COMPOSITION OF THE ARGUMENT: archive entry names enter neither the file map nor the project map, so no further ' +
    'evidence about this finding exists in the scan, and the only question left would be whether the archive contains an ' +
    'entry with this name, which is the observation itself. NOT CLAIMED: nothing has been measured for these two rules; ' +
    'the exemption rests on there being nothing to judge.',
};

export interface ArchiveEntryFindingsResult {
  findings: Finding[];
  warnings: string[];
}

function withRootPrefix(path: string, rootPrefix: string | undefined): string {
  if (rootPrefix === undefined || rootPrefix === '') return path;
  return `${rootPrefix}/${path}`;
}

interface RuleTally {
  matched: number;
  named: number;
  beyondSample: number;
  alreadyProven: number;
  unnamedPath: number;
  readAndNoData: number;
}

function emptyTally(): RuleTally {
  return { matched: 0, named: 0, beyondSample: 0, alreadyProven: 0, unnamedPath: 0, readAndNoData: 0 };
}

export const UNREAD_SQL_DUMP_EVIDENCE = 'Name suggests a database dump; contents not read';

export function isSqlDumpReadAndFound(finding: Pick<Finding, 'ruleId' | 'filePath' | 'confidence'>): boolean {
  return (
    finding.ruleId === 'data_artefact_committed' &&
    typeof finding.filePath === 'string' &&
    finding.filePath.toLowerCase().endsWith('.sql') &&
    finding.confidence === 'high'
  );
}

function alreadyReportedByContentScan(category: UnexpectedFileCategoryId, path: string): boolean {
  return category === 'cloud_credentials' && path.toLowerCase().endsWith('.json');
}

function shortfallSentence(spec: ArchiveRuleSpec, tally: RuleTally): string {
  const causes: string[] = [];
  if (tally.beyondSample > 0) {
    causes.push(
      `${tally.beyondSample} beyond the 50 paths retained per category, so they were counted but never named`,
    );
  }
  if (tally.alreadyProven > 0) {
    causes.push(
      `${tally.alreadyProven} already reported by hardcoded_secret, which read the file and proved the key block`,
    );
  }
  if (tally.unnamedPath > 0) {
    causes.push(`${tally.unnamedPath} whose path was too long to name in full`);
  }
  if (tally.readAndNoData > 0) {
    causes.push(`${tally.readAndNoData} named like a dump whose contents were read and hold no data, so they are not dumps`);
  }
  return (
    `${tally.matched} ${spec.plural} were found in this upload and this report names ${tally.named} of them: ` +
    `${causes.join('; ')}. ` +
    'The finding list is a FLOOR, not the count. The exact total is in the project shape block, which records ' +
    'every match whether or not it is named here.'
  );
}

export function archiveEntryFindings(
  carry: ArchiveWatchListCarry | undefined,
  sqlContentOf?: (archivePath: string) => SqlDumpContent | undefined,
): ArchiveEntryFindingsResult {
  if (carry === undefined) return { findings: [], warnings: [] };

  const findings: Finding[] = [];
  const tallies = new Map<ArchiveEntryRuleId, RuleTally>();
  const tallyFor = (ruleId: ArchiveEntryRuleId): RuleTally => {
    const existing = tallies.get(ruleId);
    if (existing !== undefined) return existing;
    const fresh = emptyTally();
    tallies.set(ruleId, fresh);
    return fresh;
  };

  for (const group of carry.groups) {
    const ruleId = CATEGORY_RULE[group.category];
    const spec = RULES[ruleId];
    const tally = tallyFor(ruleId);
    tally.matched += group.count;
    tally.beyondSample += Math.max(0, group.count - group.sample.paths.length);
    findings.push(...findingsForGroup(spec, group, carry.rootPrefix, tally, sqlContentOf));
  }

  const warnings: string[] = [];
  for (const ruleId of [...tallies.keys()].sort((a, b) => a.localeCompare(b))) {
    const tally = tallies.get(ruleId);
    if (tally === undefined || !hasShortfall(tally)) continue;
    warnings.push(shortfallSentence(RULES[ruleId], tally));
  }

  return { findings: findings.map((finding) => withShortfallNote(finding, tallies)), warnings };
}

function hasShortfall(tally: RuleTally): boolean {
  return tally.named + tally.readAndNoData < tally.matched;
}

function withShortfallNote(
  finding: Finding,
  tallies: ReadonlyMap<ArchiveEntryRuleId, RuleTally>,
): Finding {
  const tally = tallies.get(finding.ruleId as ArchiveEntryRuleId);
  if (tally === undefined || !hasShortfall(tally)) return finding;
  const spec = RULES[finding.ruleId as ArchiveEntryRuleId];
  return {
    ...finding,
    userExplanation: `${finding.userExplanation} ${shortfallSentence(spec, tally)}`,
  };
}

function findingsForGroup(
  spec: ArchiveRuleSpec,
  group: UnexpectedFileGroupRecord,
  rootPrefix: string | undefined,
  tally: RuleTally,
  sqlContentOf: ((archivePath: string) => SqlDumpContent | undefined) | undefined,
): Finding[] {
  const shortened = new Set(group.sample.shortened);
  const label = CATEGORY_LABEL[group.category];
  const findings: Finding[] = [];

  group.sample.paths.forEach((path, index) => {
    if (shortened.has(index) || path === '') {
      tally.unnamedPath += 1;
      return;
    }
    if (alreadyReportedByContentScan(group.category, path)) {
      tally.alreadyProven += 1;
      return;
    }
    const filePath = withRootPrefix(path, rootPrefix);
    const sqlContent =
      group.category === 'database_dumps' && path.toLowerCase().endsWith('.sql')
        ? (sqlContentOf?.(filePath) ?? 'not_read')
        : undefined;
    if (sqlContent === 'no_data') {
      tally.readAndNoData += 1;
      return;
    }
    const unread = sqlContent === 'not_read';
    tally.named += 1;
    findings.push({
      ...makeFinding({
        ruleId: spec.ruleId,
        title: spec.title,
        severity: spec.severity,
        confidence: unread ? 'medium' : 'high',
        filePath,
        lineStart: 1,
        evidence: unread ? UNREAD_SQL_DUMP_EVIDENCE : `${filePath} (${label})`,
        userExplanation: spec.userExplanation,
        technicalExplanation: spec.technicalExplanation,
        fixHint: spec.fixHint,
        category: spec.category,
        extraFixRequirements: spec.extraFixRequirements,
      }),
      adjudication: ARCHIVE_NAME_ADJUDICATION_POLICY,
    });
  });

  return findings;
}

import { createHash } from 'node:crypto';
import type { Finding } from './types.js';
import { toPosixPath } from './utils.js';

export const FINDING_IDENTITY_SCHEME = 'fi1';

declare const FINDING_IDENTITY_BRAND: unique symbol;

export type FindingIdentity = string & { readonly [FINDING_IDENTITY_BRAND]: true };

export interface FindingIdentityInput {
  ruleId: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  evidence: string;
}

const MAX_EVIDENCE_CHARS = 400;

const FILE_LINE_REFERENCE = /([A-Za-z0-9_@\-./\\]*[A-Za-z0-9_-]\.[A-Za-z0-9]{1,6}):\d+(?:-\d+)?/g;

export function normalizeEvidenceForIdentity(evidence: string): string {
  return evidence
    .replace(/\r\n?/g, '\n')
    .replace(FILE_LINE_REFERENCE, '$1:#')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, MAX_EVIDENCE_CHARS);
}

const FIELD_SEPARATOR = ' ';

export function findingIdentityGroupKey(input: FindingIdentityInput): string {
  return [
    FINDING_IDENTITY_SCHEME,
    input.ruleId,
    toPosixPath(input.filePath),
    normalizeEvidenceForIdentity(input.evidence),
  ].join(FIELD_SEPARATOR);
}

function digestIdentity(groupKey: string, occurrence: number): FindingIdentity {
  const hex = createHash('sha256')
    .update(`${groupKey}${FIELD_SEPARATOR}${occurrence}`)
    .digest('hex')
    .slice(0, 16);
  return `${FINDING_IDENTITY_SCHEME}_${hex}` as FindingIdentity;
}

function compareStrings(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

export function computeFindingIdentities(
  findings: readonly FindingIdentityInput[],
): FindingIdentity[] {
  const groups = new Map<string, { input: FindingIdentityInput; position: number }[]>();
  findings.forEach((input, position) => {
    const key = findingIdentityGroupKey(input);
    const bucket = groups.get(key);
    if (bucket === undefined) groups.set(key, [{ input, position }]);
    else bucket.push({ input, position });
  });

  const identities: (FindingIdentity | undefined)[] = new Array<FindingIdentity | undefined>(
    findings.length,
  ).fill(undefined);
  let assigned = 0;

  for (const [key, bucket] of groups) {
    bucket.sort(
      (a, b) =>
        a.input.lineStart - b.input.lineStart ||
        a.input.lineEnd - b.input.lineEnd ||
        compareStrings(a.input.evidence, b.input.evidence) ||
        a.position - b.position,
    );
    bucket.forEach((entry, occurrence) => {
      identities[entry.position] = digestIdentity(key, occurrence);
      assigned += 1;
    });
  }

  if (assigned !== findings.length) {
    throw new Error(
      `finding identity: assigned ${assigned} identities for ${findings.length} findings`,
    );
  }
  const result: FindingIdentity[] = [];
  const seen = new Set<string>();
  identities.forEach((identity, position) => {
    if (identity === undefined) {
      throw new Error(`finding identity: no identity assigned at position ${position}`);
    }
    if (seen.has(identity)) {
      throw new Error(`finding identity: duplicate identity ${identity} at position ${position}`);
    }
    seen.add(identity);
    result.push(identity);
  });
  return result;
}

export function withFindingIdentities(findings: readonly Finding[]): Finding[] {
  const identities = computeFindingIdentities(findings);
  return findings.map((finding, position) => ({
    ...finding,
    stableId: identities[position] as FindingIdentity,
  }));
}

import { makeFinding } from '../../shared/findingFactory.js';
import { findMatches } from '../../shared/utils.js';
import {
  replayBucketStatements,
  reportedStatementKey,
  type BucketVerdict,
  type ReportedStatement,
} from './storageBucketReplay.js';
import type {
  Finding,
  FindingAdjudicationPolicy,
  RuleContext,
  ScanRule,
} from '../../shared/types.js';

const INSERT_BUCKET = /insert\s+into\s+storage\.buckets\b[\s\S]{0,400}?;/gi;
const UPDATE_BUCKET_PUBLIC = /update\s+storage\.buckets\s+set\b[\s\S]{0,300}?public\s*=\s*true[\s\S]{0,200}?;/gi;
const CREATE_BUCKET = /createBucket\s*\(\s*['"]([\w.\-/]+)['"][\s\S]{0,200}?public\s*:\s*true/gi;
const FIREBASE_PUBLIC = /allow\s+(?:read|write|read\s*,\s*write|write\s*,\s*read)[^;{]*:\s*if\s+true\b/g;

const FIRST_STRING = /['"]([\w.\-/]+)['"]/;

const USER_CONTENT = /avatar|upload|attachment|document|\bdoc\b|\bdocs\b|file|media|photo|image|user[-_]?content|profile|receipt|invoice|report|submission|resume|cv|id[-_]?card|passport|kyc|medical|health/i;
const CRITICAL_CONTENT = /id[-_]?card|passport|kyc|licen[cs]e|medical|health|ssn|national[-_]?id|bank|statement|tax/i;
const PUBLIC_BY_DESIGN = /^(public|public[-_]?assets?|assets?|logos?|brand|static|cdn|thumbnails?|icons?|marketing|images[-_]?public)$/i;

function publicStoragePolicy(what: string, where: string): FindingAdjudicationPolicy {
  return {
    required: false,
    reason: 'storage_bucket_public_flag_observation',
    basis:
      `${what} sets public access = true at ${where}. This is a verified configuration fact, not an inference: ` +
      'the rule read the declaration itself, detectionKind is pattern and detectionMethod is deterministic, so ' +
      'there is no detection claim left to check. COMPOSITION OF THE ARGUMENT: the only question left ' +
      'open is INTENT — whether public access is a deliberate design (public media such as avatars or listing ' +
      'images) or an accidental exposure of private files. Answering it requires what the bucket holds and what ' +
      'the application is for, and neither is present in the source, so the question is put to the app\'s ' +
      'owner in userExplanation instead. NOT CLAIMED: nothing has been measured for this rule; the exemption ' +
      'rests only on the open question being one the code cannot answer.',
  };
}

const CONFIRM_INTENT =
  ' Confirm whether this is an intentional design choice (public media such as avatars or listing images) or ' +
  'an accidental exposure of private files — we can see that the bucket is public, but not what is stored inside it.';

const CONFIRM_INTENT_FIREBASE =
  ' Confirm whether this open access is intentional (files anyone is meant to be able to download) or an ' +
  'accidental exposure — we can see that the rule grants access to everyone, but not what it is guarding. ' +
  'Note that an unconditional grant covering writes lets anyone upload or replace files, which is very rarely intended.';

function setsPublicTrue(stmt: string): boolean {
  if (/\bpublic\s*[:=]>?\s*true\b/i.test(stmt)) return true;
  return /\bpublic\b/i.test(stmt) && /\btrue\b/i.test(stmt) && !/\bpublic\s*[:=]>?\s*false\b/i.test(stmt);
}

interface BucketDecl {
  name: string | undefined;
  line: number;
  offset: number | undefined;
  end: number;
  statement: 'insert' | 'update' | 'createBucket';
}

function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i += 1) if (content[i] === '\n') line += 1;
  return line;
}
function indexOfLine(content: string, line: number): number {
  let seen = 1;
  for (let i = 0; i < content.length; i += 1) {
    if (seen === line) return i;
    if (content[i] === '\n') seen += 1;
  }
  return 0;
}

function publicBuckets(content: string): BucketDecl[] {
  const out: BucketDecl[] = [];
  const add = (stmt: string, index: number, statement: 'insert' | 'update'): void => {
    if (!setsPublicTrue(stmt)) return;
    const raw = FIRST_STRING.exec(stmt)?.[1];
    const name = raw === undefined ? undefined : (raw.split('/').pop() ?? raw);
    out.push({ name, line: lineOf(content, index), offset: index, end: index + stmt.length, statement });
  };
  for (const m of findMatches(content, new RegExp(INSERT_BUCKET.source, 'gi'))) {
    add(m.matchText, m.index ?? indexOfLine(content, m.line), 'insert');
  }
  for (const m of findMatches(content, new RegExp(UPDATE_BUCKET_PUBLIC.source, 'gi'))) {
    add(m.matchText, m.index ?? indexOfLine(content, m.line), 'update');
  }
  for (const m of findMatches(content, new RegExp(CREATE_BUCKET.source, 'gi'))) {
    const name = m.groups[0];
    if (name !== undefined) {
      out.push({
        name: name.split('/').pop() ?? name,
        line: m.line,
        offset: undefined,
        end: m.index + m.matchText.length,
        statement: 'createBucket',
      });
    }
  }
  return out;
}

function bucketEvidence(label: string, decl: BucketDecl, notes: readonly string[]): string {
  if (notes.length === 0) return `storage bucket "${label}" created with public = true`;
  const what = decl.statement === 'update' ? 'set to public = true' : 'created with public = true';
  return `storage bucket "${label}" ${what}; ${notes.join('; ')}`;
}

const NOT_REPLAYED: BucketVerdict = { keep: true, notes: [] };

const FILE_OK = (path: string, content: string): boolean =>
  /storage\.rules$/i.test(path) || /storage\.buckets|createBucket\s*\(/i.test(content);

export const publicCloudStorage: ScanRule = {
  id: 'public_cloud_storage',
  title: 'Cloud storage bucket permits public access',
  category: 'authorization',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();
    const eligible = context.fileMap.entries.filter((entry) => FILE_OK(entry.path, entry.content));
    const declsByPath = new Map(eligible.map((entry) => [entry.path, publicBuckets(entry.content)]));

    const reported = new Map<string, ReportedStatement>();
    for (const [path, decls] of declsByPath) {
      for (const decl of decls) {
        if (decl.offset === undefined) continue;
        reported.set(reportedStatementKey(path, decl.offset), { name: decl.name, end: decl.end });
      }
    }
    const replay = replayBucketStatements(context.fileMap.entries, reported);

    for (const entry of eligible) {
      for (const decl of declsByPath.get(entry.path) ?? []) {
        const verdict = decl.offset === undefined ? NOT_REPLAYED : replay.judge(entry.path, decl.offset);
        if (!verdict.keep) continue;
        const name = decl.name;
        const label = name ?? '(name set at runtime)';
        const key = `${entry.path}:${name ?? `line-${decl.line}`}`;
        if (seen.has(key)) continue;
        seen.add(key);

        let severity: 'critical' | 'high' | 'medium';
        let confidence: 'high' | 'medium' | 'low';
        let userExplanation: string;
        if (name !== undefined && CRITICAL_CONTENT.test(name)) {
          severity = 'critical';
          confidence = 'high';
          userExplanation = `Your "${name}" storage bucket is public — every file in it can be downloaded by anyone with the link, no login. The name suggests it holds identity or financial documents, so those are exposed to the whole internet. Make the bucket private and serve files through signed URLs.`;
        } else if (name !== undefined && USER_CONTENT.test(name)) {
          severity = 'high';
          confidence = 'high';
          userExplanation = `Your "${name}" storage bucket is public — every file in it can be opened by anyone with the link, no login required. This bucket looks like it holds user files, so those uploads are effectively public. Make the bucket private and serve files through signed URLs or an access-checked route.`;
        } else if (name !== undefined && PUBLIC_BY_DESIGN.test(name)) {
          severity = 'medium';
          confidence = 'low';
          userExplanation = `Your "${name}" storage bucket is public and named like a deliberately-public one — which is sometimes fine. But apps built with code generators often write user uploads (avatars, documents, receipts) into a bucket named like this. If anything user-uploaded is stored here, it is downloadable by anyone with the link. Check what writes to this bucket; if it holds user files, make it private and use signed URLs.`;
        } else {
          severity = 'high';
          confidence = name !== undefined ? 'medium' : 'low';
          userExplanation = `Your "${label}" storage bucket is public — every file in it can be opened by anyone with the link, no login required. ${name !== undefined ? "We can't tell from the name what it holds" : "Its name is set at runtime so we can't tell what it holds"}; if it stores any user files they are exposed to the whole internet. Confirm what writes to it and make it private if so.`;
        }

        findings.push({
          ...makeFinding({
            ruleId: this.id,
            title: this.title,
            severity,
            confidence,
            filePath: entry.path,
            lineStart: decl.line,
            evidence: bucketEvidence(label, decl, verdict.notes),
            userExplanation: userExplanation + CONFIRM_INTENT,
            technicalExplanation:
              `A storage.buckets row for "${label}" is created with public = true (${entry.path}:${decl.line}). Public buckets serve objects at a public URL with no authentication and support listing. Set the bucket private and scope storage.objects with RLS. Severity/confidence here are tuned by the bucket name; the finding fires regardless of name.`,
            fixHint:
              `Set the bucket to private (public = false) and add storage.objects RLS policies scoping access to the owner (e.g. USING (auth.uid()::text = (storage.foldername(name))[1])). Serve files via createSignedUrl() instead of the public URL.`,
            category: this.category,
          }),
          adjudication: publicStoragePolicy(
            `A storage.buckets row for "${label}"`,
            `${entry.path}:${decl.line}`,
          ),
        });
      }

      {
        for (const m of findMatches(entry.content, new RegExp(FIREBASE_PUBLIC.source, 'g'))) {
          const key = `${entry.path}:fb:${m.line}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({
            ...makeFinding({
              ruleId: this.id,
              title: this.title,
              severity: 'critical',
              confidence: 'high',
              filePath: entry.path,
              lineStart: m.line,
              evidence: m.matchText.trim().slice(0, 120),
              userExplanation:
                `Your Firebase Storage rules let anyone read or write files with no login, depending on what the rule grants. With read access, anyone can download your files; with write access, anyone can upload, replace or delete them. Require a signed-in user and check ownership before allowing access.` +
                CONFIRM_INTENT_FIREBASE,
              technicalExplanation:
                `A Firebase Storage rule uses an unconditional if-true grant (${entry.path}:${m.line}). Require request.auth, verify object ownership, content type and size.`,
              fixHint:
                `Replace the if-true grant with a rule that requires request.auth != null and checks ownership/content-type/size, then redeploy the Storage rules.`,
              category: this.category,
            }),
            adjudication: publicStoragePolicy(
              'A Firebase Storage rule with an unconditional if-true grant',
              `${entry.path}:${m.line}`,
            ),
          });
        }
      }
    }
    return findings;
  },
};

import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { MockDependencyVulnerabilityScanner } from '../../src/dependency-audit/dependencyAudit.js';
import { detectSupabaseRls } from '../../src/project-map/detectRls.js';
import { validateScanReport } from '../../src/report/validateReport.js';
import { publicCloudStorage } from '../../src/rules/basic/publicCloudStorage.js';
import { MAX_REPLAYED_BUCKET_STATEMENTS } from '../../src/rules/basic/storageBucketReplay.js';
import { scanProject } from '../../src/scanProject.js';
import type { Finding, ScanReport } from '../../src/shared/types.js';
import { memoryContext } from './helpers.js';

const PKG: [string, string] = ['package.json', '{"name":"x","dependencies":{"@supabase/supabase-js":"2.0.0"}}'];
const migration = (name: string, sql: string): [string, string] => [`supabase/migrations/${name}.sql`, sql];
const insert = (id: string, isPublic: boolean): string =>
  `insert into storage.buckets (id, name, public) values ('${id}', '${id}', ${isPublic});\n`;

function run(files: [string, string][]): Finding[] {
  return publicCloudStorage.run(memoryContext([PKG, ...files]));
}
const at = (findings: readonly Finding[]): string[] => findings.map((finding) => `${finding.filePath}:${finding.lineStart}`);

describe('one fixture per shape', () => {
  it('001 makes bucket a public, 002 makes it private: no finding', () => {
    const findings = run([
      migration('001_create', insert('a', true)),
      migration('002_lock', "update storage.buckets set public = false where id = 'a';\n"),
    ]);
    expect(findings).toEqual([]);
  });

  it('the reverse (private first, then public): a finding citing 002, saying where the bucket was created', () => {
    const findings = run([
      migration('001_create', insert('a', false)),
      migration('002_open', "update storage.buckets set public = true where id = 'a';\n"),
    ]);
    expect(at(findings)).toEqual(['supabase/migrations/002_open.sql:1']);
    expect(findings[0]?.evidence).toBe(
      'storage bucket "a" set to public = true; the bucket was created in supabase/migrations/001_create.sql:1',
    );
  });

  it('insert … on conflict do update set public = false, after the bucket was created: no finding', () => {
    const findings = run([
      migration('001_create', insert('a', true)),
      migration(
        '002_upsert',
        "insert into storage.buckets (id, name, public) values ('a', 'a', true) on conflict (id) do update set public = false;\n",
      ),
    ]);
    expect(findings).toEqual([]);
  });

  it('the same with `= excluded.public` on a row inserted false: no finding', () => {
    const findings = run([
      migration('001_create', insert('a', true)),
      migration(
        '002_upsert',
        "insert into storage.buckets (id, name, public) values ('a', 'a', false)\n" +
          'on conflict (id) do update set public = excluded.public;\n',
      ),
    ]);
    expect(findings).toEqual([]);
  });

  it("delete from storage.buckets where id='a' after a public insert: no finding", () => {
    const findings = run([
      migration('001_create', insert('a', true)),
      migration('002_drop', "delete from storage.buckets where id='a';\n"),
    ]);
    expect(findings).toEqual([]);
  });

  it('an update with a non-literal where: the insert is reported as before, and the evidence says the update was not applied', () => {
    const findings = run([
      migration('001_create', insert('a', true)),
      migration('002_lock', 'update storage.buckets set public = false where public = true;\n'),
    ]);
    expect(at(findings)).toEqual(['supabase/migrations/001_create.sql:1']);
    expect(findings[0]?.evidence).toBe(
      'storage bucket "a" created with public = true; not applied: supabase/migrations/002_lock.sql:1 ' +
        'changes public access without naming the bucket literally',
    );
  });

  it('a variable in the where, and no where at all, are not applied either', () => {
    for (const lock of [
      'update storage.buckets set public = false where id = bucket_id;\n',
      'update storage.buckets set public = false;\n',
      "update storage.buckets set public = false where id = 'a' and owner = auth.uid();\n",
    ]) {
      const findings = run([migration('001_create', insert('a', true)), migration('002_lock', lock)]);
      expect(at(findings), lock).toEqual(['supabase/migrations/001_create.sql:1']);
      expect(findings[0]?.evidence, lock).toContain('not applied: supabase/migrations/002_lock.sql:1');
    }
  });

  it('a delete with a non-literal where is not applied, and says it deletes buckets without naming them', () => {
    const findings = run([
      migration('001_create', insert('a', true)),
      migration('002_drop', "delete from storage.buckets where name like 'tmp-%';\n"),
    ]);
    expect(at(findings)).toEqual(['supabase/migrations/001_create.sql:1']);
    expect(findings[0]?.evidence).toContain('deletes buckets without naming them literally');
  });

  it('the field repo’s shape: assignment-files made public then private is gone; avatars and concept-card-images stay, exactly as before', () => {
    const findings = run([
      migration(
        '20250910120000_storage',
        "INSERT INTO storage.buckets (id, name, public) VALUES ('assignment-files', 'assignment-files', true);\n" +
          "INSERT INTO storage.buckets (id, name, public) VALUES ('avatars', 'avatars', true);\n" +
          "INSERT INTO storage.buckets (id, name, public) VALUES ('concept-card-images', 'concept-card-images', true);\n",
      ),
      migration(
        '20251002093000_private_assignments',
        "UPDATE storage.buckets SET public = false WHERE id = 'assignment-files';\n",
      ),
    ]);
    expect(findings.map((finding) => finding.evidence)).toEqual([
      'storage bucket "avatars" created with public = true',
      'storage bucket "concept-card-images" created with public = true',
    ]);
    const avatars = findings[0] as Finding;
    expect([avatars.severity, avatars.confidence]).toEqual(['high', 'high']);
    expect(avatars.userExplanation).toMatch(/^Your "avatars" storage bucket is public/);
    expect(avatars.fixHint).toMatch(/^Set the bucket to private \(public = false\)/);
    expect(avatars.adjudication?.reason).toBe('storage_bucket_public_flag_observation');
  });

  it('a bucket made public twice is reported once, where it was last made public, saying where it was first', () => {
    const findings = run([
      migration('001_create', insert('a', true)),
      migration('002_again', "update storage.buckets set public = true where id = 'a';\n"),
    ]);
    expect(at(findings)).toEqual(['supabase/migrations/002_again.sql:1']);
    expect(findings[0]?.evidence).toBe(
      'storage bucket "a" set to public = true; originally made public in supabase/migrations/001_create.sql:1',
    );
  });

  it('`update … set public = false where public = true` is not itself reported as a public bucket', () => {
    expect(run([migration('001_lock', 'update storage.buckets set public = false where public = true;\n')])).toEqual([]);
  });

  it('several buckets made private by one `id in (…)`, as some real projects do', () => {
    const findings = run([
      migration(
        '20260605010000_images',
        "insert into storage.buckets (id, name, public, file_size_limit)\nvalues\n  ('client-photos', 'client-photos', true, 2097152),\n" +
          "  ('asset-images', 'asset-images', true, 10485760)\non conflict (id) do update set\n  public = excluded.public;\n",
      ),
      migration(
        '20260608130000_kyc',
        "insert into storage.buckets (id, name, public) values ('kyc-documents', 'kyc-documents', true)\n" +
          'on conflict (id) do update set public = excluded.public;\n',
      ),
      migration('20260731091000_lockdown', "update storage.buckets\n   set public = false\n where id in ('kyc-documents', 'contracts');\n"),
    ]);
    expect(findings.map((finding) => finding.evidence)).toEqual(['storage bucket "client-photos" created with public = true']);
  });

  it('within one SQL file outside the migrations folder, text order applies', () => {
    expect(run([['schema.sql', insert('a', true) + "update storage.buckets set public = false where id = 'a';\n"]])).toEqual([]);
  });
});

describe('GUARDS: the bucket may still be public, so the finding stays exactly as it was', () => {
  const BEFORE = 'storage bucket "a" created with public = true';

  const kept = (files: [string, string][]): void => {
    const findings = run(files);
    expect(at(findings)).toEqual(['supabase/migrations/001_create.sql:1']);
    expect(findings[0]?.evidence).toBe(BEFORE);
  };

  it('a private statement whose order is not known (an unordered seed file) does not apply', () => {
    kept([migration('001_create', insert('a', true)), ['supabase/seed.sql', "update storage.buckets set public = false where id = 'a';\n"]]);
  });

  it('two migrations sharing a version have no order', () => {
    kept([
      migration('001_create', insert('a', true)),
      migration('002_x', 'select 1;\n'),
      ['supabase/migrations/001_lock.sql', "update storage.buckets set public = false where id = 'a';\n"],
    ]);
  });

  it('a private statement inside a comment does not apply', () => {
    kept([migration('001_create', insert('a', true)), migration('002_lock', "-- update storage.buckets set public = false where id = 'a';\n")]);
  });

  it('one inside a function body does not apply: the function runs when it is called', () => {
    kept([
      migration('001_create', insert('a', true)),
      migration(
        '002_lock',
        "create function lock_a() returns void language sql as $$ update storage.buckets set public = false where id = 'a'; $$;\n",
      ),
    ]);
  });

  it('a plain insert of the same bucket with public = false does nothing to a bucket that exists', () => {
    kept([migration('001_create', insert('a', true)), migration('002_again', insert('a', false))]);
    kept([
      migration('001_create', insert('a', true)),
      migration('002_again', "insert into storage.buckets (id, name, public) values ('a', 'a', false) on conflict do nothing;\n"),
    ]);
  });

  it('a rollback twin is not applied, so its delete does not apply', () => {
    kept([
      migration('001_create', insert('a', true)),
      migration('002_feature', 'select 1;\n'),
      migration('002_feature_down', "delete from storage.buckets where id = 'a';\n"),
    ]);
  });

  it('made private, then public again by a statement the rule does not report: the earlier finding stays', () => {
    const longInsert =
      "insert into storage.buckets (id, name, public, allowed_mime_types) values ('a', 'a', true, array[" +
      Array.from({ length: 60 }, (_, index) => `'image/x-${index}'`).join(', ') +
      ']);\n';
    kept([
      migration('001_create', insert('a', true)),
      migration('002_lock', "update storage.buckets set public = false where id = 'a';\n"),
      migration('003_reopen', longInsert),
    ]);
  });

  it('an upsert setting public = false on conflict, with no insert known before it, may create the bucket public', () => {
    kept([
      migration('001_create', insert('a', true)),
      migration('002_drop', "delete from storage.buckets where id = 'a';\n"),
      migration(
        '003_upsert',
        "insert into storage.buckets (id, name, public) values ('a', 'a', true) on conflict (id) do update set public = false;\n",
      ),
    ]);
  });

  it('…and after only an update, nothing is known to have created the bucket, so it may create it public', () => {
    const findings = run([
      migration('001_open', "update storage.buckets set public = true where id = 'a';\n"),
      migration(
        '002_upsert',
        "insert into storage.buckets (id, name, public) values ('a', 'a', true) on conflict (id) do update set public = false;\n",
      ),
    ]);
    expect(at(findings)).toEqual(['supabase/migrations/001_open.sql:1']);
    expect(findings[0]?.evidence).toBe(BEFORE);
  });

  it('the rule’s update pattern running across a `;` is judged as before: the text it reports may be another statement’s', () => {
    const findings = run([
      migration(
        '001_two',
        "update storage.buckets set public = false where id = 'a'; update storage.buckets set public = true where id = 'b';\n",
      ),
    ]);
    expect(at(findings)).toEqual(['supabase/migrations/001_two.sql:1']);
    expect(findings[0]?.evidence).toBe(BEFORE);
  });

  it('an update making a bucket public, with nothing to add, reads exactly as before', () => {
    const findings = run([migration('001_open', "update storage.buckets set public = true where id = 'a';\n")]);
    expect(findings[0]?.evidence).toBe(BEFORE);
  });

  it('a statement that may make any bucket public (a non-literal name) keeps the order open', () => {
    const findings = run([
      migration('001_create', insert('a', true)),
      ['supabase/seed.sql', 'insert into storage.buckets (id, name, public) values (bucket_id, bucket_name, true);\n'],
      migration('002_lock', "update storage.buckets set public = false where id = 'a';\n"),
    ]);
    expect(at(findings).sort()).toEqual(['supabase/migrations/001_create.sql:1', 'supabase/seed.sql:1']);
    expect(findings.find((finding) => finding.filePath.endsWith('001_create.sql'))?.evidence).toBe(BEFORE);
  });

  it('a multi-row insert stays while one of its buckets is public, and says which one ended private', () => {
    const findings = run([
      migration('001_create', "insert into storage.buckets (id, name, public) values ('a', 'a', true), ('b', 'b', true);\n"),
      migration('002_lock', "update storage.buckets set public = false where id = 'a';\n"),
    ]);
    expect(at(findings)).toEqual(['supabase/migrations/001_create.sql:1']);
    expect(findings[0]?.evidence).toBe(
      'storage bucket "a" created with public = true; "a" was made private later, in supabase/migrations/002_lock.sql:1',
    );
  });

  it('createBucket() in app code and Firebase storage.rules are not replayed', () => {
    const findings = run([
      ['src/storage.ts', "await supabase.storage.createBucket('a', { public: true });\n"],
      migration('002_lock', "update storage.buckets set public = false where id = 'a';\n"),
      ['storage.rules', 'service firebase.storage { match /{p=**} { allow read, write: if true; } }'],
    ]);
    expect(findings.map((finding) => finding.filePath).sort()).toEqual(['src/storage.ts', 'storage.rules']);
  });

  it('past the replay bound, nothing is replayed', () => {
    const many = Array.from({ length: MAX_REPLAYED_BUCKET_STATEMENTS }, (_, index) => insert(`b${index}`, false)).join('');
    kept([
      migration('001_create', insert('a', true)),
      migration('002_lock', "update storage.buckets set public = false where id = 'a';\n"),
      migration('003_many', many),
    ]);
  });
});

describe('through the whole scan', () => {
  const temporaries: string[] = [];
  afterEach(async () => {
    await Promise.all(temporaries.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });
  async function scan(files: [string, string][]): Promise<ScanReport> {
    const root = await mkdtemp(path.join(tmpdir(), 'epherem-9t-bucket-'));
    temporaries.push(root);
    for (const [name, content] of files) {
      await mkdir(path.dirname(path.join(root, name)), { recursive: true });
      await writeFile(path.join(root, name), content);
    }
    return scanProject(root, { dependencyScanner: new MockDependencyVulnerabilityScanner() });
  }
  const row = (report: ScanReport) => report.ruleResults.find((result) => result.ruleId === 'public_cloud_storage');

  it('a bucket made private by a later migration: no finding, the check passes, the report validates', async () => {
    const report = await scan([
      PKG,
      migration('001_create', insert('a', true)),
      migration('002_lock', "update storage.buckets set public = false where id = 'a';\n"),
    ]);
    expect(report.findings.filter((finding) => finding.ruleId === 'public_cloud_storage')).toEqual([]);
    expect(row(report)?.status).toBe('passed');
    expect(validateScanReport(report).valid).toBe(true);
  });

  it('one still public: the check fails with its one finding, and the report validates', async () => {
    const report = await scan([
      PKG,
      migration('001_create', insert('a', true) + insert('avatars', true)),
      migration('002_lock', "update storage.buckets set public = false where id = 'a';\n"),
    ]);
    expect(report.findings.filter((finding) => finding.ruleId === 'public_cloud_storage').map((finding) => finding.evidence)).toEqual([
      'storage bucket "avatars" created with public = true',
    ]);
    expect(row(report)?.status).toBe('failed');
    expect(validateScanReport(report).valid).toBe(true);
  });
});

describe('§1 confirmed, not rebuilt: storage policies are already replayed in order', () => {
  it('"Anyone can manage files" created, dropped, then "Admins can manage files" created: only the admin policy is in the model', () => {
    const rls = detectSupabaseRls(
      memoryContext([
        PKG,
        migration(
          '001_storage_policies',
          "CREATE POLICY \"Anyone can manage files\" ON storage.objects FOR ALL USING (bucket_id = 'assignment-files');\n",
        ),
        migration('002_tighten', 'DROP POLICY "Anyone can manage files" ON storage.objects;\n'),
        migration(
          '003_admins',
          'CREATE POLICY "Admins can manage files" ON storage.objects FOR ALL\n' +
            "  USING (bucket_id = 'assignment-files' AND public.has_role(auth.uid(), 'admin'));\n",
        ),
      ]).fileMap,
    );
    const onObjects = rls.policies.filter((policy) => policy.table === 'objects');
    expect(onObjects.map((policy) => `${policy.filePath}:${policy.line}`)).toEqual([
      'supabase/migrations/003_admins.sql:1',
    ]);
    expect(onObjects[0]?.usingExpression).toContain("has_role(auth.uid(), 'admin')");
    expect(rls.uncertainTables).toEqual([]);
  });
});

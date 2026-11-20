import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { IGNORED_DIRECTORIES } from '../../src/shared/constants.js';
import {
  MAX_RECORDED_SCANNED_PATHS,
  archiveScannedFolders,
  createArchiveNameCollector,
  emptyArchiveNameScan,
  scanArchiveNames,
  type ArchiveNameObservation,
  type ArchiveNameScan,
} from '../../src/upload/archiveNameScan.js';
import {
  MAX_REPORTED_PATH_SAMPLE,
  MAX_REPORTED_SKIPPED_PATH_LENGTH,
  MAX_REPORTED_WATCHLIST_PATH_LENGTH,
  reportedPath,
  sanitizeReportedPath,
} from '../../src/upload/reportedPath.js';

function file(path: string, eligible = true): ArchiveNameObservation {
  return { path, isDirectory: false, eligible };
}

function directory(path: string): ArchiveNameObservation {
  return { path, isDirectory: true, eligible: false };
}

function github(paths: readonly ArchiveNameObservation[], root = 'repo-a1b2c3d'): ArchiveNameObservation[] {
  return [directory(root), ...paths.map((entry) => ({ ...entry, path: `${root}/${entry.path}` }))];
}

function samplePaths(scan: ArchiveNameScan, category: keyof ArchiveNameScan['unexpectedFiles']): string[] {
  return scan.unexpectedFiles[category].sample.map((entry) => entry.path);
}

describe('archive name scan — files that should not be there', () => {
  it('P1 records private keys and certificates, by extension and by exact name', () => {
    const scan = scanArchiveNames([
      file('certs/server.pem'),
      file('certs/server.key'),
      file('certs/bundle.p12'),
      file('certs/bundle.pfx'),
      file('android/release.jks'),
      file('android/.keystore'),
      file('.ssh/id_rsa'),
      file('.ssh/id_dsa'),
      file('.ssh/id_ecdsa'),
      file('.ssh/id_ed25519'),
    ]);
    expect(scan.unexpectedFiles.private_keys.count).toBe(10);
  });

  it('P1 does not fire on names that merely resemble a key', () => {
    const scan = scanArchiveNames([
      file('src/keyboard.ts'),
      file('src/monkey.js'),
      file('src/id_rsa_helper.ts'),
      file('docs/pem.md'),
      file('src/keys.ts'),
    ]);
    expect(scan.unexpectedFiles.private_keys.count).toBe(0);
  });

  it('P2 records cloud service-account credentials, including the .aws path form', () => {
    const scan = scanArchiveNames([
      file('serviceAccountKey.json'),
      file('config/service-account.json'),
      file('config/firebase-adminsdk-abc123.json'),
      file('config/prod-credentials.json'),
      file('.aws/credentials'),
    ]);
    expect(scan.unexpectedFiles.cloud_credentials.count).toBe(5);
  });

  it('P2 does not fire on ordinary config JSON, nor on credentials outside .aws', () => {
    const scan = scanArchiveNames([
      file('config/service.json'),
      file('config/accounts.json'),
      file('src/credentials.ts'),
      file('docs/credentials'),
      file('firebase-adminsdk.md'),
    ]);
    expect(scan.unexpectedFiles.cloud_credentials.count).toBe(0);
  });

  it('P3 records databases and dumps, and only names .sql files that say so', () => {
    const scan = scanArchiveNames([
      file('data/app.sqlite'),
      file('data/app.sqlite3'),
      file('data/app.db'),
      file('data/nightly.dump'),
      file('data/old.sqlite.bak'),
      file('data/pg_dump.sql'),
      file('data/backup-2026.sql'),
      file('data/export-users.sql'),
    ]);
    expect(scan.unexpectedFiles.database_dumps.count).toBe(8);
  });

  it('P3 leaves ordinary migrations and schema files alone', () => {
    const scan = scanArchiveNames([
      file('migrations/001_create_users.sql'),
      file('db/schema.sql'),
      file('src/db.ts'),
      file('docs/database.md'),
    ]);
    expect(scan.unexpectedFiles.database_dumps.count).toBe(0);
  });

  it('P4 records Terraform state and its backup', () => {
    const scan = scanArchiveNames([
      file('infra/terraform.tfstate'),
      file('infra/terraform.tfstate.backup'),
    ]);
    expect(scan.unexpectedFiles.infrastructure_state.count).toBe(2);
  });

  it('P4 does not fire on Terraform source', () => {
    const scan = scanArchiveNames([file('infra/main.tf'), file('infra/variables.tf')]);
    expect(scan.unexpectedFiles.infrastructure_state.count).toBe(0);
  });

  it('matches case-insensitively, because Windows and macOS produce these names', () => {
    const scan = scanArchiveNames([
      file('.ssh/ID_RSA'),
      file('CERTS/Server.PEM'),
      file('Infra/Terraform.TFState'),
      file('Config/ServiceAccountKey.JSON'),
      file('Data/App.SQLite'),
    ]);
    expect(scan.unexpectedFiles.private_keys.count).toBe(2);
    expect(scan.unexpectedFiles.infrastructure_state.count).toBe(1);
    expect(scan.unexpectedFiles.cloud_credentials.count).toBe(1);
    expect(scan.unexpectedFiles.database_dumps.count).toBe(1);
  });

  it('never records a match inside an ignored directory: it belongs to a dependency', () => {
    const inside = [...IGNORED_DIRECTORIES].map((ignored) => file(`${ignored}/pkg/server.pem`));
    const scan = scanArchiveNames([...inside, file('certs/mine.pem')]);
    expect(scan.unexpectedFiles.private_keys.count).toBe(1);
    expect(samplePaths(scan, 'private_keys')).toEqual(['certs/mine.pem']);
  });

  it('records a directory named like a key as a directory, not as a key', () => {
    const scan = scanArchiveNames([directory('secrets.key'), file('src/index.ts')]);
    expect(scan.unexpectedFiles.private_keys.count).toBe(0);
  });

  it('the COUNT is exact and only the SAMPLE is capped: 200 keys report 200 and name 50', () => {
    const keys = Array.from({ length: 200 }, (_unused, index) => file(`certs/key-${String(index)}.pem`));
    const scan = scanArchiveNames(keys);
    expect(scan.unexpectedFiles.private_keys.count).toBe(200);
    expect(scan.unexpectedFiles.private_keys.sample).toHaveLength(MAX_REPORTED_PATH_SAMPLE);
    expect(scan.unexpectedFiles.private_keys.count).not.toBe(MAX_REPORTED_PATH_SAMPLE);
  });

  it('every category is present even when empty, so absence is stated rather than missing', () => {
    const scan = emptyArchiveNameScan();
    expect(Object.keys(scan.unexpectedFiles).sort()).toEqual([
      'cloud_credentials',
      'database_dumps',
      'infrastructure_state',
      'private_keys',
    ]);
    for (const group of Object.values(scan.unexpectedFiles)) {
      expect(group.count).toBe(0);
      expect(group.sample).toEqual([]);
    }
  });
});

describe('archive name scan — files that should be there', () => {
  it('M1 finds a .gitignore at the project root and not one buried below it', () => {
    expect(scanArchiveNames([file('.gitignore'), file('src/a.ts')]).expectedFiles.gitignore).toBe('present');
    expect(
      scanArchiveNames([file('package.json'), file('src/.gitignore')]).expectedFiles.gitignore,
    ).toBe('absent');
  });

  it('M2 is not_applicable without a Dockerfile, and judged with one', () => {
    expect(scanArchiveNames([file('src/a.ts')]).expectedFiles.dockerignore).toBe('not_applicable');
    expect(scanArchiveNames([file('Dockerfile'), file('src/a.ts')]).expectedFiles.dockerignore).toBe('absent');
    expect(
      scanArchiveNames([file('Dockerfile'), file('.dockerignore')]).expectedFiles.dockerignore,
    ).toBe('present');
    expect(
      scanArchiveNames([file('docker/Dockerfile.prod'), file('src/a.ts')]).expectedFiles.dockerignore,
    ).toBe('absent');
  });

  it('M3 is not_applicable with no dependency manifest, and judged with one', () => {
    expect(scanArchiveNames([file('index.html')]).expectedFiles.lockfile).toBe('not_applicable');
    expect(scanArchiveNames([file('package.json')]).expectedFiles.lockfile).toBe('absent');
    for (const lock of [
      'package-lock.json',
      'yarn.lock',
      'pnpm-lock.yaml',
      'bun.lockb',
      'poetry.lock',
      'Pipfile.lock',
    ]) {
      expect(scanArchiveNames([file('package.json'), file(lock)]).expectedFiles.lockfile).toBe('present');
    }
  });

  it('M4 finds an env template under any of its three names', () => {
    expect(scanArchiveNames([file('src/a.ts')]).expectedFiles.env_template).toBe('absent');
    for (const name of ['.env.example', '.env.sample', '.env.template']) {
      expect(scanArchiveNames([file(name)]).expectedFiles.env_template).toBe('present');
    }
  });

  it('M5 finds automated dependency updates at their exact configured paths', () => {
    expect(scanArchiveNames([file('src/a.ts')]).expectedFiles.dependency_updates).toBe('absent');
    for (const name of ['.github/dependabot.yml', '.github/renovate.json', 'renovate.json']) {
      expect(
        scanArchiveNames([file('package.json'), file(name)]).expectedFiles.dependency_updates,
      ).toBe('present');
    }
    expect(
      scanArchiveNames([file('package.json'), file('config/dependabot.yml')]).expectedFiles
        .dependency_updates,
    ).toBe('absent');
    expect(
      scanArchiveNames(github([file('package.json'), file('config/dependabot.yml')])).expectedFiles
        .dependency_updates,
    ).toBe('absent');
    expect(
      scanArchiveNames(github([file('package.json'), file('.github/dependabot.yml')])).expectedFiles
        .dependency_updates,
    ).toBe('present');
  });

  it('every check is present in the record even when nothing was observed', () => {
    expect(emptyArchiveNameScan().expectedFiles).toEqual({
      gitignore: 'absent',
      dockerignore: 'not_applicable',
      lockfile: 'not_applicable',
      env_template: 'absent',
      dependency_updates: 'absent',
    });
  });
});

describe('archive name scan — the root prefix', () => {
  it('records a single top-level directory and strips it from every retained path', () => {
    const scan = scanArchiveNames(
      github([file('src/index.ts'), file('certs/server.pem', false), directory('src')]),
    );
    expect(scan.rootPrefix).toBe('repo-a1b2c3d');
    expect(scan.scannedPaths.map((entry) => entry.path)).toEqual(['src/index.ts']);
    expect(samplePaths(scan, 'private_keys')).toEqual(['certs/server.pem']);
    expect(scan.directoryPaths.map((entry) => entry.path)).toEqual(['', 'src']);
  });

  it('M1 and M2 test the PROJECT root, one level inside a GitHub archive', () => {
    const scan = scanArchiveNames(
      github([file('.gitignore'), file('Dockerfile'), file('.dockerignore'), file('src/a.ts')]),
    );
    expect(scan.rootPrefix).toBe('repo-a1b2c3d');
    expect(scan.expectedFiles.gitignore).toBe('present');
    expect(scan.expectedFiles.dockerignore).toBe('present');
  });

  it('M5 is anchored to the project root too, not to the archive root', () => {
    const scan = scanArchiveNames(github([file('.github/dependabot.yml'), file('src/a.ts')]));
    expect(scan.expectedFiles.dependency_updates).toBe('present');
  });

  it('records the ABSENCE of a common root rather than inventing one', () => {
    const scan = scanArchiveNames([
      directory('service-a'),
      file('service-a/src/index.ts'),
      directory('service-b'),
      file('service-b/src/index.ts'),
    ]);
    expect(scan.rootPrefix).toBeUndefined();
    expect(scan.scannedPaths.map((entry) => entry.path)).toEqual([
      'service-a/src/index.ts',
      'service-b/src/index.ts',
    ]);
  });

  it('a file at the archive root means there is no wrapper directory', () => {
    const scan = scanArchiveNames([directory('repo-a1b2'), file('repo-a1b2/src/a.ts'), file('README.md')]);
    expect(scan.rootPrefix).toBeUndefined();
  });

  it('strips a wrapper directory whose name has a capital letter in it', () => {
    const scan = scanArchiveNames(
      github(
        [file('pnpm-lock.yaml'), file('next.config.mjs'), directory('app'), file('app/page.tsx')],
        'Shopfront-main',
      ),
    );
    expect(scan.rootPrefix).toBe('Shopfront-main');
    expect(scan.scannedPaths.map((entry) => entry.path)).toEqual([
      'pnpm-lock.yaml',
      'next.config.mjs',
      'app/page.tsx',
    ]);
    expect(scan.directoryPaths.map((entry) => entry.path)).toEqual(['', 'app']);
  });

  it('strips it whatever the case, and records the name the archive gave', () => {
    for (const root of ['Shopfront-main', 'SHOPFRONT-MAIN', 'MyApp_Repo-Main', 'lower-case-main']) {
      const scan = scanArchiveNames(github([file('src/index.ts')], root));
      expect(scan.rootPrefix, `wrapper ${root}`).toBe(root);
      expect(scan.scannedPaths.map((entry) => entry.path)).toEqual(['src/index.ts']);
    }
  });

  it('the M-checks still find the PROJECT root under a mixed-case wrapper', () => {
    const scan = scanArchiveNames(
      github([file('.gitignore'), file('Dockerfile'), file('.dockerignore')], 'Shopfront-main'),
    );
    expect(scan.expectedFiles.gitignore).toBe('present');
    expect(scan.expectedFiles.dockerignore).toBe('present');
  });

  it('two roots differing only in case are two roots, and neither is stripped', () => {
    const scan = scanArchiveNames([
      directory('Service'),
      file('Service/src/index.ts'),
      directory('service'),
      file('service/src/index.ts'),
    ]);
    expect(scan.rootPrefix).toBeUndefined();
    expect(scan.scannedPaths.map((entry) => entry.path)).toEqual([
      'Service/src/index.ts',
      'service/src/index.ts',
    ]);
  });

  it('the watch list is still folded, under a mixed-case wrapper', () => {
    const scan = scanArchiveNames(github([file('keys/ID_RSA', false), file('certs/SERVER.PEM', false)], 'MyApp-Main'));
    expect(scan.rootPrefix).toBe('MyApp-Main');
    expect(samplePaths(scan, 'private_keys')).toEqual(['keys/ID_RSA', 'certs/SERVER.PEM']);
  });

  it('falls back to the archive root for M-checks when there is no single root', () => {
    const scan = scanArchiveNames([file('.gitignore'), file('a/x.ts'), file('b/y.ts')]);
    expect(scan.rootPrefix).toBeUndefined();
    expect(scan.expectedFiles.gitignore).toBe('present');
  });
});

describe('archive name scan — the shape', () => {
  it('records only the files the walk accepted for scanning', () => {
    const scan = scanArchiveNames([
      file('src/index.ts'),
      file('assets/logo.png', false),
      file('node_modules/left-pad/index.js', false),
    ]);
    expect(scan.scannedPaths.map((entry) => entry.path)).toEqual(['src/index.ts']);
  });

  it('derives the folder list rather than storing a second copy of it', () => {
    const scan = scanArchiveNames(github([file('src/api/routes/users.ts'), file('src/index.ts')]));
    expect(archiveScannedFolders(scan)).toEqual(['src', 'src/api', 'src/api/routes']);
    expect(Object.keys(scan)).not.toContain('scannedFolders');
  });

  it('distinguishes a scanned-but-empty folder from a folder that was never scanned', () => {
    const scan = scanArchiveNames([
      directory('src'),
      file('src/index.ts'),
      directory('public'),
      file('public/logo.png', false),
      directory('node_modules'),
      file('node_modules/left-pad/index.js', false),
    ]);
    const folders = archiveScannedFolders(scan);
    expect(folders).toContain('public');
    expect(folders).not.toContain('node_modules');
    expect(scan.scannedPaths.some((entry) => entry.path.startsWith('public/'))).toBe(false);
    expect(scan.directoryPaths.map((entry) => entry.path)).toEqual(['src', 'public']);
  });

  it('says so when a cap stopped the record short, so a diff cannot read it as complete', () => {
    const many = Array.from({ length: 12 }, (_unused, index) => file(`src/m${String(index)}.ts`));
    const complete = scanArchiveNames(many);
    expect(complete.truncationReasons).toEqual([]);

    const cut = scanArchiveNames(many, { maxScannedPaths: 5 });
    expect(cut.scannedPaths).toHaveLength(5);
    expect(cut.truncationReasons).toEqual(['scanned_path_cap']);

    const cutDirectories = scanArchiveNames(
      Array.from({ length: 12 }, (_unused, index) => directory(`d${String(index)}`)),
      { maxDirectoryPaths: 5 },
    );
    expect(cutDirectories.truncationReasons).toEqual(['directory_path_cap']);
  });

  it('the default scanned-path cap sits at the eligible-file cap', () => {
    expect(MAX_RECORDED_SCANNED_PATHS).toBe(5_000);
  });
});

describe('archive name scan — line endings and hostile names', () => {
  it('carries no multi-line regex anchor anywhere in the matcher', () => {
    const source = readFileSync(new URL('../../src/upload/archiveNameScan.ts', import.meta.url), 'utf8');
    const patterns = source.match(/\/(?![/*])(?:\\.|\[[^\]]*\]|[^\\/\n])+\/[a-z]*/g) ?? [];
    for (const pattern of patterns) {
      const flags = pattern.slice(pattern.lastIndexOf('/') + 1);
      expect(flags).not.toContain('m');
    }
    expect(source).not.toContain('\\r\\n');
  });

  it('normalises a name before matching it, so a control byte cannot hide a key', () => {
    const scan = scanArchiveNames([
      file('package.json'),
      { path: 'certs/server.pem\r', isDirectory: false, eligible: false },
    ]);
    expect(scan.unexpectedFiles.private_keys.count).toBe(1);
    expect(samplePaths(scan, 'private_keys')).toEqual(['certs/server.pem']);
  });

  it('strips markup and bidi overrides from a retained name', () => {
    const scan = scanArchiveNames([
      file('package.json'),
      { path: 'certs/<script>\u202Eevil.pem', isDirectory: false, eligible: false },
    ]);
    expect(samplePaths(scan, 'private_keys')).toEqual(['certs/scriptevil.pem']);
  });

  it('matches a key whose path is longer than the display cap, and flags the shortening', () => {
    const deep = `certs/${'d'.repeat(MAX_REPORTED_WATCHLIST_PATH_LENGTH)}/server.pem`;
    const scan = scanArchiveNames([
      file('package.json'),
      { path: deep, isDirectory: false, eligible: false },
    ]);
    expect(scan.unexpectedFiles.private_keys.count).toBe(1);
    expect(scan.unexpectedFiles.private_keys.sample[0]?.truncated).toBe(true);
    expect(scan.unexpectedFiles.private_keys.sample[0]?.path).toHaveLength(
      MAX_REPORTED_WATCHLIST_PATH_LENGTH,
    );
  });
});

function isWellFormedUtf16(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

const DINOSAUR = '\u{1F995}';
const SATELLITE = '\u{1F6F0}';

describe('reported paths', () => {
  it('keeps the 200-character skipped-path form byte-identical for BMP paths', () => {
    expect(MAX_REPORTED_SKIPPED_PATH_LENGTH).toBe(200);
    const long = `${'a'.repeat(400)}.txt`;
    expect(sanitizeReportedPath(long)).toBe('a'.repeat(200));
    expect(sanitizeReportedPath('ok<>\u0007.txt')).toBe('ok.txt');
  });

  it('cuts on a character boundary at the 200-unit cap', () => {
    const name = `${'a'.repeat(199)}${DINOSAUR} Kiddy (KidSafe)/server.pem`;
    const cut = reportedPath(name, MAX_REPORTED_SKIPPED_PATH_LENGTH);
    expect(cut.truncated).toBe(true);
    expect(isWellFormedUtf16(cut.path)).toBe(true);
    expect(cut.path.length).toBeLessThanOrEqual(MAX_REPORTED_SKIPPED_PATH_LENGTH);
    expect(cut.path).toBe('a'.repeat(199));
    expect(sanitizeReportedPath(name)).toBe(cut.path);
  });

  it('cuts on a character boundary at the 1,024-unit cap', () => {
    const name = `${'b'.repeat(1_023)}${SATELLITE} IBN5100/id_rsa`;
    const cut = reportedPath(name, MAX_REPORTED_WATCHLIST_PATH_LENGTH);
    expect(cut.truncated).toBe(true);
    expect(isWellFormedUtf16(cut.path)).toBe(true);
    expect(cut.path.length).toBeLessThanOrEqual(MAX_REPORTED_WATCHLIST_PATH_LENGTH);
    expect(cut.path).toBe('b'.repeat(1_023));
  });

  it('keeps an astral character that fits entirely inside the cap', () => {
    const name = `${'c'.repeat(198)}${DINOSAUR}${'d'.repeat(50)}`;
    const cut = reportedPath(name, MAX_REPORTED_SKIPPED_PATH_LENGTH);
    expect(cut.path.length).toBe(MAX_REPORTED_SKIPPED_PATH_LENGTH);
    expect(isWellFormedUtf16(cut.path)).toBe(true);
    expect(cut.path.endsWith(DINOSAUR)).toBe(true);
  });

  it('carries the boundary-safe cut into a watch-list sample', () => {
    const name = `certs/${'e'.repeat(1_017)}${DINOSAUR}/Kiddy.pem`;
    const scan = scanArchiveNames([
      file('package.json'),
      { path: name, isDirectory: false, eligible: false },
    ]);
    const sample = scan.unexpectedFiles.private_keys.sample[0];
    expect(scan.unexpectedFiles.private_keys.count).toBe(1);
    expect(sample?.truncated).toBe(true);
    expect(isWellFormedUtf16(sample?.path ?? '')).toBe(true);
    expect((sample?.path ?? '').length).toBeLessThanOrEqual(MAX_REPORTED_WATCHLIST_PATH_LENGTH);
  });

  it('marks a shortened path as shortened rather than offering it as openable', () => {
    const within = reportedPath('src/index.ts', MAX_REPORTED_WATCHLIST_PATH_LENGTH);
    expect(within).toEqual({ path: 'src/index.ts', truncated: false });

    const beyond = reportedPath('x'.repeat(MAX_REPORTED_WATCHLIST_PATH_LENGTH + 5), MAX_REPORTED_WATCHLIST_PATH_LENGTH);
    expect(beyond.path).toHaveLength(MAX_REPORTED_WATCHLIST_PATH_LENGTH);
    expect(beyond.truncated).toBe(true);
  });

  it('spends the display budget on the path, not on the wrapper directory', () => {
    const scan = scanArchiveNames(
      github([file('src/index.ts'), file('certs/server.pem', false)], 'repo-0123456789abcdef'),
    );
    expect(samplePaths(scan, 'private_keys')).toEqual(['certs/server.pem']);
  });
});

describe('archive name scan — the collector and the list form agree', () => {
  it('produces the same record whichever way it is fed', () => {
    const entries = github([
      file('src/index.ts'),
      file('.gitignore'),
      file('certs/server.pem', false),
      directory('src'),
    ]);
    const collector = createArchiveNameCollector();
    for (const entry of entries) collector.observe(entry);
    expect(collector.result()).toEqual(scanArchiveNames(entries));
  });

  it('holds no filesystem access: the module imports nothing from node:fs', () => {
    const source = readFileSync(new URL('../../src/upload/archiveNameScan.ts', import.meta.url), 'utf8');
    expect(source).not.toContain("from 'node:fs'");
    expect(source).not.toContain("from 'node:fs/promises'");
    expect(source).not.toContain("from 'node:path'");
  });
});

import type { DependencyEcosystem, FileMap } from '../shared/types.js';
import { basename } from '../shared/utils.js';
import { parsePep440 } from '../dependency-audit/pep440.js';
import { INGESTED_LOCKFILE_NAMES, MAX_AUDITED_DEPENDENCIES } from '../shared/constants.js';
import { pythonRequirementsRole, type PythonRequirementsRole } from '../shared/pythonRequirementFiles.js';

const MAX_LEGACY_NPM_DEPENDENCY_NODES = 50_000;
const MAX_LEGACY_NPM_DEPENDENCY_DEPTH = 64;

interface RawDependency {
  name: string;
  version?: string;
  source: string;
  line?: number;
}

export function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

export function isExactVersion(value: string): boolean {
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(value.trim());
}

export function isExactPythonVersion(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed === '' || trimmed.includes('*')) return false;
  if (/[<>~^=]/.test(trimmed)) return false;
  return parsePep440(trimmed) !== undefined;
}

export interface CollectedDependencies {
  dependencies: CollectedDependency[];
  diagnostics: string[];
}

export interface CollectedDependency {
  ecosystem: DependencyEcosystem;
  name: string;
  installedVersion?: string;
  declaredRange?: string;
  declaredIn?: string;
  lockfile?: string;
  source: string;
}

export function collectDependencies(fileMap: FileMap): CollectedDependency[] {
  return collectDependenciesWithDiagnostics(fileMap).dependencies;
}

interface Installed {
  ecosystem: DependencyEcosystem;
  name: string;
  version: string;
  lockfile: string;
}

interface Declared {
  ecosystem: DependencyEcosystem;
  name: string;
  range?: string;
  declaredIn: string;
}

export const UNSUPPORTED_DEPENDENCY_FILES: Record<string, string> = {
  'cargo.toml': 'Rust/Cargo',
  'cargo.lock': 'Rust/Cargo',
  'gemfile': 'Ruby/Bundler',
  'gemfile.lock': 'Ruby/Bundler',
  'go.mod': 'Go modules',
  'go.sum': 'Go modules',
  'composer.json': 'PHP/Composer',
  'composer.lock': 'PHP/Composer',
  'podfile.lock': 'CocoaPods',
  'pubspec.lock': 'Dart/Flutter',
  'pubspec.yaml': 'Dart/Flutter',
  'packages.config': 'NuGet/.NET',
  'gradle.lockfile': 'Gradle/JVM',
  'mix.lock': 'Elixir/Hex',
};

export const UNPARSED_DEPENDENCY_FILES: Record<string, string> = {
  'pipfile': 'PyPI',
  'pipfile.lock': 'PyPI',
  'npm-shrinkwrap.json': 'npm',
  'bun.lockb': 'npm',
  'uv.lock': 'PyPI',
};

const READABLE_FORMATS: Record<string, string> = {
  npm: 'package.json, package-lock.json, yarn.lock (v1 and Berry), pnpm-lock.yaml, bun.lock',
  PyPI: 'requirements.txt, pyproject.toml, poetry.lock',
};

const DEPENDENCY_LIST_NAMES: ReadonlySet<string> = new Set([
  'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'requirements.txt', 'pyproject.toml', 'poetry.lock',
]);

export function isDependencyListPath(path: string): boolean {
  return DEPENDENCY_LIST_NAMES.has(basename(path).toLowerCase()) || pythonRequirementsRole(path) === 'requirements';
}

export function collectDependenciesWithDiagnostics(
  fileMap: FileMap,
  maxDependencies: number = MAX_AUDITED_DEPENDENCIES,
): CollectedDependencies {
  const diagnostics: string[] = [];
  const declared: Declared[] = [];
  const installed: Installed[] = [];
  const unsupportedEcosystems = new Set<string>();
  const unparsedFormats = new Map<string, string>();
  const lockfileDeclared: Declared[] = [];
  const requirementFiles = new Map<string, RequirementFile>();

  for (const path of [
    ...fileMap.entries.map((entry) => entry.path),
    ...fileMap.skipped.map((skip) => skip.path),
  ]) {
    const name = basename(path).toLowerCase();
    const unsupported = UNSUPPORTED_DEPENDENCY_FILES[name];
    if (unsupported !== undefined) unsupportedEcosystems.add(unsupported);
    const unparsed = UNPARSED_DEPENDENCY_FILES[name];
    if (unparsed !== undefined) unparsedFormats.set(name, unparsed);
  }

  for (const entry of fileMap.entries) {
    const name = basename(entry.path).toLowerCase();
    if (!DEPENDENCY_LIST_NAMES.has(name)) continue;
    if (name === 'package.json') {
      for (const raw of parsePackageManifest(entry.content, entry.path, diagnostics)) {
        declared.push({
          ecosystem: 'npm',
          name: raw.name,
          ...(raw.version !== undefined ? { range: raw.version } : {}),
          declaredIn: entry.path,
        });
      }
    } else if (name === 'package-lock.json') {
      pushNpmInstalled(installed, parseNpmLockfile(entry.content, entry.path, diagnostics));
    } else if (name === 'yarn.lock') {
      pushNpmInstalled(installed, parseYarnLockfile(entry.content, entry.path, diagnostics));
    } else if (name === 'pnpm-lock.yaml') {
      pushNpmInstalled(installed, parsePnpmLockfile(entry.content, entry.path, diagnostics));
    } else if (name === 'bun.lock') {
      const bun = parseBunLockfile(entry.content, entry.path, diagnostics);
      pushNpmInstalled(installed, bun.installed);
      for (const raw of bun.declared) {
        lockfileDeclared.push({
          ecosystem: 'npm',
          name: raw.name,
          ...(raw.version !== undefined ? { range: raw.version } : {}),
          declaredIn: entry.path,
        });
      }
    } else if (name === 'requirements.txt') {
      const includes: RequirementInclude[] = [];
      const raws = parseRequirementsTxt(entry.content, entry.path, diagnostics, includes);
      for (const raw of raws) {
        classifyPython(raw, entry.path, declared, installed);
      }
      requirementFiles.set(entry.path, { role: 'requirements', raws, includes });
    } else if (name === 'pyproject.toml') {
      for (const raw of parsePyprojectToml(entry.content, entry.path, diagnostics)) {
        classifyPython(raw, entry.path, declared, installed);
      }
    } else if (name === 'poetry.lock') {
      for (const raw of parsePoetryLock(entry.content, entry.path, diagnostics)) {
        if (raw.version !== undefined && isExactPythonVersion(raw.version)) {
          installed.push({ ecosystem: 'PyPI', name: raw.name, version: raw.version, lockfile: entry.path });
        }
      }
    }
  }

  readPythonRequirementFiles(fileMap, requirementFiles, declared, installed, diagnostics);

  declared.push(...lockfileDeclared);

  const isNpmLockfile = (path: string): boolean => NPM_LOCKFILE_NAMES.has(basename(path).toLowerCase());
  const npmLockfileSeen =
    fileMap.entries.some((entry) => isNpmLockfile(entry.path)) || fileMap.skipped.some((skip) => isNpmLockfile(skip.path));
  if (!npmLockfileSeen && fileMap.skippedCount <= fileMap.skipped.length) {
    auditUnlockedNpmPins(declared, installed, diagnostics);
  }

  for (const skip of fileMap.skipped) {
    const name = basename(skip.path).toLowerCase();
    if (!INGESTED_LOCKFILE_NAMES.has(name)) continue;
    diagnostics.push(
      `Lockfile not read (${skip.path}): the input walk skipped it (${skip.reason ?? 'unknown reason'}), so the ` +
        'exact installed versions it records were not checked for known vulnerabilities.',
    );
  }

  for (const ecosystem of [...unsupportedEcosystems].sort((a, b) => a.localeCompare(b))) {
    diagnostics.push(
      `Unsupported dependency ecosystem detected (${ecosystem}). This scanner audits only npm and PyPI ` +
        'dependencies, so those packages were not checked for known vulnerabilities. Their safety is unverified.',
    );
  }

  for (const [fileName, ecosystem] of [...unparsedFormats].sort((a, b) => a[0].localeCompare(b[0]))) {
    const readable = READABLE_FORMATS[ecosystem];
    diagnostics.push(
      `Dependency file format not read (${fileName}). Its ecosystem (${ecosystem}) IS audited, but this ` +
        'file format is not parsed, so any dependencies declared only there were not checked for known ' +
        `vulnerabilities.${readable === undefined ? '' : ` Formats read for ${ecosystem}: ${readable}.`}`,
    );
  }

  if (fileMap.skippedCount > fileMap.skipped.length) {
    diagnostics.push(
      `Dependency-file detection was incomplete: the input walk skipped ${fileMap.skippedCount} file(s) but ` +
        `lists only ${fileMap.skipped.length} of them individually, so a dependency manifest may have been ` +
        'skipped without being seen. This is a limit of this check, not a statement about any ecosystem.',
    );
  }

  const assembled = assemble(declared, installed);
  if (assembled.length > maxDependencies) {
    diagnostics.push(
      `Collected-dependency cap reached: ${assembled.length} dependencies exceed the maximum of ` +
        `${maxDependencies}; ${assembled.length - maxDependencies} were dropped and not audited.`,
    );
    return { dependencies: assembled.slice(0, maxDependencies), diagnostics };
  }
  return { dependencies: assembled, diagnostics };
}

function pushNpmInstalled(installed: Installed[], raws: RawDependency[]): void {
  for (const raw of raws) {
    if (raw.version === undefined || !isExactVersion(raw.version)) continue;
    installed.push({ ecosystem: 'npm', name: raw.name, version: raw.version, lockfile: raw.source });
  }
}

const NPM_LOCKFILE_NAMES: ReadonlySet<string> = new Set([
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lock',
  'bun.lockb',
]);

function auditUnlockedNpmPins(declared: Declared[], installed: Installed[], diagnostics: string[]): void {
  const pinsByManifest = new Map<string, number>();
  const seen = new Set<string>();
  for (const decl of declared) {
    if (decl.ecosystem !== 'npm' || decl.range === undefined) continue;
    if (basename(decl.declaredIn).toLowerCase() !== 'package.json') continue;
    if (!isExactVersion(decl.range)) continue;
    const version = decl.range.trim();
    const key = `${decl.name} ${version} ${decl.declaredIn}`;
    if (seen.has(key)) continue;
    seen.add(key);
    installed.push({ ecosystem: 'npm', name: decl.name, version, lockfile: decl.declaredIn });
    pinsByManifest.set(decl.declaredIn, (pinsByManifest.get(decl.declaredIn) ?? 0) + 1);
  }
  for (const [manifest, count] of [...pinsByManifest].sort((a, b) => a[0].localeCompare(b[0]))) {
    diagnostics.push(
      `No lockfile was found in this project, so ${count} exact version pin(s) in ${manifest} were taken as ` +
        'the installed version for the audit, but the packages they pull in (transitive dependencies) are recorded ' +
        'only in a lockfile, so those were not checked for known vulnerabilities.',
    );
  }
}

function classifyPython(raw: RawDependency, source: string, declared: Declared[], installed: Installed[]): void {
  if (raw.version !== undefined && isExactPythonVersion(raw.version)) {
    installed.push({ ecosystem: 'PyPI', name: raw.name, version: raw.version, lockfile: source });
    declared.push({ ecosystem: 'PyPI', name: raw.name, declaredIn: source });
  } else {
    declared.push({
      ecosystem: 'PyPI',
      name: raw.name,
      ...(raw.version !== undefined ? { range: raw.version } : {}),
      declaredIn: source,
    });
  }
}

interface RequirementFile {
  role: PythonRequirementsRole;
  raws: RawDependency[];
  includes: RequirementInclude[];
}

interface IncludeEdge {
  from: string;
  include: RequirementInclude;
  to: string;
}

type ResolvedInclude = { kind: 'path'; path: string } | { kind: 'url' } | { kind: 'outside' };

function resolveRequirementInclude(from: string, target: string): ResolvedInclude {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(target) || /^file:/i.test(target)) return { kind: 'url' };
  if (/^[\\/~]/.test(target) || /^[a-z]:/i.test(target)) return { kind: 'outside' };
  const parts = from.split('/').slice(0, -1);
  for (const part of target.replace(/\\/g, '/').split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (parts.length === 0) return { kind: 'outside' };
      parts.pop();
      continue;
    }
    parts.push(part);
  }
  return { kind: 'path', path: parts.join('/') };
}

function readPythonRequirementFiles(
  fileMap: FileMap,
  files: Map<string, RequirementFile>,
  declared: Declared[],
  installed: Installed[],
  diagnostics: string[],
): void {
  const content = new Map(fileMap.entries.map((entry) => [entry.path, entry.content]));
  const read = (path: string, role: PythonRequirementsRole): void => {
    const includes: RequirementInclude[] = [];
    const raws = parseRequirementsTxt(content.get(path) ?? '', path, diagnostics, includes);
    if (role === 'requirements') {
      for (const raw of raws) classifyPython(raw, path, declared, installed);
    }
    files.set(path, { role, raws, includes });
  };

  const order: string[] = [...files.keys()];
  for (const entry of fileMap.entries) {
    const role = pythonRequirementsRole(entry.path);
    if (role === undefined || files.has(entry.path)) continue;
    read(entry.path, role);
    order.push(entry.path);
  }

  const skipped = new Map(fileMap.skipped.map((skip) => [skip.path, skip.reason ?? 'unknown reason']));
  const edges = new Map<string, IncludeEdge[]>();
  for (let index = 0; index < order.length; index += 1) {
    const from = order[index] as string;
    for (const include of (files.get(from) as RequirementFile).includes) {
      const where = `${from} line ${include.line}: ${include.flag} ${include.target.slice(0, 80)}`;
      const notRead = (why: string): void => {
        diagnostics.push(
          `Requirements include not read (${where}): ${why}, so any dependencies declared only there were not ` +
            'checked for known vulnerabilities.',
        );
      };
      const target = resolveRequirementInclude(from, include.target);
      if (target.kind === 'url') {
        notRead('it is a URL');
        continue;
      }
      if (target.kind === 'outside') {
        notRead('the path leads outside the project');
        continue;
      }
      if (!files.has(target.path)) {
        if (!content.has(target.path)) {
          const reason = skipped.get(target.path);
          notRead(
            reason !== undefined
              ? `the input walk skipped the file (${reason})`
              : 'the file is not among the files this scan read',
          );
          continue;
        }
        read(target.path, include.flag === '-c' ? 'constraints' : 'requirements');
        order.push(target.path);
      }
      const list = edges.get(from) ?? [];
      list.push({ from, include, to: target.path });
      edges.set(from, list);
    }
  }

  const state = new Map<string, 'open' | 'done'>();
  const visit = (path: string): void => {
    state.set(path, 'open');
    for (const edge of edges.get(path) ?? []) {
      const seen = state.get(edge.to);
      if (seen === 'open') {
        diagnostics.push(
          `Requirements include cycle (${edge.from} line ${edge.include.line}: ${edge.include.flag} ` +
            `${edge.include.target.slice(0, 80)}): the file it names includes this one again, directly or ` +
            'through other files. Each file in the loop was read once.',
        );
      } else if (seen === undefined) {
        visit(edge.to);
      }
    }
    state.set(path, 'done');
  };
  for (const path of order) if (!state.has(path)) visit(path);

  const reach = (starts: string[], follow: (edge: IncludeEdge) => boolean): string[] => {
    const seen = new Set<string>();
    const reached: string[] = [];
    const stack = [...starts];
    while (stack.length > 0) {
      const path = stack.pop() as string;
      if (seen.has(path)) continue;
      seen.add(path);
      reached.push(path);
      for (const edge of edges.get(path) ?? []) if (follow(edge)) stack.push(edge.to);
    }
    return reached;
  };

  const usedPins = new Set<string>();
  for (const root of order) {
    if ((files.get(root) as RequirementFile).role !== 'requirements') continue;
    const installs = reach([root], (edge) => edge.include.flag === '-r');
    const named = new Map<string, string>();
    const pinned = new Set<string>();
    for (const path of installs) {
      const file = files.get(path) as RequirementFile;
      if (file.role !== 'requirements') continue;
      for (const raw of file.raws) {
        const key = normalizePypiName(raw.name);
        if (raw.version !== undefined && isExactPythonVersion(raw.version)) pinned.add(key);
        else if (!named.has(key)) named.set(key, raw.name);
      }
    }
    const constraintStarts = installs.flatMap((path) =>
      (edges.get(path) ?? []).filter((edge) => edge.include.flag === '-c').map((edge) => edge.to),
    );
    for (const path of reach(constraintStarts, () => true)) {
      for (const raw of (files.get(path) as RequirementFile).raws) {
        if (raw.version === undefined || !isExactPythonVersion(raw.version)) continue;
        const pin = normalizePypiName(raw.name);
        if (pinned.has(pin)) {
          usedPins.add(`${path}\n${raw.line}`);
          continue;
        }
        const name = named.get(pin);
        if (name === undefined) continue;
        usedPins.add(`${path}\n${raw.line}`);
        installed.push({ ecosystem: 'PyPI', name, version: raw.version, lockfile: path });
      }
    }
  }

  for (const path of order) {
    const file = files.get(path) as RequirementFile;
    if (file.role !== 'constraints') continue;
    const unused = file.raws.filter(
      (raw) =>
        raw.version !== undefined && isExactPythonVersion(raw.version) && !usedPins.has(`${path}\n${raw.line}`),
    ).length;
    if (unused === 0) continue;
    diagnostics.push(
      `Constraint pins not applied (${path}): ${unused} exact pin(s) there fix the version of packages that no ` +
        'requirements file read here asks for through it, so whether those versions are installed is unknown and ' +
        'they were not checked for known vulnerabilities.',
    );
  }
}

function assemble(declared: Declared[], installed: Installed[]): CollectedDependency[] {
  const declaredByKey = new Map<string, Declared>();
  for (const d of declared) {
    const key = `${d.ecosystem} ${d.name}`;
    const existing = declaredByKey.get(key);
    if (existing === undefined || (existing.range === undefined && d.range !== undefined)) {
      declaredByKey.set(key, d);
    }
  }

  const out = new Map<string, CollectedDependency>();
  const ecosystemNamesWithInstall = new Set<string>();

  for (const inst of installed) {
    const nameKey = `${inst.ecosystem} ${inst.name}`;
    ecosystemNamesWithInstall.add(nameKey);
    const distinctKey = `${inst.ecosystem} ${inst.name} ${inst.version} ${inst.lockfile}`;
    if (out.has(distinctKey)) continue;
    const decl = declaredByKey.get(nameKey);
    out.set(distinctKey, {
      ecosystem: inst.ecosystem,
      name: inst.name,
      installedVersion: inst.version,
      lockfile: inst.lockfile,
      ...(decl?.range !== undefined ? { declaredRange: decl.range } : {}),
      ...(decl?.declaredIn !== undefined ? { declaredIn: decl.declaredIn } : {}),
      source: inst.lockfile,
    });
  }

  for (const [key, decl] of declaredByKey) {
    if (ecosystemNamesWithInstall.has(key)) continue;
    const distinctKey = `${decl.ecosystem} ${decl.name}  ${decl.declaredIn}`;
    if (out.has(distinctKey)) continue;
    out.set(distinctKey, {
      ecosystem: decl.ecosystem,
      name: decl.name,
      ...(decl.range !== undefined ? { declaredRange: decl.range } : {}),
      declaredIn: decl.declaredIn,
      source: decl.declaredIn,
    });
  }

  return [...out.values()].sort(
    (a, b) =>
      a.ecosystem.localeCompare(b.ecosystem) ||
      a.name.localeCompare(b.name) ||
      (a.installedVersion ?? '').localeCompare(b.installedVersion ?? '') ||
      lockfilePrecedence(a.source) - lockfilePrecedence(b.source) ||
      a.source.localeCompare(b.source),
  );
}

function lockfilePrecedence(source: string): number {
  const name = basename(source).toLowerCase();
  if (name === 'bun.lock') return 1;
  return name !== 'requirements.txt' && pythonRequirementsRole(source) !== undefined ? 2 : 0;
}

function parsePackageManifest(content: string, source: string, diagnostics: string[]): RawDependency[] {
  const dependencies: RawDependency[] = [];
  try {
    const parsed: unknown = JSON.parse(content);
    if (parsed === null || typeof parsed !== 'object') {
      diagnostics.push(`Manifest ${source} is not a JSON object; dependencies not collected.`);
      return dependencies;
    }
    const manifest = parsed as Record<string, unknown>;
    for (const key of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
      const section = manifest[key];
      if (section === null || typeof section !== 'object') continue;
      for (const [name, version] of Object.entries(section as Record<string, unknown>)) {
        dependencies.push({ name, ...(typeof version === 'string' ? { version } : {}), source });
      }
    }
  } catch (error) {
    diagnostics.push(
      `Malformed manifest ${source} could not be parsed (${error instanceof Error ? error.message : String(error)}); ` +
        'its dependencies were not audited.',
    );
  }
  return dependencies;
}

function parseNpmLockfile(content: string, source: string, diagnostics: string[]): RawDependency[] {
  const dependencies: RawDependency[] = [];
  try {
    const parsed: unknown = JSON.parse(content);
    if (parsed === null || typeof parsed !== 'object') {
      diagnostics.push(`Lockfile ${source} is not a JSON object; exact versions not collected.`);
      return dependencies;
    }
    const lockfile = parsed as Record<string, unknown>;
    const packages = lockfile['packages'];
    if (packages !== null && typeof packages === 'object') {
      for (const [key, value] of Object.entries(packages as Record<string, unknown>)) {
        const match = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/.exec(key);
        if (match === null || match[1] === undefined) continue;
        const version =
          value !== null && typeof value === 'object' ? (value as Record<string, unknown>)['version'] : undefined;
        dependencies.push({ name: match[1], ...(typeof version === 'string' ? { version } : {}), source });
      }
    }
    const legacy = lockfile['dependencies'];
    if (dependencies.length === 0 && legacy !== null && typeof legacy === 'object') {
      collectLegacyNpm(legacy as Record<string, unknown>, source, dependencies, diagnostics);
    }
    if (dependencies.length === 0) {
      diagnostics.push(`Lockfile ${source} parsed but contained no resolvable package versions.`);
    }
  } catch (error) {
    diagnostics.push(
      `Malformed lockfile ${source} could not be parsed (${error instanceof Error ? error.message : String(error)}); ` +
        'exact versions were not audited.',
    );
  }
  return dependencies;
}

function collectLegacyNpm(
  root: Record<string, unknown>,
  source: string,
  out: RawDependency[],
  diagnostics: string[],
): void {
  const stack: Array<{ node: Record<string, unknown>; depth: number }> = [{ node: root, depth: 0 }];
  let visited = 0;
  let nodeCapHit = false;
  let depthCapHit = false;

  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined) break;
    if (current.depth > MAX_LEGACY_NPM_DEPENDENCY_DEPTH) {
      depthCapHit = true;
      continue;
    }

    for (const [name, value] of Object.entries(current.node)) {
      visited += 1;
      if (visited > MAX_LEGACY_NPM_DEPENDENCY_NODES) {
        nodeCapHit = true;
        stack.length = 0;
        break;
      }
      if (value === null || typeof value !== 'object') continue;
      const record = value as Record<string, unknown>;
      const version = record['version'];
      if (typeof version === 'string') out.push({ name, version, source });
      const nested = record['dependencies'];
      if (nested !== null && typeof nested === 'object') {
        stack.push({ node: nested as Record<string, unknown>, depth: current.depth + 1 });
      }
    }
  }

  if (nodeCapHit) {
    diagnostics.push(`Legacy npm lockfile ${source} exceeded the dependency-node limit (${MAX_LEGACY_NPM_DEPENDENCY_NODES}); some exact versions were not audited.`);
  }
  if (depthCapHit) {
    diagnostics.push(`Legacy npm lockfile ${source} exceeded the dependency-depth limit (${MAX_LEGACY_NPM_DEPENDENCY_DEPTH}); nested exact versions beyond that depth were not audited.`);
  }
}

export function jsoncToJson(text: string): string {
  let out = '';
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i] as string;
    if (inString) {
      out += char;
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') {
      inString = true;
      out += char;
      continue;
    }
    if (char === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i += 1;
      out += '\n';
      continue;
    }
    if (char === '/' && text[i + 1] === '*') {
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i += 1;
      i += 1;
      continue;
    }
    out += char;
  }
  return stripTrailingCommas(out);
}

function stripTrailingCommas(text: string): string {
  let out = '';
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i] as string;
    if (inString) {
      out += char;
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') {
      inString = true;
      out += char;
      continue;
    }
    if (char === ',') {
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j] as string)) j += 1;
      if (text[j] === '}' || text[j] === ']') continue;
    }
    out += char;
  }
  return out;
}

export function splitNameAtVersion(identity: string): { name: string; version: string } | undefined {
  const at = identity.lastIndexOf('@');
  if (at <= 0) return undefined;
  const name = identity.slice(0, at);
  const version = identity.slice(at + 1);
  if (name === '' || version === '') return undefined;
  return { name, version };
}

interface BunDependencies {
  installed: RawDependency[];
  declared: RawDependency[];
}

function parseBunLockfile(content: string, source: string, diagnostics: string[]): BunDependencies {
  const installed: RawDependency[] = [];
  const declared: RawDependency[] = [];
  try {
    const parsed: unknown = JSON.parse(jsoncToJson(content));
    if (parsed === null || typeof parsed !== 'object') {
      diagnostics.push(`Lockfile ${source} is not a JSON object; exact versions not collected.`);
      return { installed, declared };
    }
    const lockfile = parsed as Record<string, unknown>;

    const packages = lockfile['packages'];
    if (packages !== null && typeof packages === 'object') {
      for (const value of Object.values(packages as Record<string, unknown>)) {
        if (!Array.isArray(value)) continue;
        const identity = value[0];
        if (typeof identity !== 'string') continue;
        const split = splitNameAtVersion(identity);
        if (split === undefined) continue;
        installed.push({ name: split.name, version: split.version, source });
      }
    }

    const workspaces = lockfile['workspaces'];
    if (workspaces !== null && typeof workspaces === 'object') {
      for (const workspace of Object.values(workspaces as Record<string, unknown>)) {
        if (workspace === null || typeof workspace !== 'object') continue;
        const record = workspace as Record<string, unknown>;
        for (const key of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
          const section = record[key];
          if (section === null || typeof section !== 'object') continue;
          for (const [name, range] of Object.entries(section as Record<string, unknown>)) {
            declared.push({ name, ...(typeof range === 'string' ? { version: range } : {}), source });
          }
        }
      }
    }

    if (installed.length === 0) {
      diagnostics.push(`Lockfile ${source} parsed but contained no resolvable package versions.`);
    }
  } catch (error) {
    diagnostics.push(
      `Malformed lockfile ${source} could not be parsed (${error instanceof Error ? error.message : String(error)}); ` +
        'exact versions were not audited.',
    );
  }
  return { installed, declared };
}

const YARN_ENTRY = /^"?((?:@[^@/\s"]+\/)?[^@/\s"]+)@[^:]*:\s*$/;
export const YARN_BERRY_ENTRY = /^"?((?:@[^@/\s"]+\/)?[^@/\s"]+)@npm(?:%3A|:)([^,"]*)/;

export function berryPackageName(ident: string, spec: string): string {
  const at = spec.lastIndexOf('@');
  return at <= 0 ? ident : spec.slice(0, at);
}
const YARN_VERSION = /^\s{2}version:?\s+"?([^"\s]+)"?/;

function parseYarnLockfile(content: string, source: string, diagnostics: string[]): RawDependency[] {
  const dependencies: RawDependency[] = [];
  let currentName: string | undefined;
  for (const line of content.split('\n')) {
    const classicMatch = YARN_ENTRY.exec(line);
    if (classicMatch !== null) {
      currentName = classicMatch[1];
      continue;
    }
    const berryMatch = YARN_BERRY_ENTRY.exec(line);
    if (berryMatch !== null && berryMatch[1] !== undefined) {
      currentName = berryPackageName(berryMatch[1], berryMatch[2] ?? '');
      continue;
    }
    const versionMatch = YARN_VERSION.exec(line);
    if (versionMatch !== null && currentName !== undefined && versionMatch[1] !== undefined) {
      dependencies.push({ name: currentName, version: versionMatch[1], source });
      currentName = undefined;
      continue;
    }
    if (line.trim() !== '' && !/^\s/.test(line)) currentName = undefined;
  }
  if (dependencies.length === 0 && content.trim() !== '') {
    diagnostics.push(`yarn.lock ${source} could not be parsed (unrecognized format); exact versions were not audited.`);
  }
  return dependencies;
}

const PNPM_ENTRY = /^\s{2}\/?((?:@[^/\s']+\/)?[^/\s'@]+)@([^\s':(]+)/;

function parsePnpmLockfile(content: string, source: string, diagnostics: string[]): RawDependency[] {
  const dependencies: RawDependency[] = [];
  let inPackages = false;
  let sawPackages = false;
  for (const line of content.split('\n')) {
    if (/^packages:/.test(line)) {
      inPackages = true;
      sawPackages = true;
      continue;
    }
    if (inPackages && /^\S/.test(line)) inPackages = false;
    if (!inPackages) continue;
    const match = PNPM_ENTRY.exec(line.replace(/^(\s{2})(['"])(.*)\2(\s*:)/, '$1$3$4'));
    if (match !== null && match[1] !== undefined && match[2] !== undefined) {
      dependencies.push({ name: match[1], version: match[2], source });
    }
  }
  if (!sawPackages && content.trim() !== '') {
    diagnostics.push(`pnpm-lock.yaml ${source} could not be parsed (no packages section); exact versions were not audited.`);
  }
  return dependencies;
}

const PY_REQUIREMENT = /^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(===|==|~=|!=|>=|<=|>|<)?\s*([^;#\s]+)?/;

interface RequirementInclude {
  flag: '-r' | '-c';
  target: string;
  line: number;
}

const REQUIREMENT_OPTION =
  /^(--requirement|--constraint|--editable|-r|-c|-e)(?:\s*=\s*|\s+|(?=[^\s=-]))(\S.*)?$/;

function unreadRequirementKind(line: string): string | undefined {
  if (/^(?:git|hg|svn|bzr)\+/i.test(line)) return 'a version-control (VCS) reference';
  if (/^(?:https?:|file:)/i.test(line)) return 'a URL';
  return undefined;
}

function parseRequirementsTxt(
  content: string,
  source: string,
  diagnostics: string[],
  includes?: RequirementInclude[],
): RawDependency[] {
  const dependencies: RawDependency[] = [];
  const lines = content.split('\n');
  const unread = (lineNumber: number, text: string, kind: string): void => {
    diagnostics.push(
      `Requirement not read (${source} line ${lineNumber}): "${text.slice(0, 60)}" installs from ${kind}, so ` +
        'what it installs was not checked for known vulnerabilities.',
    );
  };
  for (let index = 0; index < lines.length; index += 1) {
    const line = (lines[index] ?? '').trim();
    if (line === '' || line.startsWith('#')) continue;
    if (line.startsWith('-')) {
      const option = REQUIREMENT_OPTION.exec(line.replace(/\s+#.*$/, ''));
      const value = option?.[2]?.trim();
      if (option === null || value === undefined) continue;
      if (option[1] === '-e' || option[1] === '--editable') {
        unread(index + 1, line, 'an editable install (-e)');
      } else if (includes !== undefined) {
        const flag = option[1] === '-r' || option[1] === '--requirement' ? '-r' : '-c';
        includes.push({ flag, target: value, line: index + 1 });
      }
      continue;
    }
    const kind = unreadRequirementKind(line);
    if (kind !== undefined) {
      unread(index + 1, line, kind);
      continue;
    }
    const match = PY_REQUIREMENT.exec(line);
    if (match === null || match[1] === undefined) {
      diagnostics.push(`Unparseable requirement in ${source}: "${line.slice(0, 60)}"; skipped.`);
      continue;
    }
    const operator = match[2];
    const spec = match[3];
    const version =
      operator === '==' || operator === '===' ? spec : operator !== undefined ? `${operator}${spec ?? ''}` : undefined;
    dependencies.push({ name: match[1], ...(version !== undefined ? { version } : {}), source, line: index + 1 });
  }
  return dependencies;
}

function parsePyprojectToml(content: string, source: string, diagnostics: string[]): RawDependency[] {
  const dependencies: RawDependency[] = [];
  const lines = content.split('\n');
  let section = '';
  let inPep621Array = false;

  for (let index = 0; index < lines.length; index += 1) {
    const line = (lines[index] ?? '').trim();
    const lineNumber = index + 1;
    if (line === '' || line.startsWith('#')) continue;

    const header = /^\[([^\]]+)\]/.exec(line);
    if (header !== null) {
      section = (header[1] ?? '').trim();
      inPep621Array = false;
      continue;
    }

    if (section === 'project' && /^dependencies\s*=/.test(line)) {
      inPep621Array = /\[/.test(line);
      for (const req of extractQuotedRequirements(line)) pushPep508(dependencies, req, source, diagnostics, lineNumber);
      if (line.includes(']')) inPep621Array = false;
      continue;
    }
    if (inPep621Array) {
      for (const req of extractQuotedRequirements(line)) pushPep508(dependencies, req, source, diagnostics, lineNumber);
      if (line.includes(']')) inPep621Array = false;
      continue;
    }

    if (/^tool\.poetry(\.group\.[^.]+)?\.dependencies$/.test(section)) {
      const kv = /^([A-Za-z0-9._-]+)\s*=\s*(.+)$/.exec(line);
      if (kv === null || kv[1] === undefined) continue;
      if (kv[1].toLowerCase() === 'python') continue;
      const value = kv[2] ?? '';
      const inline = /version\s*=\s*"([^"]+)"/.exec(value);
      const simple = /^"([^"]+)"/.exec(value);
      const versionSpec = inline?.[1] ?? simple?.[1];
      if (versionSpec !== undefined) {
        dependencies.push({ name: kv[1], version: versionSpec.trim(), source, line: lineNumber });
      } else {
        diagnostics.push(`Dependency "${kv[1]}" in ${source} uses an unsupported form; declared range not resolved.`);
        dependencies.push({ name: kv[1], source });
      }
    }
  }
  return dependencies;
}

function extractQuotedRequirements(line: string): string[] {
  const out: string[] = [];
  const re = /"([^"]+)"|'([^']+)'/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line)) !== null) {
    const value = m[1] ?? m[2];
    if (value !== undefined) out.push(value);
  }
  return out;
}

function pushPep508(
  dependencies: RawDependency[],
  requirement: string,
  source: string,
  diagnostics: string[],
  line: number,
): void {
  const match = PY_REQUIREMENT.exec(requirement.trim());
  if (match === null || match[1] === undefined) {
    diagnostics.push(`Unparseable PEP 508 requirement in ${source}: "${requirement.slice(0, 60)}"; skipped.`);
    return;
  }
  const operator = match[2];
  const spec = match[3];
  const version =
    operator === '==' || operator === '===' ? spec : operator !== undefined ? `${operator}${spec ?? ''}` : undefined;
  dependencies.push({ name: match[1], ...(version !== undefined ? { version } : {}), source, line });
}

function parsePoetryLock(content: string, source: string, diagnostics: string[]): RawDependency[] {
  const dependencies: RawDependency[] = [];
  let inPackage = false;
  let sawPackage = false;
  let name: string | undefined;
  let nameLine: number | undefined;
  let version: string | undefined;
  const flush = (): void => {
    if (name !== undefined && version !== undefined) {
      dependencies.push({ name, version, source, ...(nameLine !== undefined ? { line: nameLine } : {}) });
    }
    name = undefined;
    nameLine = undefined;
    version = undefined;
  };
  const lines = content.split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const line = (lines[index] ?? '').trim();
    if (line === '[[package]]') {
      flush();
      inPackage = true;
      sawPackage = true;
      continue;
    }
    if (line.startsWith('[') && line !== '[[package]]') {
      flush();
      inPackage = false;
      continue;
    }
    if (!inPackage) continue;
    const nameMatch = /^name\s*=\s*"([^"]+)"/.exec(line);
    if (nameMatch !== null) {
      name = nameMatch[1];
      nameLine = index + 1;
      continue;
    }
    const versionMatch = /^version\s*=\s*"([^"]+)"/.exec(line);
    if (versionMatch !== null) version = versionMatch[1];
  }
  flush();
  if (!sawPackage && content.trim() !== '') {
    diagnostics.push(`poetry.lock ${source} could not be parsed (no [[package]] blocks); exact versions were not audited.`);
  }
  return dependencies;
}

export function pythonDependencyLine(
  path: string,
  content: string,
  packageName: string,
  version: string,
): number | undefined {
  const file = basename(path).toLowerCase();
  const ignored: string[] = [];
  const entries =
    pythonRequirementsRole(path) !== undefined
      ? parseRequirementsTxt(content, path, ignored)
      : file === 'pyproject.toml'
        ? parsePyprojectToml(content, path, ignored)
        : file === 'poetry.lock'
          ? parsePoetryLock(content, path, ignored)
          : [];
  const wanted = normalizePypiName(packageName);
  const lines = new Set<number>();
  for (const dep of entries) {
    if (normalizePypiName(dep.name) !== wanted || dep.version !== version) continue;
    if (dep.line === undefined) return undefined;
    lines.add(dep.line);
  }
  return lines.size === 1 ? [...lines][0] : undefined;
}

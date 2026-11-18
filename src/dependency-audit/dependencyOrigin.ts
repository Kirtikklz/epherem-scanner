import type {
  DependencyEcosystem,
  DependencyOrigin,
  DependencyOriginUndeterminedReason,
  FileMap,
} from '../shared/types.js';
import { basename } from '../shared/utils.js';
import { pythonRequirementsRole } from '../shared/pythonRequirementFiles.js';
import {
  berryPackageName,
  jsoncToJson,
  normalizePypiName,
  splitNameAtVersion,
  YARN_BERRY_ENTRY,
} from '../stack-detection/collectDependencies.js';

export const MAX_ORIGIN_CHAIN_DEPTH = 8;
export const MAX_ORIGIN_SEARCH_NODES = 5_000;
export const MAX_ORIGIN_GRAPH_NODES = 30_000;
export const MAX_ORIGIN_GRAPH_EDGES = 300_000;
const MAX_LEGACY_TREE_DEPTH = 64;

const NPM_DEPENDENCY_SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];

interface OriginNode {
  name: string;
  version: string;
}

interface ManifestDeclaration {
  ecosystem: DependencyEcosystem;
  path: string;
  dir: string;
  names: Map<string, string>;
}

interface OriginGraph {
  source: string;
  nodes: Map<string, OriginNode>;
  parents: Map<string, string[]>;
  idsByNameVersion: Map<string, string[]>;
  controlled: Set<string>;
  controlKnown: boolean;
  truncated: boolean;
}

export interface DependencyOriginQuery {
  ecosystem: DependencyEcosystem;
  packageName: string;
  installedVersion: string;
  sourcePath?: string;
}

export interface DependencyOriginResolver {
  resolve(query: DependencyOriginQuery): DependencyOrigin;
}

interface LocatedTargets {
  graph: OriginGraph;
  ids: string[];
}

export function createDependencyOriginResolver(fileMap: FileMap): DependencyOriginResolver {
  const { declaredIn, manifests } = collectManifestDeclarations(fileMap);
  const lockfileContent = collectLockfiles(fileMap);
  const graphCache = new Map<string, OriginGraph | undefined>();

  function graphFor(path: string): OriginGraph | undefined {
    if (!graphCache.has(path)) {
      const content = lockfileContent.get(path);
      graphCache.set(path, content === undefined ? undefined : buildGraph(path, content, manifests));
    }
    return graphCache.get(path);
  }

  function anyGraphAvailable(): boolean {
    for (const path of lockfileContent.keys()) if (graphFor(path) !== undefined) return true;
    return false;
  }

  function locate(query: DependencyOriginQuery, bounds: Set<string>): LocatedTargets[] {
    const found: LocatedTargets[] = [];
    for (const path of orderedGraphCandidates(query.sourcePath, lockfileContent)) {
      const graph = graphFor(path);
      if (graph === undefined) continue;
      if (graph.truncated) bounds.add(`graph-truncated:${path}`);
      const ids = graph.idsByNameVersion.get(`${query.packageName}@${query.installedVersion}`);
      if (ids !== undefined && ids.length > 0) found.push({ graph, ids });
    }
    return found;
  }

  return {
    resolve(query: DependencyOriginQuery): DependencyOrigin {
      const manifest = declaredIn.get(declarationKey(query.ecosystem, query.packageName));
      const bounds = new Set<string>();

      if (query.ecosystem !== 'npm') {
        if (manifest !== undefined) return { relationship: 'direct', declaredIn: manifest };
        return undetermined(declaredIn.size === 0 ? 'no_manifest_found' : 'no_dependency_graph');
      }

      const located = locate(query, bounds);

      if (manifest !== undefined) {
        return directOrigin(manifest, query, located, bounds);
      }
      if (declaredIn.size === 0) return undetermined('no_manifest_found');
      if (!anyGraphAvailable()) return undetermined('no_dependency_graph');

      let searchedAny = false;
      for (const { graph, ids } of located) {
        searchedAny = true;
        const found = searchUpward(graph, ids, (name) => declaredIn.get(declarationKey('npm', name)));
        for (const bound of found.bounds) bounds.add(bound);
        if (found.chain !== undefined && found.declaredIn !== undefined) {
          return {
            relationship: 'transitive',
            chain: found.chain,
            declaredIn: found.declaredIn,
            graphSource: graph.source,
            ...(bounds.size > 0 ? { searchBounds: [...bounds].sort() } : {}),
          };
        }
      }

      const reason: DependencyOriginUndeterminedReason = bounds.size > 0 && hasSearchBound(bounds)
        ? 'search_bounded'
        : !searchedAny
          ? 'package_not_in_graph'
          : 'no_path_to_a_direct_dependency';
      return {
        relationship: 'undetermined',
        undeterminedReason: reason,
        ...(bounds.size > 0 ? { searchBounds: [...bounds].sort() } : {}),
      };
    },
  };
}

function directOrigin(
  manifest: string,
  query: DependencyOriginQuery,
  located: LocatedTargets[],
  bounds: Set<string>,
): DependencyOrigin {
  for (const { graph, ids } of located) {
    if (!graph.controlKnown) continue;
    if (ids.some((id) => graph.controlled.has(id))) {
      return {
        relationship: 'direct',
        declaredIn: manifest,
        manifestControlsInstalledCopy: true,
        graphSource: graph.source,
        ...(bounds.size > 0 ? { searchBounds: [...bounds].sort() } : {}),
      };
    }
  }
  for (const { graph, ids } of located) {
    if (!graph.controlKnown) continue;
    const found = searchUpward(graph, ids, (name) =>
      name === query.packageName ? undefined : lookupDeclared(graph, name),
    );
    for (const bound of found.bounds) bounds.add(bound);
    return {
      relationship: 'direct',
      declaredIn: manifest,
      manifestControlsInstalledCopy: false,
      ...(found.chain !== undefined ? { chain: found.chain } : {}),
      graphSource: graph.source,
      ...(bounds.size > 0 ? { searchBounds: [...bounds].sort() } : {}),
    };
  }
  return {
    relationship: 'direct',
    declaredIn: manifest,
    ...(bounds.size > 0 ? { searchBounds: [...bounds].sort() } : {}),
  };
}

const declaredNamesByGraph = new WeakMap<OriginGraph, Map<string, string>>();
function lookupDeclared(graph: OriginGraph, name: string): string | undefined {
  return declaredNamesByGraph.get(graph)?.get(name);
}

function hasSearchBound(bounds: Set<string>): boolean {
  for (const bound of bounds) if (!bound.startsWith('graph-truncated:')) return true;
  return false;
}

function undetermined(reason: DependencyOriginUndeterminedReason): DependencyOrigin {
  return { relationship: 'undetermined', undeterminedReason: reason };
}

function declarationKey(ecosystem: DependencyEcosystem, name: string): string {
  return `${ecosystem} ${normalizeName(ecosystem, name)}`;
}

function normalizeName(ecosystem: DependencyEcosystem, name: string): string {
  return ecosystem === 'PyPI' ? normalizePypiName(name) : name;
}

function directoryOf(path: string): string {
  const cut = path.replace(/\\/g, '/').lastIndexOf('/');
  return cut === -1 ? '' : path.replace(/\\/g, '/').slice(0, cut);
}

function collectManifestDeclarations(fileMap: FileMap): {
  declaredIn: Map<string, string>;
  manifests: ManifestDeclaration[];
} {
  const declaredIn = new Map<string, string>();
  const manifests: ManifestDeclaration[] = [];
  const record = (ecosystem: DependencyEcosystem, name: string, path: string): void => {
    if (name === '') return;
    const key = declarationKey(ecosystem, name);
    const existing = declaredIn.get(key);
    if (existing === undefined || path.length < existing.length ||
        (path.length === existing.length && path < existing)) {
      declaredIn.set(key, path);
    }
  };

  for (const entry of fileMap.entries) {
    const file = basename(entry.path).toLowerCase();
    let ecosystem: DependencyEcosystem;
    let names: Map<string, string>;
    if (file === 'package.json') {
      ecosystem = 'npm';
      names = parsePackageJsonDeclarations(entry.content);
    } else if (pythonRequirementsRole(entry.path) === 'requirements') {
      ecosystem = 'PyPI';
      names = parseRequirementsNames(entry.content);
    } else if (file === 'pyproject.toml') {
      ecosystem = 'PyPI';
      names = parsePyprojectNames(entry.content);
    } else {
      continue;
    }
    if (names.size === 0) continue;
    manifests.push({ ecosystem, path: entry.path, dir: directoryOf(entry.path), names });
    for (const name of names.keys()) record(ecosystem, name, entry.path);
  }
  return { declaredIn, manifests };
}

function parsePackageJsonDeclarations(content: string): Map<string, string> {
  const names = new Map<string, string>();
  try {
    const parsed: unknown = JSON.parse(content);
    if (parsed === null || typeof parsed !== 'object') return names;
    const manifest = parsed as Record<string, unknown>;
    for (const section of NPM_DEPENDENCY_SECTIONS) {
      const value = manifest[section];
      if (value === null || typeof value !== 'object') continue;
      for (const [name, range] of Object.entries(value as Record<string, unknown>)) {
        if (!names.has(name)) names.set(name, typeof range === 'string' ? range : '');
      }
    }
  } catch {
  }
  return names;
}

function parseRequirementsNames(content: string): Map<string, string> {
  const names = new Map<string, string>();
  for (const raw of content.split('\n')) {
    const line = raw.split('#')[0]?.trim() ?? '';
    if (line === '' || line.startsWith('-')) continue;
    const match = /^([A-Za-z0-9._-]+)/.exec(line);
    if (match?.[1] !== undefined) names.set(match[1], '');
  }
  return names;
}

function parsePyprojectNames(content: string): Map<string, string> {
  const names = new Map<string, string>();
  let inDependencyTable = false;
  for (const raw of content.split('\n')) {
    const line = raw.trim();
    if (line.startsWith('[')) {
      inDependencyTable = /^\[(?:tool\.poetry\.(?:dev-)?dependencies|project\.optional-dependencies)/.test(line);
      continue;
    }
    if (inDependencyTable) {
      const table = /^([A-Za-z0-9._-]+)\s*=/.exec(line);
      if (table?.[1] !== undefined && table[1].toLowerCase() !== 'python') names.set(table[1], '');
      continue;
    }
    const listed = /^["']([A-Za-z0-9._-]+)\s*(?:[<>=!~[;].*)?["'],?$/.exec(line);
    if (listed?.[1] !== undefined) names.set(listed[1], '');
  }
  return names;
}

const LOCKFILE_NAMES = new Set([
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lock',
]);

function collectLockfiles(fileMap: FileMap): Map<string, string> {
  const out = new Map<string, string>();
  for (const entry of fileMap.entries) {
    if (LOCKFILE_NAMES.has(basename(entry.path).toLowerCase())) out.set(entry.path, entry.content);
  }
  return out;
}

function orderedGraphCandidates(sourcePath: string | undefined, lockfiles: Map<string, string>): string[] {
  const all = [...lockfiles.keys()].sort((a, b) => a.length - b.length || a.localeCompare(b));
  if (sourcePath === undefined || !lockfiles.has(sourcePath)) return all;
  return [sourcePath, ...all.filter((path) => path !== sourcePath)];
}

function buildGraph(source: string, content: string, manifests: ManifestDeclaration[]): OriginGraph | undefined {
  const npmManifests = manifests.filter((manifest) => manifest.ecosystem === 'npm');
  const file = basename(source).toLowerCase();
  const graph =
    file === 'package-lock.json' || file === 'npm-shrinkwrap.json'
      ? buildNpmGraph(source, content, npmManifests)
      : file === 'yarn.lock'
        ? buildYarnGraph(source, content, npmManifests)
        : file === 'pnpm-lock.yaml'
          ? buildPnpmGraph(source, content)
          : file === 'bun.lock'
            ? buildBunGraph(source, content)
            : undefined;
  if (graph !== undefined) {
    const byName = new Map<string, string>();
    for (const manifest of npmManifests) {
      for (const name of manifest.names.keys()) if (!byName.has(name)) byName.set(name, manifest.path);
    }
    declaredNamesByGraph.set(graph, byName);
  }
  return graph;
}

function emptyGraph(source: string): OriginGraph {
  return {
    source,
    nodes: new Map(),
    parents: new Map(),
    idsByNameVersion: new Map(),
    controlled: new Set(),
    controlKnown: false,
    truncated: false,
  };
}

function addNode(graph: OriginGraph, id: string, node: OriginNode): boolean {
  if (graph.nodes.has(id)) return true;
  if (graph.nodes.size >= MAX_ORIGIN_GRAPH_NODES) {
    graph.truncated = true;
    return false;
  }
  graph.nodes.set(id, node);
  const key = `${node.name}@${node.version}`;
  const existing = graph.idsByNameVersion.get(key);
  if (existing === undefined) graph.idsByNameVersion.set(key, [id]);
  else existing.push(id);
  return true;
}

function addEdge(graph: OriginGraph, parentId: string, childId: string): void {
  const existing = graph.parents.get(childId);
  if (existing === undefined) graph.parents.set(childId, [parentId]);
  else if (!existing.includes(parentId)) existing.push(parentId);
}

const NPM_LOCK_KEY_NAME = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/;

function buildNpmGraph(
  source: string,
  content: string,
  manifests: ManifestDeclaration[],
): OriginGraph | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return undefined;
  }
  if (parsed === null || typeof parsed !== 'object') return undefined;
  const lockfile = parsed as Record<string, unknown>;

  const packagesValue = lockfile['packages'];
  let packages: Record<string, Record<string, unknown>>;
  if (packagesValue !== null && typeof packagesValue === 'object' &&
      Object.keys(packagesValue as Record<string, unknown>).length > 0) {
    packages = {};
    for (const [key, value] of Object.entries(packagesValue as Record<string, unknown>)) {
      if (value !== null && typeof value === 'object') packages[key] = value as Record<string, unknown>;
    }
  } else {
    const legacy = lockfile['dependencies'];
    if (legacy === null || typeof legacy !== 'object') return undefined;
    packages = flattenLegacyNpmTree(legacy as Record<string, unknown>);
  }

  const graph = emptyGraph(source);
  const linkTargets = new Map<string, string>();

  for (const [key, record] of Object.entries(packages)) {
    if (record['link'] === true) {
      const resolved = record['resolved'];
      if (typeof resolved === 'string') linkTargets.set(key, resolved);
      continue;
    }
    const version = record['version'];
    if (typeof version !== 'string') continue;
    const nameFromKey = NPM_LOCK_KEY_NAME.exec(key)?.[1];
    const nameField = record['name'];
    const name = nameFromKey ?? (typeof nameField === 'string' ? nameField : undefined);
    if (name === undefined || key === '') continue;
    if (!addNode(graph, key, { name, version })) break;
  }

  const resolveFrom = (fromKey: string, name: string): string | undefined => {
    let dir = fromKey;
    for (;;) {
      const candidate = dir === '' ? `node_modules/${name}` : `${dir}/node_modules/${name}`;
      if (graph.nodes.has(candidate)) return candidate;
      const linked = linkTargets.get(candidate);
      if (linked !== undefined && graph.nodes.has(linked)) return linked;
      if (dir === '') return undefined;
      const cut = dir.lastIndexOf('/');
      dir = cut === -1 ? '' : dir.slice(0, cut);
    }
  };

  let edges = 0;
  for (const [key, record] of Object.entries(packages)) {
    if (!graph.nodes.has(key)) continue;
    for (const section of NPM_DEPENDENCY_SECTIONS) {
      const value = record[section];
      if (value === null || typeof value !== 'object') continue;
      for (const childName of Object.keys(value as Record<string, unknown>)) {
        if (edges >= MAX_ORIGIN_GRAPH_EDGES) {
          graph.truncated = true;
          return graph;
        }
        const childId = resolveFrom(key, childName);
        if (childId === undefined || childId === key) continue;
        addEdge(graph, key, childId);
        edges += 1;
      }
    }
  }

  graph.controlKnown = true;
  for (const manifest of manifests) {
    for (const name of manifest.names.keys()) {
      const id = resolveFrom(manifest.dir, name);
      if (id !== undefined) graph.controlled.add(id);
    }
  }
  return graph;
}

function flattenLegacyNpmTree(root: Record<string, unknown>): Record<string, Record<string, unknown>> {
  const out: Record<string, Record<string, unknown>> = {};
  const stack: Array<{ node: Record<string, unknown>; prefix: string; depth: number }> =
    [{ node: root, prefix: '', depth: 0 }];
  let visited = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined) break;
    if (current.depth > MAX_LEGACY_TREE_DEPTH) continue;
    for (const [name, value] of Object.entries(current.node)) {
      visited += 1;
      if (visited > MAX_ORIGIN_GRAPH_NODES) return out;
      if (value === null || typeof value !== 'object') continue;
      const record = value as Record<string, unknown>;
      const key = current.prefix === '' ? `node_modules/${name}` : `${current.prefix}/node_modules/${name}`;
      const version = record['version'];
      const requires = record['requires'];
      out[key] = {
        ...(typeof version === 'string' ? { version } : {}),
        name,
        ...(requires !== null && typeof requires === 'object' ? { dependencies: requires } : {}),
      };
      const nested = record['dependencies'];
      if (nested !== null && typeof nested === 'object') {
        stack.push({ node: nested as Record<string, unknown>, prefix: key, depth: current.depth + 1 });
      }
    }
  }
  return out;
}

const YARN_SPEC = /^((?:@[^/\s]+\/)?[^@\s]+)@(.+)$/;

const YARN_VERSION_LINE = /^version:?\s+"?([^"\s]+)"?$/;

const YARN_DEP_LINE = /^"?((?:@[^/"\s]+\/)?[^"\s:]+)"?:?\s+"?([^"]*)"?$/;

const BERRY_PROTOCOL = /^npm(?:%3A|:)/;

function buildYarnGraph(
  source: string,
  content: string,
  manifests: ManifestDeclaration[],
): OriginGraph | undefined {
  interface YarnBlock { specs: string[]; version?: string; deps: Array<[string, string]> }
  const blocks: YarnBlock[] = [];
  let current: YarnBlock | undefined;
  let inDeps = false;

  for (const raw of content.split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (line.trim() === '' || line.trimStart().startsWith('#')) continue;
    if (!/^\s/.test(line)) {
      const header = line.replace(/:\s*$/, '');
      current = {
        specs: header.split(',').map((spec) => spec.trim().replace(/^"|"$/g, '')).filter(Boolean),
        deps: [],
      };
      blocks.push(current);
      inDeps = false;
      continue;
    }
    if (current === undefined) continue;
    const indent = line.length - line.trimStart().length;
    const trimmed = line.trim();
    if (indent <= 2) {
      inDeps = /^(?:dependencies|optionalDependencies):$/.test(trimmed);
      const version = YARN_VERSION_LINE.exec(trimmed);
      if (version?.[1] !== undefined) current.version = version[1];
      continue;
    }
    if (inDeps) {
      const dep = YARN_DEP_LINE.exec(trimmed);
      if (dep?.[1] !== undefined && dep[2] !== undefined) current.deps.push([dep[1], dep[2]]);
    }
  }

  const graph = emptyGraph(source);
  const bySpec = new Map<string, string>();
  const fileSpec = (spec: string, id: string): void => {
    if (!bySpec.has(spec)) bySpec.set(spec, id);
    const at = spec.indexOf('@', 1);
    if (at <= 0) return;
    const range = spec.slice(at + 1);
    if (!BERRY_PROTOCOL.test(range)) return;
    const plain = `${spec.slice(0, at)}@${range.replace(BERRY_PROTOCOL, '')}`;
    if (!bySpec.has(plain)) bySpec.set(plain, id);
  };

  const specPackageName = (spec: string): string | undefined => {
    const berry = YARN_BERRY_ENTRY.exec(spec);
    if (berry?.[1] !== undefined) return berryPackageName(berry[1], berry[2] ?? '');
    return YARN_SPEC.exec(spec)?.[1];
  };

  for (const block of blocks) {
    if (block.version === undefined) continue;
    const first = block.specs[0];
    if (first === undefined) continue;
    const parsedName = specPackageName(first);
    if (parsedName === undefined) continue;
    const id = `${parsedName}@${block.version}`;
    if (!addNode(graph, id, { name: parsedName, version: block.version })) break;
    for (const spec of block.specs) fileSpec(spec, id);
  }
  if (graph.nodes.size === 0) return undefined;

  let edges = 0;
  for (const block of blocks) {
    if (block.version === undefined) continue;
    const first = block.specs[0];
    if (first === undefined) continue;
    const parentName = specPackageName(first);
    if (parentName === undefined) continue;
    const parentId = `${parentName}@${block.version}`;
    if (!graph.nodes.has(parentId)) continue;
    for (const [childName, range] of block.deps) {
      if (edges >= MAX_ORIGIN_GRAPH_EDGES) {
        graph.truncated = true;
        return graph;
      }
      const childId = bySpec.get(`${childName}@${range}`);
      if (childId === undefined || childId === parentId) continue;
      addEdge(graph, parentId, childId);
      edges += 1;
    }
  }

  for (const manifest of manifests) {
    for (const [name, range] of manifest.names) {
      const id = bySpec.get(`${name}@${range}`);
      if (id !== undefined) graph.controlled.add(id);
    }
  }
  graph.controlKnown = graph.controlled.size > 0;
  return graph;
}

function buildPnpmGraph(source: string, content: string): OriginGraph | undefined {
  const graph = emptyGraph(source);
  const pending: Array<[string, string]> = [];
  const controlled: string[] = [];
  let section: 'none' | 'packages' | 'snapshots' | 'importers' = 'none';
  let currentId: string | undefined;
  let inDeps = false;
  let importerName: string | undefined;
  let sawImporters = false;

  for (const raw of content.split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (line.trim() === '' || line.trimStart().startsWith('#')) continue;
    if (!/^\s/.test(line)) {
      const head = line.replace(/:\s*$/, '').trim();
      section = head === 'snapshots' ? 'snapshots' : head === 'packages' ? 'packages' : head === 'importers' ? 'importers' : 'none';
      if (section === 'importers') sawImporters = true;
      currentId = undefined;
      inDeps = false;
      importerName = undefined;
      continue;
    }
    if (section === 'none') continue;
    const indent = line.length - line.trimStart().length;
    const trimmed = line.trim();

    if (section === 'importers') {
      if (indent === 4) {
        inDeps = /^(?:dependencies|devDependencies|optionalDependencies):$/.test(trimmed);
        importerName = undefined;
        continue;
      }
      if (indent === 6 && inDeps && trimmed.endsWith(':')) {
        importerName = trimmed.slice(0, -1).replace(/^['"]|['"]$/g, '');
        continue;
      }
      if (indent >= 8 && inDeps && importerName !== undefined) {
        const version = /^version:\s*(.+)$/.exec(trimmed);
        if (version?.[1] !== undefined) {
          const id = pnpmNodeId(`${importerName}@${version[1]}`);
          if (id !== undefined) controlled.push(id);
        }
      }
      continue;
    }

    if (indent === 2 && trimmed.endsWith(':')) {
      currentId = pnpmNodeId(trimmed.slice(0, -1));
      inDeps = false;
      if (currentId !== undefined) {
        const at = currentId.lastIndexOf('@');
        if (!addNode(graph, currentId, { name: currentId.slice(0, at), version: currentId.slice(at + 1) })) break;
      }
      continue;
    }
    if (currentId === undefined) continue;
    if (indent === 4) {
      inDeps = /^(?:dependencies|optionalDependencies):$/.test(trimmed);
      continue;
    }
    if (indent >= 6 && inDeps) {
      const dep = /^'?((?:@[^/'\s]+\/)?[^'\s:]+)'?:\s*(.+)$/.exec(trimmed);
      const childName = dep?.[1];
      const childVersion = dep?.[2];
      if (childName === undefined || childVersion === undefined) continue;
      const childId = pnpmNodeId(`${childName}@${childVersion}`);
      if (childId !== undefined) pending.push([currentId, childId]);
    }
  }

  if (graph.nodes.size === 0) return undefined;
  let edges = 0;
  for (const [parentId, childId] of pending) {
    if (edges >= MAX_ORIGIN_GRAPH_EDGES) {
      graph.truncated = true;
      return graph;
    }
    if (!graph.nodes.has(parentId) || !graph.nodes.has(childId) || parentId === childId) continue;
    addEdge(graph, parentId, childId);
    edges += 1;
  }
  graph.controlKnown = sawImporters;
  for (const id of controlled) if (graph.nodes.has(id)) graph.controlled.add(id);
  return graph;
}

function pnpmNodeId(rawKey: string): string | undefined {
  let key = rawKey.trim().replace(/^['"]|['"]$/g, '');
  const paren = key.indexOf('(');
  if (paren !== -1) key = key.slice(0, paren);
  key = key.trim();
  if (key.startsWith('/')) {
    key = key.slice(1);
    const lastSlash = key.lastIndexOf('/');
    if (lastSlash !== -1 && !key.slice(lastSlash + 1).includes('@')) {
      key = `${key.slice(0, lastSlash)}@${key.slice(lastSlash + 1)}`;
    }
  }
  const at = key.lastIndexOf('@');
  if (at <= 0) return undefined;
  const name = key.slice(0, at);
  const version = key.slice(at + 1);
  if (name === '' || version === '' || version.includes('/')) return undefined;
  return `${name}@${version}`;
}


function buildBunGraph(source: string, content: string): OriginGraph | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsoncToJson(content));
  } catch {
    return undefined;
  }
  if (parsed === null || typeof parsed !== 'object') return undefined;
  const lockfile = parsed as Record<string, unknown>;
  const packagesValue = lockfile['packages'];
  if (packagesValue === null || typeof packagesValue !== 'object') return undefined;

  const graph = emptyGraph(source);
  const parentKeyOf = new Map<string, string>();
  const records = new Map<string, unknown[]>();

  for (const [key, value] of Object.entries(packagesValue as Record<string, unknown>)) {
    if (!Array.isArray(value)) continue;
    const identity = value[0];
    if (typeof identity !== 'string') continue;
    const split = splitNameAtVersion(identity);
    if (split === undefined || key === '') continue;
    const suffix = `/${split.name}`;
    parentKeyOf.set(key, key.endsWith(suffix) ? key.slice(0, key.length - suffix.length) : '');
    records.set(key, value);
    if (!addNode(graph, key, { name: split.name, version: split.version })) break;
  }

  if (graph.nodes.size === 0) return undefined;

  const resolveFrom = (fromKey: string, name: string): string | undefined => {
    let dir = fromKey;
    for (;;) {
      const candidate = dir === '' ? name : `${dir}/${name}`;
      if (graph.nodes.has(candidate)) return candidate;
      if (dir === '') return undefined;
      dir = parentKeyOf.get(dir) ?? '';
    }
  };

  let edges = 0;
  for (const [key, value] of records) {
    if (!graph.nodes.has(key)) continue;
    const fragment = value[2];
    if (fragment === null || typeof fragment !== 'object') continue;
    const sections = fragment as Record<string, unknown>;
    for (const section of NPM_DEPENDENCY_SECTIONS) {
      const declared = sections[section];
      if (declared === null || typeof declared !== 'object') continue;
      for (const childName of Object.keys(declared as Record<string, unknown>)) {
        if (edges >= MAX_ORIGIN_GRAPH_EDGES) {
          graph.truncated = true;
          return graph;
        }
        const childId = resolveFrom(key, childName);
        if (childId === undefined || childId === key) continue;
        addEdge(graph, key, childId);
        edges += 1;
      }
    }
  }

  const workspaces = lockfile['workspaces'];
  let sawWorkspaceDeclarations = false;
  if (workspaces !== null && typeof workspaces === 'object') {
    for (const workspace of Object.values(workspaces as Record<string, unknown>)) {
      if (workspace === null || typeof workspace !== 'object') continue;
      const record = workspace as Record<string, unknown>;
      const workspaceName = record['name'];
      const from =
        typeof workspaceName === 'string' && graph.nodes.has(workspaceName) ? workspaceName : '';
      for (const section of NPM_DEPENDENCY_SECTIONS) {
        const declared = record[section];
        if (declared === null || typeof declared !== 'object') continue;
        for (const name of Object.keys(declared as Record<string, unknown>)) {
          sawWorkspaceDeclarations = true;
          const id = resolveFrom(from, name);
          if (id !== undefined) graph.controlled.add(id);
        }
      }
    }
  }
  graph.controlKnown = sawWorkspaceDeclarations;
  return graph;
}

interface UpwardResult {
  chain?: string[];
  declaredIn?: string;
  bounds: string[];
}

function searchUpward(
  graph: OriginGraph,
  targets: string[],
  declaredIn: (name: string) => string | undefined,
): UpwardResult {
  const bounds: string[] = [];
  const cameFrom = new Map<string, string>();
  const seen = new Set<string>(targets);
  let frontier = [...targets];
  let visited = targets.length;

  for (let depth = 1; depth <= MAX_ORIGIN_CHAIN_DEPTH; depth += 1) {
    const next: string[] = [];
    for (const childId of frontier) {
      for (const parentId of graph.parents.get(childId) ?? []) {
        if (seen.has(parentId)) continue;
        if (visited >= MAX_ORIGIN_SEARCH_NODES) {
          bounds.push(`search-node-cap-${MAX_ORIGIN_SEARCH_NODES}`);
          return { bounds };
        }
        seen.add(parentId);
        visited += 1;
        cameFrom.set(parentId, childId);
        const parent = graph.nodes.get(parentId);
        if (parent === undefined) continue;
        const manifest = declaredIn(parent.name);
        if (manifest !== undefined) {
          return { chain: chainFrom(graph, cameFrom, parentId), declaredIn: manifest, bounds };
        }
        next.push(parentId);
      }
    }
    if (next.length === 0) return { bounds };
    frontier = next;
  }
  bounds.push(`chain-depth-cap-${MAX_ORIGIN_CHAIN_DEPTH}`);
  return { bounds };
}

function chainFrom(graph: OriginGraph, cameFrom: Map<string, string>, rootId: string): string[] {
  const names: string[] = [];
  let id: string | undefined = rootId;
  const guard = new Set<string>();
  while (id !== undefined && !guard.has(id)) {
    guard.add(id);
    const node = graph.nodes.get(id);
    if (node === undefined) break;
    names.push(node.name);
    id = cameFrom.get(id);
  }
  return names;
}

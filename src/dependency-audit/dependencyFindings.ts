import { makeFinding } from '../shared/findingFactory.js';
import type {
  DependencyAuditSummary,
  DependencyEcosystem,
  DependencyOrigin,
  DependencyVulnerability,
  Finding,
  FindingAdjudicationPolicy,
  Severity,
} from '../shared/types.js';
import { basename } from '../shared/utils.js';
import { MAX_ORIGIN_CHAIN_DEPTH, type DependencyOriginResolver } from './dependencyOrigin.js';

const DEPENDENCY_RULE_ID = 'dependency_vulnerability';
const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

const DEPENDENCY_ADJUDICATION_POLICY: FindingAdjudicationPolicy = {
  required: false,
  reason: 'database_backed_dependency_advisory',
  basis:
    'This rule is not a heuristic: it reports that an exact installed version falls inside the affected ' +
    'range published for an advisory, so there is nothing further to judge. ' +
    'MEASUREMENT: all 232 dependency findings on an earlier 12-project / 388-finding test set were re-checked against an ' +
    'independent re-implementation of the OSV affected-range test, and all 232 version decisions agreed. ' +
    'NOT COVERED BY IT: every one of those checks was answered by the bundled offline OSV data. Online ' +
    'scans query the live service, and that path has not been measured.',
};

export type PythonDependencyLineLocator = (
  sourcePath: string,
  packageName: string,
  installedVersion: string,
) => number | undefined;

export function dependencyVulnerabilitiesToFindings(
  audit: DependencyAuditSummary,
  originResolver?: DependencyOriginResolver,
  pythonLine?: PythonDependencyLineLocator,
): Finding[] {
  const groups = new Map<string, DependencyVulnerability[]>();
  for (const vulnerability of audit.vulnerabilities) {
    const key = `${vulnerability.ecosystem} ${vulnerability.dependency} ${vulnerability.version ?? 'unknown'}`;
    const existing = groups.get(key);
    if (existing === undefined) groups.set(key, [vulnerability]);
    else existing.push(vulnerability);
  }
  return [...groups.values()].map((vulnerabilities) => toFinding(vulnerabilities, originResolver, pythonLine));
}

function toFinding(
  vulnerabilities: DependencyVulnerability[],
  originResolver: DependencyOriginResolver | undefined,
  pythonLine: PythonDependencyLineLocator | undefined,
): Finding {
  const sorted = [...vulnerabilities].sort(
    (a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.advisoryId.localeCompare(b.advisoryId),
  );
  const seen = new Set<string>();
  const ordered = sorted.filter((vulnerability) => {
    if (seen.has(vulnerability.advisoryId)) return false;
    seen.add(vulnerability.advisoryId);
    return true;
  });
  const primary = ordered[0] as DependencyVulnerability;
  const version = primary.version ?? 'unknown';
  const filePath = primary.sourcePath ?? '(dependencies)';
  const dataSource = primary.dataSource ?? 'fallback';
  const advisoryIds = ordered.map((vulnerability) => vulnerability.advisoryId);
  const count = ordered.length;

  const origin =
    originResolver === undefined
      ? undefined
      : originResolver.resolve({
          ecosystem: primary.ecosystem,
          packageName: primary.dependency,
          installedVersion: version,
          ...(primary.sourcePath !== undefined ? { sourcePath: primary.sourcePath } : {}),
        });

  const title =
    count === 1
      ? `Vulnerable dependency: ${primary.dependency}@${version} (${primary.advisoryId})`
      : `Vulnerable dependency: ${primary.dependency}@${version} (${count} advisories)`;

  const advisoryList = ordered
    .map((vulnerability) => `${vulnerability.advisoryId} [${vulnerability.severity}]: ${vulnerability.summary}`)
    .join('; ');

  const advisoryPhrase = count === 1 ? primary.advisoryId : `all ${count} advisories`;

  const pinned: PinnedInManifest | undefined =
    primary.ecosystem === 'npm' &&
    primary.sourcePath !== undefined &&
    basename(primary.sourcePath).toLowerCase() === 'package.json'
      ? { path: primary.sourcePath, version }
      : undefined;

  const base = makeFinding({
    ruleId: DEPENDENCY_RULE_ID,
    title,
    severity: primary.severity,
    confidence: 'high',
    filePath,
    lineStart:
      primary.ecosystem === 'PyPI' && primary.sourcePath !== undefined && primary.version !== undefined
        ? (pythonLine?.(primary.sourcePath, primary.dependency, primary.version) ?? 1)
        : 1,
    evidence: truncate(`${primary.ecosystem} ${primary.dependency}@${version} — ${advisoryList}`, 600),
    userExplanation:
      count === 1
        ? `The project depends on ${primary.dependency} ${version}, which has a known security advisory (${primary.advisoryId}). Update it to a patched version.`
        : `The project depends on ${primary.dependency} ${version}, which has ${count} known security advisories (${advisoryIds.join(', ')}). One upgrade fixes all of them.`,
    technicalExplanation:
      `${primary.dependency}@${version} (${primary.ecosystem}) is inside the affected range of ${count} ` +
      `advisor${count === 1 ? 'y' : 'ies'}: ${advisoryList}`,
    fixHint: buildFixHint(primary.dependency, primary.ecosystem, advisoryPhrase, origin, pinned),
    category: 'dependencies',
    extraFixRequirements: [
      pinned !== undefined
        ? `Bump ${primary.dependency} where it is ${pinnedPhrase(pinned)}, so the installed version actually changes.`
        : `Bump ${primary.dependency} in the ${primary.ecosystem === 'PyPI' ? 'Python' : 'npm'} manifest AND regenerate the lockfile so the installed version actually changes.`,
      pinned !== undefined
        ? `${primary.dependency} is ${pinnedPhrase(pinned)} — change the version there.`
        : originRequirement(primary.dependency, primary.ecosystem, origin),
      'Do not silence the advisory with an ignore/allowlist; apply a real version bump.',
      'Check that transitive dependencies do not re-pin the vulnerable version.',
    ],
  });

  return {
    ...base,
    dependency: {
      ecosystem: primary.ecosystem,
      package: primary.dependency,
      installedVersion: version,
      advisoryId: primary.advisoryId,
      advisoryIds,
      ...(advisoryIds.length > 1 ? { relatedAdvisoryIds: advisoryIds } : {}),
      ...(origin !== undefined ? { origin } : {}),
      ...(primary.sourcePath !== undefined ? { sourcePath: primary.sourcePath } : {}),
      dataSource,
      ...(primary.reference !== undefined ? { reference: primary.reference } : {}),
    },
    adjudication: DEPENDENCY_ADJUDICATION_POLICY,
  };
}

interface PinnedInManifest {
  path: string;
  version: string;
}

function pinnedPhrase(pinned: PinnedInManifest): string {
  return `pinned to exactly ${pinned.version} in ${pinned.path} (no lockfile was found, so this is the version npm installs for it directly)`;
}

function pinAdvice(packageName: string, ecosystem: DependencyEcosystem): string {
  return ecosystem === 'PyPI'
    ? `pin a patched ${packageName} directly in your own requirements`
    : `force a patched ${packageName} with an npm "overrides" (pnpm "resolutions") entry`;
}

function buildFixHint(
  packageName: string,
  ecosystem: DependencyEcosystem,
  advisoryPhrase: string,
  origin: DependencyOrigin | undefined,
  pinned?: PinnedInManifest,
): string {
  if (pinned !== undefined) {
    return (
      `Upgrade ${packageName} past the fixed version for ${advisoryPhrase}, then reinstall. ` +
      `You depend on ${packageName} directly — it is ${pinnedPhrase(pinned)}, so change the version there.`
    );
  }
  const reinstall = 'then reinstall so the lockfile is updated';

  if (origin?.relationship === 'direct') {
    const manifest = origin.declaredIn ?? 'your package manifest';
    if (origin.manifestControlsInstalledCopy === false) {
      const throughChain =
        origin.chain !== undefined && origin.chain.length >= 2
          ? `this copy came in through ${origin.chain.join(' -> ')}. Upgrade ${origin.chain[0] as string} to a ` +
            `release with a patched ${packageName}, or ${pinAdvice(packageName, ecosystem)}`
          : `we could not trace which package installed this copy, so ${pinAdvice(packageName, ecosystem)}`;
      return (
        `${packageName} IS listed in ${manifest}, but that entry is not what installed the copy carrying ` +
        `${advisoryPhrase} — ${throughChain}, ${reinstall}. Changing your own ${packageName} entry alone ` +
        'may leave this copy in place.'
      );
    }
    const unconfirmed =
      origin.manifestControlsInstalledCopy === true
        ? ''
        : ` (no lockfile was readable here, so we could not confirm that entry installs the copy carrying ${advisoryPhrase})`;
    return (
      `Upgrade ${packageName} past the fixed version for ${advisoryPhrase}, ${reinstall}. ` +
      `You depend on ${packageName} directly — it is listed in ${manifest}, so change the version there${unconfirmed}.`
    );
  }

  if (origin?.relationship === 'transitive' && origin.chain !== undefined && origin.chain.length >= 2) {
    const root = origin.chain[0] as string;
    return (
      `You did not add ${packageName} yourself — ${requiredByProse(origin.chain)}, a package you depend on ` +
      `directly (listed in ${origin.declaredIn ?? 'your package manifest'}). Upgrade ${root} to a release ` +
      `with a patched ${packageName}, or ${pinAdvice(packageName, ecosystem)}, ${reinstall}.${boundsNote(origin)}`
    );
  }

  return (
    `Upgrade ${packageName} past the fixed version for ${advisoryPhrase}, ${reinstall}. ` +
    `We could not determine where ${packageName} came from (${undeterminedProse(origin)}), so we cannot tell ` +
    `you whether it is yours to upgrade. Search your package manifest for "${packageName}": if it is listed, ` +
    `change the version there; if it is not, another package brought it in and that package — or ` +
    `${pinAdvice(packageName, ecosystem)} — is what has to change.`
  );
}

function requiredByProse(chain: string[]): string {
  const reversed = [...chain].reverse();
  const parts: string[] = [];
  for (let index = 1; index < reversed.length; index += 1) {
    const child = reversed[index - 1] as string;
    const parent = reversed[index] as string;
    parts.push(index === 1 ? `${child} is required by ${parent}` : `which is required by ${parent}`);
  }
  return parts.join(', ');
}

function undeterminedProse(origin: DependencyOrigin | undefined): string {
  switch (origin?.undeterminedReason) {
    case 'no_manifest_found':
      return 'no package manifest was found in this project, so we could not check whether you list it yourself';
    case 'no_dependency_graph':
      return 'no lockfile was found that records which package requires which';
    case 'package_not_in_graph':
      return 'the lockfile does not record this exact version, so we could not trace it';
    case 'no_path_to_a_direct_dependency':
      return 'no package in the lockfile records requiring it';
    case 'search_bounded':
      return `the chain of packages runs deeper than the ${MAX_ORIGIN_CHAIN_DEPTH} levels this check follows`;
    default:
      return "the project's own files were not available to this check";
  }
}

function boundsNote(origin: DependencyOrigin): string {
  return origin.searchBounds === undefined || origin.searchBounds.length === 0
    ? ''
    : ' (this project\'s dependency graph was too large to read in full, so a shorter route may also exist).';
}

function originRequirement(
  packageName: string,
  ecosystem: DependencyEcosystem,
  origin: DependencyOrigin | undefined,
): string {
  if (origin?.relationship === 'direct' && origin.manifestControlsInstalledCopy === false) {
    return (
      `${packageName} is declared in ${origin.declaredIn ?? 'the package manifest'}, but that entry does NOT ` +
      `control the affected copy${origin.chain !== undefined ? ` (${origin.chain.join(' -> ')})` : ''}; bumping ` +
      `it alone may not remove the vulnerable copy — verify after reinstalling, and ${pinAdvice(packageName, ecosystem)} if it survives.`
    );
  }
  if (origin?.relationship === 'direct') {
    return (
      `${packageName} is declared in ${origin.declaredIn ?? 'the package manifest'} — change the version there; ` +
      'editing the lockfile by hand does not survive a reinstall.'
    );
  }
  if (origin?.relationship === 'transitive' && origin.chain !== undefined && origin.chain.length >= 2) {
    const root = origin.chain[0] as string;
    return (
      `${packageName} is present only transitively (${origin.chain.join(' -> ')}); upgrade ${root} or ` +
      `${pinAdvice(packageName, ecosystem)} — editing the lockfile by hand does not survive a reinstall.`
    );
  }
  return (
    `It is not established whether ${packageName} is a direct or a transitive dependency here; determine that ` +
    'from the manifest before choosing between a version bump and an overrides/resolutions pin. Editing the ' +
    'lockfile by hand does not survive a reinstall.'
  );
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

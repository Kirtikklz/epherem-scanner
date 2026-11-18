export interface Pep440Version {
  epoch: number;
  release: number[];
  pre?: [number, number];
  post?: number;
  dev?: number;
}

const PRE_KIND: Record<string, number> = {
  a: 0, alpha: 0, b: 1, beta: 1, c: 2, rc: 2, pre: 2, preview: 2,
};

const PEP440_RE = new RegExp(
  '^\\s*v?' +
    '(?:(?<epoch>\\d+)!)?' +
    '(?<release>\\d+(?:\\.\\d+)*)' +
    '(?<pre>[-_.]?(?<prekind>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?<prenum>\\d+)?)?' +
    '(?<post>(?:[-_.]?post[-_.]?(?<postn>\\d+)?)|(?:-(?<postimplicit>\\d+)))?' +
    '(?<dev>[-_.]?dev[-_.]?(?<devn>\\d+)?)?' +
    '(?:\\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?' +
    '\\s*$',
  'i',
);

export function parsePep440(raw: string): Pep440Version | undefined {
  const match = PEP440_RE.exec(raw.trim());
  if (match === null || match.groups === undefined) return undefined;
  const g = match.groups;
  const releaseStr = g['release'];
  if (releaseStr === undefined) return undefined;
  const release = releaseStr.split('.').map((part) => Number(part));
  if (release.some((value) => !Number.isInteger(value))) return undefined;

  const version: Pep440Version = {
    epoch: g['epoch'] !== undefined ? Number(g['epoch']) : 0,
    release,
  };
  if (g['pre'] !== undefined && g['prekind'] !== undefined) {
    const kind = PRE_KIND[g['prekind'].toLowerCase()];
    if (kind !== undefined) version.pre = [kind, g['prenum'] !== undefined ? Number(g['prenum']) : 0];
  }
  if (g['post'] !== undefined) {
    version.post = Number(g['postn'] ?? g['postimplicit'] ?? 0);
  }
  if (g['dev'] !== undefined) {
    version.dev = Number(g['devn'] ?? 0);
  }
  return version;
}

const NEG_INF = Number.NEGATIVE_INFINITY;
const POS_INF = Number.POSITIVE_INFINITY;

function cmpNumberArrays(a: number[], b: number[]): number {
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function preRank(v: Pep440Version): [number, number, number] {
  if (v.pre === undefined) {
    if (v.post === undefined && v.dev !== undefined) return [NEG_INF, 0, 0];
    return [POS_INF, 0, 0];
  }
  return [0, v.pre[0], v.pre[1]];
}

export function comparePep440(a: string, b: string): number | undefined {
  const va = parsePep440(a);
  const vb = parsePep440(b);
  if (va === undefined || vb === undefined) return undefined;

  if (va.epoch !== vb.epoch) return va.epoch < vb.epoch ? -1 : 1;
  const releaseCmp = cmpNumberArrays(va.release, vb.release);
  if (releaseCmp !== 0) return releaseCmp;

  const pa = preRank(va);
  const pb = preRank(vb);
  for (let i = 0; i < 3; i += 1) {
    const x = pa[i] as number;
    const y = pb[i] as number;
    if (x !== y) return x < y ? -1 : 1;
  }

  const postA = va.post ?? NEG_INF;
  const postB = vb.post ?? NEG_INF;
  if (postA !== postB) return postA < postB ? -1 : 1;

  const devA = va.dev ?? POS_INF;
  const devB = vb.dev ?? POS_INF;
  if (devA !== devB) return devA < devB ? -1 : 1;

  return 0;
}

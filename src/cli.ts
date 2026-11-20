import { open, realpath, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { DependencyVulnerabilityScanner } from './dependency-audit/dependencyAudit.js';
import { CachedOsvClient, safeLoadBundledOsvCache } from './dependency-audit/osvClient.js';
import { OsvDependencyScanner } from './dependency-audit/osvDependencyScanner.js';
import { HTML_REPORT_MARKER, renderHtmlReport } from './report/htmlReport.js';
import { datasetDate, type SeverityKey } from './report/reportModel.js';
import { renderTextReport } from './report/textReport.js';
import { scanProject } from './scanProject.js';
import { ScannerError } from './shared/errors.js';
import type { ScanReport } from './shared/types.js';

export const VERSION = '1.0.0';

export const USAGE = 'Usage: epherem-scanner [project-folder] [--json] [--severity high|medium|low] [--offline] [--html <file>] [--help] [--version]';

const HELP = [
  'Epherem scanner: a security scanner for apps built with AI tools.',
  '',
  USAGE,
  '',
  'Scans the project folder (the current folder if none is given) and prints the report.',
  'It reads your files and never runs them. It saves nothing unless you ask for --html.',
  '',
  '  --json               print the full report as JSON instead of text, with each',
  "                       finding's fix prompt for an AI coding tool",
  '  --severity <level>   print only findings at this severity or above: high, medium or low',
  '                       (the counts always cover every finding; --json always prints them all)',
  '  --offline            check packages against the advisory data bundled with the scanner,',
  '                       and send nothing anywhere',
  '  --html <file>        also save the report as one web page (a file ending in .html,',
  '                       outside the project folder)',
  '  --help               show this help',
  '  --version            show the version',
  '',
  'Online (the default), the package check sends package names and versions to OSV.dev',
  'to look up known vulnerabilities. Nothing else leaves your computer.',
  '',
  'Exit code 0: the scan finished, with or without findings. 1: the scan could not run.',
  '2: the command was not understood.',
];

// Wall-clock cap on the package check, so a slow network cannot hang a scan.
const DEPENDENCY_DEADLINE_MS = 120_000;
const SEVERITIES: readonly SeverityKey[] = ['high', 'medium', 'low'];

export interface CliIo {
  out: (text: string) => void;
  err: (text: string) => void;
  cwd: string;
  color: boolean;
}

export interface CliArgs {
  folder: string | undefined;
  json: boolean;
  severity: SeverityKey | undefined;
  offline: boolean;
  html: string | undefined;
  help: boolean;
  version: boolean;
}

export class CliError extends Error {}
export class UsageError extends CliError {}

export function parseArgs(argv: readonly string[]): CliArgs {
  const args: CliArgs = { folder: undefined, json: false, severity: undefined, offline: false, html: undefined, help: false, version: false };
  const valueOf = (name: string, i: number, arg: string): [string, number] => {
    if (arg.startsWith(`${name}=`)) return [arg.slice(name.length + 1), i];
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) throw new UsageError(`${name} needs a value.`);
    return [next, i + 1];
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === '--help' || arg === '-h') args.help = true;
    else if (arg === '--version' || arg === '-v') args.version = true;
    else if (arg === '--json') args.json = true;
    else if (arg === '--offline') args.offline = true;
    else if (arg === '--severity' || arg.startsWith('--severity=')) {
      const [value, next] = valueOf('--severity', i, arg);
      i = next;
      const level = value.toLowerCase() as SeverityKey;
      if (!SEVERITIES.includes(level)) throw new UsageError(`--severity takes high, medium or low, not "${value}".`);
      args.severity = level;
    } else if (arg === '--html' || arg.startsWith('--html=')) {
      const [value, next] = valueOf('--html', i, arg);
      i = next;
      if (value === '') throw new UsageError('--html needs a file name.');
      args.html = value;
    } else if (arg.startsWith('-') && arg !== '-') {
      throw new UsageError(`Unknown option: ${arg}`);
    } else if (args.folder === undefined) {
      args.folder = arg;
    } else {
      throw new UsageError('Give one project folder at a time.');
    }
  }
  return args;
}

export async function runCli(argv: readonly string[], io: CliIo): Promise<number> {
  let args: CliArgs;
  try {
    args = parseArgs(argv);
  } catch (error) {
    io.err(`${error instanceof Error ? error.message : String(error)}\n${USAGE}\nRun epherem-scanner --help for details.\n`);
    return 2;
  }
  if (args.help) {
    io.out(`${HELP.join('\n')}\n`);
    return 0;
  }
  if (args.version) {
    io.out(`${VERSION}\n`);
    return 0;
  }
  try {
    return await scanAndReport(args, io);
  } catch (error) {
    io.err(`${plainMessage(error)}\n`);
    // Exit codes: 0 scan finished, 1 could not scan, 2 command not understood.
    return error instanceof UsageError ? 2 : 1;
  }
}

async function scanAndReport(args: CliArgs, io: CliIo): Promise<number> {
  const folder = path.resolve(io.cwd, args.folder ?? '.');
  await requireFolder(folder);
  // Checked before scanning, so a bad --html target fails fast.
  const htmlPath = args.html !== undefined ? await checkHtmlTarget(path.resolve(io.cwd, args.html), folder) : undefined;
  // With --json, stdout carries the JSON alone; status lines go to stderr.
  const say = args.json ? io.err : io.out;

  say(`${modeLine(args.offline)}\nScanning ${folder}\n\n`);
  if (args.json && args.severity !== undefined) io.err('--severity applies to the text report; --json prints every finding.\n');

  const dependencyScanner: DependencyVulnerabilityScanner | undefined = args.offline
    ? new OsvDependencyScanner({ client: new CachedOsvClient() })
    : undefined;
  const report: ScanReport = await scanProject(folder, {
    deadlineMs: DEPENDENCY_DEADLINE_MS,
    watchFolderNames: true,
    ...(dependencyScanner !== undefined ? { dependencyScanner } : {}),
  });

  const projectName = path.basename(folder) || folder;
  if (args.json) {
    io.out(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    io.out(renderTextReport(report, {
      projectName,
      color: io.color,
      ...(args.severity !== undefined ? { minSeverity: args.severity } : {}),
    }));
  }

  if (htmlPath !== undefined) {
    const html = renderHtmlReport(report, { projectName, dependencyMode: args.offline ? 'offline' : 'online', version: VERSION });
    await writeFile(htmlPath, html, 'utf8');
    say(`Saved the report as a web page: ${htmlPath}\n`);
  }

  if (report.statusSummary.state === 'failed') {
    io.err(`The scan did not finish: ${report.statusSummary.headline}\n`);
    return 1;
  }
  return 0;
}

function modeLine(offline: boolean): string {
  if (!offline) {
    return 'Package check: online. Package names and versions are sent to OSV.dev to look up known vulnerabilities. Nothing else leaves this computer. (--offline sends nothing.)';
  }
  const date = datasetDate(safeLoadBundledOsvCache().cache.generatedAt);
  return `Package check: offline, using the advisory data bundled with this scanner${date !== '' ? ` (from ${date})` : ''}. Nothing leaves this computer.`;
}

async function requireFolder(folder: string): Promise<void> {
  let info;
  try {
    info = await stat(folder);
  } catch {
    throw new CliError(`Can't find the folder ${folder}.`);
  }
  if (info.isDirectory()) return;
  // Archives are never opened: folders only.
  if (/\.zip$/i.test(folder)) throw new CliError(`${folder} is a ZIP file. Epherem scans folders: unzip it first, then scan the folder.`);
  throw new CliError(`${folder} is a file, not a folder. Give the folder that holds your project.`);
}

// The only write: a .html file outside the scanned folder, new or our own.
async function checkHtmlTarget(target: string, folder: string): Promise<string> {
  if (!/\.html?$/i.test(target)) throw new UsageError(`--html needs a file name ending in .html, not ${target}.`);
  // Compare real paths, so a link cannot place the report inside the project.
  if (isInside(await canonical(target), await canonical(folder))) {
    throw new CliError(
      `Epherem never saves anything inside the project it scans, and ${target} is inside ${folder}. ` +
        `Choose a file outside it, for example ${path.join(path.dirname(folder), `${path.basename(folder) || 'project'}-epherem-report.html`)}.`,
    );
  }
  const parent = await stat(path.dirname(target)).catch(() => null);
  if (parent === null || !parent.isDirectory()) throw new CliError(`The folder for the HTML report doesn't exist: ${path.dirname(target)}.`);
  const existing = await stat(target).catch(() => null);
  if (existing !== null) {
    // Never overwrite a file this command did not write.
    if (!existing.isFile() || !(await startsLikeOwnReport(target))) {
      throw new CliError(`${target} already exists and isn't an Epherem report, so it was left alone. Choose another file name.`);
    }
  }
  return target;
}

async function startsLikeOwnReport(file: string): Promise<boolean> {
  const handle = await open(file, 'r');
  try {
    const buffer = Buffer.alloc(4096);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    return buffer.subarray(0, bytesRead).toString('utf8').includes(HTML_REPORT_MARKER);
  } finally {
    await handle.close();
  }
}

// Resolve the deepest existing parent, then re-append the missing tail.
export async function canonical(target: string): Promise<string> {
  const rest: string[] = [];
  let current = target;
  for (;;) {
    try {
      return path.join(await realpath(current), ...rest.reverse());
    } catch {
      const parent = path.dirname(current);
      if (parent === current) return target;
      rest.push(path.basename(current));
      current = parent;
    }
  }
}

export function isInside(child: string, parent: string): boolean {
  // Windows paths compare case-insensitively.
  const fold = (p: string): string => (process.platform === 'win32' ? p.toLowerCase() : p);
  const rel = path.relative(fold(parent), fold(child));
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel));
}

function plainMessage(error: unknown): string {
  if (error instanceof CliError) return error.message;
  if (error instanceof ScannerError) return `The scan could not run: ${error.message}`;
  return `The scan could not finish: ${error instanceof Error ? error.message : String(error)}`;
}

export async function main(argv: readonly string[]): Promise<number> {
  return runCli(argv, {
    out: (text) => process.stdout.write(text),
    err: (text) => process.stderr.write(text),
    cwd: process.cwd(),
    color: process.stdout.isTTY === true && process.env.NO_COLOR === undefined,
  });
}

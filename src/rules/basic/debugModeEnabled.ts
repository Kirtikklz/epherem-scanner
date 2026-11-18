import { isScannerInternalPath } from '../../input/fileFilters.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { Confidence, Finding, RuleContext, ScanRule, Severity } from '../../shared/types.js';
import { findMatches, lineAt } from '../../shared/utils.js';
import { stripCommentsOnly, usesHashComments } from '../../shared/source.js';
import { isPythonNonProductionSetting } from '../../shared/pythonSettings.js';
import { isPythonRequirementsPath } from '../../shared/pythonRequirementFiles.js';

const SCANNABLE = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.json', '.yaml', '.yml', '.toml', '.env']);

interface DebugProbe {
  key: string;
  pattern: RegExp;
  severity: Severity;
  confidence: Confidence;
  message: string;
  tech: string;
  fix: string;
}

const PROBES: DebugProbe[] = [
  {
    key: 'flask_debug',
    pattern: /app\.run\s*\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True|FLASK_DEBUG\s*=\s*1/g,
    severity: 'high',
    confidence: 'medium',
    message: 'Your Python web app runs with debug mode on. That exposes an interactive debugger and stack traces to anyone hitting an error, which can allow remote code execution. Turn debug off in production.',
    tech: 'Flask/Django debug mode enabled. Debug exposes the Werkzeug console (RCE) and detailed tracebacks. Drive it from an env var that is false in production.',
    fix: 'Set debug/DEBUG to False in production and control it via an environment variable (e.g. DEBUG = os.environ.get("DEBUG") == "1").',
  },
  {
    key: 'starlette_debug',
    pattern: /\b(?:FastAPI|Starlette)\s*\([^)]*\bdebug\s*=\s*True\b/g,
    severity: 'high',
    confidence: 'medium',
    message: 'Your Python web app is created with debug mode on. Every unhandled error then sends the full traceback, with code and local values, to whoever caused it. Turn debug off in production.',
    tech: 'FastAPI/Starlette is constructed with debug=True, so ServerErrorMiddleware returns the traceback page for unhandled exceptions. Drive it from an env var that is false in production.',
    fix: 'Remove debug=True from the FastAPI()/Starlette() call, or set it from an environment variable that is false in production (e.g. debug=os.environ.get("DEBUG") == "1").',
  },
  {
    key: 'node_env_dev',
    pattern: /NODE_ENV\s*[:=]\s*['"]development['"]/g,
    severity: 'low',
    confidence: 'low',
    message: 'A setting pins the app to development mode. If this ships to production, you lose optimizations and may expose extra debug info. Make sure production sets NODE_ENV=production.',
    tech: 'NODE_ENV is hardcoded to "development". Ensure production deploys set NODE_ENV=production; avoid hardcoding it in committed config.',
    fix: 'Do not hardcode NODE_ENV=development in committed files; set NODE_ENV=production in the production environment.',
  },
];

const DJANGO_FILE = /^(?:(?:INSTALLED_APPS|ROOT_URLCONF|DJANGO_SETTINGS_MODULE)[ \t]*(?::[^=\n]+)?\+?=|(?:from|import)[ \t]+django\b)/m;

function titleKey(probe: DebugProbe, content: string, match: { matchText: string; index: number }): string {
  if (probe.key !== 'flask_debug' || !/^DEBUG\s*=/.test(match.matchText)) return probe.key;
  return content.slice(Math.max(0, match.index - 7), match.index) === 'DJANGO_' || DJANGO_FILE.test(content)
    ? 'django_debug'
    : probe.key;
}

const EXAMPLE_CONFIG_FILE = /\.(?:example|sample|template)$|^(?:example|sample|template)\.env$|^\.env\.(?:example|sample|template)\./i;
const PYTHON_MANIFEST_FILE = /^(?:manage\.py|pyproject\.toml|setup\.py|setup\.cfg|Pipfile)$/;

function pythonAppFolders(context: RuleContext): ReadonlySet<string> {
  const folders = new Set<string>();
  for (const entry of context.fileMap.entries) {
    const path = entry.path.replace(/\\/g, '/');
    const slash = path.lastIndexOf('/');
    if (PYTHON_MANIFEST_FILE.test(path.slice(slash + 1)) || isPythonRequirementsPath(path)) folders.add(path.slice(0, Math.max(slash, 0)));
  }
  return folders;
}

function isPythonExampleConfig(path: string, pythonFolders: ReadonlySet<string>): boolean {
  const normalized = path.replace(/\\/g, '/');
  const slash = normalized.lastIndexOf('/');
  if (!EXAMPLE_CONFIG_FILE.test(normalized.slice(slash + 1))) return false;
  let folder = normalized.slice(0, Math.max(slash, 0));
  for (;;) {
    if (pythonFolders.has(folder)) return true;
    if (folder === '') return false;
    const up = folder.lastIndexOf('/');
    folder = up === -1 ? '' : folder.slice(0, up);
  }
}

export const debugModeEnabled: ScanRule = {
  id: 'debug_mode_enabled',
  title: 'Debug or development mode enabled',
  category: 'configuration',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    let pythonFolders: ReadonlySet<string> | undefined;
    for (const entry of context.fileMap.entries) {
      if (!SCANNABLE.has(entry.extension) && entry.label !== 'env') continue;
      if (isScannerInternalPath(entry.path, context.projectMap.scannerRootPrefix)) continue;
      const hashComments = usesHashComments(entry.extension, entry.label);
      const scanContent = stripCommentsOnly(entry.content, hashComments);
      for (const probe of PROBES) {
        for (const match of findMatches(scanContent, probe.pattern)) {
          if (entry.extension === '.py' && probe.key !== 'node_env_dev'
            && isPythonNonProductionSetting(entry.path, scanContent, match.index)) continue;
          if (probe.key === 'flask_debug'
            && isPythonExampleConfig(entry.path, pythonFolders ??= pythonAppFolders(context))) continue;
          findings.push(
            makeFinding({
              ruleId: this.id,
              title: `${this.title}: ${titleKey(probe, scanContent, match).replace(/_/g, ' ')}`,
              severity: probe.severity,
              confidence: probe.confidence,
              filePath: entry.path,
              lineStart: match.line,
              evidence: lineAt(entry.content, match.line),
              userExplanation: probe.message,
              technicalExplanation: `${entry.path}:${match.line}: ${probe.tech}`,
              fixHint: probe.fix,
              category: this.category,
            }),
          );
        }
      }
    }
    return findings;
  },
};

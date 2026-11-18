import { isGeneratedOrVendorPath } from '../../input/fileFilters.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches } from '../../shared/utils.js';
import { CODE_AND_CONFIG } from './patternRule.js';

const SERVED_OUTPUT_SEGMENT =
  /(^|\/)(?:public|static|wwwroot|www|htdocs|_next|dist|build|out)(\/)/i;

function sitsUnderServedOutput(filePath: string): boolean {
  return SERVED_OUTPUT_SEGMENT.test(filePath.replace(/\\/g, '/'));
}

function mapsOnlyVendoredSources(content: string): boolean | undefined {
  let parsed: { sources?: unknown };
  try {
    parsed = JSON.parse(content) as { sources?: unknown };
  } catch {
    return undefined;
  }
  const sources = parsed.sources;
  if (!Array.isArray(sources) || sources.length === 0) return undefined;
  if (!sources.every((source) => typeof source === 'string')) return undefined;
  return (sources as string[]).every((source) => {
    const path = source.replace(/^[a-z-]+:\/{0,3}/i, '').replace(/^\.\//, '');
    return isGeneratedOrVendorPath(path) || /(^|\/)node_modules\//i.test(path);
  });
}

export const exposedSourceMaps: ScanRule = {
  id: 'exposed_source_maps',
  title: 'Production source maps may expose original source',
  category: 'data_exposure',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const entry of context.fileMap.entries) {
      if (entry.extension === '.map') {
        if (!sitsUnderServedOutput(entry.path)) continue;
        if (mapsOnlyVendoredSources(entry.content) === true) continue;
        findings.push(makeFinding({
          ruleId: this.id, title: this.title, severity: 'medium', confidence: 'medium', filePath: entry.path,
          lineStart: 1, evidence: 'Source map file included in the uploaded project',
          userExplanation: 'A source map may publish original source code, internal file paths, and comments if deployed with public assets.',
          technicalExplanation: `${entry.path}: a .map artefact sits under a directory the web server publishes, and it maps application source. Deployment exposure must be checked.`,
          fixHint: 'Exclude source maps from public deployment, or upload them privately to error monitoring and block public access.', category: this.category,
        }));
      }
      if (!CODE_AND_CONFIG.has(entry.extension)) continue;
      for (const match of findMatches(entry.content, /productionBrowserSourceMaps\s*:\s*true|devtool\s*:\s*['"](?:source-map|inline-source-map|eval-source-map)['"]|sourcemap\s*:\s*true/g)) {
        findings.push(makeFinding({
          ruleId: this.id, title: this.title, severity: 'medium', confidence: 'high', filePath: entry.path,
          lineStart: match.line, evidence: match.snippet,
          userExplanation: 'The production build is configured to emit browser source maps that can reveal original application source.',
          technicalExplanation: `${entry.path}:${match.line}: production-capable source-map generation is enabled.`,
          fixHint: 'Disable publicly deployed production source maps, or send them only to a private error-monitoring service and remove them from served assets.', category: this.category,
        }));
      }
    }
    return findings;
  },
};

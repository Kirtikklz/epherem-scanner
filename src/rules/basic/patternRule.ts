import { isScannerInternalPath } from '../../input/fileFilters.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { Confidence, Finding, FindingCategory, RuleContext, ScanRule, Severity } from '../../shared/types.js';
import { stripCommentsOnly, usesHashComments } from '../../shared/source.js';
import { findMatches, lineAt } from '../../shared/utils.js';

export const CODE = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);
export const CODE_AND_CONFIG = new Set([...CODE, '.json', '.yaml', '.yml', '.toml', '.sql', '.rules']);

export interface Probe {
  pattern: RegExp;
  title: string;
  severity: Severity;
  confidence: Confidence;
  explanation: string;
  technical: string;
  fix: string;
  suppress?: (match: { content: string; index: number; matchText: string; line: number; path: string }) => boolean;
}

export interface PatternRuleOptions {
  id: string;
  title: string;
  category: FindingCategory;
  extensions?: ReadonlySet<string>;
  probes: readonly Probe[];
  fileFilter?: (path: string, content: string) => boolean;
}

export function patternRule(options: PatternRuleOptions): ScanRule {
  return {
    id: options.id,
    title: options.title,
    category: options.category,
    kind: 'basic',
    run(context: RuleContext): Finding[] {
      const findings: Finding[] = [];
      for (const entry of context.fileMap.entries) {
        if (!(options.extensions ?? CODE).has(entry.extension)) continue;
        if (isScannerInternalPath(entry.path, context.projectMap.scannerRootPrefix)) continue;
        if (options.fileFilter !== undefined && !options.fileFilter(entry.path, entry.content)) continue;
        const scanContent = stripCommentsOnly(entry.content, usesHashComments(entry.extension, entry.label));
        for (const probe of options.probes) {
          for (const match of findMatches(scanContent, probe.pattern)) {
            if (probe.suppress?.({
              content: scanContent,
              index: match.index,
              matchText: match.matchText,
              line: match.line,
              path: entry.path,
            }) === true) continue;
            findings.push(makeFinding({
              ruleId: this.id,
              title: `${this.title}: ${probe.title}`,
              severity: probe.severity,
              confidence: probe.confidence,
              filePath: entry.path,
              lineStart: match.line,
              evidence: lineAt(entry.content, match.line),
              userExplanation: probe.explanation,
              technicalExplanation: `${entry.path}:${match.line}: ${probe.technical}`,
              fixHint: probe.fix,
              category: this.category,
            }));
          }
        }
      }
      return findings;
    },
  };
}

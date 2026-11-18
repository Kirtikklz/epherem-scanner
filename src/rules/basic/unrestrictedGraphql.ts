import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches } from '../../shared/utils.js';
import { CODE, type Probe } from './patternRule.js';

export const unrestrictedGraphql: ScanRule = {
  id: 'unrestricted_graphql',
  title: 'GraphQL server permits unrestricted operations',
  category: 'configuration',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const entry of context.fileMap.entries) {
      if (!CODE.has(entry.extension) || !/(?:apollo|graphql|createYoga|mercurius)/i.test(entry.content)) continue;
      const probes: Probe[] = [
        {
          pattern: /\b(?:introspection|playground)\s*:\s*true\b/g,
          title: 'production discovery feature enabled', severity: 'medium', confidence: 'high',
          explanation: 'GraphQL introspection or the interactive playground is explicitly enabled. In production this can expose the full API schema and ease automated probing.',
          technical: 'A GraphQL discovery/development feature is unconditionally enabled.',
          fix: 'Disable playground/introspection in production unless intentionally public and protected; keep authenticated developer access separate.',
        },
      ];
      for (const probe of probes) {
        for (const match of findMatches(entry.content, probe.pattern)) {
          findings.push(makeFinding({ ruleId: this.id, title: `${this.title}: ${probe.title}`, severity: probe.severity,
            confidence: probe.confidence, filePath: entry.path, lineStart: match.line, evidence: match.snippet,
            userExplanation: probe.explanation, technicalExplanation: `${entry.path}:${match.line}: ${probe.technical}`,
            fixHint: probe.fix, category: this.category }));
        }
      }
      const hasServer = /(?:ApolloServer|createYoga|mercurius)\s*\(/.test(entry.content);
      const hasCostControl = /depthLimit|maxDepth|complexity|costLimit|maxComplexity|graphql-query-complexity/i.test(entry.content);
      if (hasServer && !hasCostControl) {
        const match = findMatches(entry.content, /(?:ApolloServer|createYoga|mercurius)\s*\(/g)[0];
        if (match !== undefined) findings.push(makeFinding({
          ruleId: this.id, title: `${this.title}: no query cost limit`, severity: 'high', confidence: 'medium',
          filePath: entry.path, lineStart: match.line, evidence: match.snippet,
          userExplanation: 'The GraphQL server has no visible depth or complexity limit. A deeply nested or expensive query can exhaust CPU, memory, or database capacity.',
          technicalExplanation: `${entry.path}:${match.line}: server construction has no visible query depth/complexity control in this file.`,
          fixHint: 'Enforce query depth and complexity/cost limits, cap aliases and batch size, use pagination limits, timeouts, and per-user rate limits.',
          category: this.category,
        }));
      }
    }
    return findings;
  },
};

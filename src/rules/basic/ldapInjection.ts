import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches, lineAt } from '../../shared/utils.js';
import { routeHandlerScopeForLine } from '../../shared/handlerScope.js';

const CODE = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);
const LDAP_SEARCH = /\.(?:search|bind)\s*\(|ldap3?\.|ldapjs|ldap\.initialize|ldap\.filter/g;
const LDAP_FILTER_WITH_INPUT = /\([^)]*\$\{\s*(?:req|request)\.|['"][^'"\n]*(?:uid|cn|mail|memberOf)=[^'"\n]*['"]\s*\+\s*(?:req|request)\.|f['"][^'"\n]*(?:uid|cn|mail|memberOf)=\{[^}]+\}/i;
const ESCAPED = /escapeFilter|ldapEscape|escapeLDAP|Filter\.escape|ldap\.filter/i;

export const ldapInjection: ScanRule = {
  id: 'ldap_injection',
  title: 'Possible LDAP injection from unsafe filter construction',
  category: 'injection',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const entry of context.fileMap.entries) {
      if (!CODE.has(entry.extension)) continue;
      for (const match of findMatches(entry.content, LDAP_SEARCH)) {
        const scope = routeHandlerScopeForLine(entry.content, match.line);
        if (!LDAP_FILTER_WITH_INPUT.test(scope)) continue;
        if (ESCAPED.test(scope)) continue;
        findings.push(makeFinding({
          ruleId: this.id,
          title: this.title,
          severity: 'high',
          confidence: 'medium',
          filePath: entry.path,
          lineStart: match.line,
          evidence: lineAt(entry.content, match.line),
          userExplanation: 'This LDAP filter appears to include request input directly. Attackers can inject LDAP filter syntax to bypass authentication or search outside the intended scope.',
          technicalExplanation: `${entry.path}:${match.line} constructs an LDAP filter with request-derived input and no visible LDAP escaping.`,
          fixHint: 'Escape LDAP filter metacharacters with a maintained LDAP escaping helper, or use a filter builder/parameterized API that treats values as data.',
          category: this.category,
        }));
      }
    }
    return findings;
  },
};

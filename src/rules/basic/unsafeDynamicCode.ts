import { analyzeFileAst, astVerdict, confidenceWithProof, userTaintedLines } from '../../ast/astAnalysis.js';
import { crossFileAstHits } from '../../ast/crossFileTaint.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches, lineAt } from '../../shared/utils.js';
import { stripCommentsOnly, usesHashComments } from '../../shared/source.js';
import { CODE, type Probe } from './patternRule.js';

const PROBES: readonly Probe[] = [
  {
    pattern: /\beval\s*\(\s*(?:req\.(?:body|query|params)|request\.(?:args|form|json)|input\s*\(|[a-z_$][\w$]*)/gi,
    title: 'eval call', severity: 'high', confidence: 'medium',
    explanation: 'The application evaluates a runtime value as code. If an attacker controls any part of it, they can execute arbitrary commands in the application process.',
    technical: 'eval is called with a non-literal expression and cannot provide a safe trust boundary.',
    fix: 'Remove eval and parse the input as a strict data format or map an allowlisted command name to a fixed function.',
  },
  {
    pattern: /\bnew\s+Function\s*\(\s*(?!['"`][^'"`]*['"`]\s*\))/g,
    title: 'Function constructor', severity: 'critical', confidence: 'medium',
    explanation: 'The Function constructor compiles a runtime string as executable JavaScript.',
    technical: 'new Function is equivalent to eval for attacker-controlled strings.',
    fix: 'Replace dynamic compilation with fixed functions selected through an allowlist; treat submitted expressions as data, not code.',
  },
  {
    pattern: /\b(?:setTimeout|setInterval)\s*\(\s*(?:['"][^'"]*['"]|`[^`]*\$\{[^`]*`|[A-Za-z_$][\w$]*\s*\+[^,]+|[^,]+\+\s*[A-Za-z_$][\w$]*)\s*,/gi,
    title: 'string timer callback', severity: 'high', confidence: 'low',
    explanation: 'A runtime value may be executed as a timer callback string.',
    technical: 'Browser and Node timers evaluate string callbacks as code. Function references such as setTimeout(resolve, ms) are intentionally not reported.',
    fix: 'Pass a real function callback, never a string assembled from input.',
  },
];

const PYTHON_PROBES: readonly Probe[] = [
  {
    pattern: /(?<![\w.])exec\s*\(\s*(?:request\.(?:args|form|json|values|data|get_json)|input\s*\(|(?![A-Z][A-Z0-9_]*\s*[,)])(?![\w.]*\.read_text\s*\()(?!open\s*\()[A-Za-z_]\w*)/g,
    title: 'exec call', severity: 'high', confidence: 'medium',
    explanation: 'The application runs a runtime value as Python code. If an attacker controls any part of it, they can run any code they like on your server.',
    technical: 'exec is called with a non-literal expression and cannot provide a safe trust boundary.',
    fix: 'Remove exec. Parse the input as data (json.loads, a strict format), or map an allowlisted command name to a fixed function.',
  },
  {
    pattern: /(?<![\w.])render_template_string\s*\(\s*(?:[rbRB]?[fF][rbRB]?["']|["'][^"'\n]*["']\s*(?:%|\+|\.\s*format\s*\()|(?![A-Z][A-Z0-9_]*\s*[,)])[A-Za-z_][\w.]*\s*(?:[,)+%]|\[))/g,
    title: 'template built from a runtime string', severity: 'high', confidence: 'medium',
    explanation: 'This page template is put together from a runtime value before Jinja compiles it. If anything a user typed becomes part of the template text, they can run code on your server (server-side template injection).',
    technical: 'render_template_string compiles its first argument as a Jinja template; here that argument is formatted, joined or passed in as a variable rather than written as a fixed template.',
    fix: 'Pass a fixed template and give the values as arguments: render_template_string("<h1>Hi {{ name }}</h1>", name=name), or move the template to a file and use render_template.',
  },
];

export const unsafeDynamicCode: ScanRule = {
  id: 'unsafe_dynamic_code',
  title: 'Dynamic code execution may evaluate untrusted input',
  category: 'injection',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const entry of context.fileMap.entries) {
      if (!CODE.has(entry.extension)) continue;
      const ast = analyzeFileAst(entry.path, entry.content, entry.extension, crossFileAstHits(context.projectMap.crossFileTaint, entry.path));
      const scanContent = stripCommentsOnly(entry.content, usesHashComments(entry.extension, entry.label));
      const seen = new Set<number>();
      for (const probe of entry.extension === '.py' ? [...PROBES, ...PYTHON_PROBES] : PROBES) {
        for (const match of findMatches(scanContent, probe.pattern)) {
          if (seen.has(match.line)) continue;
          if (entry.extension === '.py' && probe === PROBES[0] && /\.\s*$/.test(scanContent.slice(Math.max(0, match.index - 40), match.index))) continue;
          const verdict = astVerdict(ast, 'dynamic_code', match.line);
          if (verdict === 'suppress' && probe.title !== 'string timer callback') continue;
          seen.add(match.line);
          findings.push(makeFinding({
            ruleId: this.id,
            title: `${this.title}: ${probe.title}`,
            severity: verdict === 'confirm' ? 'critical' : probe.severity,
            confidence: confidenceWithProof(verdict, probe.confidence),
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
      for (const [line] of userTaintedLines(ast, 'dynamic_code')) {
        if (seen.has(line)) continue;
        seen.add(line);
        findings.push(makeFinding({
          ruleId: this.id,
          title: `${this.title}: evaluator receives user input`,
          severity: 'critical',
          confidence: 'high',
          filePath: entry.path,
          lineStart: line,
          evidence: lineAt(entry.content, line),
          userExplanation: 'A code evaluator (eval/new Function/string timer) receives a value derived from user input, allowing arbitrary code execution.',
          technicalExplanation: `${entry.path}:${line}: syntax-aware analysis traced request-derived data into a dynamic code evaluator.`,
          fixHint: 'Remove dynamic evaluation; treat submitted expressions as data and select behaviour through allowlisted mappings.',
          category: this.category,
        }));
      }
    }
    return findings;
  },
};

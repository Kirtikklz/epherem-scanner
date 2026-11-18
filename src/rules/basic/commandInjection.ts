import { analyzeFileAst, astVerdict, confidenceWithProof, userTaintedLines } from '../../ast/astAnalysis.js';
import { crossFileAstHits } from '../../ast/crossFileTaint.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches, lineAt } from '../../shared/utils.js';
import { windowAround } from '../../shared/userInput.js';
import { analyzeTaint, usesUserInput } from '../../shared/taint.js';

const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);

const JS_EXEC =
  /\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(\s*(`[^`]*\$\{[^`]*`|['"][^'"]*['"]\s*\+|[A-Za-z_$][\w$.]*\s*\+)/g;
const PY_SHELL =
  /\b(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output))\s*\([^)]*(?:f["']|["'][^"']*["']\s*[+%]|\+\s*\w|shell\s*=\s*True)/g;

export const commandInjection: ScanRule = {
  id: 'command_injection',
  title: 'Possible command injection into an OS command',
  category: 'injection',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const entry of context.fileMap.entries) {
      if (!CODE_EXTENSIONS.has(entry.extension)) continue;
      const taint = analyzeTaint(entry.content);
      const ast = analyzeFileAst(entry.path, entry.content, entry.extension, crossFileAstHits(context.projectMap.crossFileTaint, entry.path));
      const seen = new Set<number>();
      for (const pattern of [JS_EXEC, PY_SHELL]) {
        for (const match of findMatches(entry.content, pattern)) {
          if (seen.has(match.line)) continue;
          const verdict = astVerdict(ast, 'command', match.line);
          if (verdict === 'suppress') continue;
          const scope = windowAround(entry.content, match.index, 360);
          const shellTrue = /shell\s*=\s*True/.test(match.matchText);
          if (verdict !== 'confirm' && !shellTrue && !usesUserInput(scope, taint, match.index)) continue;
          seen.add(match.line);
          findings.push(
            makeFinding({
              ruleId: this.id,
              title: this.title,
              severity: 'critical',
              confidence: confidenceWithProof(verdict, 'medium'),
              filePath: entry.path,
              lineStart: match.line,
              evidence: match.snippet,
              userExplanation:
                'This code runs an operating-system command whose text includes values that may come from the user. An attacker can inject extra commands and take control of the server. Pass arguments as a list and never build the command from user input.',
              technicalExplanation:
                `${entry.path}:${match.line} invokes a shell/exec sink with a dynamically built command (or shell=True) while user input is in scope. Use argument arrays (execFile/spawn with args[]) and avoid a shell; validate/allowlist any user-provided values.`,
              fixHint:
                'Use the array form of spawn/execFile (no shell), pass user values as separate arguments, and allowlist expected values. In Python use subprocess.run([...], shell=False). Never concatenate user input into a command string.',
              category: this.category,
            }),
          );
        }
      }
      for (const [line] of userTaintedLines(ast, 'command')) {
        if (seen.has(line)) continue;
        seen.add(line);
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'critical',
            confidence: 'high',
            filePath: entry.path,
            lineStart: line,
            evidence: lineAt(entry.content, line),
            userExplanation:
              'This code runs an operating-system command built from user input. An attacker can inject extra commands and take control of the server.',
            technicalExplanation:
              `${entry.path}:${line}: syntax-aware analysis traced request-derived data into a shell/exec sink. Use execFile/spawn with argument arrays and validate inputs.`,
            fixHint:
              'Do not build a shell command from user input. Use a parameterized process API (execFile/spawn with an argument array and shell:false), a fixed command name, and an allowlist of permitted arguments; validate any user value used as an argument. Preserve the intended command behavior.',
            category: this.category,
          }),
        );
      }
    }
    return findings;
  },
};

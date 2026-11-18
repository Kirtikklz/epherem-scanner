import { analyzeFileAst, astVerdict, confidenceWithProof, userTaintedLines } from '../../ast/astAnalysis.js';
import { crossFileAstHits } from '../../ast/crossFileTaint.js';
import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches, lineAt } from '../../shared/utils.js';
import { referencesUserInput, windowAround } from '../../shared/userInput.js';
import { analyzeTaint, classifyExpression, type TaintMap } from '../../shared/taint.js';
import { routeHandlerScopeForLine } from '../../shared/handlerScope.js';
import { pythonCallArguments, pythonCheckActsBefore, pythonDependencyAliases, pythonFileHasSources, pythonFunctionSpan, pythonIdentifiers, pythonValueReaches, type FollowOptions } from '../../shared/pythonFlow.js';

const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);

const JS_FS_SINK =
  /\b(?:fs|fsp|fs\.promises)\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync|readdir|readdirSync|sendFile|stat|statSync|open|openSync)\s*\(/g;
const JS_SENDFILE = /\.sendFile\s*\(/g;

const PY_FS_SINK = /(?<![.\w$])(?:open|os\.remove|os\.unlink|send_file)\s*\(/g;

const PY_FILE_RESPONSE = /(?<![.\w$])FileResponse\s*\(/g;

function sinkPatternsFor(extension: string): RegExp[] {
  return extension === '.py' ? [PY_FS_SINK, PY_FILE_RESPONSE] : [JS_FS_SINK, JS_SENDFILE];
}

function pythonPathReaches(content: string, openParen: number, opts: FollowOptions): boolean {
  const first = pythonCallArguments(content, openParen)[0];
  if (first === undefined || !pythonValueReaches(content, first.start, first.end, opts)) return false;
  const names = [...pythonIdentifiers(content.slice(first.start, first.end))].filter((n) => !/^(?:open|str|os|path|join)$/.test(n));
  return !pythonCheckActsBefore(content, openParen, (condition) => names.some((n) =>
    new RegExp(String.raw`\b${n}\s*\.\s*is_relative_to\s*\(|commonpath\s*\([^)]*\b${n}\b`).test(condition)));
}

// process.argv is the operator's input, not a request's.
const ARGV_READ = /\bprocess\.argv\b/g;

function readsRequestInput(content: string): boolean {
  return referencesUserInput(content.replace(ARGV_READ, 'process.commandLine'));
}

// Real confinement only: path.resolve alone does not stop ../ escapes.
const CONFINEMENT_GUARD =
  /path\.basename\s*\(|os\.path\.basename\s*\(|secure_filename\s*\(|send_from_directory\s*\(|startsWith\s*\(\s*[^)]*\+\s*(?:path\.sep\b|['"`][/\\])|startsWith\s*\(\s*[`][^`]*\$\{[^}]*\}[/\\]/i;

// The path argument itself must carry request data; nearby mentions do not.
function argumentCarriesUserInput(arg: string, taint: TaintMap, at: number): boolean {
  if (referencesUserInput(arg)) return true;
  for (const identifier of arg.match(/[A-Za-z_$][\w$]*/g) ?? []) {
    if (taint.kindAt(identifier, at) === 'user') return true;
  }
  return false;
}

// Without a dataflow model (e.g. Python), proximity is the only evidence.
function hasDataflowModel(extension: string): boolean {
  return extension !== '.py';
}

function firstArg(content: string, openParenIndex: number): string {
  let depth = 0;
  let out = '';
  for (let i = openParenIndex; i < content.length && i < openParenIndex + 300; i += 1) {
    const ch = content[i] ?? '';
    if (ch === '(') { depth += 1; if (depth === 1) continue; }
    if (ch === ')') { depth -= 1; if (depth === 0) break; }
    if (ch === ',' && depth === 1) break;
    out += ch;
  }
  return out.trim();
}

export const pathTraversal: ScanRule = {
  id: 'path_traversal',
  title: 'Possible path traversal from user-controlled file path',
  category: 'path_traversal',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const entry of context.fileMap.entries) {
      if (!CODE_EXTENSIONS.has(entry.extension)) continue;
      const taint = analyzeTaint(entry.content);
      const crossFile = crossFileAstHits(context.projectMap.crossFileTaint, entry.path);
      if (crossFile.length === 0 && !readsRequestInput(entry.content) && !(entry.extension === '.py' && pythonFileHasSources(entry.content))) continue;
      const ast = analyzeFileAst(entry.path, entry.content, entry.extension, crossFile);
      const seen = new Set<number>();

      for (const pattern of sinkPatternsFor(entry.extension)) {
        for (const match of findMatches(entry.content, pattern)) {
          if (seen.has(match.line)) continue;
          const verdict = astVerdict(ast, 'path', match.line);
          if (verdict === 'suppress') continue;
          const openParen = entry.content.indexOf('(', match.index);
          const arg = openParen === -1 ? '' : firstArg(entry.content, openParen);

          const scope = windowAround(entry.content, match.index, 260);
          const argKind = classifyExpression(arg, taint, match.index);
          const followed = entry.extension === '.py' && openParen !== -1 && pythonPathReaches(entry.content, openParen, { aliases: pythonDependencyAliases(context.fileMap.entries) });
          const userControlled = pattern === PY_FILE_RESPONSE ? followed : (
            argKind === 'user' ||
            argumentCarriesUserInput(arg, taint, match.index) ||
            (!hasDataflowModel(entry.extension) && referencesUserInput(scope)) ||
            followed);
          if (verdict !== 'confirm' && !userControlled) continue;

          const fn = followed ? pythonFunctionSpan(entry.content, match.index) : undefined;
          const guardScope = fn === undefined ? scope : entry.content.slice(
            Math.max(fn.from, match.index - 260), Math.min(fn.to, match.index + 260));
          if (CONFINEMENT_GUARD.test(guardScope)) continue;

          seen.add(match.line);
          findings.push(
            makeFinding({
              ruleId: this.id,
              title: this.title,
              severity: 'high',
              confidence: confidenceWithProof(verdict, 'medium'),
              filePath: entry.path,
              lineStart: match.line,
              evidence: match.snippet,
              userExplanation:
                'This code opens or sends a file using a path that includes user input, with no check that keeps it inside an allowed folder. Note that path.resolve() alone does not help — an attacker can still use "../" or an absolute path to reach files like /etc/passwd. Confine the path to a safe base directory.',
              technicalExplanation:
                `${entry.path}:${match.line} passes user-influenced input to a filesystem sink without a confinement guard. path.resolve() normalises but does not confine; verify the resolved path stays inside the base (path.relative has no ".." / prefix check including the separator), or reduce the input to path.basename().`,
              fixHint:
                'Resolve the path against a fixed base, then confirm it stays inside: e.g. const full = path.resolve(base, name); if (!full.startsWith(base + path.sep)) throw. Or reduce the input to path.basename() when only a filename is valid.',
              category: this.category,
            }),
          );
        }
      }
      for (const [line] of userTaintedLines(ast, 'path')) {
        if (seen.has(line)) continue;
        if (CONFINEMENT_GUARD.test(routeHandlerScopeForLine(entry.content, line))) continue;
        seen.add(line);
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: this.title,
            severity: 'high',
            confidence: 'high',
            filePath: entry.path,
            lineStart: line,
            evidence: lineAt(entry.content, line),
            userExplanation:
              'This code opens or sends a file using a path that includes user input, with no check that keeps it inside an allowed folder.',
            technicalExplanation:
              `${entry.path}:${line}: syntax-aware analysis traced request-derived data into a filesystem sink without a confinement guard in this file.`,
            fixHint:
              'Resolve the user-supplied path against a fixed base directory and confirm the result stays inside it (e.g. const p = path.resolve(BASE, userPath); if (!p.startsWith(BASE + path.sep)) reject). Reject "..", encoded traversal, and absolute paths, and never pass raw request input to fs.*/res.sendFile. Keep the intended file access working for valid names.',
            category: this.category,
          }),
        );
      }
    }
    return findings;
  },
};

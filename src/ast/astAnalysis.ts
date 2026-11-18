// Parser only: project code is never executed, imported or type-checked.
import type { Confidence } from '../shared/types.js';
import { AsyncLocalStorage } from 'node:async_hooks';
import ts from 'typescript';
import { collectCalleeProvenance, isShellExecCallee, type CalleeProvenance } from '../shared/shellCommandSink.js';
import { CappedNames } from '../shared/cappedNames.js';

export const MAX_AST_FILE_BYTES = 400_000;
export const MAX_AST_NODES_PER_FILE = 300_000;
export const MAX_AST_NODES_PER_SCAN = 3_000_000;

export type TaintLevel = 'user' | 'trusted' | 'sanitized' | 'literal' | 'unknown';

export type SinkKind =
  | 'sql'
  | 'command'
  | 'path'
  | 'request'
  | 'redirect'
  | 'html'
  | 'dynamic_code';

export interface AstSinkHit {
  kind: SinkKind;
  line: number;
  taint: TaintLevel;
  callee: string;
}

export interface AstFileAnalysis {
  parsed: true;
  hits: AstSinkHit[];
  incomplete?: 'node-budget' | 'scan-budget';
}

export type AstGapReason = 'node-budget' | 'scan-budget' | 'too-large';

export type AstAnalysisGaps = Readonly<Record<AstGapReason, CappedNames>>;

export interface AstCacheOptions {
  nodesPerScan?: number;
  recordGaps?: boolean;
}

const MAX_DEGRADED_NAMED = 5;

interface AstScanState {
  cache: Map<string, AstFileAnalysis | undefined>;
  nodesRemaining: number;
  degraded: CappedNames;
  gaps?: AstAnalysisGaps;
}

const astStore = new AsyncLocalStorage<AstScanState>();

export function runWithAstCache<T>(fn: () => T, options: AstCacheOptions = {}): T {
  return astStore.run(
    {
      cache: new Map(),
      nodesRemaining: options.nodesPerScan ?? MAX_AST_NODES_PER_SCAN,
      degraded: new CappedNames(MAX_DEGRADED_NAMED),
      ...(options.recordGaps === false
        ? {}
        : { gaps: { 'node-budget': new CappedNames(), 'scan-budget': new CappedNames(), 'too-large': new CappedNames() } }),
    },
    fn,
  );
}

export function astAnalysisGaps(): AstAnalysisGaps | undefined {
  return astStore.getStore()?.gaps;
}

export function degradedAstFiles(): string[] {
  return [...(astStore.getStore()?.degraded.named ?? [])].sort((a, b) => a.localeCompare(b));
}

export function degradedAstFilesUnnamed(): number {
  return astStore.getStore()?.degraded.unnamed ?? 0;
}

const JS_TS_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

export function isAstAnalyzable(extension: string): boolean {
  return JS_TS_EXTENSIONS.has(extension);
}

function scriptKindFor(extension: string): ts.ScriptKind {
  switch (extension) {
    case '.tsx':
      return ts.ScriptKind.TSX;
    case '.ts':
      return ts.ScriptKind.TS;
    case '.jsx':
      return ts.ScriptKind.JSX;
    default:
      return ts.ScriptKind.JS;
  }
}

const USER_SOURCE_TEXT =
  /\breq(?:uest)?\.(?:body|query|params|headers|cookies|url|originalUrl)\b|\bsearchParams\b|\bformData\.get\s*\(|\bevent\.(?:body|queryStringParameters|pathParameters)\b|\bctx\.(?:request|query|params)\b|\bparams\.[A-Za-z_$]|\bprocess\.argv\b|\buseSearchParams\b/;

const USER_CALL_TEXT = /\breq(?:uest)?\.(?:json|text|formData)\s*\(|\bformData\.get\s*\(|\bsearchParams\.get\s*\(/;

const TRUSTED_TEXT =
  /\bsession\s*[?.]|\breq\.session\b|\bres\.locals\.user\b|\bctx\.state\.user\b|\bgetServerSession\s*\(\s*\)|\bgetSession\s*\(\s*\)|\bgetUser\s*\(\s*\)|\bcurrentUser\b|\bauth\s*\(\s*\)|\bverifyIdToken\s*\(|\bjwt\.verify\s*\(|\bverifyToken\s*\(|\bdecodedToken\b/;

const SANITIZER_NAME =
  /(?:^|\.)(?:encodeURIComponent|encodeURI|parseInt|parseFloat|basename|secure_filename|slugify|cleanPath|cleanUrl|resolveSafe)$/i;

function maxTaint(a: TaintLevel, b: TaintLevel): TaintLevel {
  const order: TaintLevel[] = ['user', 'unknown', 'sanitized', 'trusted', 'literal'];
  return order.indexOf(a) <= order.indexOf(b) ? a : b;
}

interface HelperSummary {
  returnsParamDerived: boolean;
  returnTaint: TaintLevel;
}

interface FileEnv {
  vars: Map<string, TaintLevel>;
  helpers: Map<string, HelperSummary>;
  sf: ts.SourceFile;
}

const FS_PATH_METHODS = new Set([
  'readFile', 'readFileSync', 'createReadStream', 'createWriteStream', 'writeFile', 'writeFileSync',
  'appendFile', 'appendFileSync', 'unlink', 'unlinkSync', 'rm', 'rmSync', 'readdir', 'readdirSync',
  'stat', 'statSync', 'open', 'openSync', 'mkdir', 'mkdirSync', 'copyFile', 'copyFileSync',
]);

const REQUEST_BASES = new Set(['axios', 'got', 'superagent', 'http', 'https', 'undici', 'ky', 'request']);

const REDIRECT_STATUS_LITERAL = /^3\d\d$/;

export function redirectDestination(args: readonly ts.Expression[]): ts.Expression | undefined {
  const first = args[0];
  if (first === undefined) return undefined;
  const second = args[1];
  if (second !== undefined && ts.isNumericLiteral(first) && REDIRECT_STATUS_LITERAL.test(first.text)) return second;
  return first;
}
const REQUEST_METHODS = new Set(['get', 'post', 'put', 'delete', 'patch', 'head', 'request', 'fetch', 'stream']);

const SQL_VERBS = /\b(?:SELECT|INSERT|UPDATE|DELETE|UPSERT|DROP|ALTER|CREATE|WITH|FROM|WHERE)\b/i;
const KNOWN_SQL_RECEIVERS = /^(?:db|pool|client|conn|connection|database|knex|sequelize|prisma|sql|drizzle|dataSource|repository|repo|entityManager|manager)(?:\.|$)/i;

function expressionLooksSql(node: ts.Expression, sf: ts.SourceFile): boolean {
  const text = node.getText(sf);
  return SQL_VERBS.test(text);
}

function isRecognizedSqlSink(calleeText: string, arg0: ts.Expression | undefined, sf: ts.SourceFile): boolean {
  if (arg0 === undefined) return false;
  if (/\$(?:queryRawUnsafe|executeRawUnsafe)$/.test(calleeText)) return true;
  if (/(?:^|\.)(?:query|execute|raw)$/.test(calleeText)) {
    return KNOWN_SQL_RECEIVERS.test(calleeText) || expressionLooksSql(arg0, sf);
  }
  return false;
}

export function analyzeFileAst(
  path: string,
  content: string,
  extension: string,
  additionalHits: readonly AstSinkHit[] = [],
): AstFileAnalysis | undefined {
  if (!isAstAnalyzable(extension)) return undefined;

  const state = astStore.getStore();
  if (content.length > MAX_AST_FILE_BYTES) {
    state?.gaps?.['too-large'].add(path);
    return undefined;
  }

  if (state !== undefined) {
    if (state.cache.has(path)) return state.cache.get(path);
    if (state.nodesRemaining <= 0) {
      state.gaps?.['scan-budget'].add(path);
      state.cache.set(path, undefined);
      return undefined;
    }
  }

  const result = analyzeUncached(path, content, extension, state);
  const merged = result === undefined ? undefined : mergeAstHits(result, additionalHits);
  state?.cache.set(path, merged);
  return merged;
}

function mergeAstHits(analysis: AstFileAnalysis, additional: readonly AstSinkHit[]): AstFileAnalysis {
  if (additional.length === 0) return analysis;
  const hits = new Map<string, AstSinkHit>();
  for (const hit of [...analysis.hits, ...additional]) {
    hits.set(`${hit.kind}\0${hit.line}\0${hit.taint}\0${hit.callee}`, hit);
  }
  return {
    parsed: true,
    hits: [...hits.values()].sort((a, b) => a.line - b.line || a.kind.localeCompare(b.kind) || a.callee.localeCompare(b.callee)),
    ...(analysis.incomplete !== undefined ? { incomplete: analysis.incomplete } : {}),
  };
}

function analyzeUncached(
  path: string,
  content: string,
  extension: string,
  state: AstScanState | undefined,
): AstFileAnalysis | undefined {
  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile(path, content, ts.ScriptTarget.Latest,  false, scriptKindFor(extension));
  } catch {
    return undefined;
  }

  const fileBudget = { remaining: Math.min(MAX_AST_NODES_PER_FILE, state?.nodesRemaining ?? MAX_AST_NODES_PER_FILE) };
  const spent = (): number => Math.min(MAX_AST_NODES_PER_FILE, state?.nodesRemaining ?? MAX_AST_NODES_PER_FILE) - fileBudget.remaining;
  let cut = false;
  const budgetSpent = (): boolean => {
    if (fileBudget.remaining > 0) return false;
    cut = true;
    return true;
  };

  const env: FileEnv = { vars: new Map(), helpers: new Map(), sf };
  const hits: AstSinkHit[] = [];

  const calleeProvenance: CalleeProvenance = collectCalleeProvenance(sf);

  const functionBindings = new Set<string>();

  const paramTypeMayBeString = (param: ts.ParameterDeclaration): boolean => {
    const typeNode = param.type;
    if (typeNode === undefined) return false;
    if (typeNode.kind === ts.SyntaxKind.StringKeyword || typeNode.kind === ts.SyntaxKind.AnyKeyword) return true;
    if (ts.isUnionTypeNode(typeNode)) {
      return typeNode.types.some((member) => member.kind === ts.SyntaxKind.StringKeyword || member.kind === ts.SyntaxKind.AnyKeyword);
    }
    if (ts.isLiteralTypeNode(typeNode) && ts.isStringLiteralLike(typeNode.literal)) return true;
    return false;
  };

  const lineOf = (node: ts.Node): number => sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;

  const text = (node: ts.Node): string => {
    try {
      return content.slice(node.getStart(sf), node.end);
    } catch {
      return '';
    }
  };

  const classify = (node: ts.Expression): TaintLevel => {
    if (ts.isStringLiteralLike(node) || ts.isNumericLiteral(node)) return 'literal';
    if (node.kind === ts.SyntaxKind.TrueKeyword || node.kind === ts.SyntaxKind.FalseKeyword) return 'literal';
    if (ts.isTemplateExpression(node)) {
      let level: TaintLevel = 'literal';
      for (const span of node.templateSpans) level = maxTaint(level, classify(span.expression));
      return level;
    }
    if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isNonNullExpression(node)) {
      return classify(node.expression);
    }
    if (ts.isAwaitExpression(node)) return classify(node.expression);
    if (ts.isBinaryExpression(node)) {
      if (node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
        return maxTaint(classify(node.left), classify(node.right));
      }
      if (node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken || node.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
        return maxTaint(classify(node.left), classify(node.right));
      }
      return 'unknown';
    }
    if (ts.isConditionalExpression(node)) {
      return maxTaint(classify(node.whenTrue), classify(node.whenFalse));
    }
    if (ts.isIdentifier(node)) {
      return env.vars.get(node.text) ?? 'unknown';
    }
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const t = text(node);
      const leading = /^([A-Za-z_$][\w$]*)/.exec(t);
      if (leading?.[1] !== undefined && env.vars.has(leading[1])) {
        return env.vars.get(leading[1]) ?? 'unknown';
      }
      if (USER_SOURCE_TEXT.test(t)) return 'user';
      if (TRUSTED_TEXT.test(t)) return 'trusted';
      return 'unknown';
    }
    if (ts.isNewExpression(node)) {
      if (ts.isIdentifier(node.expression) && node.expression.text === 'URL') {
        const first = node.arguments?.[0];
        return first !== undefined ? classify(first) : 'unknown';
      }
      return 'unknown';
    }
    if (ts.isTaggedTemplateExpression(node)) {
      const tag = text(node.tag);
      if (tag === 'sql' || tag.endsWith('.sql') || tag === 'prisma.$queryRaw' || tag.endsWith('.$queryRaw')) return 'sanitized';
      return ts.isTemplateExpression(node.template) ? classify(node.template) : 'literal';
    }
    if (ts.isCallExpression(node)) {
      const calleeText = text(node.expression);
      if (USER_CALL_TEXT.test(`${calleeText}(`)) return 'user';
      if (SANITIZER_NAME.test(calleeText)) return 'sanitized';
      if (TRUSTED_TEXT.test(text(node))) return 'trusted';
      if (/^path\.(?:join|resolve)$/.test(calleeText)) {
        let level: TaintLevel = 'literal';
        for (const arg of node.arguments) level = maxTaint(level, classify(arg));
        return level;
      }
      if (ts.isIdentifier(node.expression)) {
        const summary = env.helpers.get(node.expression.text);
        if (summary !== undefined) {
          let level = summary.returnTaint;
          if (summary.returnsParamDerived) {
            for (const arg of node.arguments) level = maxTaint(level, classify(arg));
          }
          return level;
        }
      }
      return 'unknown';
    }
    return 'unknown';
  };

  const summarizeFunction = (name: string, fn: ts.FunctionLikeDeclaration): void => {
    if (fn.body === undefined) return;
    const paramNames = new Set<string>();
    for (const param of fn.parameters) {
      if (ts.isIdentifier(param.name)) paramNames.add(param.name.text);
    }
    let returnsParamDerived = false;
    let returnTaint: TaintLevel = 'literal';
    const inspectReturn = (expr: ts.Expression): void => {
      const t = text(expr);
      for (const p of paramNames) {
        if (new RegExp(`\\b${p.replace(/[$]/g, '\\$&')}\\b`).test(t)) returnsParamDerived = true;
      }
      if (USER_SOURCE_TEXT.test(t) || USER_CALL_TEXT.test(t)) returnTaint = 'user';
    };
    const walkFn = (node: ts.Node): void => {
      if (budgetSpent()) return;
      fileBudget.remaining -= 1;
      if (ts.isReturnStatement(node) && node.expression !== undefined) inspectReturn(node.expression);
      ts.forEachChild(node, walkFn);
    };
    if (ts.isBlock(fn.body)) walkFn(fn.body);
    else inspectReturn(fn.body);
    env.helpers.set(name, { returnsParamDerived, returnTaint });
  };

  const collectHelpers = (node: ts.Node): void => {
    if (budgetSpent()) return;
    fileBudget.remaining -= 1;
    if (ts.isFunctionDeclaration(node) && node.name !== undefined) {
      summarizeFunction(node.name.text, node);
      functionBindings.add(node.name.text);
    } else if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer !== undefined) {
      if (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer)) {
        summarizeFunction(node.name.text, node.initializer);
        functionBindings.add(node.name.text);
      }
    }
    if (ts.isFunctionLike(node)) {
      for (const param of node.parameters) {
        if (ts.isIdentifier(param.name) && !paramTypeMayBeString(param)) {
          functionBindings.add(param.name.text);
        }
      }
    }
    if (ts.isImportDeclaration(node) && node.importClause !== undefined) {
      const clause = node.importClause;
      if (clause.name !== undefined) functionBindings.add(clause.name.text);
      const namedBindings = clause.namedBindings;
      if (namedBindings !== undefined) {
        if (ts.isNamespaceImport(namedBindings)) functionBindings.add(namedBindings.name.text);
        else for (const specifier of namedBindings.elements) functionBindings.add(specifier.name.text);
      }
    }
    ts.forEachChild(node, collectHelpers);
  };

  const bindDestructured = (pattern: ts.BindingPattern, level: TaintLevel): void => {
    for (const element of pattern.elements) {
      if (!ts.isBindingElement(element)) continue;
      if (ts.isIdentifier(element.name)) env.vars.set(element.name.text, level);
      else if (ts.isObjectBindingPattern(element.name) || ts.isArrayBindingPattern(element.name)) {
        bindDestructured(element.name, level);
      }
    }
  };

  const recordHit = (kind: SinkKind, node: ts.Node, taint: TaintLevel, callee: string): void => {
    hits.push({ kind, line: lineOf(node), taint, callee: callee.slice(0, 80) });
  };

  const handleCall = (node: ts.CallExpression): void => {
    const calleeText = text(node.expression);
    const args = node.arguments;
    const arg0 = args[0];
    const taint0 = arg0 !== undefined ? classify(arg0) : 'unknown';

    if (isRecognizedSqlSink(calleeText, arg0, sf) && arg0 !== undefined) {
      const dynamic = !ts.isStringLiteralLike(arg0);
      recordHit('sql', node, dynamic ? taint0 : 'literal', calleeText);
    }

    if (/(?:^|\.)(?:exec|execSync)$/.test(calleeText) && !/\.(?:bind|apply|call)\./.test(calleeText)) {
      if (arg0 !== undefined && isShellExecCallee(node.expression, calleeProvenance)) {
        recordHit('command', node, taint0, calleeText);
      }
    } else if (/(?:^|\.)(?:spawn|spawnSync|execFile|execFileSync)$/.test(calleeText)) {
      if (arg0 !== undefined) recordHit('command', node, ts.isStringLiteralLike(arg0) ? 'literal' : taint0, calleeText);
    } else if (
      ts.isIdentifier(node.expression) &&
      calleeProvenance.shellFn.has(calleeText) &&
      arg0 !== undefined
    ) {
      recordHit('command', node, ts.isStringLiteralLike(arg0) ? 'literal' : taint0, calleeText);
    }

    {
      const fsMatch = /^(?:fs(?:\.promises)?|fsp)\.(\w+)$/.exec(calleeText);
      if (fsMatch?.[1] !== undefined && FS_PATH_METHODS.has(fsMatch[1]) && arg0 !== undefined) {
        recordHit('path', node, taint0, calleeText);
      } else if (/\.sendFile$/.test(calleeText) && arg0 !== undefined) {
        recordHit('path', node, taint0, calleeText);
      }
    }

    {
      let isRequest = false;
      if (calleeText === 'fetch' || calleeText === 'got' || calleeText === 'axios') isRequest = true;
      const m = /^([A-Za-z_$][\w$]*)\.(\w+)$/.exec(calleeText);
      if (m?.[1] !== undefined && m[2] !== undefined && REQUEST_BASES.has(m[1]) && REQUEST_METHODS.has(m[2])) isRequest = true;
      if (isRequest && arg0 !== undefined) recordHit('request', node, taint0, calleeText);
    }

    if (/(?:^|\.)redirect$/.test(calleeText) && arg0 !== undefined) {
      const destination = redirectDestination(args);
      recordHit(
        'redirect',
        node,
        destination === undefined || destination === arg0 ? taint0 : classify(destination),
        calleeText,
      );
    }

    if (/^document\.write(?:ln)?$/.test(calleeText) && arg0 !== undefined) {
      recordHit('html', node, taint0, calleeText);
    } else if (/\.insertAdjacentHTML$/.test(calleeText) && args[1] !== undefined) {
      recordHit('html', node, classify(args[1]), calleeText);
    }

    if (calleeText === 'eval' && arg0 !== undefined) {
      recordHit('dynamic_code', node, taint0, calleeText);
    } else if (/^(?:setTimeout|setInterval)$/.test(calleeText) && arg0 !== undefined) {
      if (ts.isStringLiteralLike(arg0)) {
        recordHit('dynamic_code', node, 'literal', calleeText);
      } else if (ts.isArrowFunction(arg0) || ts.isFunctionExpression(arg0)) {
      } else if (ts.isIdentifier(arg0)) {
        const binding = env.vars.get(arg0.text);
        if (binding === 'user') {
          recordHit('dynamic_code', node, 'user', calleeText);
        } else if (functionBindings.has(arg0.text)) {
          recordHit('dynamic_code', node, 'sanitized', calleeText);
        } else if (binding !== undefined) {
          recordHit('dynamic_code', node, binding, calleeText);
        }
      } else {
        recordHit('dynamic_code', node, taint0, calleeText);
      }
    }
  };

  const walk = (node: ts.Node): void => {
    if (budgetSpent()) return;
    fileBudget.remaining -= 1;

    if (ts.isVariableDeclaration(node) && node.initializer !== undefined) {
      const level = classify(node.initializer);
      if (ts.isIdentifier(node.name)) env.vars.set(node.name.text, level);
      else if (ts.isObjectBindingPattern(node.name) || ts.isArrayBindingPattern(node.name)) {
        bindDestructured(node.name, level);
      }
    } else if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken
    ) {
      if (ts.isIdentifier(node.left)) {
        env.vars.set(node.left.text, classify(node.right));
      } else if (ts.isPropertyAccessExpression(node.left) && /\.(?:innerHTML|outerHTML)$/.test(text(node.left))) {
        recordHit('html', node, classify(node.right), text(node.left));
      }
    } else if (ts.isCallExpression(node)) {
      handleCall(node);
    } else if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'Function') {
      const allLiteral = (node.arguments ?? []).every((arg) => ts.isStringLiteralLike(arg));
      let level: TaintLevel = allLiteral ? 'literal' : 'unknown';
      for (const arg of node.arguments ?? []) level = maxTaint(level, classify(arg));
      if (!allLiteral) recordHit('dynamic_code', node, level, 'new Function');
    } else if (ts.isJsxAttribute(node) && node.name.getText(sf) === 'dangerouslySetInnerHTML') {
      const init = node.initializer;
      if (init !== undefined && ts.isJsxExpression(init) && init.expression !== undefined) {
        let level: TaintLevel = 'unknown';
        if (ts.isObjectLiteralExpression(init.expression)) {
          for (const prop of init.expression.properties) {
            if (ts.isPropertyAssignment(prop) && prop.name.getText(sf) === '__html') {
              level = classify(prop.initializer);
            }
          }
        }
        recordHit('html', node, level, 'dangerouslySetInnerHTML');
      }
    } else if (ts.isTaggedTemplateExpression(node)) {
      const tag = text(node.tag);
      if (tag === 'sql' || tag.endsWith('.sql') || tag === 'prisma.$queryRaw' || tag.endsWith('.$queryRaw')) {
        recordHit('sql', node, 'sanitized', tag);
      }
    }

    ts.forEachChild(node, walk);
  };

  try {
    collectHelpers(sf);
    walk(sf);
  } catch {
    if (state !== undefined) state.degraded.add(path);
    return undefined;
  }

  const allowance = Math.min(MAX_AST_NODES_PER_FILE, state?.nodesRemaining ?? MAX_AST_NODES_PER_FILE);
  const incomplete: AstFileAnalysis['incomplete'] = !cut
    ? undefined
    : allowance < MAX_AST_NODES_PER_FILE
      ? 'scan-budget'
      : 'node-budget';

  if (state !== undefined) {
    state.nodesRemaining = Math.max(0, state.nodesRemaining - spent());
  }

  hits.sort((a, b) => a.line - b.line || a.kind.localeCompare(b.kind) || a.callee.localeCompare(b.callee));
  if (incomplete === undefined || state?.gaps === undefined) return { parsed: true, hits };
  state.gaps[incomplete].add(path);
  return { parsed: true, hits, incomplete };
}

export type AstVerdict = 'confirm' | 'suppress' | 'none';

export function confidenceWithProof(verdict: AstVerdict, fallback: Confidence): Confidence {
  return verdict === 'confirm' ? 'high' : fallback;
}

export function astVerdict(analysis: AstFileAnalysis | undefined, kind: SinkKind, line: number): AstVerdict {
  if (analysis === undefined) return 'none';
  const relevant = analysis.hits.filter((hit) => hit.kind === kind && hit.line === line);
  if (relevant.length === 0) return 'none';
  if (relevant.some((hit) => hit.taint === 'user')) return 'confirm';
  if (relevant.every((hit) => hit.taint === 'literal' || hit.taint === 'sanitized' || hit.taint === 'trusted')) {
    return 'suppress';
  }
  return 'none';
}

export function userTaintedLines(analysis: AstFileAnalysis | undefined, kind: SinkKind): Map<number, AstSinkHit> {
  const lines = new Map<number, AstSinkHit>();
  if (analysis === undefined) return lines;
  for (const hit of analysis.hits) {
    if (hit.kind === kind && hit.taint === 'user' && !lines.has(hit.line)) lines.set(hit.line, hit);
  }
  return lines;
}





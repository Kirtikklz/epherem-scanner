import ts from 'typescript';

const SHELL_MODULE_SPECIFIER =
  /^(?:node:)?child_process$|^cross-spawn$|^execa$|^shelljs$|^shelljs$|^zx$/;

export function isShellModuleSpecifier(specifier: string): boolean {
  return SHELL_MODULE_SPECIFIER.test(specifier);
}

export interface CalleeProvenance {
  readonly shell: ReadonlySet<string>;
  readonly regex: ReadonlySet<string>;
  readonly shellFn: ReadonlySet<string>;
  readonly truncated: boolean;
}

export const EMPTY_PROVENANCE: CalleeProvenance = {
  shell: new Set(),
  regex: new Set(),
  shellFn: new Set(),
  truncated: true,
};

const MAX_PROVENANCE_NODES = 120_000;

const SHELL_FUNCTION_NAMES: ReadonlySet<string> = new Set([
  'exec',
  'execSync',
  'execFile',
  'execFileSync',
  'spawn',
  'spawnSync',
]);

function trailingName(node: ts.Expression): string | undefined {
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  return undefined;
}

function promisifiedShellFunction(node: ts.Expression, provenance: CalleeProvenance): boolean {
  if (!ts.isCallExpression(node)) return false;
  if (trailingName(node.expression) !== 'promisify') return false;
  const inner = node.arguments[0];
  if (inner === undefined) return false;
  const name = trailingName(inner);
  if (name === undefined || !SHELL_FUNCTION_NAMES.has(name)) return false;
  return isShellExecCallee(inner, provenance);
}

function requiresShellModule(node: ts.Expression): boolean {
  if (!ts.isCallExpression(node)) return false;
  if (!ts.isIdentifier(node.expression) || node.expression.text !== 'require') return false;
  const first = node.arguments[0];
  return first !== undefined && ts.isStringLiteralLike(first) && isShellModuleSpecifier(first.text);
}

function bindingNames(name: ts.BindingName, out: Set<string>): void {
  if (ts.isIdentifier(name)) { out.add(name.text); return; }
  for (const element of name.elements) {
    if (ts.isBindingElement(element)) bindingNames(element.name, out);
  }
}

export function collectCalleeProvenance(sf: ts.SourceFile): CalleeProvenance {
  const shell = new Set<string>();
  const regex = new Set<string>();
  const shellFn = new Set<string>();
  let budget = MAX_PROVENANCE_NODES;

  const inspect = (node: ts.Node): void => {
    if (
      ts.isImportDeclaration(node) &&
      node.importClause !== undefined &&
      ts.isStringLiteralLike(node.moduleSpecifier) &&
      isShellModuleSpecifier(node.moduleSpecifier.text)
    ) {
      const clause = node.importClause;
      if (clause.name !== undefined) shell.add(clause.name.text);
      const named = clause.namedBindings;
      if (named !== undefined) {
        if (ts.isNamespaceImport(named)) shell.add(named.name.text);
        else for (const specifier of named.elements) shell.add(specifier.name.text);
      }
    }

    if (ts.isVariableDeclaration(node) && node.initializer !== undefined) {
      if (requiresShellModule(node.initializer)) bindingNames(node.name, shell);
      const promisified = promisifiedShellFunction(node.initializer, { shell, regex, shellFn, truncated: false });
      if (promisified && ts.isIdentifier(node.name)) shellFn.add(node.name.text);
      if (ts.isIdentifier(node.name)) {
        if (ts.isRegularExpressionLiteral(node.initializer)) regex.add(node.name.text);
        else if (
          ts.isNewExpression(node.initializer) &&
          ts.isIdentifier(node.initializer.expression) &&
          node.initializer.expression.text === 'RegExp'
        ) {
          regex.add(node.name.text);
        }
      }
    }

  };

  const stack: ts.Node[] = [sf];
  while (stack.length > 0) {
    const node = stack.pop();
    if (node === undefined) break;
    if (budget <= 0) return { shell, regex, shellFn, truncated: true };
    budget -= 1;
    inspect(node);
    ts.forEachChild(node, (child) => { stack.push(child); });
  }
  return { shell, regex, shellFn, truncated: false };
}

export function isShellExecCallee(callee: ts.Expression, provenance: CalleeProvenance): boolean {
  if (ts.isIdentifier(callee)) return true;
  if (!ts.isPropertyAccessExpression(callee) && !ts.isElementAccessExpression(callee)) return false;

  const receiver = callee.expression;
  if (ts.isRegularExpressionLiteral(receiver)) return false;
  if (ts.isNewExpression(receiver) && ts.isIdentifier(receiver.expression) && receiver.expression.text === 'RegExp') {
    return false;
  }
  if (requiresShellModule(receiver)) return true;
  if (ts.isIdentifier(receiver)) {
    if (provenance.regex.has(receiver.text)) return false;
    return provenance.shell.has(receiver.text) || provenance.truncated;
  }
  if (ts.isPropertyAccessExpression(receiver) && ts.isIdentifier(receiver.expression)) {
    return provenance.shell.has(receiver.expression.text) || provenance.truncated;
  }
  return provenance.truncated;
}

const provenanceCache = new WeakMap<ts.SourceFile, CalleeProvenance>();

export function calleeProvenanceFor(sf: ts.SourceFile): CalleeProvenance {
  const cached = provenanceCache.get(sf);
  if (cached !== undefined) return cached;
  const fresh = collectCalleeProvenance(sf);
  provenanceCache.set(sf, fresh);
  return fresh;
}

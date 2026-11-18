import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import ts from 'typescript';

export interface ImportGraph {
  readonly files: readonly string[];
  readonly external: ReadonlyMap<string, readonly string[]>;
  readonly assets: readonly string[];
}

export function walkImportGraph(scannerRoot: string, entries: readonly string[]): ImportGraph {
  const seen = new Set<string>();
  const external = new Map<string, string[]>();
  const assets = new Set<string>();
  const queue = entries.map((entry) => path.resolve(scannerRoot, entry));
  const rel = (file: string): string => path.relative(scannerRoot, file).split(path.sep).join('/');

  while (queue.length > 0) {
    const file = queue.shift()!;
    if (seen.has(file)) continue;
    if (!existsSync(file)) throw new Error(`import graph: ${rel(file)} does not exist`);
    seen.add(file);
    for (const specifier of specifiersOf(file)) {
      if (!specifier.startsWith('.')) {
        const importers = external.get(specifier) ?? [];
        importers.push(rel(file));
        external.set(specifier, importers);
        continue;
      }
      const target = path.resolve(path.dirname(file), specifier);
      if (/\.(?:json|wasm)$/.test(target)) {
        assets.add(rel(target));
        continue;
      }
      const source = target.replace(/\.js$/, '.ts');
      if (!existsSync(source)) throw new Error(`import graph: ${rel(file)} imports ${specifier}, which resolves to nothing`);
      queue.push(source);
    }
  }
  return {
    files: [...seen].map(rel).sort(),
    external,
    assets: [...assets].sort(),
  };
}

export function valueUsesOf(scannerRoot: string, files: readonly string[], names: ReadonlySet<string>): string[] {
  const uses: string[] = [];
  for (const file of files) {
    const absolute = path.resolve(scannerRoot, file);
    const sourceFile = ts.createSourceFile(absolute, readFileSync(absolute, 'utf8'), ts.ScriptTarget.Latest, true);
    const visit = (node: ts.Node): void => {
      if (ts.isIdentifier(node) && names.has(node.text) && isValueUse(node)) {
        uses.push(`${file}:${sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1}`);
      }
      ts.forEachChild(node, visit);
    };
    visit(sourceFile);
  }
  return uses;
}

function isValueUse(node: ts.Identifier): boolean {
  const parent = node.parent;
  if (ts.isPropertyAccessExpression(parent) && parent.name === node) return false;
  if ((ts.isPropertyAssignment(parent) || ts.isPropertySignature(parent) || ts.isPropertyDeclaration(parent) ||
    ts.isMethodDeclaration(parent) || ts.isMethodSignature(parent)) && parent.name === node) return false;
  if ((ts.isFunctionDeclaration(parent) || ts.isVariableDeclaration(parent) || ts.isParameter(parent) ||
    ts.isClassDeclaration(parent) || ts.isInterfaceDeclaration(parent) || ts.isTypeAliasDeclaration(parent)) && parent.name === node) return false;
  if (ts.isImportSpecifier(parent) || ts.isExportSpecifier(parent) || ts.isQualifiedName(parent)) return false;
  return true;
}

export function dynamicCodeSites(scannerRoot: string, files: readonly string[]): string[] {
  const sites: string[] = [];
  for (const file of files) {
    const absolute = path.resolve(scannerRoot, file);
    const sourceFile = ts.createSourceFile(absolute, readFileSync(absolute, 'utf8'), ts.ScriptTarget.Latest, true);
    const visit = (node: ts.Node): void => {
      if ((ts.isCallExpression(node) || ts.isNewExpression(node)) && ts.isIdentifier(node.expression) &&
        (node.expression.text === 'eval' || node.expression.text === 'Function')) {
        sites.push(`${file}:${sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1}`);
      }
      ts.forEachChild(node, visit);
    };
    visit(sourceFile);
  }
  return sites;
}

function specifiersOf(file: string): string[] {
  const sourceFile = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
  const found: string[] = [];
  const visit = (node: ts.Node): void => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier !== undefined) {
      if (ts.isStringLiteral(node.moduleSpecifier)) found.push(node.moduleSpecifier.text);
    } else if (ts.isImportTypeNode(node)) {
      const argument = node.argument;
      if (ts.isLiteralTypeNode(argument) && ts.isStringLiteral(argument.literal)) found.push(argument.literal.text);
    } else if (ts.isCallExpression(node)) {
      const [first] = node.arguments;
      const isImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
      const isRequire = ts.isIdentifier(node.expression) && node.expression.text === 'require';
      if ((isImport || isRequire) && first !== undefined) {
        if (ts.isStringLiteralLike(first)) found.push(first.text);
        else throw new Error(`import graph: ${file} loads a computed specifier, which cannot be followed`);
      }
    } else if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'URL') {
      const [first, second] = node.arguments ?? [];
      if (
        first !== undefined &&
        ts.isStringLiteralLike(first) &&
        first.text.startsWith('.') &&
        second !== undefined &&
        second.getText(sourceFile) === 'import.meta.url'
      ) {
        found.push(first.text);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return found;
}

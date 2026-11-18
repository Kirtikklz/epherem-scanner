import type { ApiRoute, FileMapEntry } from '../shared/types.js';
import { inPythonProse } from '../shared/pythonScope.js';
import { isAstAnalyzable } from '../ast/astAnalysis.js';
import { fileRoutedHandlers } from '../shared/frameworkModel.js';
import { findMatches } from '../shared/utils.js';

const EXPRESS_ROUTE = /\b(?:app|router)\.(get|post|put|delete|patch|all)\s*\(\s*['"`]([^'"`]+)['"`]/g;
const FASTAPI_ROUTE = /@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]/g;
const FLASK_ROUTE = /@(?:app|bp)\.route\s*\(\s*['"]([^'"]+)['"](?:[^)]*methods\s*=\s*\[([^\]]*)\])?/g;

export function extractApiRoutes(entry: FileMapEntry): ApiRoute[] {
  const routes: ApiRoute[] = [];
  const { path: filePath, content } = entry;

  const fileRouted = fileRoutedHandlers(entry);
  if (fileRouted !== undefined) return fileRouted;

  const readsJavaScript = isAstAnalyzable(entry.extension);
  const readsPython = entry.extension === '.py';

  for (const match of readsJavaScript ? findMatches(content, EXPRESS_ROUTE) : []) {
    const [method, routePath] = match.groups;
    if (method === undefined || routePath === undefined) continue;
    routes.push({
      filePath,
      framework: 'express',
      routePath,
      methods: [method.toUpperCase()],
      line: match.line,
    });
  }
  for (const match of readsPython ? findMatches(content, FASTAPI_ROUTE) : []) {
    const [method, routePath] = match.groups;
    if (method === undefined || routePath === undefined) continue;
    if (inPythonProse(content, match.index)) continue;
    routes.push({
      filePath,
      framework: 'fastapi',
      routePath,
      methods: [method.toUpperCase()],
      line: match.line,
    });
  }
  for (const match of readsPython ? findMatches(content, FLASK_ROUTE) : []) {
    const [routePath, methodList] = match.groups;
    if (routePath === undefined) continue;
    if (inPythonProse(entry.content, match.index)) continue;
    const methods =
      methodList !== undefined
        ? methodList.split(',').map((method) => method.replace(/['"\s]/g, '').toUpperCase()).filter(Boolean)
        : ['GET'];
    routes.push({ filePath, framework: 'flask', routePath, methods, line: match.line });
  }

  return routes;
}

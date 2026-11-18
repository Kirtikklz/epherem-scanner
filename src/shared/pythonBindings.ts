import type { PyNode, PyTree } from './pythonParser.js';

const TARGET_WRAPPERS = new Set([
  'pattern_list', 'tuple_pattern', 'list_pattern', 'list_splat_pattern', 'parenthesized_expression',
  'tuple', 'list', 'expression_list', 'as_pattern_target', 'list_splat', 'parenthesized_list_splat',
]);

export function isBindingIdentifier(node: PyNode): boolean {
  if (node.type !== 'identifier') return false;
  let child = node;
  let parent = node.parent;
  while (parent !== undefined && TARGET_WRAPPERS.has(parent.type)) { child = parent; parent = parent.parent; }
  if (parent === undefined) return false;
  switch (parent.type) {
    case 'assignment':
    case 'augmented_assignment':
    case 'for_statement':
    case 'for_in_clause':
      return child.field === 'left';
    case 'named_expression':
      return child.field === 'name';
    case 'as_pattern':
      return child.field === 'alias' || child.type === 'as_pattern_target' || precededByAs(child);
    case 'except_clause':
    case 'except_group_clause':
      return child.field === 'alias' || precededByAs(child);
    case 'global_statement':
    case 'nonlocal_statement':
    case 'delete_statement':
      return true;
    case 'function_definition':
    case 'class_definition':
      return child.same(parent.child('name'));
    case 'aliased_import':
      return child.field === 'alias';
    case 'dotted_name': {
      if (hasAncestor(parent, 'case_pattern')) return parent.parent?.type !== 'class_pattern' && parent.namedChildren.length === 1;
      const statement = parent.parent;
      const first = parent.children[0];
      if (statement === undefined || first === undefined || !first.same(child)) return false;
      if (statement.type === 'import_statement') return true;
      return statement.type === 'import_from_statement' && parent.field === 'name';
    }
    default:
      return hasAncestor(node, 'case_pattern') && parent.type !== 'attribute' && parent.type !== 'keyword_argument' && parent.type !== 'keyword_pattern'
        && parent.type !== 'call' && parent.type !== 'class_pattern';
  }
}

function precededByAs(node: PyNode): boolean {
  const siblings = node.parent?.children ?? [];
  const at = siblings.findIndex((s) => s.same(node));
  return at > 0 && siblings[at - 1]!.type === 'as';
}

function hasAncestor(node: PyNode, type: string): boolean {
  for (let p = node.parent; p !== undefined; p = p.parent) if (p.type === type) return true;
  return false;
}

export function functionAt(tree: PyTree, line: number): PyNode | undefined {
  let best: PyNode | undefined;
  for (const fn of tree.find((n) => n.type === 'function_definition')) {
    if (fn.line <= line && line <= fn.endLine && (best === undefined || fn.start >= best.start)) best = fn;
  }
  return best;
}

export function parameterNames(fn: PyNode): string[] {
  const params = fn.child('parameters');
  if (params === undefined) return [];
  const out: string[] = [];
  for (const p of params.namedChildren) {
    const id = p.type === 'identifier' ? p : p.children.find((c) => c.type === 'identifier');
    if (id !== undefined) out.push(id.text);
  }
  return out;
}

export interface Binding {
  node: PyNode;
  value?: PyNode;
}

export function bindingsOf(fn: PyNode, name: string): Binding[] {
  const body = fn.child('body');
  if (body === undefined) return [];
  const out: Binding[] = [];
  for (const node of body.descendants()) {
    if (node.type !== 'identifier' || node.text !== name || !isBindingIdentifier(node)) continue;
    const parent = node.parent;
    const plain = parent !== undefined && parent.type === 'assignment' && node.field === 'left';
    const value = plain ? parent.child('right') : undefined;
    out.push(value !== undefined ? { node, value } : { node });
  }
  return out;
}

export function statementOf(n: PyNode): PyNode {
  let node = n;
  for (let p = n.parent; p !== undefined; p = p.parent) {
    if (p.type === 'block' || p.type === 'module') return node;
    node = p;
  }
  return node;
}

export function isPlainLiteral(node: PyNode): boolean {
  if (['integer', 'float', 'true', 'false', 'none'].includes(node.type)) return true;
  if (node.type === 'string') return !node.children.some((c) => c.type === 'interpolation');
  if (node.type === 'concatenated_string') return node.namedChildren.every(isPlainLiteral);
  return false;
}

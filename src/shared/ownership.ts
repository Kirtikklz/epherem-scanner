import { classifyExpression, type TaintMap } from './taint.js';

export interface FilterPair {
  key: string;
  value: string;
}

export const OWNERSHIP_FIELD =
  /^(user_?id|owner_?id|owner|user|account_?id|tenant_?id|tenant|author_?id|created_?by|member_?id|org_?id|organization_?id)$/i;

const KEY_VALUE = /([A-Za-z_$][\w$]*)\s*:\s*([^,}\n]+)/g;
const SHORTHAND = /(?:^|[{,])\s*([A-Za-z_$][\w$]*)\s*(?=[,}]|$)/g;
const SUPABASE_EQ = /\.(?:eq|match)\s*\(\s*['"]([^'"]+)['"]\s*,\s*([^)]+)\)/g;

export function parseObjectFilter(text: string): FilterPair[] {
  const pairs: FilterPair[] = [];
  const seen = new Set<string>();
  KEY_VALUE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = KEY_VALUE.exec(text)) !== null) {
    const key = match[1];
    const value = match[2];
    if (key === undefined || value === undefined) continue;
    if (seen.has(key)) continue;
    seen.add(key);
    pairs.push({ key, value: value.trim() });
  }
  SHORTHAND.lastIndex = 0;
  while ((match = SHORTHAND.exec(text)) !== null) {
    const key = match[1];
    if (key === undefined || seen.has(key)) continue;
    seen.add(key);
    pairs.push({ key, value: key });
  }
  return pairs;
}

const BUILDER_EQ =
  /\beq\s*\(\s*['"]?([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)['"]?\s*,\s*([^(),]+?)\s*\)/g;

export function parseBuilderEq(text: string): FilterPair[] {
  const pairs: FilterPair[] = [];
  BUILDER_EQ.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = BUILDER_EQ.exec(text)) !== null) {
    const column = match[1];
    const value = match[2];
    if (column === undefined || value === undefined) continue;
    const segments = column.split('.').map((part) => part.trim());
    const key = segments[segments.length - 1];
    if (key === undefined || key === '') continue;
    pairs.push({ key, value: value.trim() });
  }
  return pairs;
}

export function parseEqChain(text: string): FilterPair[] {
  const pairs: FilterPair[] = [];
  SUPABASE_EQ.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = SUPABASE_EQ.exec(text)) !== null) {
    const key = match[1];
    const value = match[2];
    if (key === undefined || value === undefined) continue;
    pairs.push({ key, value: value.trim() });
  }
  return pairs;
}

export function hasTrustedOwnership(pairs: FilterPair[], taint: TaintMap, at?: number): boolean {
  return pairs.some(
    (pair) => OWNERSHIP_FIELD.test(pair.key) && classifyExpression(pair.value, taint, at) === 'trusted',
  );
}

export function hasRequestControlledOwnership(pairs: FilterPair[], taint: TaintMap, at?: number): boolean {
  return pairs.some(
    (pair) => OWNERSHIP_FIELD.test(pair.key) && classifyExpression(pair.value, taint, at) === 'user',
  );
}

export function hasRequestControlledId(pairs: FilterPair[], taint: TaintMap, at?: number): boolean {
  return pairs.some(
    (pair) => /id$/i.test(pair.key) && classifyExpression(pair.value, taint, at) === 'user',
  );
}

import type { EnvVariableUsage, FileMapEntry } from '../shared/types.js';
import { findMatches } from '../shared/utils.js';

const ENV_PATTERNS: { pattern: RegExp; accessor: EnvVariableUsage['accessor'] }[] = [
  { pattern: /process\.env\.([A-Z][A-Z0-9_]*)/g, accessor: 'process.env' },
  { pattern: /process\.env\[\s*['"]([A-Z][A-Z0-9_]*)['"]\s*\]/g, accessor: 'process.env' },
  { pattern: /import\.meta\.env\.([A-Z][A-Z0-9_]*)/g, accessor: 'import.meta.env' },
  { pattern: /os\.environ(?:\.get)?\s*[([]\s*['"]([A-Z][A-Z0-9_]*)['"]/g, accessor: 'other' },
  { pattern: /getenv\(\s*['"]([A-Z][A-Z0-9_]*)['"]/g, accessor: 'other' },
];

export function detectEnvUsage(entry: FileMapEntry): EnvVariableUsage[] {
  const usages: EnvVariableUsage[] = [];
  for (const { pattern, accessor } of ENV_PATTERNS) {
    for (const match of findMatches(entry.content, pattern)) {
      const name = match.groups[0];
      if (name !== undefined) usages.push({ filePath: entry.path, line: match.line, name, accessor });
    }
  }
  usages.sort((a, b) => a.line - b.line || a.name.localeCompare(b.name));
  return usages;
}

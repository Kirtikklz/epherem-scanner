import type { DangerousOperation, FileMapEntry } from '../shared/types.js';
import { findMatches } from '../shared/utils.js';

interface DangerProbe {
  kind: string;
  pattern: RegExp;
}

const DANGER_PROBES: DangerProbe[] = [
  { kind: 'eval', pattern: /\beval\s*\(/g },
  { kind: 'new_function', pattern: /new\s+Function\s*\(/g },
  { kind: 'child_process', pattern: /child_process|\bexecSync\s*\(|\bspawnSync\s*\(/g },
  { kind: 'os_system', pattern: /os\.system\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True/g },
  { kind: 'pickle_load', pattern: /pickle\.loads?\s*\(/g },
  { kind: 'dangerously_set_inner_html', pattern: /dangerouslySetInnerHTML/g },
  { kind: 'document_write', pattern: /document\.write\s*\(/g },
];

export function detectDangerousOperations(entry: FileMapEntry): DangerousOperation[] {
  const operations: DangerousOperation[] = [];
  for (const probe of DANGER_PROBES) {
    for (const match of findMatches(entry.content, probe.pattern)) {
      operations.push({ filePath: entry.path, line: match.line, kind: probe.kind, snippet: match.snippet });
    }
  }
  operations.sort((a, b) => a.line - b.line || a.kind.localeCompare(b.kind));
  return operations;
}

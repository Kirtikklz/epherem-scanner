import { mayVouchForProject } from '../input/fileFilters.js';
import type { FileMapEntry, RuleContext } from './types.js';

export function creditScopedEntries(context: RuleContext): FileMapEntry[] {
  const prefix = context.projectMap.scannerRootPrefix;
  return context.fileMap.entries.filter((entry) => mayVouchForProject(entry.path, prefix));
}

const SARIF_SCHEMA_MARKER = /"\$schema"\s*:\s*"[^"]*sarif[^"]*"/i;
const SARIF_RUNS_MARKER = /"runs"\s*:\s*\[/;

export function isScanReport(entry: FileMapEntry): boolean {
  if (/\.sarif$/i.test(entry.path)) return true;
  return SARIF_SCHEMA_MARKER.test(entry.content) && SARIF_RUNS_MARKER.test(entry.content);
}

const DECLARATION_LABELS: ReadonlySet<string> = new Set(['package_manifest', 'lockfile']);
const PROSE_EXTENSIONS: ReadonlySet<string> = new Set(['.md', '.mdx', '.markdown', '.rst', '.adoc']);
const MARKUP_EXTENSIONS: ReadonlySet<string> = new Set(['.html', '.htm']);
const MARKUP_CONTROL_ELEMENT = /<(?:meta|input)\b[^>]*>/gi;

export function creditEvidence(entry: FileMapEntry): string {
  if (DECLARATION_LABELS.has(entry.label)) return '';
  const extension = entry.extension.toLowerCase();
  if (PROSE_EXTENSIONS.has(extension)) return '';
  if (MARKUP_EXTENSIONS.has(extension)) {
    return (entry.content.match(MARKUP_CONTROL_ELEMENT) ?? []).join('\n');
  }
  return entry.content;
}

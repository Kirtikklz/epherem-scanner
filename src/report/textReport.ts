import type { ScanReport } from '../shared/types.js';
import {
  bySeverity,
  cap,
  countSentence,
  coverageRows,
  entryTexts,
  fileCounts,
  GROUP_ORDER,
  GROUP_WORDS,
  howFound,
  location,
  NOT_EVERYTHING,
  NOTICE_ALL,
  oneLine,
  PARTIAL_LINE,
  partialRules,
  plural,
  reportModel,
  scanNotes,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  severityIndex,
  shownTitle,
  stackText,
  startHere,
  UNVERIFIED,
  verdict,
  whereText,
  type ReportEntry,
  type SeverityKey,
} from './reportModel.js';

export interface TextReportOptions {
  projectName: string;
  minSeverity?: SeverityKey;
  color?: boolean;
}

const MAX_NOTES = 20;
const MAX_PLACES = 20;
export const PROMPTS_ELSEWHERE = "Each finding's fix prompt, written for an AI coding tool, is in the --json output (fixPrompt) and on the --html page.";

const SEVERITY_COLOR: Readonly<Record<SeverityKey, string>> = { critical: '35', high: '31', medium: '33', low: '36' };

export function renderTextReport(report: ScanReport, options: TextReportOptions): string {
  const color = options.color === true;
  const bold = (s: string): string => (color ? `\u001b[1m${s}\u001b[22m` : s);
  const sev = (s: SeverityKey): string => (color ? `\u001b[${SEVERITY_COLOR[s]}m${SEVERITY_LABEL[s]}\u001b[39m` : SEVERITY_LABEL[s]);
  const model = reportModel(report);
  const L: string[] = [];

  L.push(bold(`Epherem security report: ${oneLine(options.projectName)}`), '');
  const { read, skipped } = fileCounts(model);
  if (read !== null) L.push(`Files read: ${read}${skipped !== null && skipped > 0 ? ` (${skipped} skipped)` : ''}`);
  const stack = stackText(model);
  L.push(`Stack detected: ${stack !== '' ? oneLine(stack) : 'none recognised'}`);
  L.push('');

  const v = verdict(model);
  if (v !== null) {
    L.push(bold(v.headline));
    if (v.line !== '') L.push(v.line);
    if (v.fit !== null) {
      L.push(oneLine(v.fit.text));
      for (const s of v.fit.also) L.push(`- ${oneLine(s)}`);
    }
    if (v.libraries !== '') L.push(v.libraries);
    if (v.partial) L.push(`${PARTIAL_LINE} See "What this scan couldn't check", below.`);
    L.push('');
  }

  const groups = GROUP_ORDER.map((g) => `${GROUP_WORDS[g].title} ${model.byGroup[g]}`).join(', ');
  const severities = SEVERITY_ORDER.map((s) => `${SEVERITY_LABEL[s]} ${model.bySev[s]}`).join(', ');
  L.push(`Findings: ${model.nFindings} (${groups})`);
  L.push(`By severity: ${severities}`);
  if (model.nFindings > 0) L.push(countSentence(model.nFindings, model.nPlaces));
  for (const g of GROUP_ORDER) if (model.byGroup[g] > 0) L.push(`- ${GROUP_WORDS[g].title}: ${GROUP_WORDS[g].explain}`);

  const min = options.minSeverity;
  const ordered = bySeverity(model);
  const shown = min === undefined ? ordered : ordered.filter((e) => severityIndex(e.sev) <= severityIndex(min));
  const hidden = ordered.length - shown.length;
  if (min !== undefined) {
    L.push(hidden > 0
      ? `Showing findings at ${SEVERITY_LABEL[min]} or above: ${plural(hidden, 'finding')} below ${SEVERITY_LABEL[min]} ${hidden === 1 ? 'is' : 'are'} hidden. Run without --severity to see every finding.`
      : `Showing findings at ${SEVERITY_LABEL[min]} or above: none hidden.`);
  }
  L.push('');

  const start = v !== null ? startHere(model).filter((e) => shown.includes(e)) : [];
  if (start.length > 0) {
    L.push(bold('Start here'));
    start.forEach((e, i) => {
      L.push(`${i + 1}. ${oneLine(shownTitle(e))} (${SEVERITY_LABEL[e.sev]}, ${oneLine(whereText(e))})`);
    });
    L.push('');
  }

  if (shown.length > 0) {
    L.push(NOTICE_ALL, '');
    L.push(bold('Findings, most serious first'), UNVERIFIED, PROMPTS_ELSEWHERE, '');
    shown.forEach((e, i) => L.push(...findingLines(e, i + 1, model, bold, sev)));
  } else if (model.nFindings === 0) {
    L.push("This scan flagged no findings in the code it read. That doesn't mean there are none: see what it couldn't check, below.", '');
  }

  L.push(bold("What this scan couldn't check"));
  for (const row of coverageRows(model)) L.push(`- ${oneLine(row.name)} (${oneLine(row.tag)}): ${oneLine(row.detail)}`);
  const rules = partialRules(model);
  if (rules.length > 0) {
    L.push('', 'Checks that did not cover your whole project:');
    for (const rule of rules) L.push(`- ${oneLine(rule.ruleId)} (${oneLine(rule.coverage)})${rule.reason !== '' ? `: ${oneLine(rule.reason)}` : ''}`);
  }
  const notes = scanNotes(model);
  if (notes.length > 0) {
    L.push('', 'What the scan said about files it skipped or read only in part:');
    for (const note of notes.slice(0, MAX_NOTES)) L.push(`- ${oneLine(note)}`);
    if (notes.length > MAX_NOTES) L.push(`- ...and ${notes.length - MAX_NOTES} more (run with --json to see them all).`);
  }
  L.push('', NOT_EVERYTHING, '');
  return L.join('\n');
}

function findingLines(
  e: ReportEntry,
  number: number,
  model: ReturnType<typeof reportModel>,
  bold: (s: string) => string,
  sev: (s: SeverityKey) => string,
): string[] {
  const texts = entryTexts(model, e);
  const files = new Set(e.places.map((p) => p.path)).size;
  const L: string[] = [];
  L.push(bold(`${number}. ${oneLine(shownTitle(e))}`));
  if (e.plain !== null) L.push(`   Technical name: ${oneLine(e.title)}`);
  L.push(`   Severity: ${sev(e.sev)} | Group: ${GROUP_WORDS[e.group].item}${e.single ? ` | Confidence: ${oneLine(cap(String(e.places[0]!.raw.confidence ?? '') || 'not recorded'))}` : ''}`);
  if (e.single) {
    L.push(`   Where: ${oneLine(location(e.places[0]!))}`);
  } else {
    L.push(`   Where: ${plural(e.n, 'place')} in ${plural(files, 'file')}`);
    for (const p of e.places.slice(0, MAX_PLACES)) L.push(`   - ${oneLine(location(p))}`);
    if (e.n > MAX_PLACES) L.push(`   - ...and ${e.n - MAX_PLACES} more (run with --json to see them all)`);
  }
  L.push(`   Check: ${oneLine(e.label)} (rule ${oneLine(e.ruleId)}). ${howFound(e.absent)}.`);
  const why = [e.plain?.line ?? '', texts.lead, texts.happen].filter(Boolean).map(oneLine).join(' ');
  if (why !== '') L.push(`   Why it matters: ${why}`);
  if (e.absent && texts.found !== '') L.push(`   What the scan saw: ${oneLine(texts.found)}`);
  const fix = texts.fix !== '' ? texts.fix : texts.fixPerPlace
    ? 'Each place has its own fix: ' + e.places.map((p) => `${location(p)}: ${String(p.raw.fixHint ?? '')}`).join('; ')
    : 'This finding carries no fix text. The prompt below asks an AI coding tool to check it first.';
  L.push(`   How to fix it: ${oneLine(fix)}`, '');
  return L;
}

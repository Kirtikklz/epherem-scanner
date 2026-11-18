import type { ScanReport } from '../shared/types.js';
import {
  bySeverity,
  cap,
  cleanText,
  countSentence,
  coverageRows,
  datasetDate,
  entryTexts,
  fileCounts,
  fixPrompt,
  GROUP_ORDER,
  GROUP_WORDS,
  howFound,
  location,
  NOT_EVERYTHING,
  PARTIAL_LINE,
  partialRules,
  plural,
  reportModel,
  scanNotes,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  shownTitle,
  stackText,
  startHere,
  UNVERIFIED,
  verdict,
  whereText,
  type ReportEntry,
  type ReportModel,
} from './reportModel.js';

export interface HtmlReportOptions {
  projectName: string;
  dependencyMode: 'online' | 'offline';
  version: string;
}

// Lets --html replace its own earlier report and nothing else.
export const HTML_REPORT_MARKER = '<meta name="generator" content="epherem-scanner">';

// Every string from the scanned project passes through here.
export function escapeHtml(v: unknown): string {
  return cleanText(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const CSS = `
:root{color-scheme:light dark;--bg:#fff;--fg:#1b1b1f;--muted:#5b5b66;--line:#dcdce3;--card:#f6f6f9;--critical:#8a1c7c;--high:#b3261e;--medium:#8a5a00;--low:#0b6b8a}
@media (prefers-color-scheme:dark){:root{--bg:#141417;--fg:#ececf1;--muted:#a3a3b0;--line:#33333c;--card:#1d1d22;--critical:#e48ad8;--high:#ff8a80;--medium:#f2c25c;--low:#7fd3ee}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:20px;margin:36px 0 12px}h3{font-size:17px;margin:0 0 6px}
.muted{color:var(--muted)}.verdict{border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:20px 0;background:var(--card)}.verdict h2{margin:0 0 6px}
table{border-collapse:collapse;width:100%;margin:8px 0}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
.finding{border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:14px 0}.meta{margin:6px 0 10px;color:var(--muted)}
.sev{font-weight:600}.sev-critical{color:var(--critical)}.sev-high{color:var(--high)}.sev-medium{color:var(--medium)}.sev-low{color:var(--low)}
pre{white-space:pre-wrap;word-break:break-word;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin:8px 0}
details{margin:8px 0}summary{cursor:pointer;font-weight:600}ul{padding-left:20px}footer{margin-top:40px;color:var(--muted);font-size:13px}
@media print{details{display:block}details>summary{display:none}.finding{break-inside:avoid}}
`;

export function renderHtmlReport(report: ScanReport, options: HtmlReportOptions): string {
  const model = reportModel(report);
  const e = escapeHtml;
  const H: string[] = [];
  const { read, skipped } = fileCounts(model);
  const stack = stackText(model);
  const date = datasetDate(model.report.createdAt);

  H.push(`<h1>Epherem security report: ${e(options.projectName)}</h1>`);
  H.push(`<p class="muted">${[
    date !== '' ? `Scanned on ${e(date)}` : '',
    read !== null ? `${plural(read, 'file')} read${skipped !== null && skipped > 0 ? `, ${skipped} skipped` : ''}` : '',
    `Stack detected: ${stack !== '' ? e(stack) : 'none recognised'}`,
  ].filter(Boolean).join(' · ')}</p>`);
  H.push(`<p class="muted">${options.dependencyMode === 'offline'
    ? 'Package check: offline, against the advisory data bundled with the scanner. Nothing was sent anywhere.'
    : 'Package check: online. Package names and versions were sent to OSV.dev; nothing else left the computer.'}</p>`);

  const v = verdict(model);
  if (v !== null) {
    H.push('<section class="verdict">', `<h2>${e(v.headline)}</h2>`);
    if (v.line !== '') H.push(`<p>${e(v.line)}</p>`);
    if (v.fit !== null) {
      H.push(`<p>${e(v.fit.text)}</p>`);
      if (v.fit.also.length > 0) H.push(`<ul>${v.fit.also.map((s) => `<li>${e(s)}</li>`).join('')}</ul>`);
    }
    if (v.libraries !== '') H.push(`<p>${e(v.libraries)}</p>`);
    if (v.partial) H.push(`<p>${e(PARTIAL_LINE)} See “What this scan couldn’t check”, below.</p>`);
    H.push('</section>');
  }

  H.push('<table><thead><tr><th>Group</th><th>Findings</th><th>What it means</th></tr></thead><tbody>');
  for (const g of GROUP_ORDER) H.push(`<tr><td>${GROUP_WORDS[g].title}</td><td>${model.byGroup[g]}</td><td>${e(GROUP_WORDS[g].explain)}</td></tr>`);
  H.push('</tbody></table>');
  H.push(`<p>${SEVERITY_ORDER.map((s) => `<span class="sev sev-${s}">${SEVERITY_LABEL[s]}</span> ${model.bySev[s]}`).join(' · ')}</p>`);
  if (model.nFindings > 0) H.push(`<p class="muted">${e(countSentence(model.nFindings, model.nPlaces))}</p>`);

  const start = v !== null ? startHere(model) : [];
  if (start.length > 0) {
    H.push('<h2>Start here</h2><ol>');
    for (const s of start) H.push(`<li><a href="#${s.key}">${e(shownTitle(s))}</a> <span class="muted">${e(whereText(s))}</span></li>`);
    H.push('</ol>');
  }

  if (model.nFindings > 0) {
    H.push('<h2>Findings, most serious first</h2>', `<p class="muted">${e(UNVERIFIED)}</p>`);
    for (const entry of bySeverity(model)) H.push(findingHtml(model, entry));
  } else {
    H.push('<p>This scan flagged no findings in the code it read. That doesn’t mean there are none: see what it couldn’t check, below.</p>');
  }

  H.push('<h2>What this scan couldn’t check</h2><table><tbody>');
  for (const row of coverageRows(model)) H.push(`<tr><td>${e(row.name)}</td><td class="muted">${e(row.tag)}</td><td>${e(row.detail)}</td></tr>`);
  H.push('</tbody></table>');
  const rules = partialRules(model);
  if (rules.length > 0) {
    H.push('<details><summary>Checks that did not cover your whole project</summary><ul>');
    for (const r of rules) H.push(`<li>${e(r.ruleId)} <span class="muted">(${e(r.coverage)})</span>${r.reason !== '' ? `: ${e(r.reason)}` : ''}</li>`);
    H.push('</ul></details>');
  }
  const notes = scanNotes(model);
  if (notes.length > 0) {
    H.push('<details><summary>What the scan said about files it skipped or read only in part</summary><ul>');
    for (const n of notes) H.push(`<li>${e(n)}</li>`);
    H.push('</ul></details>');
  }
  H.push(`<p><strong>${e(NOT_EVERYTHING)}</strong></p>`);
  H.push(`<footer>Made by epherem-scanner ${e(options.version)}. This file was written on your computer and has not been sent anywhere.</footer>`);

  return [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    // No scripts and no requests: the page cannot load anything.
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
    '<meta name="referrer" content="no-referrer">',
    HTML_REPORT_MARKER,
    `<title>Epherem report: ${e(options.projectName)}</title>`,
    `<style>${CSS}</style>`,
    '</head>',
    '<body><main>',
    ...H,
    '</main></body>',
    '</html>',
    '',
  ].join('\n');
}

function findingHtml(model: ReportModel, entry: ReportEntry): string {
  const e = escapeHtml;
  const texts = entryTexts(model, entry);
  const files = new Set(entry.places.map((p) => p.path)).size;
  const H: string[] = [`<section class="finding" id="${entry.key}">`, `<h3>${e(shownTitle(entry))}</h3>`];
  if (entry.plain !== null) H.push(`<div class="muted">Technical name: ${e(entry.title)}</div>`);
  H.push(`<div class="meta"><span class="sev sev-${entry.sev}">${SEVERITY_LABEL[entry.sev]}</span> · ${GROUP_WORDS[entry.group].item} · ${
    entry.single ? e(location(entry.places[0]!)) : `${plural(entry.n, 'place')} in ${plural(files, 'file')}`} · ${e(howFound(entry.absent))}</div>`);
  const why = [entry.plain?.line ?? '', texts.lead, texts.happen].filter(Boolean).join(' ');
  if (why !== '') H.push(`<p><strong>Why it matters:</strong> ${e(why)}</p>`);
  if (entry.absent && texts.found !== '') H.push(`<p><strong>What the scan saw:</strong> ${e(texts.found)}</p>`);
  if (texts.fix !== '') H.push(`<p><strong>How to fix it:</strong> ${e(texts.fix)}</p>`);
  if (!entry.single) {
    H.push('<ul>');
    for (const p of entry.places) {
      const hint = texts.fixPerPlace && typeof p.raw.fixHint === 'string' ? ` — ${e(p.raw.fixHint)}` : '';
      H.push(`<li>${e(location(p))} <span class="muted">(${e(cap(String(p.raw.confidence ?? '') || 'unrecorded'))} confidence)</span>${hint}</li>`);
    }
    H.push('</ul>');
  } else if (!entry.absent && typeof entry.places[0]!.raw.evidence === 'string' && entry.places[0]!.raw.evidence !== '') {
    H.push(`<pre>${e(entry.places[0]!.raw.evidence)}</pre>`);
  }
  H.push('<details><summary>Fix prompt for an AI coding tool</summary>', `<pre>${e(fixPrompt(model, entry))}</pre>`, '</details>');
  if (texts.tech !== '') H.push(`<details><summary>Technical details</summary><p>${e(texts.tech)}</p></details>`);
  H.push(`<div class="muted">Check: ${e(entry.label)} (rule ${e(entry.ruleId)})</div>`, '</section>');
  return H.join('\n');
}

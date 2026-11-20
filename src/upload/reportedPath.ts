export const MAX_REPORTED_PATH_SAMPLE = 50;

export const MAX_REPORTED_SKIPPED_PATH_LENGTH = 200;

export const MAX_REPORTED_WATCHLIST_PATH_LENGTH = 1_024;

export interface ReportedPath {
  path: string;
  truncated: boolean;
}

export function reportedPath(entryPath: string, maxLength: number): ReportedPath {
  const stripped = stripHostileCharacters(entryPath);
  if (stripped.length <= maxLength) return { path: stripped, truncated: false };
  const end = isHighSurrogate(stripped.charCodeAt(maxLength - 1)) ? maxLength - 1 : maxLength;
  return { path: stripped.slice(0, end), truncated: true };
}

function isHighSurrogate(unit: number): boolean {
  return unit >= 0xd800 && unit <= 0xdbff;
}

export function stripHostileCharacters(entryPath: string): string {
  let out = '';
  for (const char of entryPath) {
    const code = char.codePointAt(0) ?? 0;
    const isC0 = code < 0x20;
    const isDelOrC1 = code >= 0x7f && code <= 0x9f;
    const isBidiOverride =
      (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069);
    const isMarkup = char === '<' || char === '>';
    if (isC0 || isDelOrC1 || isBidiOverride || isMarkup) continue;
    out += char;
  }
  return out;
}

export function sanitizeReportedPath(entryPath: string): string {
  return reportedPath(entryPath, MAX_REPORTED_SKIPPED_PATH_LENGTH).path;
}

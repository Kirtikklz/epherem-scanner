import { commentSyntaxFor, stripComments } from './source.js';

export { isGeneratedOrVendorPath, isNonProductionCodePath, mayVouchForProject } from '../input/fileFilters.js';

export function isInsideComment(
  content: string,
  index: number,
  extension: string,
  label?: string,
): boolean {
  if (index < 0 || index >= content.length) return false;
  const stripped = stripComments(content, commentSyntaxFor(extension, label));
  return stripped[index] === ' ' && content[index] !== ' ';
}

const BANNER = /^﻿?\s*\/\*![\s\S]{0,1200}?\*\//;
const BANNER_VERSION = /\bv?\d+\.\d+(?:\.\d+)?\b/;
const BANNER_PROVENANCE = /https?:\/\/|\blicen[cs]e\b|\bcopyright\b|\(c\)/i;

export function isVendoredBundleContent(content: string): boolean {
  const banner = BANNER.exec(content)?.[0];
  if (banner === undefined) return false;
  return BANNER_VERSION.test(banner) && BANNER_PROVENANCE.test(banner);
}

const DEV_GUARD =
  /\bif\s*\(\s*(?:[A-Za-z_$][\w$]*\s*&&\s*)?(?:process\.env\.NODE_ENV|import\.meta\.env\.MODE)\s*(?:!==?\s*['"]production['"]|===?\s*['"](?:development|dev|test|staging)['"])\s*\)\s*\{/g;

export function isInsideDevelopmentOnlyBlock(content: string, index: number): boolean {
  DEV_GUARD.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = DEV_GUARD.exec(content)) !== null) {
    const open = match.index + match[0].length - 1;
    if (open >= index) continue;
    const close = matchingBrace(content, open);
    if (close !== undefined && index < close) return true;
  }
  return false;
}

function matchingBrace(content: string, open: number): number | undefined {
  let depth = 0;
  for (let i = open; i < content.length; i += 1) {
    const c = content[i];
    if (c === '{') depth += 1;
    else if (c === '}') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return undefined;
}

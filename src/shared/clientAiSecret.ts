import { isPlaceholderValue } from './utils.js';
import { isPublicByDesignSecret } from './publicIdentifier.js';

const MASKED_TOKEN =
  /(?<![A-Za-z0-9])(?:redacted|masked|hidden|removed|elided|scrubbed|sanitized|sanitised|notarealkey|fake|invalid)(?![A-Za-z0-9])/i;

const MASKING_GLYPH_RUN = /[*••…]{3,}/;

export function looksMaskedOrRedacted(value: string): boolean {
  return MASKED_TOKEN.test(value) || MASKING_GLYPH_RUN.test(value);
}

export interface ClientExposedAiSecretQuery {
  content: string;
  valueIndex: number;
  value: string;
  clientReachable: boolean;
}

export function isClientExposedAiSecret(query: ClientExposedAiSecretQuery): boolean {
  if (!query.clientReachable) return false;
  if (isPlaceholderValue(query.value)) return false;
  if (looksMaskedOrRedacted(query.value)) return false;
  if (isPublicByDesignSecret(query.content, query.valueIndex, query.value)) return false;
  return true;
}

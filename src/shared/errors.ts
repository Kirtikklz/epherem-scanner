export const SCANNER_ERROR_CODES = [
  'INPUT_NOT_FOUND',
  'INPUT_NOT_A_DIRECTORY',
  'INPUT_EMPTY',
  'INPUT_TRUNCATED_BEFORE_ANY_FILE',
  'INVALID_CONFIG',
  'SCAN_TIMEOUT',
  'UNSAFE_PRODUCTION_HOST',
  'PIPELINE_FAILURE',
] as const;

export type ScannerErrorCode = (typeof SCANNER_ERROR_CODES)[number];

export type ScannerErrorReasonCode = Lowercase<ScannerErrorCode>;

export const SCANNER_ERROR_REASON_CODES: readonly ScannerErrorReasonCode[] = SCANNER_ERROR_CODES.map(
  (code) => scannerErrorReasonCode(code),
);

export function scannerErrorReasonCode(code: ScannerErrorCode): ScannerErrorReasonCode {
  return code.toLowerCase() as ScannerErrorReasonCode;
}

export class ScannerError extends Error {
  constructor(
    message: string,
    readonly code: ScannerErrorCode = 'PIPELINE_FAILURE',
  ) {
    super(message);
    this.name = 'ScannerError';
  }
}

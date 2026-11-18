import { readFileSync } from 'node:fs';
import { Ajv2020, type ErrorObject, type ValidateFunction } from 'ajv/dist/2020.js';
import addFormatsModule from 'ajv-formats';
import type { ScanReport } from '../shared/types.js';

export interface ReportValidationResult {
  valid: boolean;
  errors: string[];
}

let validator: ValidateFunction<ScanReport> | undefined;

let cachedSchema: object | undefined;

function loadSchema(): object {
  cachedSchema ??= JSON.parse(
    readFileSync(new URL('./scan-report.schema.json', import.meta.url), 'utf8'),
  ) as object;
  return cachedSchema;
}

function reportValidator(): ValidateFunction<ScanReport> {
  if (validator !== undefined) return validator;
  const schema = loadSchema();
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const addFormats = addFormatsModule as unknown as (instance: Ajv2020) => Ajv2020;
  addFormats(ajv);
  const compiled = ajv.compile<ScanReport>(schema);
  validator = compiled;
  return compiled;
}

export function validateScanReport(value: unknown): ReportValidationResult {
  const validate = reportValidator();
  const valid = validate(value);
  return { valid, errors: valid ? [] : formatErrors(validate.errors ?? []) };
}

export function assertValidScanReport(value: unknown): asserts value is ScanReport {
  const result = validateScanReport(value);
  if (!result.valid) throw new TypeError(`Invalid Epherem ScanReport ${schemaReportVersion()}: ${result.errors.join('; ')}`);
}

function schemaReportVersion(): string {
  const id = String((loadSchema() as { $id?: unknown }).$id ?? '');
  return /scan-report-(\d+\.\d+)\.json$/.exec(id)?.[1] ?? 'unknown version';
}

function formatErrors(errors: readonly ErrorObject[]): string[] {
  return errors.map((error) => `${error.instancePath || '/'} ${error.message ?? 'is invalid'}`).sort();
}

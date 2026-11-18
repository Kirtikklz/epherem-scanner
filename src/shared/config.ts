import { CONFIG_BOUNDS, DEFAULT_INPUT_LIMITS } from './constants.js';
import { ScannerError } from './errors.js';
import type { InputLimits } from './types.js';

function assertPositive(name: string, value: number, max: number, opts: { integer?: boolean } = {}): void {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    throw new ScannerError(`Invalid config: ${name} must be a number, got ${String(value)}.`, 'INVALID_CONFIG');
  }
  if (!Number.isFinite(value)) {
    throw new ScannerError(`Invalid config: ${name} must be finite, got ${String(value)}.`, 'INVALID_CONFIG');
  }
  if (value <= 0) {
    throw new ScannerError(`Invalid config: ${name} must be greater than zero, got ${value}.`, 'INVALID_CONFIG');
  }
  if (opts.integer === true && !Number.isInteger(value)) {
    throw new ScannerError(`Invalid config: ${name} must be an integer, got ${value}.`, 'INVALID_CONFIG');
  }
  if (value > max) {
    throw new ScannerError(`Invalid config: ${name} of ${value} exceeds the maximum allowed (${max}).`, 'INVALID_CONFIG');
  }
}

function assertNonNegative(name: string, value: number, max: number, opts: { integer?: boolean } = {}): void {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    throw new ScannerError(`Invalid config: ${name} must be a number, got ${String(value)}.`, 'INVALID_CONFIG');
  }
  if (!Number.isFinite(value)) {
    throw new ScannerError(`Invalid config: ${name} must be finite, got ${String(value)}.`, 'INVALID_CONFIG');
  }
  if (value < 0) {
    throw new ScannerError(`Invalid config: ${name} must not be negative, got ${value}.`, 'INVALID_CONFIG');
  }
  if (opts.integer === true && !Number.isInteger(value)) {
    throw new ScannerError(`Invalid config: ${name} must be an integer, got ${value}.`, 'INVALID_CONFIG');
  }
  if (value > max) {
    throw new ScannerError(`Invalid config: ${name} of ${value} exceeds the maximum allowed (${max}).`, 'INVALID_CONFIG');
  }
}

export function resolveInputLimits(overrides?: Partial<InputLimits>): InputLimits {
  const merged: InputLimits = { ...DEFAULT_INPUT_LIMITS, ...(overrides ?? {}) };
  const B = CONFIG_BOUNDS;
  assertPositive('inputLimits.maxFileSizeBytes', merged.maxFileSizeBytes, B.maxByteSize, { integer: true });
  assertPositive('inputLimits.maxLockfileSizeBytes', merged.maxLockfileSizeBytes, B.maxByteSize, { integer: true });
  assertPositive('inputLimits.maxTotalFiles', merged.maxTotalFiles, B.maxCount, { integer: true });
  assertPositive('inputLimits.maxTotalContentBytes', merged.maxTotalContentBytes, B.maxByteSize, { integer: true });
  assertPositive('inputLimits.maxDirectoryDepth', merged.maxDirectoryDepth, B.maxDepth, { integer: true });
  assertPositive('inputLimits.maxVisitedEntries', merged.maxVisitedEntries, B.maxCount, { integer: true });
  assertPositive('inputLimits.maxDirectories', merged.maxDirectories, B.maxCount, { integer: true });
  assertPositive('inputLimits.maxSkippedDetails', merged.maxSkippedDetails, B.maxCount, { integer: true });
  assertPositive('inputLimits.maxScanDurationMs', merged.maxScanDurationMs, B.maxDurationMs, { integer: true });
  assertPositive('inputLimits.maxSourceNestingDepth', merged.maxSourceNestingDepth, B.maxCount, { integer: true });
  return merged;
}

export interface ValidatedTimeouts {
  deadlineMs?: number;
}

export function validateDeadlineMs(deadlineMs?: number): number | undefined {
  if (deadlineMs === undefined) return undefined;
  assertPositive('deadlineMs', deadlineMs, CONFIG_BOUNDS.maxDurationMs, { integer: false });
  return deadlineMs;
}

export function validateConcurrency(name: string, value: number): number {
  assertPositive(name, value, CONFIG_BOUNDS.maxConcurrency, { integer: true });
  return value;
}

export function validateTimeoutMs(name: string, value: number): number {
  assertPositive(name, value, CONFIG_BOUNDS.maxDurationMs, { integer: false });
  return value;
}

export function validateRetries(name: string, value: number): number {
  assertNonNegative(name, value, CONFIG_BOUNDS.maxRetries, { integer: true });
  return value;
}

export function validateFreshnessDays(value: number): number {
  assertPositive('freshnessDays', value, 3_650, { integer: false });
  return value;
}

export function validateMaxFindings(value: number): number {
  assertPositive('maxFindings', value, CONFIG_BOUNDS.maxCount, { integer: true });
  return value;
}

export function validateCountLimit(name: string, value: number): number {
  assertPositive(name, value, CONFIG_BOUNDS.maxCount, { integer: true });
  return value;
}

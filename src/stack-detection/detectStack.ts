import type { DetectedStack, FileMap } from '../shared/types.js';
import { probeStacks } from './detectors.js';

export function detectStack(fileMap: FileMap): DetectedStack {
  const stacks = probeStacks(fileMap).sort((a, b) => a.name.localeCompare(b.name));
  return { stacks };
}

export function hasStack(detected: DetectedStack, name: string): boolean {
  return detected.stacks.some((stack) => stack.name === name);
}

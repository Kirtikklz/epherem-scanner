import { describe, expect, it } from 'vitest';
import { hasStack } from '../../src/stack-detection/detectStack.js';
import { loadFixtureContext } from './helpers.js';

describe('detectStack', () => {
  it('detects Next.js + React + Supabase + Node in next-supabase-insecure', async () => {
    const { stack } = await loadFixtureContext('next-supabase-insecure');
    for (const name of ['nextjs', 'react', 'supabase', 'nodejs']) {
      expect(hasStack(stack, name), `expected ${name}`).toBe(true);
    }
    expect(hasStack(stack, 'firebase')).toBe(false);
  });

  it('detects Firebase in firebase-open-rules', async () => {
    const { stack } = await loadFixtureContext('firebase-open-rules');
    expect(hasStack(stack, 'firebase')).toBe(true);
    const firebase = stack.stacks.find((detection) => detection.name === 'firebase');
    expect(firebase?.confidence).toBe('high');
    expect(firebase?.evidence.length).toBeGreaterThan(0);
  });

  it('detects Express in express-cors-insecure', async () => {
    const { stack } = await loadFixtureContext('express-cors-insecure');
    expect(hasStack(stack, 'express')).toBe(true);
    expect(hasStack(stack, 'nodejs')).toBe(true);
  });

  it('does not over-detect on the clean project', async () => {
    const { stack } = await loadFixtureContext('clean-basic-project');
    expect(hasStack(stack, 'nextjs')).toBe(true);
    expect(hasStack(stack, 'supabase')).toBe(false);
    expect(hasStack(stack, 'python')).toBe(false);
  });
});

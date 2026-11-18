import { defineConfig } from 'vitest/config';
import { TEST_TIMEOUT_MS } from './scripts/test-timeouts.mjs';

export default defineConfig({
  test: {
    include: ['tests/unit/**/*.test.ts'],
    environment: 'node',
    testTimeout: TEST_TIMEOUT_MS,
  },
});

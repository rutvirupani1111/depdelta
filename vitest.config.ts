import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // Tests are fully offline: every registry call goes through an injected fake fetch.
    env: {
      NO_COLOR: '1',
      DEPDELTA_NO_NETWORK: '1',
    },
  },
});

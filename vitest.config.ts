import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // test/.tmp is scratch space (temp repos, copies of the project): never collect tests from it.
    exclude: ['**/node_modules/**', 'test/.tmp/**'],
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

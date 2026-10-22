import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    cli: 'src/cli.ts',
  },
  format: ['esm', 'cjs'],
  dts: { entry: { index: 'src/index.ts' } },
  target: 'node18',
  platform: 'node',
  clean: true,
  shims: true,
  splitting: false,
  sourcemap: false,
  minify: false,
});

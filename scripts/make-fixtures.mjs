#!/usr/bin/env node
// Writes the synthetic demo packages to examples/fixtures/*.tgz.
// The malicious-looking fixture is inert (it throws on its first line) and
// uses fake endpoints and tokens; it exists only to be parsed by depdelta.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { benignV1, benignV2, maliciousV2, walletHookV2 } from '../test/fixtures/packages.mjs';
import { makeTgz } from '../test/fixtures/tar.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const outDir = join(root, 'examples', 'fixtures');
mkdirSync(outDir, { recursive: true });

const fixtures = {
  'tiny-colors-1.0.0.tgz': benignV1(),
  'tiny-colors-1.0.1.tgz': benignV2(),
  'tiny-colors-1.0.2.tgz': maliciousV2(),
  'tiny-colors-1.0.3.tgz': walletHookV2(),
};

for (const [name, files] of Object.entries(fixtures)) {
  writeFileSync(join(outDir, name), makeTgz(files));
  console.log(`wrote examples/fixtures/${name}`);
}

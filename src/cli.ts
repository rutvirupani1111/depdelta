#!/usr/bin/env node
import { runCli } from './cli/main.js';

runCli(process.argv.slice(2), {
  stdout: process.stdout,
  stderr: process.stderr,
  env: process.env,
  cwd: process.cwd(),
}).then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    process.stderr.write(`depdelta: ${(err as Error)?.stack ?? String(err)}\n`);
    process.exitCode = 2;
  },
);

// Local harness: runs the shell steps of action.yml the way a GitHub runner would
// (bash --noprofile --norc -eo pipefail), against a throwaway git repository.
// Usage: npm run build && node scripts/action-harness.mjs [changed|unchanged|push-new-branch]
// 'changed' downloads chalk 5.3.0 and 5.4.1 from the public registry. Work files go to test/.tmp/smoke.
// On Windows, set SMOKE_BASH to Git Bash (WSL's bash.exe would otherwise win on PATH).
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseYaml } from '../dist/index.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const scenario = process.argv[2] ?? 'changed';
const bash = process.env.SMOKE_BASH ?? 'bash';
const action = parseYaml(readFileSync(join(root, 'action.yml'), 'utf8'));
const work = join(root, 'test/.tmp/smoke', scenario);
rmSync(work, { recursive: true, force: true });
const repo = join(work, 'repo');
const temp = join(work, 'runner-temp');
mkdirSync(repo, { recursive: true });
mkdirSync(temp, { recursive: true });

const gitEnv = { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.com', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.com' };
const git = (...a) =>
  execFileSync('git', ['-c', 'core.autocrlf=false', '-c', 'commit.gpgsign=false', '-c', `core.hooksPath=${join(work, 'no-hooks')}`, ...a], { cwd: repo, encoding: 'utf8', env: gitEnv }).trim();

const lock = (chalk) =>
  JSON.stringify(
    {
      name: 'smoke-app',
      version: '1.0.0',
      lockfileVersion: 3,
      requires: true,
      packages: {
        '': { name: 'smoke-app', version: '1.0.0', dependencies: { chalk: `^${chalk}` } },
        'node_modules/chalk': { version: chalk, resolved: `https://registry.npmjs.org/chalk/-/chalk-${chalk}.tgz` },
      },
    },
    null,
    2,
  ) + '\n';

git('init', '-q');
writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'smoke-app', version: '1.0.0', dependencies: { chalk: '^5.3.0' } }, null, 2));
writeFileSync(join(repo, 'package-lock.json'), lock('5.3.0'));
git('add', '.');
git('commit', '-q', '-m', 'base');
const baseSha = git('rev-parse', 'HEAD');
if (scenario === 'changed') writeFileSync(join(repo, 'package-lock.json'), lock('5.4.1'));

const inputs = Object.fromEntries(Object.entries(action.inputs).map(([k, v]) => [k, v.default === '${{ github.token }}' ? 'fake-token' : String(v.default ?? '')]));
Object.assign(inputs, JSON.parse(process.env.SMOKE_INPUTS ?? '{}'));
const github = {
  event_name: scenario === 'push-new-branch' ? 'push' : 'pull_request',
  'event.pull_request.base.sha': baseSha,
  'event.merge_group.base_sha': '',
  'event.before': scenario === 'push-new-branch' ? '0000000000000000000000000000000000000000' : '',
  'event.pull_request.number': '',
  repository: 'example/smoke',
  token: 'fake-token',
};
const outputs = {};
const expr = (s) =>
  String(s ?? '').replace(/\$\{\{\s*([^}]+?)\s*\}\}/g, (_, e) => {
    let m;
    if ((m = /^inputs\.([\w-]+)$/.exec(e))) return inputs[m[1]] ?? '';
    if ((m = /^steps\.([\w-]+)\.outputs\.([\w-]+)$/.exec(e))) return outputs[m[1]]?.[m[2]] ?? '';
    if ((m = /^github\.(.+)$/.exec(e))) return github[m[1]] ?? '';
    throw new Error(`unsupported expression ${e}`);
  });
const cond = (c) => {
  if (!c) return true;
  let m;
  if ((m = /^steps\.([\w-]+)\.outputs\.([\w-]+) != 'true'$/.exec(c))) return (outputs[m[1]]?.[m[2]] ?? '') !== 'true';
  if (c.includes('github.event.pull_request.number')) return false; // no PR in the harness
  throw new Error(`unsupported condition ${c}`);
};

const summary = join(work, 'step-summary.md');
writeFileSync(summary, '');
for (const step of action.runs.steps) {
  if (!cond(step.if)) {
    console.log(`--- skip: ${step.name}`);
    continue;
  }
  console.log(`--- run: ${step.name}`);
  const outFile = join(work, `out-${step.id ?? 'x'}.txt`);
  writeFileSync(outFile, '');
  const script = join(work, `step-${(step.id ?? step.name).replace(/\W+/g, '-')}.sh`);
  writeFileSync(script, step.run);
  const env = { ...process.env, GITHUB_OUTPUT: outFile, GITHUB_STEP_SUMMARY: summary, GITHUB_ACTION_PATH: root, GITHUB_WORKSPACE: repo, RUNNER_TEMP: temp, CI: 'true' };
  for (const [k, v] of Object.entries(step.env ?? {})) env[k] = expr(v);
  const cwd = step['working-directory'] ? resolve(repo, expr(step['working-directory'])) : repo;
  const r = spawnSync(bash, ['--noprofile', '--norc', '-eo', 'pipefail', script], { cwd, env, stdio: 'inherit' });
  if (step.id) {
    outputs[step.id] = Object.fromEntries(
      readFileSync(outFile, 'utf8')
        .split('\n')
        .filter((l) => l.includes('='))
        .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
    );
  }
  if (r.status !== 0) {
    console.log(`--- step failed with exit code ${r.status}`);
    break;
  }
}
console.log('=== outputs', JSON.stringify(outputs, null, 1));
console.log('=== step summary\n' + readFileSync(summary, 'utf8'));
if (outputs.run?.['sarif-file']) console.log('=== sarif exists:', existsSync(outputs.run['sarif-file']));

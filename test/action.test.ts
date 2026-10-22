import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseYaml } from '../src/lockfile/yaml.js';
import { LOCKFILE_NAMES } from '../src/lockfile/index.js';
import { MARKDOWN_MARKER } from '../src/report/index.js';

// Structural checks for the composite action and the example workflow: they cannot
// run here, so these tests pin down the wiring between inputs, steps and outputs.

interface Step {
  name: string;
  id?: string;
  if?: string;
  shell?: string;
  run?: string;
  uses?: string;
  env?: Record<string, string>;
  with?: Record<string, string>;
}

const read = (path: string): string => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const actionText = read('action.yml');
const action = parseYaml(actionText) as unknown as {
  name: string;
  description: string;
  branding: Record<string, string>;
  inputs: Record<string, { description: string; default?: string }>;
  outputs: Record<string, { description: string; value: string }>;
  runs: { using: string; steps: Step[] };
};
const steps = action.runs.steps;
const workflow = parseYaml(read('examples/github-action.yml')) as unknown as {
  on: { pull_request: { paths: string[] } };
  permissions: Record<string, string>;
  jobs: Record<string, { steps: Step[] }>;
};

/** Variables the runner provides to every step. */
const RUNNER_VARS = new Set(['GITHUB_OUTPUT', 'GITHUB_STEP_SUMMARY', 'GITHUB_ACTION_PATH', 'GITHUB_WORKSPACE', 'RUNNER_TEMP']);

describe('action.yml', () => {
  it('is a composite action with a name, description and branding', () => {
    expect(action.runs.using).toBe('composite');
    expect(action.name).toBe('depdelta');
    expect(action.description.length).toBeGreaterThan(20);
    expect(action.branding).toEqual({ icon: 'shield', color: 'orange' });
  });

  it('runs every script in bash and never interpolates expressions into a script', () => {
    for (const step of steps.filter((s) => s.run)) {
      expect(step.shell, step.name).toBe('bash');
      expect(step.run, step.name).not.toContain('${{');
    }
  });

  it('gives every script the variables it reads', () => {
    for (const step of steps.filter((s) => s.run)) {
      const used = new Set(Array.from(step.run!.matchAll(/\$\{?([A-Z][A-Z0-9_]+)/g), (m) => m[1]!));
      for (const name of used) expect(RUNNER_VARS.has(name) || Object.hasOwn(step.env ?? {}, name), `${step.name}: $${name}`).toBe(true);
    }
  });

  it('documents every input and uses each one', () => {
    const referenced = new Set(Array.from(actionText.matchAll(/inputs\.([\w-]+)/g), (m) => m[1]!));
    for (const [name, input] of Object.entries(action.inputs)) {
      expect(input.description.length, name).toBeGreaterThan(10);
      expect(referenced.has(name), `input ${name} is never used`).toBe(true);
    }
    for (const name of referenced) expect(Object.keys(action.inputs)).toContain(name);
  });

  it('maps every output to a value a step writes to GITHUB_OUTPUT', () => {
    for (const [name, output] of Object.entries(action.outputs)) {
      const m = /^\$\{\{ steps\.([\w-]+)\.outputs\.([\w-]+) \}\}$/.exec(output.value);
      expect(m, name).not.toBeNull();
      const step = steps.find((s) => s.id === m![1]);
      expect(step, name).toBeDefined();
      expect(step!.run).toMatch(new RegExp(`${m![2]}=`));
    }
  });

  it('builds dist/cli.js without install scripts when the checkout has no dist', () => {
    const build = steps.find((s) => s.name === 'Build depdelta')!.run!;
    const pkg = JSON.parse(read('package.json')) as { bin: Record<string, string> };
    expect(pkg.bin.depdelta).toBe('./dist/cli.js');
    expect(build).toContain('if [ -f dist/cli.js ]');
    expect(build).toContain('npm ci --ignore-scripts');
    expect(steps.find((s) => s.id === 'run')!.run).toContain('node "$GITHUB_ACTION_PATH/dist/cli.js"');
  });

  it('finds its own pull request comment by the marker the markdown report starts with', () => {
    expect(steps.find((s) => s.name === 'Comment on the pull request')!.run).toContain(`startswith("${MARKDOWN_MARKER}")`);
  });

  it('checks the same lockfile names the CLI auto-detects', () => {
    expect(steps.find((s) => s.id === 'changes')!.run).toContain(`set -- ${LOCKFILE_NAMES.join(' ')}`);
  });
});

describe('examples/github-action.yml', () => {
  const job = Object.values(workflow.jobs)[0]!;
  const depdelta = job.steps.find((s) => s.uses?.startsWith('rutvirupani1111/depdelta'))!;

  it('runs on pull requests that change any supported lockfile', () => {
    expect([...workflow.on.pull_request.paths].sort()).toEqual(LOCKFILE_NAMES.map((n) => `**/${n}`).sort());
    expect(workflow.permissions.contents).toBe('read');
  });

  it('uses the action from main with valid inputs and outputs', () => {
    expect(depdelta.uses).toBe('rutvirupani1111/depdelta@main');
    for (const key of Object.keys(depdelta.with ?? {})) expect(Object.keys(action.inputs)).toContain(key);
    const refs = Array.from(JSON.stringify(job.steps).matchAll(/steps\.depdelta\.outputs\.([\w-]+)/g), (m) => m[1]!);
    expect(refs.length).toBeGreaterThan(0);
    for (const name of refs) expect(Object.keys(action.outputs)).toContain(name);
  });
});

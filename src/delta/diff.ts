/**
 * The capability delta: what a new version can do that the old one could not,
 * expressed as plain-language findings with evidence.
 */
import type {
  CapabilityChange,
  CapabilityKey,
  Evidence,
  Finding,
  PackageAnalysis,
  PackageDelta,
  RiskLevel,
  Severity,
  UpdateType,
} from '../types.js';
import { SEVERITY_RANK } from '../types.js';
import { NETWORK_GLOBALS, WALLET_GLOBALS, isHighValueSecret, isSecretEnvName } from '../analysis/patterns.js';
import { classifyUpdate } from '../util/semver.js';
import { listProse, plural, shortHash } from '../util/text.js';
import { ruleById, type RuleDef } from './rules.js';

type Ctx = 'update' | 'major' | 'new';

const LADDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function raise(s: Severity, n = 1, max: Severity = 'critical'): Severity {
  const idx = Math.min(LADDER.indexOf(s) + n, LADDER.indexOf(max));
  return LADDER[Math.max(idx, LADDER.indexOf(s))]!;
}

export function lower(s: Severity, n = 1): Severity {
  return LADDER[Math.max(0, LADDER.indexOf(s) - n)]!;
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

const POLYFILL = ' (if missing)';

function walletPhrase(v: string): string {
  if (v.endsWith(' address')) return `${v}es`;
  if (v === 'wallet RPC') return 'wallet RPC methods';
  const m = /^wallet provider \((.+)\)$/.exec(v);
  if (m) return `access to the window.${m[1]} wallet provider`;
  return v;
}

const OBFUSCATION_TEXT: Record<string, string> = {
  'hex-identifiers': '_0x-style identifiers (javascript-obfuscator output)',
  'escaped-strings': 'strings hidden behind \\x / \\u escapes',
  'charcode-strings': 'strings assembled from character codes',
  'encoded-strings': 'module names, URLs or commands hidden in encoded strings',
  'encoded-script': 'base64-encoded JavaScript',
  'decode-and-eval': 'decoded code passed to eval',
  'embedded-executable': 'an executable embedded as base64',
};

const BLOB_TEXT: Record<string, string> = {
  'base64-blob': 'large base64 data',
  'high-entropy-strings': 'high-entropy strings (keys or encoded data)',
  'embedded-archive': 'an embedded gzip/zip archive',
};

/** Read-only helpers over the before/after analyses. */
class DeltaView {
  constructor(
    readonly before: PackageAnalysis | null,
    readonly after: PackageAnalysis,
  ) {}

  cap(key: CapabilityKey) {
    return this.after.capabilities[key];
  }

  prev(key: CapabilityKey) {
    return this.before?.capabilities[key];
  }

  has(key: CapabilityKey): boolean {
    return Boolean(this.cap(key));
  }

  isNewKey(key: CapabilityKey): boolean {
    return this.has(key) && !this.prev(key);
  }

  values(key: CapabilityKey): string[] {
    return this.cap(key)?.values ?? [];
  }

  newValues(key: CapabilityKey): string[] {
    const cap = this.cap(key);
    if (!cap) return [];
    const prev = new Set(this.prev(key)?.values ?? []);
    return cap.values.filter((v) => !prev.has(v));
  }

  installTime(key: CapabilityKey, values?: string[]): boolean {
    const cap = this.cap(key);
    if (!cap) return false;
    if (!values) return cap.installTime;
    return values.some((v) => cap.installTimeValues.includes(v));
  }

  installTimeValues(key: CapabilityKey): string[] {
    return this.cap(key)?.installTimeValues ?? [];
  }

  evidence(key: CapabilityKey, values?: string[], limit = 3): Evidence[] {
    const cap = this.cap(key);
    if (!cap) return [];
    const wanted = values ? new Set(values) : undefined;
    const seen = new Set<string>();
    const out: Evidence[] = [];
    const sorted = [...cap.evidence].sort((a, b) => Number(Boolean(b.installTime)) - Number(Boolean(a.installTime)));
    for (const e of sorted) {
      if (wanted && e.value !== undefined && !wanted.has(e.value)) continue;
      const id = `${e.file}:${e.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(e);
      if (out.length >= limit) break;
    }
    return out;
  }

  evidenceFiles(key: CapabilityKey, values?: string[]): string[] {
    return [...new Set(this.evidence(key, values, 50).map((e) => e.file))];
  }
}

interface Draft {
  rule: RuleDef;
  severity: Severity;
  title: string;
  message: string;
  evidence: Evidence[];
  capability?: CapabilityKey;
  values?: string[];
  installTime?: boolean;
}

function baseSeverity(rule: RuleDef, ctx: Ctx): Severity {
  return ctx === 'new' ? rule.newSeverity : ctx === 'major' ? rule.majorSeverity : rule.severity;
}

function code(s: string): string {
  return `\`${s.replace(/`/g, "'")}\``;
}

/** Env var names render as code; labels such as "SSH keys" stay prose. */
function fmtSecret(v: string): string {
  return /^[A-Z][A-Z0-9_]*$/.test(v) ? code(v) : v;
}

function stripPolyfill(v: string): string {
  return v.endsWith(POLYFILL) ? v.slice(0, -POLYFILL.length) : v;
}

function isHookTarget(v: string): boolean {
  const head = stripPolyfill(v).split('.')[0]!;
  return NETWORK_GLOBALS.has(head) || WALLET_GLOBALS.has(head) || head === 'navigator';
}

/** Plain phrases for what install-time code does, e.g. "reads NPM_TOKEN". */
function installPayload(view: DeltaView): string[] {
  const out: string[] = [];
  const secrets = view.installTimeValues('env-secrets');
  if (secrets.length) out.push(`reads ${listProse(secrets.map(fmtSecret))}`);
  if (view.installTimeValues('env-dump').length) out.push('reads the whole environment');
  const creds = view.installTimeValues('credential-files');
  if (creds.length) out.push(`touches ${listProse(creds)}`);
  const net = view.installTimeValues('network');
  if (net.length) out.push(`uses the network (${listProse(net)})`);
  const susp = view.installTimeValues('suspicious-endpoint');
  if (susp.length) out.push(`contacts ${listProse(susp)}`);
  const cp = view.installTimeValues('child_process');
  if (cp.length) out.push(`starts processes (${listProse(cp)})`);
  if (view.installTimeValues('shell-download').length) out.push('downloads code with shell commands');
  if (view.installTimeValues('npm-publish').length) out.push('calls npm publish/token commands');
  if (view.installTimeValues('eval').includes('decoded payload')) out.push('decodes and runs hidden code');
  if (view.installTimeValues('obfuscation').length) out.push('is obfuscated');
  return out;
}

/** Install-time behaviour that is never expected from a routine native build step. */
function installRedFlags(view: DeltaView): boolean {
  return (
    view.installTimeValues('env-secrets').some(isHighValueSecret) ||
    view.installTimeValues('env-dump').length > 0 ||
    view.installTimeValues('credential-files').length > 0 ||
    view.installTimeValues('suspicious-endpoint').length > 0 ||
    view.installTimeValues('npm-publish').length > 0 ||
    view.installTimeValues('obfuscation').length > 0 ||
    view.installTimeValues('eval').includes('decoded payload')
  );
}

const RISKY_SCRIPT_FLAGS = new Set(['shell-download', 'pipe-to-shell', 'remote-package', 'inline-code', 'env-secret']);

function rulesFor(view: DeltaView, ctx: Ctx): Draft[] {
  const drafts: Draft[] = [];
  const { before, after } = view;
  const add = (d: Draft): void => {
    drafts.push(d);
  };

  // DD001 new install scripts ----------------------------------------------------
  const newEvents = view.newValues('install-script');
  if (newEvents.length) {
    const rule = ruleById('DD001');
    const scripts = after.installScripts.filter((s) => newEvents.includes(s.event));
    const flags = new Set(scripts.flatMap((s) => s.flags));
    const payload = installPayload(view);
    let sev = baseSeverity(rule, ctx);
    const riskyFlags = [...flags].some((f) => RISKY_SCRIPT_FLAGS.has(f));
    const onlyPrepare = scripts.every((s) => s.event === 'prepare');
    const onlyBuild = scripts.every((s) => s.flags.includes('native-build') || s.flags.includes('known-tool'));
    if (ctx === 'new') {
      if (installRedFlags(view) || flags.has('pipe-to-shell') || flags.has('env-secret')) sev = 'critical';
      else if (riskyFlags) sev = 'high';
      else if (onlyBuild || onlyPrepare) sev = 'low';
    } else {
      if (installRedFlags(view)) sev = 'critical';
      else if (riskyFlags || payload.length) sev = maxSeverity(sev, 'high');
      else if (onlyPrepare) sev = lower(sev);
    }
    const described = scripts.map((s) => (s.implicit ? `${code(s.event)} (implicit: binding.gyp makes npm run ${code('node-gyp rebuild')})` : `${code(s.event)} runs ${code(s.command)}`));
    let message = `${listProse(described)} automatically during npm install, before any of your code imports the package.`;
    if (payload.length) message += ` That install-time code ${listProse(payload, 8)}.`;
    if (onlyPrepare) message += ' (prepare only runs for git and local installs.)';
    const evidence = [...view.evidence('install-script', newEvents, 2)];
    for (const k of ['env-secrets', 'suspicious-endpoint', 'network', 'child_process'] as CapabilityKey[]) {
      for (const e of view.evidence(k, view.installTimeValues(k), 1)) if (e.installTime && evidence.length < 4) evidence.push(e);
    }
    add({
      rule,
      severity: sev,
      title: `New install script: ${scripts.map((s) => s.event).join(', ')}`,
      message,
      evidence,
      capability: 'install-script',
      values: newEvents,
      installTime: true,
    });
  }

  // DD002 changed install scripts ---------------------------------------------------
  if (before) {
    for (const s of after.installScripts) {
      const old = before.installScripts.find((b) => b.event === s.event);
      if (!old || old.command === s.command || (old.implicit && s.implicit)) continue;
      const rule = ruleById('DD002');
      const oldFlags = new Set(old.flags);
      const newFlags = s.flags.filter((f) => !oldFlags.has(f));
      const newTargets = s.targets.filter((t) => !old.targets.includes(t));
      let sev = baseSeverity(rule, ctx);
      if (installRedFlags(view)) sev = 'critical';
      else if (newFlags.some((f) => RISKY_SCRIPT_FLAGS.has(f))) sev = 'high';
      let message = `${code(s.event)} changed from ${code(old.command)} to ${code(s.command)}.`;
      if (newTargets.length) message += ` It now runs ${listProse(newTargets.map(code))}.`;
      const payload = installPayload(view);
      if (payload.length && newTargets.length) message += ` That code ${listProse(payload, 8)}.`;
      add({
        rule,
        severity: sev,
        title: `Install script changed: ${s.event}`,
        message,
        evidence: view.evidence('install-script', [s.event], 1),
        capability: 'install-script',
        values: [s.event],
        installTime: true,
      });
    }
  }

  // Simple "new capability" rules ---------------------------------------------------
  const simple = (
    id: string,
    key: CapabilityKey,
    phrase: (values: string[], isNew: boolean) => string,
    opts: { filter?: (v: string) => boolean; keepValueSeverity?: boolean; titleSuffix?: (values: string[]) => string } = {},
  ): void => {
    let nv = view.newValues(key);
    if (opts.filter) nv = nv.filter(opts.filter);
    if (nv.length === 0) return;
    const rule = ruleById(id);
    const isNew = view.isNewKey(key);
    let sev = baseSeverity(rule, ctx);
    if (!isNew && !opts.keepValueSeverity) sev = lower(sev);
    const inst = view.installTime(key, nv);
    if (inst) sev = raise(sev, 1, 'high');
    let message = phrase(nv, isNew);
    if (inst) message += ' This code runs at install time.';
    add({
      rule,
      severity: sev,
      title: opts.titleSuffix ? `${rule.title}${opts.titleSuffix(nv)}` : rule.title,
      message,
      evidence: view.evidence(key, nv),
      capability: key,
      values: nv,
      installTime: inst,
    });
  };

  simple('DD003', 'child_process', (v, isNew) =>
    isNew ? `Can now start other programs (${listProse(v)}).` : `Now also starts programs with ${listProse(v)}.`,
  );
  simple('DD004', 'network', (v, isNew) =>
    isNew ? `Can now make network requests (${listProse(v)}).` : `Now also uses ${listProse(v)} for network access.`,
  );
  simple(
    'DD005',
    'env-secrets',
    (v) => `Now reads ${listProse(v.map(code))} from the environment.`,
    { keepValueSeverity: true, titleSuffix: (v) => `: ${listProse(v, 3)}` },
  );
  simple('DD006', 'env-dump', (v) => `Now reads the entire environment (${listProse(v)}).`);
  simple(
    'DD008',
    'eval',
    (v, isNew) => (isNew ? `Now runs code built at runtime (${listProse(v)}).` : `Now also runs dynamic code via ${listProse(v)}.`),
    { filter: (v) => v !== 'decoded payload' },
  );
  simple('DD010', 'dynamic-require', () => 'Now loads modules whose names are computed at runtime, which can hide what is loaded.');
  simple('DD024', 'fs', () => 'Can now read and write files.');
  simple('DD025', 'os', (v) => `Now reads system information${v.some((x) => x !== 'os') ? ` (${listProse(v.filter((x) => x !== 'os'))})` : ''}.`);
  simple('DD026', 'vm', () => 'Now compiles or runs code with the vm module.');
  simple('DD027', 'worker_threads', () => 'Now starts worker threads.');
  simple('DD028', 'process.binding', (v) => `Now uses internal process bindings (${listProse(v)}).`);

  // DD007 exfiltration chain ---------------------------------------------------------
  {
    const rule = ruleById('DD007');
    const credLabels = new Set(view.values('credential-files'));
    const isValuable = (v: string): boolean => isHighValueSecret(v) || v === 'the whole environment' || credLabels.has(v);
    const secretNew = [
      ...view.newValues('env-secrets'),
      ...(view.newValues('env-dump').length && view.isNewKey('env-dump') ? ['the whole environment'] : []),
      ...view.newValues('credential-files'),
    ];
    const secretAll = [...view.values('env-secrets'), ...(view.has('env-dump') ? ['the whole environment'] : []), ...view.values('credential-files')];
    const sinkNew: string[] = [];
    if (view.isNewKey('network')) sinkNew.push(`the network (${listProse(view.values('network'))})`);
    const suspNew = view.newValues('suspicious-endpoint');
    if (suspNew.length) sinkNew.push(listProse(suspNew));
    if (view.isNewKey('shell-download')) sinkNew.push('shell download commands');
    const sinkAll: string[] = [];
    if (view.has('network')) sinkAll.push(`the network (${listProse(view.values('network'))})`);
    if (view.has('suspicious-endpoint')) sinkAll.push(listProse(view.values('suspicious-endpoint')));

    const secretInstall =
      view.installTimeValues('env-secrets').length > 0 || view.installTimeValues('env-dump').length > 0 || view.installTimeValues('credential-files').length > 0;
    const sinkInstall = view.installTimeValues('network').length > 0 || view.installTimeValues('suspicious-endpoint').length > 0;
    const atInstall = secretInstall && sinkInstall;
    const evidence = (secrets: string[]): Evidence[] => {
      const ev = [...view.evidence('env-secrets', secrets, 2), ...view.evidence('env-dump', undefined, 1), ...view.evidence('credential-files', secrets, 1)].slice(0, 2);
      ev.push(...view.evidence('suspicious-endpoint', undefined, 1));
      if (ev.length < 4) ev.push(...view.evidence('network', undefined, 4 - ev.length));
      return ev.slice(0, 4);
    };
    const tail = atInstall ? ' Both happen in code that runs at install time.' : '';
    let draft: Draft | undefined;
    if (ctx !== 'new') {
      if (secretNew.length && sinkNew.length) {
        draft = {
          rule,
          severity: 'critical',
          title: rule.title,
          message: `This release starts reading ${listProse(secretNew.map(fmtSecret))} and can now send data out through ${listProse(sinkNew)}.${tail} That is the shape of a token-stealing update.`,
          evidence: evidence(secretNew),
        };
      } else if (secretNew.some(isValuable) && sinkAll.length) {
        const valuable = secretNew.filter(isValuable);
        draft = {
          rule,
          severity: 'high',
          title: rule.title,
          message: `Now reads ${listProse(valuable.map(fmtSecret))} in a package that can already send data through ${listProse(sinkAll)}.${tail}`,
          evidence: evidence(valuable),
        };
      } else if (sinkNew.length && secretAll.some(isValuable)) {
        const valuable = secretAll.filter(isValuable);
        draft = {
          rule,
          severity: 'high',
          title: rule.title,
          message: `Already read ${listProse(valuable.map(fmtSecret))}; this release adds a way to send data out: ${listProse(sinkNew)}.${tail}`,
          evidence: evidence(valuable),
        };
      }
    } else if (secretAll.some(isValuable) && sinkAll.length) {
      const valuable = secretAll.filter(isValuable);
      draft = {
        rule,
        severity: atInstall ? 'critical' : baseSeverity(rule, ctx),
        title: rule.title,
        message: `Reads ${listProse(valuable.map(fmtSecret))} and can send data through ${listProse(sinkAll)}.${tail}`,
        evidence: evidence(valuable),
      };
    }
    if (draft) add({ ...draft, values: [...new Set([...secretNew, ...secretAll])].sort(), installTime: atInstall });
  }

  // DD009 decode and run -----------------------------------------------------------
  if (view.newValues('eval').includes('decoded payload')) {
    const rule = ruleById('DD009');
    const inst = view.installTime('eval', ['decoded payload']);
    add({
      rule,
      severity: inst ? 'critical' : baseSeverity(rule, ctx),
      title: rule.title,
      message: `Decodes a hidden string at runtime and executes it with eval/new Function.${inst ? ' This runs at install time.' : ''}`,
      evidence: view.evidence('eval', ['decoded payload']),
      capability: 'eval',
      values: ['decoded payload'],
      installTime: inst,
    });
  }

  // DD011 / DD012 global and prototype patches ---------------------------------------
  {
    const nv = view.newValues('global-patch');
    const hooks = nv.filter((v) => isHookTarget(v) && !v.endsWith(POLYFILL));
    if (hooks.length) {
      const rule = ruleById('DD011');
      const wallet = hooks.some((v) => WALLET_GLOBALS.has(v.split('.')[0]!));
      add({
        rule,
        severity: baseSeverity(rule, ctx),
        title: `${rule.title}: ${listProse(hooks, 3)}`,
        message: `Now replaces ${listProse(hooks.map(code))}. Every ${wallet ? 'wallet call and request' : 'request'} the app makes would pass through this package's code first.`,
        evidence: view.evidence('global-patch', hooks),
        capability: 'global-patch',
        values: hooks,
        installTime: view.installTime('global-patch', hooks),
      });
    }
    const overrides = [...nv.filter((v) => !isHookTarget(v) && !v.endsWith(POLYFILL)), ...view.newValues('prototype-patch').filter((v) => !v.endsWith(POLYFILL))];
    const polyfills = [...nv.filter((v) => v.endsWith(POLYFILL)), ...view.newValues('prototype-patch').filter((v) => v.endsWith(POLYFILL))];
    const rule = ruleById('DD012');
    if (overrides.length) {
      add({
        rule,
        severity: baseSeverity(rule, ctx),
        title: rule.title,
        message: `Now overrides ${listProse(overrides.map(code))}, which changes behaviour for all code in the process.`,
        evidence: [...view.evidence('global-patch', overrides, 2), ...view.evidence('prototype-patch', overrides, 2)].slice(0, 3),
        capability: 'prototype-patch',
        values: overrides,
      });
    } else if (polyfills.length) {
      add({
        rule,
        severity: lower(baseSeverity(rule, ctx)),
        title: `${rule.title} (polyfill)`,
        message: `Now installs ${listProse(polyfills.map((p) => code(stripPolyfill(p))))} when missing. Polyfills are usually benign.`,
        evidence: [...view.evidence('global-patch', polyfills, 2), ...view.evidence('prototype-patch', polyfills, 2)].slice(0, 3),
        capability: 'prototype-patch',
        values: polyfills,
      });
    }
  }

  simple('DD013', 'loader-hook', (v) => `Now hooks Node's module loader (${listProse(v.map(code))}); it can rewrite modules as they load.`, { keepValueSeverity: true });

  // DD014 obfuscation ------------------------------------------------------------------
  {
    const nv = view.newValues('obfuscation');
    if (nv.length) {
      const rule = ruleById('DD014');
      let sev = baseSeverity(rule, ctx);
      if (!view.isNewKey('obfuscation')) sev = lower(sev);
      const files = view.evidenceFiles('obfuscation', nv);
      const inst = view.installTime('obfuscation', nv);
      add({
        rule,
        severity: inst ? raise(sev) : sev,
        title: rule.title,
        message: `${listProse(files.map(code))} now ${files.length === 1 ? 'contains' : 'contain'} ${listProse(nv.map((s) => OBFUSCATION_TEXT[s] ?? s))}. Readable open-source code has no reason to hide itself.${inst ? ' It runs at install time.' : ''}`,
        evidence: view.evidence('obfuscation', nv),
        capability: 'obfuscation',
        values: nv,
        installTime: inst,
      });
    }
  }

  // DD015 minified where readable before ------------------------------------------------
  if (ctx !== 'new' && before && view.isNewKey('minified') && before.stats.jsFiles > 0) {
    const rule = ruleById('DD015');
    const files = view.values('minified');
    add({
      rule,
      severity: baseSeverity(rule, ctx),
      title: rule.title,
      message: `${listProse(files.map(code))} ${files.length === 1 ? 'is' : 'are'} minified, while ${before.version} shipped readable code. Minified code is hard to review and easy to hide a payload in.`,
      evidence: view.evidence('minified', undefined, 3),
      capability: 'minified',
      values: files,
      installTime: view.installTime('minified'),
    });
  }

  // DD016 encoded blobs ----------------------------------------------------------------
  simple('DD016', 'encoded-blob', (v) => `New ${listProse(v.map((s) => BLOB_TEXT[s] ?? s))} in ${listProse(view.evidenceFiles('encoded-blob', v).map(code))}.`, {
    keepValueSeverity: true,
  });

  // DD017 native binaries --------------------------------------------------------------
  {
    const nv = view.newValues('native-binary');
    if (nv.length) {
      const rule = ruleById('DD017');
      const embedded = nv.filter((v) => v.startsWith('embedded '));
      const files = nv.filter((v) => !v.startsWith('embedded '));
      if (embedded.length) {
        add({
          rule,
          severity: 'high',
          title: 'Executable hidden in a string',
          message: `Contains ${listProse(embedded)} encoded inside JavaScript. Binaries shipped this way are designed to avoid review.`,
          evidence: view.evidence('native-binary', embedded),
          capability: 'native-binary',
          values: embedded,
        });
      }
      if (files.length) {
        const hadBinaries = (view.prev('native-binary')?.values ?? []).some((v) => !v.startsWith('embedded '));
        let sev = baseSeverity(rule, ctx);
        if (hadBinaries) sev = lower(sev);
        add({
          rule,
          severity: sev,
          title: rule.title,
          message: `Now ships ${plural(files.length, 'binary file')}: ${listProse(files.map(code))}.`,
          evidence: view.evidence('native-binary', files),
          capability: 'native-binary',
          values: files,
          installTime: view.installTime('native-binary', files),
        });
      }
    }
  }

  // DD018 suspicious endpoints ------------------------------------------------------------
  simple('DD018', 'suspicious-endpoint', (v) => `References ${listProse(v)}. Libraries rarely talk to webhooks, tunnels, paste sites or metadata services.`, {
    keepValueSeverity: true,
  });

  // DD019 new hosts -------------------------------------------------------------------------
  {
    const suspiciousHosts = new Set(view.values('suspicious-endpoint').map((v) => /\(([^)]+)\)$/.exec(v)?.[1]).filter(Boolean) as string[]);
    const nv = view.newValues('endpoint').filter((h) => !suspiciousHosts.has(h));
    if (nv.length) {
      const rule = ruleById('DD019');
      let sev = baseSeverity(rule, ctx);
      if (!view.has('network')) sev = 'info';
      add({
        rule,
        severity: sev,
        title: `${rule.title}: ${listProse(nv, 3)}`,
        message: `Mentions ${plural(nv.length, 'host')} the previous version did not: ${listProse(nv, 6)}.`,
        evidence: view.evidence('endpoint', nv),
        capability: 'endpoint',
        values: nv,
      });
    }
  }

  // DD020 wallets --------------------------------------------------------------------------
  {
    const nv = view.newValues('crypto-wallet');
    if (nv.length) {
      const rule = ruleById('DD020');
      const strong = nv.filter((v) => !v.startsWith('wallet provider'));
      let sev = baseSeverity(rule, ctx);
      if (!view.isNewKey('crypto-wallet')) sev = 'low';
      else if (strong.length === 0) sev = lower(sev);
      add({
        rule,
        severity: sev,
        title: rule.title,
        message: `Now contains ${listProse(nv.map(walletPhrase))}. Outside web3 libraries this usually means a wallet drainer.`,
        evidence: view.evidence('crypto-wallet', nv),
        capability: 'crypto-wallet',
        values: nv,
      });
    }
  }

  simple('DD021', 'credential-files', (v) => `Now references ${listProse(v)}.`, { keepValueSeverity: true });
  simple(
    'DD022',
    'npm-publish',
    (v) => `Now contains npm publishing or token commands (${listProse(v.map(code))}). Worms such as Shai-Hulud use them to republish every package a stolen token can reach.`,
    { keepValueSeverity: true },
  );
  simple('DD023', 'ci-tamper', (v) => `Now references ${listProse(v.map(code))}; code that writes there can plant a persistent CI backdoor.`, {
    keepValueSeverity: true,
  });

  // DD029 bin ---------------------------------------------------------------------------------
  {
    const nv = view.newValues('bin');
    if (nv.length) {
      const rule = ruleById('DD029');
      const shadow = nv.filter((v) => v.includes('shadows a system command'));
      add({
        rule,
        severity: shadow.length ? 'high' : baseSeverity(rule, ctx),
        title: shadow.length ? 'Shadows a system command' : rule.title,
        message: `Adds ${nv.length === 1 ? 'command' : 'commands'} ${listProse(nv.map(code))} to node_modules/.bin.`,
        evidence: view.evidence('bin', nv),
        capability: 'bin',
        values: nv,
      });
    }
  }

  simple('DD032', 'shell-download', (v) => `Now contains shell commands that download or run remote code (${listProse(v)}).`, { keepValueSeverity: true });

  // DD033 new config env vars (info) ------------------------------------------------------------
  if (ctx !== 'new') {
    const nv = view.newValues('env').filter((v) => v !== '(computed)' && !isSecretEnvName(v));
    if (nv.length) {
      const rule = ruleById('DD033');
      add({
        rule,
        severity: 'info',
        title: `${rule.title}: ${listProse(nv, 3)}`,
        message: `Reads ${listProse(nv.map(code), 6)} (none look like secrets).`,
        evidence: view.evidence('env', nv),
        capability: 'env',
        values: nv,
      });
    }
  }

  return drafts;
}

const WEIGHT: Record<Severity, number> = { critical: 0.9, high: 0.6, medium: 0.3, low: 0.1, info: 0 };

/** 0-100 score from active (unsuppressed) findings; independent findings compound. */
export function scoreFindings(findings: Finding[]): { score: number; level: RiskLevel } {
  let keep = 1;
  let level: RiskLevel = 'none';
  for (const f of findings) {
    if (f.suppressed) continue;
    keep *= 1 - WEIGHT[f.severity];
    if (f.severity !== 'info' && (level === 'none' || SEVERITY_RANK[f.severity] > SEVERITY_RANK[level])) level = f.severity;
  }
  return { score: Math.round(100 * (1 - keep)), level };
}

/** Within one severity, the rules a reviewer should read first. */
const RULE_PRIORITY = ['DD031', 'DD007', 'DD022', 'DD009', 'DD011', 'DD001', 'DD014', 'DD018', 'DD032', 'DD021', 'DD023', 'DD020', 'DD030', 'DD003', 'DD005', 'DD006', 'DD004'];

function priority(rule: string): number {
  const i = RULE_PRIORITY.indexOf(rule);
  return i === -1 ? RULE_PRIORITY.length : i;
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      priority(a.rule) - priority(b.rule) ||
      a.rule.localeCompare(b.rule) ||
      a.title.localeCompare(b.title),
  );
}

export function findingId(rule: string, pkg: string, version: string, values: readonly string[] | undefined): string {
  return `${rule}-${shortHash(`${pkg}@${version}|${rule}|${(values ?? []).join(',')}`)}`;
}

export interface DiffOptions {
  /** Overrides the update type computed from the two versions. */
  updateType?: UpdateType;
}

/**
 * Compares two analyses of the same package. Pass `null` as `before` for a newly
 * added package (or a single-version scan).
 */
export function diffCapabilities(before: PackageAnalysis | null, after: PackageAnalysis, options: DiffOptions = {}): PackageDelta {
  const updateType = options.updateType ?? classifyUpdate(before ? before.version : null, after.version);
  const ctx: Ctx = before === null ? 'new' : updateType === 'major' ? 'major' : 'update';
  const view = new DeltaView(before, after);

  const findings = sortFindings(
    rulesFor(view, ctx).map((d) => ({
      id: findingId(d.rule.id, after.name, after.version, d.values),
      rule: d.rule.id,
      slug: d.rule.slug,
      severity: d.severity,
      title: d.title,
      message: d.message,
      capability: d.capability,
      values: d.values,
      evidence: d.evidence,
      installTime: d.installTime || undefined,
    })),
  );

  const added: CapabilityChange[] = [];
  const removed: CapabilityChange[] = [];
  const unchanged: CapabilityKey[] = [];
  const keys = new Set<CapabilityKey>([
    ...(Object.keys(after.capabilities) as CapabilityKey[]),
    ...(Object.keys(before?.capabilities ?? {}) as CapabilityKey[]),
  ]);
  for (const key of [...keys].sort()) {
    const a = after.capabilities[key];
    const b = before?.capabilities[key];
    if (a && !b) added.push({ key, values: a.values, isNew: true });
    else if (!a && b) removed.push({ key, values: b.values, isNew: true });
    else if (a && b) {
      const bs = new Set(b.values);
      const as = new Set(a.values);
      const plus = a.values.filter((v) => !bs.has(v));
      const minus = b.values.filter((v) => !as.has(v));
      if (plus.length) added.push({ key, values: plus, isNew: false });
      if (minus.length) removed.push({ key, values: minus, isNew: false });
      if (!plus.length) unchanged.push(key);
    }
  }

  const beforeFiles = new Map((before?.files ?? []).map((f) => [f.path, f.hash]));
  const afterPaths = new Set(after.files.map((f) => f.path));
  const files = { added: 0, removed: 0, modified: 0, unchanged: 0 };
  for (const f of after.files) {
    const h = beforeFiles.get(f.path);
    if (h === undefined) files.added++;
    else if (h !== f.hash) files.modified++;
    else files.unchanged++;
  }
  for (const p of beforeFiles.keys()) if (!afterPaths.has(p)) files.removed++;

  const beforeDeps = new Set(before?.manifest.dependencies ?? []);
  const afterDeps = new Set(after.manifest.dependencies);
  const { score, level } = scoreFindings(findings);
  return {
    name: after.name,
    from: before ? before.version : null,
    to: after.version,
    updateType,
    findings,
    added,
    removed,
    unchanged,
    riskScore: score,
    riskLevel: level,
    files,
    dependencies: {
      added: before ? after.manifest.dependencies.filter((d) => !beforeDeps.has(d)) : [],
      removed: before ? before.manifest.dependencies.filter((d) => !afterDeps.has(d)) : [],
    },
  };
}

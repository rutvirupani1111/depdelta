import type { Capabilities, Capability, CapabilityKey, Evidence } from '../types.js';

const PER_VALUE_PER_FILE = 3;
const PER_VALUE_TOTAL = 4;
const PER_CAPABILITY_TOTAL = 40;
const MAX_VALUES = 300;

interface Hit {
  key: CapabilityKey;
  value: string;
  count: number;
  evidence: Evidence[];
}

/** Collects capability hits for one file, de-duplicating repeated locations. */
export class FileCollector {
  readonly file: string;
  private readonly hits = new Map<string, Hit>();

  constructor(file: string) {
    this.file = file;
  }

  add(key: CapabilityKey, value: string, line: number, column: number, excerpt: string): void {
    const id = `${key}\u0000${value}`;
    let hit = this.hits.get(id);
    if (!hit) {
      hit = { key, value, count: 0, evidence: [] };
      this.hits.set(id, hit);
    }
    if (hit.evidence.some((e) => e.line === line && e.column === column)) return;
    hit.count++;
    if (hit.evidence.length < PER_VALUE_PER_FILE && !hit.evidence.some((e) => e.line === line)) {
      hit.evidence.push({ file: this.file, line, column, excerpt, value });
    }
  }

  has(key: CapabilityKey, value?: string): boolean {
    if (value !== undefined) return this.hits.has(`${key}\u0000${value}`);
    for (const h of this.hits.values()) if (h.key === key) return true;
    return false;
  }

  values(key: CapabilityKey): string[] {
    const out: string[] = [];
    for (const h of this.hits.values()) if (h.key === key) out.push(h.value);
    return out;
  }

  entries(): IterableIterator<Hit> {
    return this.hits.values();
  }
}

interface Acc {
  key: CapabilityKey;
  values: Map<string, { count: number; evidence: Evidence[]; installTime: boolean }>;
  count: number;
}

/** Merges per-file hits into package-level capabilities. */
export class PackageCollector {
  private readonly acc = new Map<CapabilityKey, Acc>();

  addFile(collector: FileCollector, installTime: boolean): void {
    for (const hit of collector.entries()) {
      this.addHit(hit.key, hit.value, hit.count, hit.evidence, installTime);
    }
  }

  addHit(key: CapabilityKey, value: string, count: number, evidence: Evidence[], installTime: boolean): void {
    let a = this.acc.get(key);
    if (!a) {
      a = { key, values: new Map(), count: 0 };
      this.acc.set(key, a);
    }
    a.count += count;
    let v = a.values.get(value);
    if (!v) {
      if (a.values.size >= MAX_VALUES) return;
      v = { count: 0, evidence: [], installTime: false };
      a.values.set(value, v);
    }
    v.count += count;
    v.installTime ||= installTime;
    for (const e of evidence) {
      const tagged: Evidence = installTime ? { ...e, installTime: true } : { ...e };
      v.evidence.push(tagged);
    }
  }

  build(): Capabilities {
    const out: Capabilities = {};
    for (const a of [...this.acc.values()].sort((x, y) => x.key.localeCompare(y.key))) {
      const values = [...a.values.keys()].sort();
      const evidence: Evidence[] = [];
      const installTimeValues: string[] = [];
      // Install-time evidence first, then by value, so the most relevant sample survives the cap.
      const ordered = [...a.values.entries()].sort((x, y) => Number(y[1].installTime) - Number(x[1].installTime) || x[0].localeCompare(y[0]));
      for (const [value, v] of ordered) {
        if (v.installTime) installTimeValues.push(value);
        const sample = [...v.evidence]
          .sort((x, y) => Number(Boolean(y.installTime)) - Number(Boolean(x.installTime)) || x.file.localeCompare(y.file) || x.line - y.line)
          .slice(0, PER_VALUE_TOTAL);
        for (const e of sample) {
          if (evidence.length >= PER_CAPABILITY_TOTAL) break;
          evidence.push(e);
        }
      }
      const cap: Capability = {
        key: a.key,
        values,
        count: a.count,
        evidence,
        installTime: installTimeValues.length > 0,
        installTimeValues: installTimeValues.sort(),
      };
      out[a.key] = cap;
    }
    return out;
  }
}

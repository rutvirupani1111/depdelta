/**
 * Minimal glob matcher for policy files: `*` (no slash), `**` (any depth),
 * `?` (one char), `{a,b}` alternatives. Matching is case-sensitive and uses `/`.
 */
const cache = new Map<string, RegExp>();

export function globToRegExp(glob: string): RegExp {
  const cached = cache.get(glob);
  if (cached) return cached;
  let re = '';
  let i = 0;
  let inGroup = 0;
  while (i < glob.length) {
    const c = glob[i]!;
    if (c === '*') {
      if (glob[i + 1] === '*') {
        // `**/` matches zero or more directories; a trailing `**` matches everything.
        if (glob[i + 2] === '/') {
          re += '(?:.*/)?';
          i += 3;
        } else {
          re += '.*';
          i += 2;
        }
      } else {
        re += '[^/]*';
        i += 1;
      }
      continue;
    }
    if (c === '?') {
      re += '[^/]';
    } else if (c === '{') {
      inGroup++;
      re += '(?:';
    } else if (c === '}' && inGroup > 0) {
      inGroup--;
      re += ')';
    } else if (c === ',' && inGroup > 0) {
      re += '|';
    } else if ('\\^$.|+()[]{}'.includes(c)) {
      re += '\\' + c;
    } else {
      re += c;
    }
    i += 1;
  }
  const compiled = new RegExp(`^${re}$`);
  cache.set(glob, compiled);
  return compiled;
}

export function matchGlob(glob: string, value: string): boolean {
  if (glob === value) return true;
  if (!/[*?{]/.test(glob)) {
    // A plain directory pattern like `test/` matches everything below it.
    if (glob.endsWith('/')) return value.startsWith(glob);
    return false;
  }
  return globToRegExp(glob).test(value);
}

export function matchAny(globs: readonly string[] | undefined, value: string): boolean {
  if (!globs || globs.length === 0) return false;
  return globs.some((g) => matchGlob(g, value));
}

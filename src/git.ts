/**
 * Minimal git access: read a file as it was at a ref. Uses execFile (no shell),
 * and refuses refs that could be parsed as options.
 */
import { execFileSync } from 'node:child_process';
import { basename, dirname } from 'node:path';

export class GitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GitError';
  }
}

function git(args: string[], cwd: string): string {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 512 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
}

/** Accepts branch names, tags, SHAs and rev expressions such as HEAD~1 or main@{1}. */
export function validateRef(ref: string): void {
  if (!ref || ref.startsWith('-') || ref.length > 256 || !/^[\w./@{}~^+-]+$/.test(ref)) {
    throw new GitError(`refusing suspicious git ref "${ref}"`);
  }
}

export function isGitRepo(cwd: string): boolean {
  try {
    return git(['rev-parse', '--is-inside-work-tree'], cwd).trim() === 'true';
  } catch {
    return false;
  }
}

/**
 * Returns the content of `filePath` (absolute or relative to `cwd`) at `ref`,
 * or null when the file does not exist at that ref.
 */
export function gitShowFile(ref: string, filePath: string, cwd: string = process.cwd()): string | null {
  validateRef(ref);
  const dir = dirname(filePath.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(filePath) ? filePath : `${cwd}/${filePath}`);
  if (!isGitRepo(dir)) throw new GitError(`${dir} is not inside a git repository (use "depdelta diff <old> <new>" to compare two files)`);
  try {
    git(['rev-parse', '--verify', '--quiet', `${ref}^{commit}`], dir);
  } catch {
    throw new GitError(`unknown git ref "${ref}"`);
  }
  try {
    return git(['show', `${ref}:./${basename(filePath)}`], dir);
  } catch (err) {
    const stderr = String((err as { stderr?: unknown }).stderr ?? '');
    if (/does not exist|exists on disk, but not in|not in '/.test(stderr)) return null;
    throw new GitError(`git show ${ref}:${basename(filePath)} failed: ${stderr.trim() || (err as Error).message}`);
  }
}

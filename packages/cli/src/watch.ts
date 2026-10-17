// `coffre export --output-file` and `--watch`: an export kept in a file
// readable by you alone, and kept current. Watching asks the environments'
// versions, which read no value and log nothing, and reads them only once
// one changed.
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

/** The longest wait between two rounds that failed. */
const MAX_WAIT_MS = 15 * 60_000;

/**
 * Put `text` in `file`, mode 0600, whole or not at all: written beside it,
 * then renamed over it, so a reader never sees half of it. False when the
 * file held exactly that already, readable by you alone, and was left as it was.
 */
export function replaceFile(file: string, text: string): boolean {
  try {
    if ((statSync(file).mode & 0o077) === 0 && readFileSync(file, 'utf8') === text) return false;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  const temporary = join(dirname(file), `.${basename(file)}.${randomBytes(6).toString('hex')}`);
  try {
    writeFileSync(temporary, text, { mode: 0o600, flag: 'wx' });
    renameSync(temporary, file);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
  return true;
}

/** `60`, `60s`, `5m` or `1h`, in milliseconds: five seconds to a day. */
export function interval(text: string): number {
  const match = /^(\d+)([smh]?)$/.exec(text);
  const unit = { '': 1_000, s: 1_000, m: 60_000, h: 3_600_000 }[match?.[2] ?? ''];
  const ms = match === null || unit === undefined ? NaN : Number(match[1]) * unit;
  // Past a day a timer would not wait (Node fires one longer than 2^31 - 1 ms at once).
  if (!(ms >= 5_000 && ms <= 86_400_000)) throw new Error(`--interval takes a duration from 5s to 24h, such as 60s or 5m, not "${text}"`);
  return ms;
}

function duration(ms: number): string {
  return ms % 60_000 === 0 ? `${ms / 60_000}m` : `${Math.round(ms / 1_000)}s`;
}

export type Watch = {
  /** The environments' versions together: they change whenever a read of them would. */
  version: () => Promise<string>;
  /** Read them: as the file holds them, and the version of exactly what was read. */
  read: () => Promise<{ text: string; version: string }>;
  file: string;
  intervalMs: number;
  /** A shell command run after each write that changed the file, before the next round. */
  onChange: string | null;
  /** A line for whoever runs it: on stderr. */
  say: (line: string) => void;
  /** Wait between two rounds; tests stop the watch by throwing here. */
  wait?: (ms: number) => Promise<unknown>;
};

/**
 * Keep `file` current, until stopped. Each round asks the version, and on a
 * new one reads, writes the file when what it holds changed, then runs the
 * hook. The first round fails as an export does, with nothing to keep; a
 * later one says why, keeps the file as it was, and waits twice as long
 * each time, up to 15 minutes, before it asks again.
 */
export async function watch({ version, read, file, intervalMs, onChange, say, wait = sleep }: Watch): Promise<never> {
  let seen: string | null = null;
  let pause = intervalMs;
  for (;;) {
    try {
      if ((await version()) !== seen) {
        // The read's own version, not the one just asked: a version comes back when a change is undone,
        // so one asked before a write that the read saw, and its undoing, would never differ again.
        const got = await read();
        const changed = replaceFile(file, got.text);
        seen = got.version;
        if (changed) {
          say(`wrote ${file}`);
          if (onChange !== null) await hook(onChange, say);
        }
      }
      pause = intervalMs;
    } catch (error) {
      if (seen === null) throw error;
      pause = Math.min(pause * 2, Math.max(MAX_WAIT_MS, intervalMs));
      say(`${error instanceof Error ? error.message : String(error)}; ${file} keeps what it had, and coffre asks again in ${duration(pause)}`);
    }
    await wait(pause);
  }
}

/** Run the command through the shell, and wait for it: it gets no value, only the file. */
async function hook(command: string, say: (line: string) => void): Promise<void> {
  const code = await new Promise<number | string>((done) => {
    const child = spawn(command, { shell: true, stdio: 'inherit' });
    child.on('error', (error) => done(error.message));
    child.on('exit', (exit, signal) => done(signal ?? exit ?? 0));
  });
  if (code !== 0) say(`--on-change ${typeof code === 'number' ? `exited with ${code}` : `failed: ${code}`}`);
}

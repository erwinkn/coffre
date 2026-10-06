// What a check is, for `coffre verify`: it passes with a line, fails with
// what it saw, or cannot run here and says why; and the list it prints, one
// line a check, run on past a failure so that one run shows everything.
import { inspect } from 'node:util';

import { CoffreError, createClient, Unreachable, type CoffreClient } from '@coffre/client';

import { style, type Output } from '../tty.ts';

/** A check that failed: what went wrong, and what was seen instead. */
export class Failure extends Error {
  readonly detail: unknown;

  constructor(message: string, detail?: unknown) {
    super(message);
    this.detail = detail;
  }
}

/** A check that cannot run against this instance, and why. */
export class Skip extends Error {}

export function expect(condition: unknown, message: string, detail?: unknown): asserts condition {
  if (!condition) throw new Failure(message, detail);
}

/** The status coffre turned a call away with. A call that went through fails the check: `what` says what it should not have done. */
export async function refused(what: string, call: Promise<unknown>): Promise<CoffreError> {
  const outcome = await call.then(
    (value) => ({ value }),
    (error: unknown) => ({ error }),
  );
  if ('value' in outcome) throw new Failure(`${what}, and was let`, outcome.value);
  if (!(outcome.error instanceof CoffreError)) throw outcome.error;
  expect(outcome.error.status >= 400 && outcome.error.status < 500, `${what}, and failed with ${outcome.error.status}`, outcome.error.message);
  return outcome.error;
}

/** End the command at once, for a mistake in how it was called: `message` on stderr, or on stdout for an exit 0 (help). */
export function stop(code: number, message: string): never {
  (code === 0 ? process.stdout : process.stderr).write(`${message}\n`);
  process.exit(code);
}

/** The API as a service or the CLI calls it, with a bearer token: every refusal thrown, as a check wants it. */
export function bearer(origin: string, token: string): CoffreClient {
  return createClient({ url: origin, headers: () => ({ authorization: `Bearer ${token}` }) });
}

type Passed<T> = string | { detail: string; value: T };

export type Status = 'ok' | 'fail' | 'skip';

/** The checks of one run, each printed as it ends: a mark, its name, and a line. */
export class Checks {
  readonly #out: Output;
  readonly #results: { name: string; status: Status; line: string }[] = [];

  constructor(out: Output) {
    this.#out = out;
  }

  get results(): readonly { name: string; status: Status; line: string }[] {
    return this.#results;
  }

  get failed(): string[] {
    return this.#results.filter(({ status }) => status === 'fail').map(({ name }) => name);
  }

  /**
   * Run one check. `needs` holds what earlier checks made: if one is
   * missing, this one is skipped rather than run against an instance that
   * is not in the state it expects.
   */
  async check<N extends Record<string, unknown>, T = undefined>(
    name: string,
    needs: N,
    run: (have: { [K in keyof N]: NonNullable<N[K]> }) => Promise<Passed<T>>,
  ): Promise<T | undefined> {
    const missing = Object.keys(needs).filter((key) => needs[key] === undefined || needs[key] === null);
    if (missing.length > 0) {
      this.#print(name, 'skip', `no ${missing.join(' or ')}: an earlier check failed`);
      return undefined;
    }
    try {
      const passed = await run(needs as { [K in keyof N]: NonNullable<N[K]> });
      this.#print(name, 'ok', typeof passed === 'string' ? passed : passed.detail);
      return typeof passed === 'string' ? undefined : passed.value;
    } catch (error) {
      if (error instanceof Skip) {
        this.#print(name, 'skip', error.message);
        return undefined;
      }
      // An instance this machine cannot reach: the message says why, and the stack nothing more.
      const detail = error instanceof Failure ? error.detail : error instanceof Unreachable ? undefined : error instanceof Error ? error.stack : error;
      this.#print(name, 'fail', error instanceof Error ? error.message : String(error), detail);
      return undefined;
    }
  }

  #print(name: string, status: Status, line: string, detail?: unknown): void {
    this.#results.push({ name, status, line });
    const s = style(this.#out);
    const mark = { ok: s.green('✓'), fail: s.red('✗'), skip: s.dim('–') }[status];
    const text = status === 'skip' ? s.dim(line) : status === 'fail' ? s.red(line) : line;
    this.#out.write(`  ${mark} ${status === 'skip' ? s.dim(name.padEnd(19)) : name.padEnd(19)} ${text}\n`);
    if (status === 'fail' && detail !== undefined) {
      const shown = typeof detail === 'string' ? detail : inspect(detail, { depth: 6, breakLength: 100, colors: false });
      this.#out.write(`${s.dim(shown.replace(/^/gm, ' '.repeat(24)))}\n`);
    }
  }
}

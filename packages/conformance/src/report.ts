// Checks, and what became of each: one line apiece, and the run goes on
// past a failure, so one report shows everything that is wrong.
import { inspect } from 'node:util';
import { setTimeout as sleep } from 'node:timers/promises';

import { CoffreError } from '@coffre/client';

/** A check that failed: what went wrong, and what was seen instead. */
export class Failure extends Error {
  readonly detail: unknown;

  constructor(message: string, detail?: unknown) {
    super(message);
    this.detail = detail;
  }
}

/** A check that cannot run against this deployment, and why. */
export class Skip extends Error {}

export function expect(condition: unknown, message: string, detail?: unknown): asserts condition {
  if (!condition) throw new Failure(message, detail);
}

/**
 * The status coffre turned a call away with. A call that went through
 * fails the check: `what` says what it should not have done.
 */
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

export async function until(what: string, probe: () => Promise<boolean>, seconds: number, alive = () => true): Promise<void> {
  for (let i = 0; i < seconds * 10; i++) {
    if (!alive()) throw new Failure(`a process exited while waiting for ${what}`);
    if (await probe().catch(() => false)) return;
    await sleep(100);
  }
  throw new Failure(`timed out waiting for ${what}`);
}

type Passed<T> = string | { detail: string; value: T };

export class Report {
  readonly #results: { name: string; status: 'ok' | 'FAIL' | 'skip'; line: string }[] = [];
  readonly #width: number;
  readonly #quiet: boolean;

  /** `quiet`: keep the lines rather than print them, for a check made of checks to sum up. */
  constructor(width = 19, quiet = false) {
    this.#width = width;
    this.#quiet = quiet;
  }

  get failed(): string[] {
    return this.#results.filter((result) => result.status === 'FAIL').map((result) => result.name);
  }

  /** Each check's name, what came of it, and its line. */
  get results(): readonly { name: string; status: 'ok' | 'FAIL' | 'skip'; line: string }[] {
    return this.#results;
  }

  /**
   * Run one check, and print what came of it. `needs` holds what earlier
   * checks produced: if any is missing, this one is skipped rather than run
   * against a deployment that is not in the state it expects.
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
      const detail = error instanceof Failure ? error.detail : error instanceof Error ? error.stack : error;
      this.#print(name, 'FAIL', error instanceof Error ? error.message : String(error), detail);
      return undefined;
    }
  }

  #print(name: string, status: 'ok' | 'FAIL' | 'skip', line: string, detail?: unknown): void {
    this.#results.push({ name, status, line });
    if (this.#quiet) return;
    const text = `  ${status.padEnd(5)} ${name.padEnd(this.#width)} ${line}`;
    if (status !== 'FAIL') {
      console.log(text);
      return;
    }
    console.error(text);
    if (detail !== undefined) {
      const shown = typeof detail === 'string' ? detail : inspect(detail, { depth: 6, breakLength: 100 });
      console.error(shown.replace(/^/gm, ' '.repeat(this.#width + 9)));
    }
  }
}

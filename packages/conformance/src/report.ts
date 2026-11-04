// Checks, and what became of each: one line apiece, and the run goes on
// past a failure, so one report shows everything that is wrong.
import { inspect, stripVTControlCharacters } from 'node:util';
import { setTimeout as sleep } from 'node:timers/promises';

import { CoffreError } from '@coffre/client';

import { recording, type Sent } from './answers.ts';

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

/**
 * A request the server answered below 500, its colours taken off: what a
 * failure's output leaves out. As wrangler logs it
 * (`[wrangler:info] GET /projects 200 OK (12ms)`), or srvx, which runs the
 * Node example (`[9:31:22 AM] GET http://127.0.0.1:3082/livez [200] (0.68ms)`).
 */
const ANSWERED = /^(?:\[wrangler:info\] [A-Z]+ \S+ [1-4]\d\d |\[[^\]]+\] [A-Z]+ \S+ \[[1-4]\d\d\])/;

/** `output` under `heading`, but for the requests the server logs answered below 500. */
function unanswered(heading: string, output: string): string {
  const lines = output.split('\n');
  const kept = lines.filter((line) => !ANSWERED.test(stripVTControlCharacters(line)));
  return `${heading}, but for ${lines.length - kept.length} requests answered below 500:\n${kept.join('\n')}`;
}

export class Report {
  readonly #results: { name: string; status: 'ok' | 'FAIL' | 'skip' }[] = [];
  readonly #width: number;
  readonly #mark: (() => () => string) | undefined;
  readonly #failures: { name: string; sent: Sent[] }[] = [];

  /** `mark` marks the processes' output, so that a check that fails prints what they wrote while it ran. */
  constructor(options: { width?: number; mark?: () => () => string } = {}) {
    this.#width = options.width ?? 19;
    this.#mark = options.mark;
  }

  get failed(): string[] {
    return this.#results.filter((result) => result.status === 'FAIL').map((result) => result.name);
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
    const since = this.#mark?.();
    const sent: Sent[] = [];
    try {
      const passed = await recording(sent, () => run(needs as { [K in keyof N]: NonNullable<N[K]> }));
      this.#print(name, 'ok', typeof passed === 'string' ? passed : passed.detail);
      return typeof passed === 'string' ? undefined : passed.value;
    } catch (error) {
      if (error instanceof Skip) {
        this.#print(name, 'skip', error.message);
        return undefined;
      }
      const detail = error instanceof Failure ? error.detail : error instanceof Error ? error.stack : error;
      this.#print(name, 'FAIL', error instanceof Error ? error.message : String(error), detail);
      this.#failures.push({ name, sent });
      const output = since?.();
      if (output) console.error(unanswered("The processes' output during this check", output).replace(/^/gm, ' '.repeat(this.#width + 9)));
      return undefined;
    }
  }

  /**
   * What the run ends with when a check failed, or nothing: the processes'
   * `output`, whole, but for the requests answered below 500, then the
   * answers of 500 and over to each failed check's requests, bodies and
   * all, and the requests that got none. Asked once the processes have
   * stopped, so that it holds what they wrote late (wrangler logs a dropped
   * connection after the request it failed) and every request has ended:
   * one a check left running (a page's other call, its first having failed
   * it) has its answer or its error by then.
   */
  async afterwards(output: string): Promise<string | undefined> {
    if (this.#failures.length === 0) return undefined;
    const met = await Promise.all(
      this.#failures.map(async ({ name, sent }) => {
        const ended = await Promise.all(sent.map(async ({ request, shown }) => ({ request, shown: await shown })));
        const lines = ended.filter(({ shown }) => shown !== null).map(({ request, shown }) => `  ${request} ${shown}`);
        return lines.length === 0 ? [] : [`${name}:`, ...lines];
      }),
    );
    const answers = met.flat();
    return [
      unanswered("The processes' output", output),
      ...(answers.length === 0 ? [] : [`The answers of 500 and over to the failed checks' requests, and those they got none to:\n${answers.join('\n')}`]),
    ].join('\n\n');
  }

  #print(name: string, status: 'ok' | 'FAIL' | 'skip', line: string, detail?: unknown): void {
    this.#results.push({ name, status });
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

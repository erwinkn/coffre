// What `--verbose` says on stderr: each request the CLI sends, how it was
// answered and how long it took, and each time it asks again. Never a
// header, a body or a query, which may carry a credential: the method, the
// path and the status, or a name for a request whose path says nothing
// (GitHub's ID token).

type Fetch<I> = (input: I, init?: RequestInit) => Promise<Response>;

/** Where a line goes: stderr, which a CI run's log shows beside the step. */
export type Say = (line: string) => void;

export const stderr: Say = (line) => void process.stderr.write(`coffre: ${line}\n`);

/** `fetchImpl`, each request said once answered: `POST /api/reveals: 200 in 1.2 s`, or `failed after 30.0 s`. */
export function timed<I extends string | Request>(fetchImpl: Fetch<I>, say: Say, name?: string): Fetch<I> {
  return async (input, init) => {
    const [method, url] = typeof input === 'string' ? [init?.method ?? 'GET', input] : [(input as Request).method, (input as Request).url];
    const what = name ?? `${method} ${new URL(url).pathname}`;
    const start = performance.now();
    try {
      const response = await fetchImpl(input, init);
      say(`${what}: ${response.status} in ${took(performance.now() - start)}`);
      return response;
    } catch (error) {
      say(`${what}: failed after ${took(performance.now() - start)}${error instanceof Error ? ` (${error.message})` : ''}`);
      throw error;
    }
  };
}

/** A duration as a person reads it: `245 ms`, `15.8 s`. */
export function took(ms: number): string {
  return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`;
}

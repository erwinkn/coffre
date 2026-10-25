// What `--verbose` says on stderr: each request the CLI sends, how it was
// answered and how long it took, and each time it asks again. Never a
// header, a body, a query or an error's words, any of which may carry a
// credential: the method, the path and the status. Only the instance's
// paths are said; any other request, a platform's proof or GitHub's ID
// token, whose path may be a credential (ECS's credentials URI), is said by
// its host. A path through the credential proxy is the app's past its first
// segment, and is cut there.

/** Where a line goes: stderr, which a CI run's log shows beside the step. */
export type Say = (line: string) => void;

export const stderr: Say = (line) => void process.stderr.write(`coffre: ${line}\n`);

/**
 * `fetchImpl`, each request said once answered: `POST /api/reveals: 200 in
 * 1.2 s`, or `failed after 30.0 s`. `instance`, the origin whose paths are
 * said; without it, every request is the instance's.
 */
export function timed(fetchImpl: typeof fetch, say: Say, instance?: string): typeof fetch {
  return async (input, init) => {
    const [method, url] = input instanceof Request ? [input.method, input.url] : [init?.method ?? 'GET', String(input)];
    const at = new URL(url);
    const what = instance === undefined || at.origin === instance ? requestLine(method, at) : `${method} ${at.host}`;
    const start = performance.now();
    try {
      const response = await fetchImpl(input, init);
      say(`${what}: ${response.status} in ${took(performance.now() - start)}`);
      return response;
    } catch (error) {
      say(`${what}: failed after ${took(performance.now() - start)} (${failure(error)})`);
      throw error;
    }
  };
}

/** A duration as a person reads it: `245 ms`, `15.8 s`. */
export function took(ms: number): string {
  return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`;
}

/** A request to the instance, as a line says it: `POST /api/reveals`; `POST /use/stripe/…`, the rest of its path the app's. */
export function requestLine(method: string, url: URL): string {
  const proxied = /^\/use\/[^/]+\/./.exec(url.pathname);
  return `${method} ${proxied === null ? url.pathname : `${proxied[0].slice(0, -1)}…`}`;
}

/** What failed, by the network's code (`ECONNREFUSED`) or the error's kind (`TypeError`), never its message. */
function failure(error: unknown): string {
  for (let cause = error; typeof cause === 'object' && cause !== null; cause = (cause as { cause?: unknown }).cause) {
    const { code } = cause as { code?: unknown };
    if (typeof code === 'string' && /^[A-Z][A-Z0-9_]+$/.test(code)) return code;
  }
  return error instanceof Error ? error.name : 'failed';
}

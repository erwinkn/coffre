// What each check's requests got: a check that fails prints the answers of
// 500 and over, bodies and all, which a client error drops when they are not
// coffre's own JSON (one of workerd's, say), and the requests that got no
// answer (`Report`).
import { AsyncLocalStorage } from 'node:async_hooks';

import { unreachable } from '@coffre/client';

/**
 * A request a check sent, and what a failure shows of how it ended, once
 * it has: its status and its whole body for an answer of 500 or over, why
 * it failed for none, and nothing for any other answer. Every request a
 * check sends goes to the processes conformance runs, so each has ended
 * once they have stopped: a failure waits for that, on no timer of its own
 * (`Report.afterwards`).
 */
export type Sent = { request: string; shown: Promise<string | null> };

const checks = new AsyncLocalStorage<Sent[]>();
let native: typeof fetch | undefined;

/**
 * Run a check's `work`, keeping in `sent` every request it starts, however
 * it fetches (a `Browser`, a client, `fetch` itself): the global `fetch` is
 * wrapped, once. A request belongs to the check that started it, wherever
 * it ends: one a check left running lands in that check's list, never the
 * next one's.
 */
export function recording<T>(sent: Sent[], work: () => Promise<T>): Promise<T> {
  if (native === undefined) {
    native = globalThis.fetch;
    globalThis.fetch = recorded;
  }
  return checks.run(sent, work);
}

async function recorded(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const sent = checks.getStore();
  if (sent === undefined) return native!(input, init);
  const request = input instanceof Request ? input : undefined;
  const url = request?.url ?? String(input);
  const at = URL.parse(url);
  let shown!: (text: string | null | Promise<string | null>) => void;
  sent.push({
    request: `${init?.method ?? request?.method ?? 'GET'} ${at?.pathname ?? url}`,
    shown: new Promise((resolve) => {
      shown = resolve;
    }),
  });
  try {
    const response = await native!(input, init);
    shown(response.status < 500 ? null : whole(response.clone()).then((body) => `${response.status}: ${body}`));
    return response;
  } catch (error) {
    shown(`no answer: ${unreachable(at?.origin ?? url, error)}`);
    throw error;
  }
}

/**
 * A body, whole, or as much of it as came before it broke off (its server
 * stopped, say). It reads a clone, a tee of the body: a check that cancels
 * its own copy waits, as a tee's cancel does, until this one has read to the
 * end, which for a body that ends is once it has come (the headers check
 * drops each so). A 5xx body that never ends, which coffre sends none of,
 * would hold such a check until the processes stop.
 */
async function whole(response: Response): Promise<string> {
  const reader = response.body?.getReader();
  if (reader === undefined) return '';
  const decoder = new TextDecoder();
  let text = '';
  try {
    for (;;) {
      const read = await reader.read();
      if (read.done) return text + decoder.decode();
      text += decoder.decode(read.value, { stream: true });
    }
  } catch (error) {
    return `${text}… (the rest unread: ${String(error)})`;
  }
}

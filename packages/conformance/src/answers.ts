// What each check's requests got: a check that fails prints the answers of
// 500 and over, bodies and all, which a client error drops when they are not
// coffre's own JSON (one of workerd's, say), and the requests that got no
// answer (`Report`).
import { AsyncLocalStorage } from 'node:async_hooks';

import { unreachable } from '@coffre/client';

/**
 * A request a check sent, and what a failure shows of how it ended, once
 * it has: its status and the start of its body for an answer of 500 or
 * over, why it failed for none, and nothing for any other answer.
 */
export type Sent = { request: string; shown: Promise<string | null> };

/** How much of a 5xx body a failure shows, and how long its read may take. */
const SHOWN = 2000;
export const WAITED = 1000;

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
    shown(response.status < 500 ? null : opening(response.clone()).then((body) => `${response.status}: ${body}`));
    return response;
  } catch (error) {
    shown(`no answer: ${unreachable(at?.origin ?? url, error)}`);
    throw error;
  }
}

/** The first `SHOWN` characters of a body, read for at most `WAITED` ms: a body that streams on, or is huge, holds up nothing. */
async function opening(response: Response): Promise<string> {
  const reader = response.body?.getReader();
  if (reader === undefined) return '';
  const decoder = new TextDecoder();
  let text = '';
  let timer: NodeJS.Timeout | undefined;
  const late = new Promise<'late'>((resolve) => {
    timer = setTimeout(resolve, WAITED, 'late');
  });
  try {
    while (text.length <= SHOWN) {
      const read = await Promise.race([reader.read(), late]);
      if (read === 'late') return `${text}… (the rest unread: the body was still coming after ${WAITED} ms)`;
      if (read.done) return text + decoder.decode();
      text += decoder.decode(read.value, { stream: true });
    }
    return `${text.slice(0, SHOWN)}… (cut at ${SHOWN} characters)`;
  } catch (error) {
    return `${text}… (the rest unread: ${String(error)})`;
  } finally {
    clearTimeout(timer);
    reader.cancel().catch(() => {});
  }
}

// A browser, reduced to what coffre sees of one: a cookie jar, and the
// headers a page on coffre's own origin sends with its calls.
import { AsyncLocalStorage } from 'node:async_hooks';

import { createClient, type CoffreClient } from '@coffre/client';

export class Browser {
  readonly origin: string;
  readonly #jar = new Map<string, string>();

  constructor(origin: string) {
    this.origin = origin;
  }

  /** The cookies coffre left this browser, to hand a real one. */
  cookies(): [string, string][] {
    return [...this.#jar];
  }

  /** Whether coffre left this browser a cookie. */
  get hasCookies(): boolean {
    return this.#jar.size > 0;
  }

  /**
   * A request as the browser makes it, cookies included, redirects not
   * followed. Nothing else is added: a caller playing another site's page
   * sets its own `origin`.
   */
  async fetch(path: string | Request, init: RequestInit = {}): Promise<Response> {
    const request = typeof path === 'string' ? new Request(new URL(path, this.origin), init) : path;
    const ours = new URL(request.url).origin === this.origin;
    if (ours && this.#jar.size > 0) {
      request.headers.set('cookie', [...this.#jar].map(([name, value]) => `${name}=${value}`).join('; '));
    }
    const response = await fetch(request, { redirect: 'manual' });
    await note(request, response);
    if (ours) {
      for (const cookie of response.headers.getSetCookie()) {
        const [pair = ''] = cookie.split(';');
        const at = pair.indexOf('=');
        const value = pair.slice(at + 1);
        if (value === '' || /max-age=0/i.test(cookie)) this.#jar.delete(pair.slice(0, at));
        else this.#jar.set(pair.slice(0, at), value);
      }
    }
    return response;
  }

  /** A call one of coffre's pages makes: JSON, from its own origin. */
  send(method: string, path: string, body?: unknown): Promise<Response> {
    return this.fetch(path, {
      method,
      headers: { origin: this.origin, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  }

  /** The API as this browser's pages call it. */
  client(): CoffreClient {
    return createClient({
      url: this.origin,
      transport: (request) => {
        request.headers.set('origin', this.origin);
        request.headers.set('sec-fetch-site', 'same-origin');
        return this.fetch(request);
      },
    });
  }
}

/** The API as the CLI or a service calls it, with a bearer token. */
export function bearer(origin: string, token: string): CoffreClient {
  return createClient({
    url: origin,
    headers: () => ({ authorization: `Bearer ${token}` }),
    transport: async (request) => {
      const response = await fetch(request);
      await note(request, response);
      return response;
    },
  });
}

/**
 * The 5xx answers a check met, each with its body, which a client error
 * drops when it is not coffre's own JSON (one of workerd's, say): a check
 * that fails prints those it met (`Report`). A request belongs to the check
 * that started it, wherever it ends: one a check left running lands in that
 * check's list, never the next one's.
 */
export const answers = new AsyncLocalStorage<string[]>();

/** How much of a 5xx body a failure shows, and how long its read may hold up the request it answered. */
const SHOWN = 2000;
const WAITED = 1000;

async function note(request: Request, response: Response): Promise<void> {
  const met = answers.getStore();
  if (met === undefined || response.status < 500) return;
  met.push(`${request.method} ${new URL(request.url).pathname} ${response.status}: ${await opening(response.clone())}`);
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

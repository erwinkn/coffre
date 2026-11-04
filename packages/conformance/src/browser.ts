// A browser, reduced to what coffre sees of one: a cookie jar, and the
// headers a page on coffre's own origin sends with its calls.
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
  return createClient({ url: origin, headers: () => ({ authorization: `Bearer ${token}` }) });
}

/**
 * The fresh check, in the browser (docs/design/passkeys.md, sections 3.4 and 4): an act that takes a session a passkey
 * touch confirmed in the last five minutes is refused `403 fresh_check_required`, writing nothing. The browser's API
 * client hears it here, in its transport, for every page at once: the page that sent the act opens "Confirm it's you"
 * (`FreshCheck`, mounted once by `CoffreProvider`), the person touches their passkey at the step-up's door, which sets
 * the new session's cookie, and the act is sent again, once. Cancelled, the refusal goes on to the page, which says it
 * (`failureMessage`). `reason: 'add_passkey'`: the person holds no passkey yet, under `optional`, and the dialog offers
 * to sign in again and add one.
 */

/** What the dialog is asked: to confirm, or, for a person with no passkey, to add one. */
export type FreshAsk = { add: boolean; settle: (confirmed: boolean) => void };

type Listener = (ask: FreshAsk | null) => void;

let current: FreshAsk | null = null;
let waiting: Promise<boolean> | null = null;
const listeners = new Set<Listener>();

/** The dialog's subscription to what is asked now, null for nothing; it answers each ask with `settle`. */
export function onFreshAsk(listener: Listener): () => void {
  listeners.add(listener);
  listener(current);
  return () => listeners.delete(listener);
}

/**
 * Ask the person to confirm, resolving true once a touch confirmed this browser's session, false if they did not.
 * Several acts refused together share one ask, and one touch: they are sent again together.
 */
export function askFresh(add: boolean): Promise<boolean> {
  if (waiting !== null) return waiting;
  waiting = new Promise<boolean>((resolve) => {
    const ask: FreshAsk = {
      add,
      // Once: the dialog's close after a touch settles nothing more, and never an ask made since.
      settle: (confirmed) => {
        if (current !== ask) return;
        current = null;
        waiting = null;
        for (const listener of listeners) listener(null);
        resolve(confirmed);
      },
    };
    current = ask;
    for (const listener of listeners) listener(current);
  });
  return waiting;
}

/** Whether an answer is the fresh check's refusal, and of a person with no passkey yet (`add`); null for any other. */
export async function freshRefusal(response: Response): Promise<{ add: boolean } | null> {
  if (response.status !== 403) return null;
  const body: unknown = await response.clone().json().catch(() => null);
  if (typeof body !== 'object' || body === null || (body as { error?: unknown }).error !== 'fresh_check_required') return null;
  return { add: (body as { reason?: unknown }).reason === 'add_passkey' };
}

/**
 * The browser client's transport: `send`, and an act refused for a fresh check sent again, once, after the person
 * confirmed (`ask`). The request is copied before it goes, its body read once into the copy. With no one to ask (no
 * dialog mounted, as outside coffre's pages), the refusal is the answer.
 */
export function freshTransport(
  send: (request: Request) => Promise<Response> = (request) => fetch(request),
  ask: (add: boolean) => Promise<boolean> = (add) => (listeners.size === 0 ? Promise.resolve(false) : askFresh(add)),
): (request: Request) => Promise<Response> {
  return async (request) => {
    const again = request.clone();
    const response = await send(request);
    const refused = await freshRefusal(response);
    if (refused === null || !(await ask(refused.add))) return response;
    return send(again);
  };
}

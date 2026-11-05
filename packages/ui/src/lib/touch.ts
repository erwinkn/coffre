import { CoffreError } from '@coffre/client';

import { authenticatorError } from './passkey-answer.ts';
import { requestOptions, toJSON, type RequestJSON } from './webauthn.ts';

/** What a `403 touch_required` asks: `get()`'s options, for this act and this session alone, and the state to send back. */
export type TouchAsked = { options: RequestJSON; state: string };

/** The act's touch, as it is sent again: that state, and the authenticator's answer. */
export type TouchAnswer = { state: string; response: Record<string, unknown> };

/** The ask a press got and has not answered yet, which the next press asks the authenticator with at once. */
export type HeldTouch = { asked: TouchAsked | null };

/**
 * One press of an act that takes a touch of its own (docs/design/passkeys.md, section 4.2): approving a terminal, an
 * MCP client's change, or connecting one. The act is sent as it is; refused `403 touch_required`, the authenticator is
 * asked with the options the refusal carries, for that act alone, and the act is sent again with the answer.
 *
 * The ask comes after a round trip, and a browser may want the touch to follow a click more closely (Safari's user
 * activation): if the authenticator throws, the ask is held, and the next press asks it first, inside its own click,
 * before anything is sent. Asked once per press: a second `touch_required` (the state expired meanwhile) is held for
 * the next press, and thrown. A person who holds no passkey is never asked: the act goes on its first send.
 */
export async function pressTouch<T>(
  held: HeldTouch,
  send: (touch?: TouchAnswer) => Promise<T>,
  ask: (options: RequestJSON) => Promise<Record<string, unknown>> = getAssertion,
): Promise<T> {
  let asked = held.asked;
  if (asked === null) {
    try {
      return await send();
    } catch (error) {
      asked = touchOf(error);
      if (asked === null) throw error;
      held.asked = asked;
    }
  }
  // Throws as `get()` does: the ask stays held for the next press.
  const response = await ask(asked.options);
  held.asked = null;
  try {
    return await send({ state: asked.state, response });
  } catch (error) {
    held.asked = touchOf(error);
    throw error;
  }
}

/**
 * What a press's failure says, when it is the touch's: the authenticator's throw, or an ask that came again (its state
 * expired before the answer reached coffre). Null for anything else, which the act's page says in its own words.
 */
export function touchMessage(error: unknown, rpId: string | undefined): string | null {
  if (error instanceof DOMException) return authenticatorError(error, rpId ?? '');
  if (touchOf(error) !== null) return 'That touch came too late. Press again to confirm with your passkey.';
  return null;
}

/** The ask a `403 touch_required` carries, or null for any other failure. */
export function touchOf(error: unknown): TouchAsked | null {
  if (!(error instanceof CoffreError) || error.code !== 'touch_required' || error.touch === undefined) return null;
  return { options: error.touch.options as RequestJSON, state: error.touch.state };
}

/** A touch of one of the passkeys the options name, as the verifier reads it. */
async function getAssertion(options: RequestJSON): Promise<Record<string, unknown>> {
  const credential = await navigator.credentials.get({ publicKey: requestOptions(options) });
  return toJSON(credential as PublicKeyCredential) as Record<string, unknown>;
}

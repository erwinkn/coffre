import { CoffreError } from '@coffre/client';

import { authenticatorError, browserClock, deadlineOf, leftOf, readClock, type Clock, type Deadline } from './passkey-answer.ts';
import { getCredential, toJSON, type RequestJSON } from './webauthn.ts';

/** What a `403 touch_required` asks: `get()`'s options, for this act and this session alone, and the state to send back. */
export type TouchAsked = { options: RequestJSON; state: string };

/** The act's touch, as it is sent again: that state, and the authenticator's answer. */
export type TouchAnswer = { state: string; response: Record<string, unknown> };

/**
 * The ask a press got and has not answered yet, which the next press asks the authenticator with at once, while its
 * options last (`ends`, dated from the send that was refused, by both clocks as a step's are). A lapsed one is dropped.
 */
export type HeldTouch = { asked: (TouchAsked & { ends: Deadline }) | null };

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
  clock: Clock = browserClock,
): Promise<T> {
  // A held ask whose options lapsed (the page left open past their five minutes) would only be refused for a new one:
  // drop it, and the press starts over, asking with the options the new refusal carries.
  if (held.asked !== null && leftOf(held.asked.ends, clock) === 0) held.asked = null;
  let asked = held.asked;
  if (asked === null) {
    const sent = readClock(clock);
    try {
      return await send();
    } catch (error) {
      asked = holding(error, sent);
      if (asked === null) throw error;
      held.asked = asked;
    }
  }
  // Throws as `get()` does: the ask stays held for the next press. The authenticator waits only what is left.
  const response = await ask({ ...asked.options, timeout: leftOf(asked.ends, clock) });
  held.asked = null;
  const sent = readClock(clock);
  try {
    return await send({ state: asked.state, response });
  } catch (error) {
    held.asked = holding(error, sent);
    throw error;
  }
}

/** The ask a refusal carries, to hold until its options lapse: their `timeout` from `sent`, the send refused. */
function holding(error: unknown, sent: { wall: number; elapsed: number }): HeldTouch['asked'] {
  const asked = touchOf(error);
  return asked === null ? null : { ...asked, ends: deadlineOf(sent, asked.options.timeout) };
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
  return toJSON(await getCredential(options)) as Record<string, unknown>;
}

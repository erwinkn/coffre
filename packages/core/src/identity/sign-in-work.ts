// What a workload's sign-in may spend on what its token and its bindings make it do, beyond reading its body: the
// token's signature tried against its issuer's keys (`verifyWorkloadToken`), and its claims matched against the
// bindings it weighs (`claimAt`, `differingClaims`). Each is linear in what it reads, but neither the token nor a
// binding has a length of its own any more, only the body's bounds, so one budget, for the sign-in, holds them
// both: a sign-in that would spend more is refused, as matching nothing, rather than run long.
import { READ_CPU_US, REQUEST_CPU_US } from '../schemas.ts';

/**
 * A sign-in's budget, in nanoseconds of CPU, for its key tries and its
 * claims together: what is left of a request's CPU once the largest body is
 * read (`REQUEST_CPU_US` less `READ_CPU_US`, 16 ms; a sign-in's own body is
 * small). A real sign-in spends well under a millisecond of it: a key or
 * two, a few claims. A token of most of a mebibyte tried against 32 keys,
 * hundreds of long names against as many long keys, or a thousand claims in
 * each of sixteen bindings would each spend hundreds of milliseconds.
 */
export const SIGN_IN_WORK_NS = (REQUEST_CPU_US - READ_CPU_US) * 1000;

// What each step costs, in nanoseconds, as a sign-in spends it: measured on Node 24 (jose 6), the median of seven,
// each rounded up.
/** A character compared, sliced, or parsed (a binding's claims, before they are read). */
export const CHAR_NS = 2.2;
/** A dot of a claim's name found, and its offset summed (400,000 of them, 58 ns each). */
export const DOT_NS = 60;
/** A key of the token's listed (`Object.keys`), once an object, then kept for every claim. */
export const KEY_LISTED_NS = 25;
/** A listed key tried against a claim's name, beside its characters. */
export const KEY_TRIED_NS = 5;
/** A slice of a claim's name looked up in the token's object, beside its characters. */
export const SLICE_NS = 10;
/** Below this, a step's slices are looked up without listing the object's keys: a short name's handful. */
export const LIST_THRESHOLD_NS = 64 * SLICE_NS;
/** A signature check that fails, beside the token's bytes: ES256, the dearer of the two (0.17 ms for a 180-byte token). */
export const KEY_TRY_NS = 170_000;
/** A token's byte, decoded and hashed again by each signature check (6.8 ns over 130 KB and 930 KB tokens). */
export const TOKEN_BYTE_NS = 7;

/** A candidate binding's row checked against its MAC, a byte of what the MAC covers (its claims, mostly): 2.67 ns over a 900 KiB row. */
export const ROW_BYTE_NS = 3;

/** A sign-in that would spend more than its budget before it could match: refused, as matching nothing. */
export class SignInWorkSpent extends Error {
  constructor() {
    super("this service's bindings on the token's issuer cost more to check than a sign-in may spend");
    this.name = 'SignInWorkSpent';
  }
}

/** What is left of a sign-in's budget (`SIGN_IN_WORK_NS`), spent as it works, and the keys it listed of each object of the token. */
export type SignInWork = { left: number; keys: WeakMap<object, { keys: string[]; chars: number }> };

/** A sign-in's budget, `SIGN_IN_WORK_NS`: one for its key tries and for every binding it weighs. */
export function signInWork(): SignInWork {
  return { left: SIGN_IN_WORK_NS, keys: new WeakMap() };
}

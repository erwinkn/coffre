import type { Bound, Presented, Trace } from '@coffre/core/vault';

/**
 * What crosses the contract, checked before any read. The app is the
 * caller's word for what a request showed, not for its shape: an input that
 * is not what the contract says is a fault, never a refusal.
 */

/** A SHA-256 as the contract carries one: lowercase hex. */
export const HASH = /^[0-9a-f]{64}$/;

/**
 * Text as the vault takes it: of a bounded length, which Postgres
 * stores and gives back as given: no NUL, and no half of a surrogate pair,
 * which JSON carries and Postgres refuses. What it names is the decision's
 * to find, or not.
 */
export const long = (value: unknown, most: number): value is string => typeof value === 'string' && value.length <= most && !value.includes('\0') && Buffer.from(value).toString() === value;

/** A name: such text, 256 characters at most. */
export const text = (value: unknown): value is string => long(value, 256);

/** Where a request came from, for the log: all a change nobody asks comes with. */
export function traced({ request, ip }: Trace): Trace {
  if (![request, ip].every((value) => value === null || text(value))) throw new TypeError("a call says where its request came from as text, or not at all");
  return { request, ip };
}

/** What a request showed, as the engine takes it: its token by the hash's bytes. */
export function presented(input: Presented): Trace & { token: Buffer; proof: string | null } {
  const { token, proof } = input;
  if (!text(token) || !HASH.test(token) || !(proof === null || text(proof))) throw new TypeError('a call names a token by its SHA-256 in lowercase hex, and its proof as text');
  return { ...traced(input), token: Buffer.from(token, 'hex'), proof };
}

/**
 * A call over a Cloudflare service binding, as the engine takes it: the
 * service its `props` name, `token:<name>`, and no token. One that names a
 * token too is no such call.
 */
export function bound(input: Bound): Trace & { bound: string } {
  const { bound: service } = input;
  if (Object.hasOwn(input, 'token') || Object.hasOwn(input, 'proof') || !text(service) || !/^token:[^\s\p{Cc}]{1,249}$/u.test(service)) {
    throw new TypeError("a call over a service binding names the service its props name, token:<name>, and no token");
  }
  return { ...traced(input), bound: service };
}

/** A key's name, as the table's own check has it (`secrets_key_check`): told before anything is read or sealed. */
export const KEY = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

/**
 * The most values one change seals: the keys of one write, as the app's
 * routes bound them, and the values a fork copies, each opened and sealed
 * again (a fork by reference, or one that inherits, seals none).
 */
export const MOST_KEYS = 2000;

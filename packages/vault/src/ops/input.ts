import type { Presented, Trace } from '@coffre/core/vault';

/**
 * What crosses the contract, checked before any read. The app is the
 * caller's word for what a request showed, not for its shape: an input that
 * is not what the contract says is a fault, never a refusal.
 */

/** A SHA-256 as the contract carries one: lowercase hex. */
export const HASH = /^[0-9a-f]{64}$/;

/** A name as the vault takes one: text of a bounded length, which Postgres stores. What it names is the decision's to find, or not. */
export const text = (value: unknown): value is string => typeof value === 'string' && value.length <= 256 && !value.includes('\0');

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

/** A key's name, as the table's own check has it (`secrets_key_check`): told before anything is read or sealed. */
export const KEY = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

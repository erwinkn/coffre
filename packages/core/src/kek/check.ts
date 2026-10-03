// What a vault key, or the app key, can be checked against without opening
// anything else: the vault's `key.check` entries, each a known value wrapped
// under one vault key, and the key id the log records for the app's entries,
// a fingerprint of the key they are signed with. The vault writes the
// checks; `coffre verify keys` holds an escrowed key to them, on the
// operator's machine, the key never sent anywhere.
import { createHash } from 'node:crypto';

import { deriveLogKey } from '../audit/chain.ts';
import type { SecretContext } from '../context.ts';
import { equalBytes, LocalKekProvider } from './local.ts';
import { KekBadClaimError, type WrappedDek } from './types.ts';

/** The action of the vault's entry that holds a vault key's check. */
export const KEY_CHECK = 'key.check';

/** The known value a check wraps: the size of a data key. */
export const KEY_CHECK_VALUE: Buffer = createHash('sha256').update('coffre.kek.check.v1').digest();

const NIL = '00000000-0000-0000-0000-000000000000';

/** The context a check is wrapped in, which no secret has: the nil UUID throughout. */
export const KEY_CHECK_CONTEXT: SecretContext = { projectId: NIL, environmentId: NIL, secretId: NIL };

/**
 * Whether `key`, a local vault key, is the one that wrapped `check`: it
 * opens it, under the vault ID the check names, to the known value. The ID
 * is bound into the wrap, so a match also says the ID is the escrowed one's.
 */
export async function opensKeyCheck(key: Buffer, check: WrappedDek): Promise<boolean> {
  if (check.kekProvider !== 'local' || key.length !== 32) return false;
  try {
    const value = await new LocalKekProvider(key, check.kekId, check.kekVersion).unwrap(check, KEY_CHECK_CONTEXT);
    const right = equalBytes(value, KEY_CHECK_VALUE);
    value.fill(0);
    return right;
  } catch (error) {
    if (error instanceof KekBadClaimError) return false;
    throw error;
  }
}

/** The id the log records for entries the app signs with `key`, its APP_KEY. */
export function appLogKeyId(key: Uint8Array): string {
  return deriveLogKey('app', key).keyId;
}

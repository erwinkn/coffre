// `coffre keys`: a deployment's keys, made here and shown once. Nothing is
// uploaded or written: the operator saves them in a password manager, then
// hands each to the component that needs it.
import { randomBytes } from 'node:crypto';
import { parseArgs } from 'node:util';

/** A deployment's keys, under the names the examples give them: one for each component. */
export type Keys = {
  /** Names the KEK in every row it wraps. Not secret. */
  KEK_ID: string;
  /** The vault's: it decrypts values, and the vault derives the key it signs its records with from it. */
  KEK: string;
  /** The app's. */
  AUDIT_CHAIN_KEY: string;
};

/**
 * Two fresh keys, each 32 random bytes in base64, and an id for the KEK
 * dated to the day, so that a rotation, even one the same month, gets a new
 * one: the vault refuses two KEKs with the same id.
 */
export function generateKeys(now = new Date()): Keys {
  const key = () => randomBytes(32).toString('base64');
  return { KEK_ID: `kek-${now.toISOString().slice(0, 10)}`, KEK: key(), AUDIT_CHAIN_KEY: key() };
}

/** The keys as a dotenv block, then, as comments, what each is for and where it goes. */
export function formatKeys(keys: Keys): string {
  return `KEK_ID=${keys.KEK_ID}
KEK=${keys.KEK}
AUDIT_CHAIN_KEY=${keys.AUDIT_CHAIN_KEY}

# Save all three in your password manager now. They are shown once, and
# coffre keeps no copy.
#
# Two keys, one for each component, so that the app, which faces the
# network, never holds what decrypts a value:
#
#   KEK              the vault's. Decrypts every value, and signs the vault's
#                    log entries, member rows and checkpoints. Lose it, and
#                    every value is lost for good.
#   AUDIT_CHAIN_KEY  the app's. Signs the app's log entries, sessions and
#                    tokens. Lose it, and everyone is signed out and the log
#                    stops verifying.
#   KEK_ID           names the KEK; not secret.
#
# Whoever has the KEK and a copy of the database has every value: keep it
# apart from the backups.
#
# On Workers, KEK_ID is a var in vault/wrangler.jsonc, and KEK and
# AUDIT_CHAIN_KEY are Worker secrets (wrangler secret put). On Node, KEK_ID
# and KEK go in vault.env, and AUDIT_CHAIN_KEY in server.env.
#
# These are for a new deployment. To rotate a deployment's KEK, take only
# KEK_ID and KEK, and keep the old pair in previousKeks, for what it wrapped
# and signed. AUDIT_CHAIN_KEY cannot be changed.
`;
}

export function keys(args: string[]): void {
  const { values } = parseArgs({ args, options: { json: { type: 'boolean', default: false } }, allowPositionals: false });
  const fresh = generateKeys();
  process.stdout.write(values.json ? `${JSON.stringify(fresh)}\n` : formatKeys(fresh));
}

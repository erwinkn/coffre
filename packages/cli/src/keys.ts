// `coffre keys`: a deployment's keys, made here and shown once. Nothing is
// uploaded or written: the operator saves them in a password manager, then
// hands each to the component that needs it.
import { randomBytes } from 'node:crypto';
import { parseArgs } from 'node:util';

/** A deployment's keys, under the names the examples give them. */
export type Keys = {
  /** Names the KEK in every row it wraps. Not secret. */
  KEK_ID: string;
  KEK: string;
  SIGNING_KEY: string;
  AUDIT_CHAIN_KEY: string;
};

/**
 * Three fresh keys, each 32 random bytes in base64, and an id for the KEK
 * dated to the day, so that a rotation, even one the same month, gets a new
 * one: the vault refuses two KEKs with the same id.
 */
export function generateKeys(now = new Date()): Keys {
  const key = () => randomBytes(32).toString('base64');
  return { KEK_ID: `kek-${now.toISOString().slice(0, 10)}`, KEK: key(), SIGNING_KEY: key(), AUDIT_CHAIN_KEY: key() };
}

/** The keys as a dotenv block, then, as comments, what each is for and where it goes. */
export function formatKeys(keys: Keys): string {
  return `KEK_ID=${keys.KEK_ID}
KEK=${keys.KEK}
SIGNING_KEY=${keys.SIGNING_KEY}
AUDIT_CHAIN_KEY=${keys.AUDIT_CHAIN_KEY}

# Save all four in your password manager now. They are shown once, and
# coffre keeps no copy.
#
# The vault gets KEK_ID, KEK and SIGNING_KEY; the app gets AUDIT_CHAIN_KEY.
# They are kept apart so that the app, which faces the network, never holds
# what decrypts a value: whoever has the KEK and a copy of the database has
# every value.
#
#   KEK              decrypts every value. Lose it, and every value is lost.
#   SIGNING_KEY      signs the vault's log entries, checkpoints and member
#                    rows. Lose it, and the log stops verifying and every
#                    member is refused.
#   AUDIT_CHAIN_KEY  signs the app's log entries, sessions and tokens. Lose
#                    it, and the log stops verifying and everyone is signed
#                    out.
#   KEK_ID           names the KEK; not secret.
#
# On Workers, KEK_ID is a var in vault/wrangler.jsonc, and the other three are
# Worker secrets (wrangler secret put). On Node, they go in vault.env and
# server.env.
#
# These are for a new deployment. To rotate a deployment's KEK, take only
# KEK_ID and KEK, and keep the old pair in previousKeks: its SIGNING_KEY and
# AUDIT_CHAIN_KEY cannot be changed.
`;
}

export function keys(args: string[]): void {
  const { values } = parseArgs({ args, options: { json: { type: 'boolean', default: false } }, allowPositionals: false });
  const fresh = generateKeys();
  process.stdout.write(values.json ? `${JSON.stringify(fresh)}\n` : formatKeys(fresh));
}

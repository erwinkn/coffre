import { createHash, randomBytes } from 'node:crypto';

/**
 * Bearer credentials coffre issues itself: browser sessions, CLI sessions and
 * service tokens.
 *
 * A token is a kind prefix and 32 random bytes, e.g.
 * `coffre_cli_Qm9Y...`. The prefix tells a person (or a secret scanner) what a
 * leaked string is; the database stores only its SHA-256, which is enough
 * for lookups and useless to anyone who reads the table. A plain hash is the
 * right tool here, unlike for passwords: 256 bits of randomness leave nothing
 * to brute-force.
 */
export type CredentialKind = 'browser' | 'cli' | 'service';

const PREFIX: Record<CredentialKind, string> = {
  browser: 'coffre_web_',
  cli: 'coffre_cli_',
  service: 'coffre_svc_',
};

const TOKEN = /^coffre_(web|cli|svc)_[A-Za-z0-9_-]{43}$/;

export function generateToken(kind: CredentialKind): string {
  return PREFIX[kind] + randomBytes(32).toString('base64url');
}

/** Whether a string has the shape of a coffre token, before any lookup. */
export function isCoffreToken(value: string): boolean {
  return TOKEN.test(value);
}

export function hashToken(token: string): Buffer {
  return createHash('sha256').update(token, 'utf8').digest();
}

/** Enough of a token to recognize it in a list, never enough to use it. */
export function tokenHint(token: string): string {
  return `${token.slice(0, token.lastIndexOf('_') + 1)}…${token.slice(-4)}`;
}

import { createHash, randomBytes } from 'node:crypto';

/**
 * Bearer credentials coffre issues itself: browser sessions, CLI sessions,
 * service tokens, personal tokens, which act as the person who made
 * them within the scope they named, and handles, which reach nothing but
 * the credential proxy (`@coffre/server/plugins/credential-proxy`): the
 * placeholder a person's app holds in place of a secret's value. And a
 * workload's sessions, which are bound to its key and useless without a
 * proof it signs (docs/design/workload-access.md, section 5), and the
 * enrollment codes CI mints for platforms that sign nothing, which are no
 * credential at all: they buy a session at `/api/auth/workload`, and every
 * other route refuses one.
 *
 * A token is a kind prefix and 32 random bytes, e.g.
 * `coffre_cli_Qm9Y...`. The prefix tells a person (or a secret scanner) what a
 * leaked string is; the database stores only its SHA-256, which is enough
 * for lookups and useless to anyone who reads the table. A plain hash is the
 * right tool here, unlike for passwords: 256 bits of randomness leave nothing
 * to brute-force.
 */
export type CredentialKind = 'browser' | 'cli' | 'service' | 'personal' | 'handle' | 'workload';

/** What a token's prefix says it is: a credential, or an enrollment code. */
export type TokenKind = CredentialKind | 'enrollment';

const PREFIX: Record<TokenKind, string> = {
  browser: 'coffre_web_',
  cli: 'coffre_cli_',
  service: 'coffre_svc_',
  personal: 'coffre_pat_',
  handle: 'coffre_use_',
  workload: 'coffre_wl_',
  enrollment: 'coffre_enr_',
};

const TOKEN = /^coffre_(web|cli|svc|pat|use|wl|enr)_[A-Za-z0-9_-]{43}$/;

export function generateToken(kind: TokenKind): string {
  return PREFIX[kind] + randomBytes(32).toString('base64url');
}

/** Whether a string has the shape of a coffre token, before any lookup. */
export function isCoffreToken(value: string): boolean {
  return TOKEN.test(value);
}

/**
 * The kind a token's prefix says, before any lookup. Its hash covers the
 * prefix, so a token found under its hash is the kind it says.
 */
export function tokenKind(token: string): TokenKind | null {
  if (!TOKEN.test(token)) return null;
  return (Object.keys(PREFIX) as TokenKind[]).find((kind) => token.startsWith(PREFIX[kind])) ?? null;
}

export function hashToken(token: string): Buffer {
  return createHash('sha256').update(token, 'utf8').digest();
}

/**
 * Enough of a token to recognize it in a list, never enough to use it: the
 * kind prefix and the last four characters. The prefix is matched rather than
 * cut at the last underscore, because base64url uses `_` too.
 */
export function tokenHint(token: string): string {
  const prefix = Object.values(PREFIX).find((candidate) => token.startsWith(candidate)) ?? '';
  return `${prefix}…${token.slice(-4)}`;
}

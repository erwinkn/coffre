/**
 * The changes of sign-in and of credentials (`packages/vault/src/ops/signin.ts`,
 * docs/design/0.16.md, "Signing in").
 */
export type SigninChanges = Signin;

export type SigninAnswers = {
  signin: Issued;
};

/**
 * The operations nobody asks: no credential comes with them, only where
 * their request came from (`Trace`). Each rests on what the app verified,
 * or on a secret of its own (a device code).
 */
export type Unasked = 'signin';

/**
 * An account at a sign-in provider, as the app verified it with the
 * provider: the vault takes it on the app's word, and its entry says so.
 * `issuer` is the hash the app keeps a provider's issuer by; `emails` are
 * the addresses the provider verified, lowercase, its primary one first, 20
 * at most.
 */
export type Account = { provider: string; issuer: string; subject: string; emails: string[] };

/**
 * A credential to make. The app draws its token and sends the SHA-256,
 * lowercase hex: the vault never sees a token. `minutes` is how long it
 * lasts, within what its kind may.
 */
export type NewCredential = { token: string; minutes: number; label: string | null };

/** A credential made: whose it is, its id, and when it ends, ISO 8601. */
export type Issued = { principal: string; credential: string; expiresAt: string };

/**
 * A person signs in to a browser with an account the app verified.
 *
 * - The account is bound, its identity not revoked: its member signs in,
 *   if they are active and of the generation it was bound in
 *   (`deactivated` otherwise).
 * - The account is new: the first of its emails that names a member names
 *   who it is (`not_registered` for none). They must be active
 *   (`deactivated`) and have no account yet (`account_mismatch`: they sign
 *   in with the one they have, and link this one). It is bound to them.
 * - An email the vault's configuration names an Owner is a member whatever
 *   the rows say: made one, or made an active Owner of the whole instance
 *   again, in the same change.
 *
 * `replaces` is the SHA-256 of the session token the browser showed, if it
 * showed one: that session ends in the same change, whoever's it was.
 */
export type Signin = { op: 'signin'; account: Account; session: NewCredential; replaces: string | null };

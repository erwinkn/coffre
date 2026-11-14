/**
 * The changes of sign-in and of credentials (`packages/vault/src/ops/signin.ts`,
 * docs/design/0.16.md, "Signing in").
 */
export type SigninChanges = Signin | CredentialEnd | AccountLink | AccountUnlink;

export type SigninAnswers = {
  signin: Issued;
  /** The credential ended. */
  'credential.end': { credential: string };
  /** The identity the account is bound by. */
  'account.link': { identity: string };
  'account.unlink': { identity: string };
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
 * - Before the vault has adopted the database nobody signs in
 *   (`adopting`, for the app to answer 503). A row the decision would read
 *   that is there and not the vault's refuses it (`tampered`).
 *
 * `replaces` is the SHA-256 of the session token the browser showed, if it
 * showed one: that session ends in the same change, whoever's it was.
 */
export type Signin = { op: 'signin'; account: Account; session: NewCredential; replaces: string | null };

/**
 * End a credential: write its row revoked. Ending one that is already
 * ended, expired, not there or not the caller's to end is one refusal,
 * `unknown_credential`, which does not say which.
 *
 * - `credential` null: the one the request came in on, signing out
 *   (`sign_out`). Any credential that stands signs itself out but a
 *   handle, which is the proxy's; one that does not is told
 *   `unauthenticated`, which the app answers as signed out all the same.
 * - `credential` an id (`token.revoke`), by what the route named it as
 *   (`of`), and by the callers 0.14.7's route reached: no personal token
 *   but on the handles route. A credential with a scope holds nothing of
 *   the instance's own (`runsInstance` in @coffre/core/access), so a
 *   service's token ends its own service's alone, or one of a service it
 *   manages:
 *   - `of` null: one of the caller's own, any kind, or anyone's for whoever
 *     runs the instance (`DELETE /sessions/:id`, which a workload's session
 *     does not reach);
 *   - `of` `'handle'`: a handle of the caller's own, and nothing else, on
 *     a personal token too (`DELETE /handles/:id`, `coffre run` ending its
 *     own);
 *   - `of` a member: a token or a workload's session of that member
 *     (`DELETE /members/:member/tokens/:id`): theirs, for a person who
 *     manages the service account (`managesService`), or for whoever runs
 *     the instance.
 */
export type CredentialEnd = { op: 'credential.end' } & ({ credential: null; of: null } | { credential: string; of: null | 'handle' | { member: string } });

/**
 * A person, on a browser session, binds a second account the app verified
 * to themselves. Refused `already_linked` if the account is bound to
 * anyone, themselves included.
 */
export type AccountLink = { op: 'account.link'; account: Account };

/**
 * The caller revokes one of their own accounts, by its identity's id
 * (`unknown_identity` for one that is not theirs, or not bound). The
 * sessions it opened end with it, with no write: the rule that reads them
 * refuses a session whose account is revoked. Their last account too: they
 * sign in again with any account a verified email of theirs names, as the
 * first time.
 */
export type AccountUnlink = { op: 'account.unlink'; identity: string };

import type { CallerIdentity } from '../identity/aws.ts';
import type { VerifiedUnder } from '../identity/proofs.ts';
import type { Issued } from './signin.ts';

/**
 * The changes of workloads signing in (`packages/vault/src/ops/workloads.ts`,
 * docs/design/0.16.md, "A workload signing in").
 */
export type WorkloadChanges = TokenExchange | WorkloadSignin | WorkloadRenew | TokenBind | TokenUnbind;

export type WorkloadAnswers = {
  'token.exchange': Exchanged;
  'workload.signin': Session;
  'workload.renew': Renewed;
  'token.bind': Bound;
  'token.unbind': { binding: string };
};

/** The workloads' changes nobody asks: a CI run, or a workload signing in, has no credential yet, only its platform's proof. */
export type WorkloadsUnasked = 'token.exchange' | 'workload.signin';

/**
 * A CI run trades its platform's ID token for a service token of five
 * minutes, issued by the oldest of the service's bindings with no policy
 * that takes it.
 *
 * - `token` is the ID token itself, which the vault reads its claims
 *   from: the app verified its signature under `under`, the issuer and
 *   the address of its keys, and the vault takes that on its word. For a
 *   binding that carries its keys, `under.jwksUri` is theirs,
 *   `sha256:<hex>`, and the vault verifies the signature itself, under the
 *   keys on its own row.
 * - `publicUrl` is the app's own, which a CI run's token names as its
 *   audience.
 * - `credential` is the SHA-256 of the token the app drew, lowercase hex.
 *
 * Refused (docs/design/0.16.md, "A refusal"): `no_match`, `audience`,
 * `expired`, `too_old`, `malformed`, `replayed`, `unknown_signer`, and
 * `tampered` for a binding or the service's row written behind the vault.
 * A refusal writes nothing and is not logged.
 */
export type TokenExchange = { op: 'token.exchange'; service: string; token: string; under: VerifiedUnder; publicUrl: string; credential: string };

/** The token made, and the binding that issued it, by which the app counts a binding's rate. */
export type Exchanged = Issued & { binding: string };

/**
 * A workload's proof, by its kind: a platform's ID token, with the keys the
 * app verified it under (`token.exchange`'s `token` and `under`), or STS's
 * answer to the `GetCallerIdentity` request the workload signed, which the
 * app checked whole and sent.
 */
export type WorkloadProof = { oidc: { token: string; under: VerifiedUnder } } | { aws: CallerIdentity };

/**
 * A workload trades its proof for a session bound to a key it holds,
 * issued by the oldest of the service's bindings with a policy, of that
 * proof's profiles, that takes it.
 *
 * - `key` is the thumbprint of the key the request's own proof (RFC 9449)
 *   named, which the app held to the request: the session is that key's
 *   alone, and a token whose audience names a key names this one.
 * - `publicUrl` and `credential` as for `token.exchange`.
 *
 * Refused as `token.exchange` is, and `frozen` for a service, a binding or
 * every workload a manager froze, as 0.14 refused it. A binding whose
 * sources the request comes from outside, or that lists reads where the
 * deployment lets none (`noReads`), is `no_match`. A refusal writes nothing
 * and is not logged.
 */
export type WorkloadSignin = { op: 'workload.signin'; service: string; proof: WorkloadProof; key: string; publicUrl: string; credential: string };

/**
 * The session made: its token's expiry, an hour on or its hard end, and
 * that hard end; the environments it reaches as of now, by id, as its row
 * lists them, which the app names by path; and the binding that issued it,
 * by which the app counts a binding's rate.
 */
export type Session = Issued & { binding: string; notAfter: string; places: string[] };

/**
 * A workload's session moves its own expiry on, by its key's proof: an
 * hour from now, never past its hard end. A frozen session renews, so that
 * lifting the freeze restores it; one stopped for any other reason, or
 * narrowed from another, does not. Refused `expired` within five seconds of
 * its expiry, so that a renewal that comes late revives nothing.
 */
export type WorkloadRenew = { op: 'workload.renew' };

/** The session's expiry, moved on, or as it was at its hard end. */
export type Renewed = { expiresAt: string };

/**
 * A binding to make, as 0.14's `POST /members/:m/bindings` took it, and
 * checked as it did (`checkBinding`, `checkPolicy`, the profile's rule):
 *
 * - `keys`: where its issuer's keys are, the address the app's discovery
 *   found (a URN profile's, its issuer), which the vault takes on the
 *   app's word and seals; or the keys themselves, uploaded, a JWKS the
 *   vault checks and keeps (`uploadedKeys`).
 * - `policy`: a workload's binding's, null for one a CI run's exchange
 *   takes (a bearer profile's; under `useOnly`, every binding is a
 *   workload's). Its `reads` name each environment by path, and its keys
 *   by name or `"*"`, which the vault finds and seals by id.
 * - `scope`: what its credentials reach, by path, as a service token's
 *   (`token.create`); null for what the bindings it replaces reached, of
 *   what the service still holds, or else all the service holds.
 * - `replaces`: the live bindings it takes the place of, by id. Those of
 *   its issuer whose keys are elsewhere go too (`keys_moved`).
 */
export type NewBinding = {
  profile: string;
  issuer: string | null;
  claims: Record<string, unknown>;
  keys: { uri: string } | { jwks: unknown };
  policy: Record<string, unknown> | null;
  scope: Record<string, string> | null;
  label: string | null;
  replaces: string[];
};

/**
 * Trust a workload as a service (`binding`), or give its bindings on an
 * issuer new keys, uploaded (`keys`): each is replaced by one the same but
 * for its keys, reaching what it did of what the service still holds.
 * Whoever manages the service (`managesService`), each grant of the scope
 * one they could give it and it holds (`issuesCredential`); its sensitive
 * values only where an Owner of the project binds it (`ownsProject`). A
 * binding is never edited: a replaced one is revoked, and the credentials
 * it issued end with it.
 *
 * Refused: `unauthenticated` and a stopped caller's words; `no_access`,
 * for one who does not manage the service, or a place not found or beyond
 * them; `unknown_principal`, a service that is not active; `tampered`, any
 * row read that is not the vault's; `invalid`, a role that is none there, a
 * read outside the scope or of a key the environment does not hold, a
 * policy its reads break, uploaded keys that are no JWKS, or replaced
 * bindings that reach nothing the service still holds or a place with two
 * roles; `no_grants`, a scope with nothing to reach; `not_owner_issued`, a
 * sensitive key read where no Owner of its project binds; `no_reads`, reads
 * where the deployment lets none; `unknown_binding`, a binding replaced
 * that is not live, or no binding on the issuer whose keys are replaced;
 * `keys_differ`, other bindings on the issuer whose keys are elsewhere,
 * uploaded on one side; `same_keys`, keys the bindings carry already;
 * `too_many_bindings`, past `MAX_BINDINGS` live.
 */
export type TokenBind = { op: 'token.bind'; member: string } & ({ binding: NewBinding } | { keys: { issuer: string; jwks: unknown } });

/** The bindings made, each with what it reaches by path and role, and the bindings revoked, by id. */
export type Bound = { bindings: { id: string; scope: Record<string, string> }[]; replaced: string[] };

/**
 * Remove a binding: whoever manages its service. Its row is revoked, and
 * the credentials it issued end with it. Refused `unknown_binding` for
 * one that is not a live binding of the service, and as `token.bind` is.
 */
export type TokenUnbind = { op: 'token.unbind'; member: string; binding: string };

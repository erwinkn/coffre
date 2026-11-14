import type { CallerIdentity } from '../identity/aws.ts';
import type { VerifiedUnder } from '../identity/proofs.ts';
import type { Issued } from './signin.ts';

/**
 * The changes of workloads signing in (`packages/vault/src/ops/workloads.ts`,
 * docs/design/0.16.md, "A workload signing in").
 */
export type WorkloadChanges = TokenExchange | WorkloadSignin | WorkloadRenew;

export type WorkloadAnswers = {
  'token.exchange': Exchanged;
  'workload.signin': Session;
  'workload.renew': Renewed;
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

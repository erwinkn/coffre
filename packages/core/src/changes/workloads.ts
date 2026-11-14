import type { VerifiedUnder } from '../identity/proofs.ts';
import type { Issued } from './signin.ts';

/**
 * The changes of workloads signing in (`packages/vault/src/ops/workloads.ts`,
 * docs/design/0.16.md, "A workload signing in").
 */
export type WorkloadChanges = TokenExchange;

export type WorkloadAnswers = {
  'token.exchange': Exchanged;
};

/** The workloads' changes nobody asks: a CI run has no credential yet, only its platform's proof. */
export type WorkloadsUnasked = 'token.exchange';

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

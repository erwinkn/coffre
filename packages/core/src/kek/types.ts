import type { SecretContext } from '../context.ts';

/**
 * A data encryption key wrapped by a key encryption key.
 *
 * The provider metadata travels with every wrapped DEK and is stored per row,
 * never as a single global key id. Rotation and provider migration are then the
 * same code path: write new rows under the new KEK, keep unwrapping old rows
 * under the old one.
 */
export type WrappedDek = {
  kekProvider: string;
  kekId: string;
  kekVersion: string;
  bytes: Buffer;
};

/** One deadline for a batch. Providers must abort and settle their work when its signal fires. */
export type KeyOperation = { deadline: number; signal: AbortSignal };

/**
 * The only interface any key encryption key backend must satisfy.
 *
 * Two methods. We generate the DEK ourselves with a CSPRNG and use the backend
 * purely to wrap it, rather than depending on a provider `GenerateDataKey`
 * primitive -- GCP KMS has no such call, and staying off it is what keeps the
 * exit plan cheap.
 *
 * `ctx` is passed through to the provider deliberately. A remote KEK service
 * cannot otherwise record *which* secret an unwrap was for, only that some
 * opaque DEK was unwrapped. AWS KMS logs it in CloudTrail as the encryption
 * context (`aws-kms.ts`). Scaleway's Audit Trail does not log Key Manager
 * Decrypt at all, which is why AWS came first.
 *
 * `unwrap` throws `KekUnavailableError` when the service cannot answer, and
 * `KekBadClaimError` when the wrapped DEK does not open under `ctx`. Other
 * errors are unexpected faults; the vault records them and fails the call.
 */
export interface KekProvider {
  readonly provider: string;
  readonly keyId: string;
  readonly keyVersion: string;

  wrap(dek: Buffer, ctx: SecretContext, operation?: KeyOperation): Promise<WrappedDek>;
  unwrap(wrapped: WrappedDek, ctx: SecretContext, operation?: KeyOperation): Promise<Buffer>;
}

/** Length of the data encryption keys we generate, in bytes (AES-256). */
export const DEK_BYTES = 32;

/**
 * The key service could not answer: it is down, throttling past the
 * retries, or refusing coffre's own credentials. Nothing is known about the
 * wrapped key, so the vault fails the call instead of refusing it.
 */
export class KekUnavailableError extends Error {
  override readonly name: string = 'KekUnavailableError';

  readonly uncertain: boolean;

  constructor(message: string, uncertain = false) {
    super(message);
    this.uncertain = uncertain;
  }
}

/** No more work may start. A request already sent may have been accepted by KMS. */
export class KekCancelledError extends KekUnavailableError {
  override readonly name = 'KekCancelledError';

  constructor(uncertain = false) {
    super('key operation was cancelled', uncertain);
  }
}

/** The ciphertext does not open under the claimed key and context. */
export class KekBadClaimError extends Error {
  override readonly name = 'KekBadClaimError';
}

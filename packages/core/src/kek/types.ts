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
 * opaque DEK was unwrapped. Since Scaleway Audit Trail does not log Key Manager
 * Decrypt at all, an independent per-secret unwrap log is something we may need
 * to build ourselves later; this parameter is what makes that possible without
 * re-encrypting existing data.
 */
export interface KekProvider {
  readonly provider: string;
  readonly keyId: string;
  readonly keyVersion: string;

  wrap(dek: Buffer, ctx: SecretContext): Promise<WrappedDek>;
  unwrap(wrapped: WrappedDek, ctx: SecretContext): Promise<Buffer>;
}

/** Length of the data encryption keys we generate, in bytes (AES-256). */
export const DEK_BYTES = 32;

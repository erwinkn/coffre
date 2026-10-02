import type { SecretContext } from '../context.ts';
import type { KekProvider, WrappedDek, KeyOperation } from './types.ts';

function refOf(provider: string, keyId: string): string {
  return `${provider}:${keyId}`;
}

/**
 * A set of active KEKs, one of which is primary.
 *
 * New secret versions are always wrapped under the primary. Old versions keep
 * unwrapping under whichever KEK produced them, looked up by the provider and
 * key id stored on their own row. Key rotation and migrating from the local
 * provider to a KMS-backed one are therefore the same operation: add a new KEK,
 * make it primary, leave the old one readable until nothing references it.
 */
export class KekRegistry {
  readonly #byRef = new Map<string, KekProvider>();
  readonly #primary: KekProvider;

  constructor(primary: KekProvider, additional: readonly KekProvider[] = []) {
    this.#primary = primary;
    for (const provider of [primary, ...additional]) {
      const ref = refOf(provider.provider, provider.keyId);
      if (this.#byRef.has(ref)) {
        throw new Error(`duplicate vault key in registry: ${ref}`);
      }
      this.#byRef.set(ref, provider);
    }
  }

  get primary(): KekProvider {
    return this.#primary;
  }

  /** Every KEK, the primary first. */
  get all(): KekProvider[] {
    return [...this.#byRef.values()];
  }

  /** The KEK a wrapped key names, or undefined when none is configured. */
  providerOf(wrapped: Pick<WrappedDek, 'kekProvider' | 'kekId'>): KekProvider | undefined {
    return this.#byRef.get(refOf(wrapped.kekProvider, wrapped.kekId));
  }

  /** Wrap under the primary KEK. Used for every new secret version. */
  wrap(dek: Buffer, ctx: SecretContext, operation?: KeyOperation): Promise<WrappedDek> {
    return this.#primary.wrap(dek, ctx, operation);
  }

  /** Unwrap under whichever KEK the row says produced it. */
  unwrap(wrapped: WrappedDek, ctx: SecretContext, operation?: KeyOperation): Promise<Buffer> {
    const ref = refOf(wrapped.kekProvider, wrapped.kekId);
    const provider = this.#byRef.get(ref);
    if (!provider) {
      // Operationally this means a KEK was removed from configuration while
      // rows still reference it. Fail loudly rather than returning a decrypt
      // error that looks like corruption.
      throw new Error(`no vault key configured for ${ref} (kek or previousKeks in the vault's config); cannot unwrap`);
    }
    return provider.unwrap(wrapped, ctx, operation);
  }
}

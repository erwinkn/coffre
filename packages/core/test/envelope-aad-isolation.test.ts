import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';

import { seal, open } from '../src/envelope.ts';
import type { SecretContext } from '../src/context.ts';
import { KekRegistry } from '../src/kek/registry.ts';
import type { KekProvider, WrappedDek } from '../src/kek/types.ts';

/**
 * A KEK provider that deliberately ignores the secret context when wrapping.
 *
 * The cross-environment test in envelope.test.ts passes at the *wrap* layer:
 * LocalKekProvider binds its AAD to the context, so a relocated row fails to
 * unwrap before the envelope's own AAD is ever checked. That leaves the
 * envelope-level binding untested -- someone could delete `cipher.setAAD(aad)`
 * from seal/open and every other test would still pass.
 *
 * This provider strips the wrap-layer protection so the envelope layer has to
 * stand on its own. Both layers are meant to be independently sufficient.
 */
class ContextBlindKekProvider implements KekProvider {
  readonly provider = 'context-blind-test-only';
  readonly keyId = 'blind-1';
  readonly keyVersion = '1';

  readonly #kek = randomBytes(32);

  async wrap(dek: Buffer, _ctx: SecretContext): Promise<WrappedDek> {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.#kek, iv);
    const body = Buffer.concat([cipher.update(dek), cipher.final()]);
    return {
      kekProvider: this.provider,
      kekId: this.keyId,
      kekVersion: this.keyVersion,
      bytes: Buffer.concat([iv, cipher.getAuthTag(), body]),
    };
  }

  async unwrap(wrapped: WrappedDek, _ctx: SecretContext): Promise<Buffer> {
    const iv = wrapped.bytes.subarray(0, 12);
    const tag = wrapped.bytes.subarray(12, 28);
    const body = wrapped.bytes.subarray(28);
    const decipher = createDecipheriv('aes-256-gcm', this.#kek, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]);
  }
}

test('the envelope AAD alone blocks cross-environment relocation', async () => {
  const projectId = randomUUID();
  const secretId = randomUUID();
  const dev: SecretContext = { projectId, environmentId: randomUUID(), secretId };
  const prod: SecretContext = { projectId, environmentId: randomUUID(), secretId };

  const keks = new KekRegistry(new ContextBlindKekProvider());

  const envelope = await seal(Buffer.from('dev-only-value', 'utf8'), dev, keks);

  // Sanity check: with a context-blind KEK the DEK unwraps fine under either
  // context, so this test really is exercising the envelope layer.
  assert.deepEqual(await open(envelope, dev, keks), Buffer.from('dev-only-value', 'utf8'));

  await assert.rejects(
    () => open(envelope, prod, keks),
    /unable to authenticate data/,
    'the envelope AAD must reject a relocated ciphertext on its own',
  );
});

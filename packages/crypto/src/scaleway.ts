import { z } from 'zod';
import { aad, b64, unb64 } from './index';
import type { KeyProvider, SecretContext, WrappedKey } from '../../contracts/src/index';
const standard64 = (data: Uint8Array) => btoa(String.fromCharCode(...data));
const fromStandard64 = (value: string) => unb64(value.replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, ''));
const refSchema = z.string().regex(/^scaleway:(fr-par|nl-ams|pl-waw):[a-f0-9-]{36}$/);
// The official Go SDK uses JSON base64 strings for []byte and *[]byte fields,
// including associated_data; it is not a { value: ... } object on the wire.
export class ScalewayKeyProvider implements KeyProvider {
  constructor(private readonly current: string, private readonly allowed: readonly string[], private readonly secret: string, private readonly fetcher: typeof fetch = fetch) {
    refSchema.parse(current); allowed.forEach(x => refSchema.parse(x));
    if (!allowed.includes(current) || !secret) throw new Error('Invalid Scaleway KMS configuration');
  }
  private async call(keyRef: string, action: 'encrypt' | 'decrypt', data: string, context: SecretContext): Promise<string> {
    if (!this.allowed.includes(keyRef)) throw new Error('Unknown wrapping key');
    const [, region, id] = refSchema.parse(keyRef).split(':');
    const response = await this.fetcher(`https://api.scaleway.com/key-manager/v1alpha1/regions/${region}/keys/${id}/${action}`, {
      method: 'POST', headers: { 'X-Auth-Token': this.secret, 'Content-Type': 'application/json' },
      body: JSON.stringify({ [action === 'encrypt' ? 'plaintext' : 'ciphertext']: data, associated_data: standard64(aad(context, 'wrap', keyRef)) }),
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) throw new Error('Key service operation failed');
    const body = z.object({ key_id: z.literal(id!), ciphertext: z.unknown().optional(), plaintext: z.string().optional() }).parse(await response.json());
    const output = action === 'encrypt' ? z.string().max(8192).parse(body.ciphertext) : z.string().max(64).parse(body.plaintext);
    return output;
  }
  async wrap(dek: Uint8Array, context: SecretContext): Promise<WrappedKey> {
    if (dek.length !== 32) throw new Error('Invalid data key');
    const ciphertext = await this.call(this.current, 'encrypt', standard64(dek), context);
    return { keyRef: this.current, data: b64(fromStandard64(ciphertext)) };
  }
  async unwrap(key: WrappedKey, context: SecretContext): Promise<Uint8Array> {
    const value = fromStandard64(await this.call(key.keyRef, 'decrypt', standard64(unb64(key.data)), context));
    if (value.length !== 32) throw new Error('Invalid unwrapped data key');
    return value;
  }
}

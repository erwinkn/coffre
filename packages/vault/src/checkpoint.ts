const PKCS8_ED25519 = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];

export type Signer = {
  /** The raw Ed25519 public key, base64. */
  publicKey: string;
  /** The first 16 hex digits of the public key's SHA-256. */
  keyId: string;
  sign(message: Uint8Array<ArrayBuffer>): Promise<string>;
};

/** An Ed25519 signer from a 32-byte seed, over WebCrypto so it runs in Node and in workerd alike. */
export async function signer(seed: Uint8Array): Promise<Signer> {
  const pkcs8 = new Uint8Array([...PKCS8_ED25519, ...seed]);
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
  // A private JWK carries its public half, `x`; the raw private key does not export it.
  const { x } = (await crypto.subtle.exportKey('jwk', privateKey)) as JsonWebKey;
  const publicKey = Buffer.from(x!, 'base64url');
  const digest = Buffer.from(await crypto.subtle.digest('SHA-256', publicKey));
  return {
    publicKey: publicKey.toString('base64'),
    keyId: digest.toString('hex').slice(0, 16),
    sign: async (message) =>
      Buffer.from(await crypto.subtle.sign('Ed25519', privateKey, message)).toString('base64'),
  };
}

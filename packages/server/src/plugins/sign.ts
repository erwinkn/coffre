/**
 * A signature with a private key, as Node's `crypto.sign(undefined, message,
 * key)` makes one, in WebCrypto alone, so the same on Workers: what a
 * signer of the credential proxy answers (docs/design/credential-proxy.md,
 * section 5). The key is a PKCS#8 PEM, and says what it is itself:
 *
 *   Ed25519          the 64 bytes of the signature
 *   ECDSA, P-256     SHA-256, DER-encoded, as OpenSSL writes it
 *   RSA              PKCS#1 v1.5 with SHA-256
 *
 * Each error names what is wrong with the key, never a byte of it.
 */

/** The OIDs a PKCS#8 key names its algorithm, and an EC key its curve, with: the contents of each, as hex. */
const ED25519 = '2b6570';
const EC = '2a8648ce3d0201';
const P256 = '2a8648ce3d030107';
const RSA = '2a864886f70d010101';

/** A key coffre cannot sign with: what is wrong with it, quoting none of it. */
export class SigningKeyError extends Error {}

export async function signWith(pem: string, message: Uint8Array<ArrayBuffer>): Promise<Uint8Array> {
  const der = pkcs8(pem);
  const algorithm = algorithmOf(der);
  const key = await crypto.subtle.importKey('pkcs8', der, algorithm, false, ['sign']).catch(() => {
    throw new SigningKeyError('is a PKCS#8 key WebCrypto does not import');
  });
  const signature = new Uint8Array(await crypto.subtle.sign(algorithm.name === 'ECDSA' ? { name: 'ECDSA', hash: 'SHA-256' } : algorithm, key, message));
  return algorithm.name === 'ECDSA' ? derSignature(signature) : signature;
}

/** A PKCS#8 PEM's bytes, its line breaks real or written `\n`, as an env file has them. */
function pkcs8(pem: string): Uint8Array<ArrayBuffer> {
  const body = /-----BEGIN PRIVATE KEY-----([A-Za-z0-9+/=\s]*?)-----END PRIVATE KEY-----/.exec(pem.replace(/\\n/g, '\n'))?.[1];
  try {
    if (body !== undefined) return Uint8Array.from(atob(body.replace(/\s/g, '')), (char) => char.charCodeAt(0));
  } catch {
    // Not base64: said below, as anything else that is no PKCS#8 PEM.
  }
  throw new SigningKeyError('is no PKCS#8 private key, -----BEGIN PRIVATE KEY-----: an EC or RSA key in another form converts with `openssl pkcs8 -topk8 -nocrypt`');
}

/** What the key is, from its PrivateKeyInfo's AlgorithmIdentifier: SEQUENCE { version, SEQUENCE { OID, parameters }, … }. */
function algorithmOf(der: Uint8Array): Algorithm | EcKeyImportParams | RsaHashedImportParams {
  const hex = (at: { start: number; end: number }) => [...der.subarray(at.start, at.end)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  let oid: string;
  let curve: string | null = null;
  try {
    const info = element(der, 0, 0x30);
    const version = element(der, info.start, 0x02);
    const identifier = element(der, version.end, 0x30);
    const algorithm = element(der, identifier.start, 0x06);
    oid = hex(algorithm);
    if (oid === EC) curve = hex(element(der, algorithm.end, 0x06));
  } catch {
    throw new SigningKeyError('is no PKCS#8 private key: its structure does not read as one');
  }
  if (oid === ED25519) return { name: 'Ed25519' };
  if (oid === EC && curve === P256) return { name: 'ECDSA', namedCurve: 'P-256' };
  if (oid === RSA) return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  throw new SigningKeyError(`is ${oid === EC ? 'an EC key on a curve other than P-256' : 'a kind of key'} coffre does not sign with: Ed25519, P-256 and RSA only`);
}

/** The DER element at `at`, of tag `tag`: where its contents start and end. */
function element(der: Uint8Array, at: number, tag: number): { start: number; end: number } {
  if (der[at] !== tag) throw new Error('unexpected tag');
  let length = der[at + 1]!;
  let start = at + 2;
  if (length & 0x80) {
    const bytes = length & 0x7f;
    if (bytes === 0 || bytes > 3) throw new Error('unexpected length');
    length = 0;
    for (let byte = 0; byte < bytes; byte += 1) length = length * 256 + der[start++]!;
  }
  if (start + length > der.length) throw new Error('past the end');
  return { start, end: start + length };
}

/** WebCrypto's ECDSA signature, r and s side by side (IEEE P1363), as DER's SEQUENCE { INTEGER r, INTEGER s }, which OpenSSL makes. */
function derSignature(signature: Uint8Array): Uint8Array {
  const integer = (bytes: Uint8Array) => {
    let at = 0;
    while (at < bytes.length - 1 && bytes[at] === 0) at += 1;
    const value = [...bytes.subarray(at)];
    // A high first bit would read as negative: a zero before it keeps it positive.
    return value[0]! & 0x80 ? [0x02, value.length + 1, 0, ...value] : [0x02, value.length, ...value];
  };
  const half = signature.length / 2;
  const body = [...integer(signature.subarray(0, half)), ...integer(signature.subarray(half))];
  return Uint8Array.from([0x30, body.length, ...body]);
}

/**
 * A software passkey authenticator (docs/design/passkeys.md, section 9):
 * what a browser and its authenticator would answer to `create()` and
 * `get()`, as `credential.toJSON()` gives it, for the tests, the seed and
 * conformance. It writes every byte itself from the W3C's formats, CBOR
 * included, and shares no code with the verifier it is held against.
 *
 * Ed25519, ES256 and RS256 keys, made in WebCrypto. Each ceremony takes
 * `tweak`, which changes what an honest authenticator would send, for the
 * negative cases: another flag byte, RP ID, `clientDataJSON`, counter,
 * extensions, or any part edited after the fact.
 *
 *   const key = await SoftAuthenticator.create('ES256');
 *   const registration = await key.register({ rpId, origin, challenge, userHandle });
 *   const assertion = await key.assert({ rpId, origin, challenge });
 */

export type SoftAlgorithm = 'Ed25519' | 'ES256' | 'RS256';

/** What the relying party asked: its RP ID, its origin and the challenge it sent. */
export type SoftCeremony = { rpId: string; origin: string; challenge: Uint8Array };

/** Authenticator data's flags (WebAuthn Level 3, 6.1). */
export const FLAGS = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40, ED: 0x80 } as const;

/** What a dishonest or broken client would change. Unset, the authenticator answers honestly. */
export type Tweak = {
  /** The flag byte, whole; AT and ED are added where the data needs them unless `exactFlags`. */
  flags?: number;
  exactFlags?: boolean;
  /** Hashes this RP ID instead of the ceremony's. */
  rpId?: string;
  signCount?: number;
  /** Fields of `clientDataJSON` set (or, `undefined`, removed) over the honest ones. */
  clientData?: Record<string, unknown>;
  /** `clientDataJSON` as text, rewritten after it is made. */
  clientDataJSON?: (json: string) => string;
  /** Raw CBOR appended as extensions, with ED set. */
  extensions?: Uint8Array;
  /** The authenticator data, edited after it is made and before it is signed. */
  authenticatorData?: (bytes: Uint8Array) => Uint8Array;
  /** The signature, edited after it is made. */
  signature?: (bytes: Uint8Array) => Uint8Array;
  /** The COSE key a registration attests, edited. */
  publicKey?: (bytes: Uint8Array) => Uint8Array;
  /** The attestation object's map, edited before it is encoded. */
  attestation?: (map: Map<CborValue, CborValue>) => Map<CborValue, CborValue>;
  /** The JSON response, edited last. */
  response?: (json: Record<string, unknown>) => Record<string, unknown>;
};

export type RegistrationJSON = {
  id: string;
  rawId: string;
  type: 'public-key';
  response: { clientDataJSON: string; attestationObject: string; transports: string[] };
  authenticatorAttachment: 'platform' | 'cross-platform';
  clientExtensionResults: Record<string, never>;
};

export type AssertionJSON = {
  id: string;
  rawId: string;
  type: 'public-key';
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle?: string };
  authenticatorAttachment: 'platform' | 'cross-platform';
  clientExtensionResults: Record<string, never>;
};

const ENCODER = new TextEncoder();

export const toBase64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>));
}

const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
};

// --- CBOR, written ------------------------------------------------------------

export type CborValue = number | string | boolean | null | Uint8Array | CborValue[] | Map<CborValue, CborValue>;

function head(major: number, value: number): Uint8Array {
  if (value < 24) return Uint8Array.of((major << 5) | value);
  if (value < 0x100) return Uint8Array.of((major << 5) | 24, value);
  if (value < 0x10000) return Uint8Array.of((major << 5) | 25, value >> 8, value & 0xff);
  if (value < 0x1_0000_0000) return Uint8Array.of((major << 5) | 26, value >>> 24, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff);
  const view = new DataView(new ArrayBuffer(9));
  view.setUint8(0, (major << 5) | 27);
  view.setBigUint64(1, BigInt(value));
  return new Uint8Array(view.buffer);
}

/** CTAP2's canonical CBOR: shortest heads, map keys in the order the caller gave (callers give CTAP's). */
export function encodeCbor(value: CborValue): Uint8Array {
  if (value === false) return Uint8Array.of(0xf4);
  if (value === true) return Uint8Array.of(0xf5);
  if (value === null) return Uint8Array.of(0xf6);
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'string') {
    const bytes = ENCODER.encode(value);
    return concat(head(3, bytes.length), bytes);
  }
  if (value instanceof Uint8Array) return concat(head(2, value.length), value);
  if (Array.isArray(value)) return concat(head(4, value.length), ...value.map(encodeCbor));
  return concat(head(5, value.size), ...[...value].flatMap(([key, item]) => [encodeCbor(key), encodeCbor(item)]));
}

// --- keys ----------------------------------------------------------------------

/** ECDSA's raw `r ‖ s`, as WebCrypto signs, in the DER an authenticator sends. */
export function rawToDer(raw: Uint8Array): Uint8Array {
  const integer = (bytes: Uint8Array) => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    const trimmed = bytes.subarray(start);
    const body = trimmed[0] & 0x80 ? concat(Uint8Array.of(0), trimmed) : trimmed;
    return concat(Uint8Array.of(0x02, body.length), body);
  };
  const body = concat(integer(raw.subarray(0, 32)), integer(raw.subarray(32)));
  return concat(Uint8Array.of(0x30, body.length), body);
}

async function generate(algorithm: SoftAlgorithm): Promise<CryptoKeyPair> {
  if (algorithm === 'Ed25519') return (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  if (algorithm === 'ES256') return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' }, true, ['sign', 'verify']);
}

/** The public key as the COSE_Key an authenticator attests, its labels in CTAP2's canonical order. */
async function coseKey(algorithm: SoftAlgorithm, publicKey: CryptoKey): Promise<Uint8Array> {
  const jwk = await crypto.subtle.exportKey('jwk', publicKey);
  const b = (text: string | undefined) => new Uint8Array(Buffer.from(text!, 'base64url'));
  if (algorithm === 'Ed25519') return encodeCbor(new Map<CborValue, CborValue>([[1, 1], [3, -8], [-1, 6], [-2, b(jwk.x)]]));
  if (algorithm === 'ES256') return encodeCbor(new Map<CborValue, CborValue>([[1, 2], [3, -7], [-1, 1], [-2, b(jwk.x)], [-3, b(jwk.y)]]));
  return encodeCbor(new Map<CborValue, CborValue>([[1, 3], [3, -257], [-1, b(jwk.n)], [-2, b(jwk.e)]]));
}

export class SoftAuthenticator {
  /** How many times it has signed: the counter it writes, unless it syncs (then always 0, as synced passkeys do). */
  #count = 0;

  readonly algorithm: SoftAlgorithm;
  readonly keys: CryptoKeyPair;
  readonly credentialId: Uint8Array;
  readonly aaguid: Uint8Array;
  /** A synced passkey: BE and BS set, and a counter that never moves. */
  readonly synced: boolean;
  /** The user handle `register` was given, which assertions return as a discoverable credential's do. */
  userHandle: Uint8Array | null = null;

  private constructor(algorithm: SoftAlgorithm, keys: CryptoKeyPair, options: { synced?: boolean; aaguid?: Uint8Array; credentialId?: Uint8Array }) {
    this.algorithm = algorithm;
    this.keys = keys;
    this.credentialId = options.credentialId ?? crypto.getRandomValues(new Uint8Array(32));
    this.aaguid = options.aaguid ?? new Uint8Array(16);
    this.synced = options.synced ?? false;
  }

  static async create(algorithm: SoftAlgorithm = 'ES256', options: { synced?: boolean; aaguid?: Uint8Array; credentialId?: Uint8Array } = {}): Promise<SoftAuthenticator> {
    return new SoftAuthenticator(algorithm, await generate(algorithm), options);
  }

  /** The COSE key this authenticator registers: what a relying party stores. */
  publicKey(): Promise<Uint8Array> {
    return coseKey(this.algorithm, this.keys.publicKey);
  }

  async #clientData(type: string, ceremony: SoftCeremony, tweak: Tweak): Promise<Uint8Array> {
    const fields: Record<string, unknown> = { type, challenge: toBase64url(ceremony.challenge), origin: ceremony.origin, crossOrigin: false, ...tweak.clientData };
    for (const [key, value] of Object.entries(fields)) if (value === undefined) delete fields[key];
    const json = JSON.stringify(fields);
    return ENCODER.encode(tweak.clientDataJSON ? tweak.clientDataJSON(json) : json);
  }

  async #authenticatorData(ceremony: SoftCeremony, tweak: Tweak, attested: Uint8Array | null): Promise<Uint8Array> {
    let flags = tweak.flags ?? FLAGS.UP | FLAGS.UV | (this.synced ? FLAGS.BE | FLAGS.BS : 0);
    if (!tweak.exactFlags) flags |= (attested ? FLAGS.AT : 0) | (tweak.extensions ? FLAGS.ED : 0);
    const count = tweak.signCount ?? (this.synced ? 0 : ++this.#count);
    const counter = new Uint8Array(4);
    new DataView(counter.buffer).setUint32(0, count);
    const data = concat(await sha256(ENCODER.encode(tweak.rpId ?? ceremony.rpId)), Uint8Array.of(flags), counter, attested ?? new Uint8Array(), tweak.extensions ?? new Uint8Array());
    return tweak.authenticatorData ? tweak.authenticatorData(data) : data;
  }

  /** Signs as the authenticator does: over `authenticatorData ‖ SHA-256(clientDataJSON)`, ES256 in DER. */
  async sign(authenticatorData: Uint8Array, clientDataJSON: Uint8Array): Promise<Uint8Array> {
    const signed = concat(authenticatorData, await sha256(clientDataJSON)) as Uint8Array<ArrayBuffer>;
    const { privateKey } = this.keys;
    if (this.algorithm === 'ES256') return rawToDer(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, signed)));
    return new Uint8Array(await crypto.subtle.sign({ name: this.algorithm === 'Ed25519' ? 'Ed25519' : 'RSASSA-PKCS1-v1_5' }, privateKey, signed));
  }

  /** `navigator.credentials.create()`, attestation `none`, keeping `userHandle` as a discoverable credential does. */
  async register(ceremony: SoftCeremony & { userHandle: Uint8Array }, tweak: Tweak = {}): Promise<RegistrationJSON> {
    this.userHandle = ceremony.userHandle;
    const clientData = await this.#clientData('webauthn.create', ceremony, tweak);
    const length = Uint8Array.of(this.credentialId.length >> 8, this.credentialId.length & 0xff);
    const key = await this.publicKey();
    const attested = concat(this.aaguid, length, this.credentialId, tweak.publicKey ? tweak.publicKey(key) : key);
    const authData = await this.#authenticatorData(ceremony, tweak, attested);
    let attestation = new Map<CborValue, CborValue>([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]);
    if (tweak.attestation) attestation = tweak.attestation(attestation);
    const id = toBase64url(this.credentialId);
    const json = {
      id,
      rawId: id,
      type: 'public-key' as const,
      response: { clientDataJSON: toBase64url(clientData), attestationObject: toBase64url(encodeCbor(attestation)), transports: this.synced ? ['hybrid', 'internal'] : ['usb'] },
      authenticatorAttachment: this.synced ? ('platform' as const) : ('cross-platform' as const),
      clientExtensionResults: {},
    };
    return (tweak.response ? tweak.response(json) : json) as RegistrationJSON;
  }

  /** `navigator.credentials.get()`: an assertion by this credential, with its user handle once registered. */
  async assert(ceremony: SoftCeremony, tweak: Tweak = {}): Promise<AssertionJSON> {
    const clientData = await this.#clientData('webauthn.get', ceremony, tweak);
    const authData = await this.#authenticatorData(ceremony, tweak, null);
    const signature = await this.sign(authData, clientData);
    const id = toBase64url(this.credentialId);
    const json = {
      id,
      rawId: id,
      type: 'public-key' as const,
      response: {
        clientDataJSON: toBase64url(clientData),
        authenticatorData: toBase64url(authData),
        signature: toBase64url(tweak.signature ? tweak.signature(signature) : signature),
        ...(this.userHandle ? { userHandle: toBase64url(this.userHandle) } : {}),
      },
      authenticatorAttachment: this.synced ? ('platform' as const) : ('cross-platform' as const),
      clientExtensionResults: {},
    };
    return (tweak.response ? tweak.response(json) : json) as AssertionJSON;
  }
}

import { createHash } from 'node:crypto';

import { HASH_SIZE, type Hash } from './tree.ts';

/**
 * Signed checkpoints in the C2SP formats the transparency ecosystem shares
 * (tlog-checkpoint inside a signed note), so a Go sumdb client, a
 * transparency-dev witness or Sigstore's tooling reads them as they are:
 *
 *   coffre.example/audit/uses     origin: which log
 *   1048576                       tree size
 *   4Ht6…=                        tree head, base64
 *   upto 2026102600000001048599   extension: every number at or below it is final
 *   at 1793048700000              extension: when it was signed, ms since the epoch
 *   floor 1793048697000           extension: the floor of `at` its barrier set
 *   prev 1793048696500            extension: the floor of the pair signed before it
 *
 *   — coffre.example/audit/uses Az3g…   key ID (4 bytes) and Ed25519 signature, base64
 *
 * `upto` is what turns a gap in the numbers from "maybe deleted" into "never
 * was": every number at or below it is in the tree or will never appear.
 * `floor` is the lowest `at` a use may still be written with once its barrier
 * ran: the database's row of it is unsigned, so the signer holds it here and
 * the next barrier must find it no lower (HotPathOne.tla's BarrierChecksFloor).
 * `prev` is the floor of the pair the signer signed just before, so that a pair
 * is provably the first past a time from its own note: its floor at or past
 * it, its `prev` below. Retention cuts a day there (Seal.tla's CutFirst); a
 * writer who deletes rows cannot make a later pair pass for it.
 * Ed25519 through WebCrypto, which Node and Workers both have.
 */
export type Checkpoint = { origin: string; size: number; root: Hash; upto: bigint; at: number; floor: number; prev: number };

/** The largest number a log entry may carry: Postgres's bigint. */
export const MAX_NUMBER = 2n ** 63n - 1n;

export function checkpointBody(c: Checkpoint): string {
  return `${c.origin}\n${c.size}\n${c.root.toString('base64')}\nupto ${c.upto}\nat ${c.at}\nfloor ${c.floor}\nprev ${c.prev}\n`;
}

/** The checkpoint a note's text holds; throws on anything else, byte for byte, since the database is a writer's to shape. */
export function parseCheckpoint(text: string): Checkpoint {
  const lines = text.split('\n');
  const [origin, size, root, upto, at, floor, prev, end] = lines;
  const hash = Buffer.from(root ?? '', 'base64');
  const ok = lines.length === 8 && end === '' && origin !== undefined && /^[^\s+]+$/.test(origin)
    && /^(0|[1-9]\d{0,15})$/.test(size ?? '') && hash.length === HASH_SIZE && hash.toString('base64') === root
    && /^upto (0|[1-9]\d{0,18})$/.test(upto ?? '') && /^at (0|[1-9]\d{0,15})$/.test(at ?? '') && /^floor (0|[1-9]\d{0,15})$/.test(floor ?? '')
    && /^prev (0|[1-9]\d{0,15})$/.test(prev ?? '');
  // Sizes and times are exact numbers up to 2^53, as the tree's arithmetic; numbers are Postgres bigints.
  const [n, t, f, b] = [Number(size), Number(at?.slice(3)), Number(floor?.slice(6)), Number(prev?.slice(5))];
  if (!ok || BigInt(upto!.slice(5)) > MAX_NUMBER || ![n, t, f, b].every(Number.isSafeInteger)) throw new Error('not a checkpoint');
  return { origin: origin!, size: n, root: hash, upto: BigInt(upto!.slice(5)), at: t, floor: f, prev: b };
}

const ED25519 = 1;
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');

/** A note key's ID: the first 4 bytes of SHA-256(name || "\n" || 0x01 || public key). */
function keyId(name: string, publicKey: Buffer): Buffer {
  return createHash('sha256').update(name).update('\n').update(Buffer.from([ED25519])).update(publicKey).digest().subarray(0, 4);
}

export type NoteSigner = {
  name: string;
  id: Buffer;
  publicKey: Buffer;
  /** Go's note verifier key: `<name>+<key ID, hex>+<base64(0x01 || public key)>`. */
  verifierKey: string;
  sign(message: Uint8Array): Promise<Buffer>;
};

export type NoteVerifier = { name: string; id: Buffer; verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> };

/** A signer named `name`, from a 32-byte Ed25519 seed. */
export async function noteSigner(name: string, seed: Uint8Array): Promise<NoteSigner> {
  if (seed.length !== 32) throw new Error('an Ed25519 seed is 32 bytes');
  if (!/^[^\s+]+$/.test(name)) throw new Error('a note key name has no spaces and no +');
  const key = await crypto.subtle.importKey('pkcs8', new Uint8Array(Buffer.concat([PKCS8_ED25519, seed])), { name: 'Ed25519' }, true, ['sign']);
  // A private JWK carries its public half, `x`; the raw private key does not export it.
  const { x } = (await crypto.subtle.exportKey('jwk', key)) as JsonWebKey;
  const publicKey = Buffer.from(x!, 'base64url');
  const id = keyId(name, publicKey);
  return {
    name,
    id,
    publicKey,
    verifierKey: `${name}+${id.toString('hex')}+${Buffer.concat([Buffer.from([ED25519]), publicKey]).toString('base64')}`,
    sign: async (message) => Buffer.from(await crypto.subtle.sign('Ed25519', key, new Uint8Array(message))),
  };
}

export async function noteVerifier(verifierKey: string): Promise<NoteVerifier> {
  // name+hash+data; the base64 data may itself hold '+'.
  const m = /^([^\s+]+)\+([0-9a-f]{8})\+(.+)$/.exec(verifierKey);
  if (m === null) throw new Error('not a note verifier key');
  const [, name, hash, data] = m as unknown as [string, string, string, string];
  const raw = Buffer.from(data, 'base64');
  if (raw[0] !== ED25519 || raw.length !== 33) throw new Error('not an Ed25519 note key');
  const publicKey = raw.subarray(1);
  const id = keyId(name, publicKey);
  if (id.toString('hex') !== hash) throw new Error('the key ID does not match the key');
  const key = await crypto.subtle.importKey('raw', new Uint8Array(publicKey), { name: 'Ed25519' }, false, ['verify']);
  return { name, id, verify: (message, signature) => crypto.subtle.verify('Ed25519', key, new Uint8Array(signature), new Uint8Array(message)) };
}

async function signatureLine(text: string, signer: NoteSigner): Promise<string> {
  return `— ${signer.name} ${Buffer.concat([signer.id, await signer.sign(Buffer.from(text))]).toString('base64')}\n`;
}

/** A signed note: the text, a blank line, then one signature line per signer. */
export async function signNote(text: string, signers: readonly NoteSigner[]): Promise<string> {
  if (!text.endsWith('\n') || text.includes('\n\n')) throw new Error('a note text ends with a newline and has no blank line');
  return `${text}\n${(await Promise.all(signers.map((s) => signatureLine(text, s)))).join('')}`;
}

/** Adds a signature (a witness's cosignature) to a signed note. */
export async function cosignNote(note: string, signer: NoteSigner): Promise<string> {
  return `${note}${await signatureLine(splitNote(note).text, signer)}`;
}

/** At most this many signature lines, as Go's note.Open: a crafted row cannot make a reader verify without end. */
const MAX_SIGNATURES = 100;

/** A key name, as Go's: not empty, no white space, no '+'. */
const validName = (name: string) => name.length > 0 && !/[\s\u0085+]/u.test(name) && !/[\uD800-\uDFFF]/u.test(name);

/**
 * A signed note's text and signature lines, read as strictly as Go's
 * note.Open, so that a note stored in the database opens here only if every
 * Go reader and C2SP witness would open it too. Throws on anything else.
 */
export function splitNote(note: string): { text: string; signatures: { name: string; id: Buffer; signature: Buffer }[] } {
  // Well-formed Unicode, and no ASCII control character but the newline.
  if (/[\u0000-\u0009\u000b-\u001f]/.test(note) || /[\uD800-\uDFFF]/u.test(note)) throw new Error('not a signed note');
  const at = note.lastIndexOf('\n\n');
  if (at < 0 || note.length === at + 2 || !note.endsWith('\n')) throw new Error('not a signed note');
  const text = note.slice(0, at + 1);
  const lines = note.slice(at + 2, -1).split('\n');
  if (lines.length > MAX_SIGNATURES) throw new Error('too many signature lines');
  const signatures = lines.map((line) => {
    if (!line.startsWith('— ')) throw new Error('malformed signature line');
    const rest = line.slice(2);
    const space = rest.indexOf(' ');
    const [name, encoded] = space < 0 ? [rest, ''] : [rest.slice(0, space), rest.slice(space + 1)];
    // Canonical base64 only: what decodes here decodes to the same bytes in Go's StdEncoding.
    const raw = Buffer.from(encoded, 'base64');
    if (!validName(name) || encoded === '' || raw.toString('base64') !== encoded || raw.length < 5) throw new Error('malformed signature line');
    return { name, id: raw.subarray(0, 4), signature: raw.subarray(4) };
  });
  return { text, signatures };
}

/**
 * The note's text if `verifier` signed it, else null; null for anything that
 * is not a signed note too. As Go's note.Open given this one key, the first
 * signature line that names this key decides: if it does not verify, the
 * whole note is invalid, whatever other lines say; later lines by the key are
 * ignored. (Given several keys, Go also refuses a bad line
 * by any of them; each tree's note is opened with its own key alone.)
 */
export async function openNote(note: string, verifier: NoteVerifier): Promise<string | null> {
  let parts: ReturnType<typeof splitNote>;
  try {
    parts = splitNote(note);
  } catch {
    return null;
  }
  let verified = false;
  for (const s of parts.signatures) {
    if (s.name !== verifier.name || !s.id.equals(verifier.id) || verified) continue;
    if (s.signature.length !== 64 || !(await verifier.verify(Buffer.from(parts.text), s.signature))) return null;
    verified = true;
  }
  return verified ? parts.text : null;
}

/** A checkpoint if `verifier` signed it and it names that key's log as its origin, else null. */
export async function openCheckpoint(note: string, verifier: NoteVerifier): Promise<Checkpoint | null> {
  const text = await openNote(note, verifier);
  if (text === null) return null;
  try {
    const c = parseCheckpoint(text);
    return c.origin === verifier.name ? c : null;
  } catch {
    return null;
  }
}

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
 *
 *   — coffre.example/audit/uses Az3g…   key ID (4 bytes) and Ed25519 signature, base64
 *
 * `upto` is what turns a gap in the numbers from "maybe deleted" into "never
 * was": every number at or below it is in the tree or will never appear.
 * Ed25519 through WebCrypto, which Node and Workers both have.
 */
export type Checkpoint = { origin: string; size: number; root: Hash; upto: bigint; at: number };

/** The largest number a log entry may carry: Postgres's bigint. */
export const MAX_NUMBER = 2n ** 63n - 1n;

export function checkpointBody(c: Checkpoint): string {
  return `${c.origin}\n${c.size}\n${c.root.toString('base64')}\nupto ${c.upto}\nat ${c.at}\n`;
}

/** The checkpoint a note's text holds; throws on anything else, byte for byte, since the database is a writer's to shape. */
export function parseCheckpoint(text: string): Checkpoint {
  const lines = text.split('\n');
  const [origin, size, root, upto, at, end] = lines;
  const hash = Buffer.from(root ?? '', 'base64');
  const ok = lines.length === 6 && end === '' && origin !== undefined && /^[^\s+]+$/.test(origin)
    && /^(0|[1-9]\d{0,14})$/.test(size ?? '') && hash.length === HASH_SIZE && hash.toString('base64') === root
    && /^upto (0|[1-9]\d{0,18})$/.test(upto ?? '') && /^at (0|[1-9]\d{0,14})$/.test(at ?? '');
  if (!ok || BigInt(upto!.slice(5)) > MAX_NUMBER) throw new Error('not a checkpoint');
  return { origin: origin!, size: Number(size), root: hash, upto: BigInt(upto!.slice(5)), at: Number(at!.slice(3)) };
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

export function splitNote(note: string): { text: string; signatures: { name: string; id: Buffer; signature: Buffer }[] } {
  const at = note.lastIndexOf('\n\n');
  if (at < 0 || !note.endsWith('\n')) throw new Error('not a signed note');
  const text = note.slice(0, at + 1);
  const signatures = note.slice(at + 2, -1).split('\n').map((line) => {
    const m = /^— (\S+) ([A-Za-z0-9+/]+={0,2})$/.exec(line);
    if (m === null) throw new Error('malformed signature line');
    const raw = Buffer.from(m[2]!, 'base64');
    if (raw.length < 5) throw new Error('malformed signature line');
    return { name: m[1]!, id: raw.subarray(0, 4), signature: raw.subarray(4) };
  });
  return { text, signatures };
}

/** The note's text if `verifier` signed it, else null; null for anything that is not a signed note too. */
export async function openNote(note: string, verifier: NoteVerifier): Promise<string | null> {
  let parts: ReturnType<typeof splitNote>;
  try {
    parts = splitNote(note);
  } catch {
    return null;
  }
  for (const s of parts.signatures) {
    if (s.name === verifier.name && s.id.equals(verifier.id) && (await verifier.verify(Buffer.from(parts.text), s.signature))) return parts.text;
  }
  return null;
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

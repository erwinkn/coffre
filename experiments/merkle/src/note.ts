import { createHash } from 'node:crypto';

/**
 * Signed checkpoints in the C2SP formats the transparency ecosystem shares
 * (tlog-checkpoint inside a signed-note), so a Go sumdb client, a
 * transparency-dev witness or Sigstore's tooling reads them as they are:
 *
 *   coffre.example/audit          origin: which log
 *   1048576                       tree size
 *   4Ht6…=                        tree head, base64
 *   upto 2026102600000001048599   extension: every number at or below it is final
 *
 *   — coffre.example/audit Az3g…  key ID (4 bytes) and Ed25519 signature, base64
 *
 * Ed25519 through WebCrypto, which Node and Workers both have.
 */
export type Checkpoint = { origin: string; size: number; root: Buffer; upto: string; at: number };

export function checkpointBody(c: Checkpoint): string {
  return `${c.origin}\n${c.size}\n${c.root.toString('base64')}\nupto ${c.upto}\nat ${c.at}\n`;
}

export function parseCheckpoint(body: string): Checkpoint {
  const [origin, size, root, upto, at] = body.split('\n');
  const hash = Buffer.from(root ?? '', 'base64');
  if (!origin || !/^\d{1,15}$/.test(size ?? '') || hash.length !== 32 || hash.toString('base64') !== root
    || !/^upto \d{1,19}$/.test(upto ?? '') || !/^at \d{1,15}$/.test(at ?? '')) {
    throw new Error('not a checkpoint');
  }
  return { origin, size: Number(size), root: hash, upto: upto!.slice(5), at: Number(at!.slice(3)) };
}

const ED25519 = 1;
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** A note key's ID: the first 4 bytes of SHA-256(name || "\n" || 0x01 || public key). */
function keyId(name: string, publicKey: Buffer): Buffer {
  return createHash('sha256').update(name).update('\n').update(Buffer.from([ED25519])).update(publicKey).digest().subarray(0, 4);
}

export type Signer = { name: string; id: Buffer; publicKey: Buffer; sign(message: Uint8Array<ArrayBuffer>): Promise<Buffer>; verifierKey: string };

/** A signer from a 32-byte Ed25519 seed. Its `verifierKey` is Go's note verifier key: name+hash+base64(0x01 || key). */
export async function signerFrom(name: string, seed: Buffer): Promise<Signer> {
  const key = await crypto.subtle.importKey('pkcs8', Buffer.concat([PKCS8_PREFIX, seed]), { name: 'Ed25519' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', key);
  const publicKey = Buffer.from(jwk.x!, 'base64url');
  const id = keyId(name, publicKey);
  return {
    name, id, publicKey,
    sign: async (message) => Buffer.from(await crypto.subtle.sign('Ed25519', key, message)),
    verifierKey: `${name}+${id.toString('hex')}+${Buffer.concat([Buffer.from([ED25519]), publicKey]).toString('base64')}`,
  };
}

export type Verifier = { name: string; id: Buffer; verify(message: Uint8Array<ArrayBuffer>, signature: Uint8Array<ArrayBuffer>): Promise<boolean> };

export async function verifierFrom(verifierKey: string): Promise<Verifier> {
  // name+hash+data; base64 data may itself hold '+'.
  const [name, hash] = verifierKey.split('+', 2);
  const raw = Buffer.from(verifierKey.slice(`${name}+${hash}+`.length), 'base64');
  if (raw[0] !== ED25519 || raw.length !== 33) throw new Error('not an Ed25519 note key');
  const publicKey = raw.subarray(1);
  const id = keyId(name!, publicKey);
  if (id.toString('hex') !== hash) throw new Error('key ID does not match');
  const key = await crypto.subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify']);
  return { name: name!, id, verify: (message, signature) => crypto.subtle.verify('Ed25519', key, signature, message) };
}

/** A signed note: the text, a blank line, then one signature line per signer. */
export async function signNote(text: string, signers: readonly Signer[]): Promise<string> {
  if (!text.endsWith('\n')) throw new Error('a note ends with a newline');
  const lines = await Promise.all(signers.map(async (s) => `— ${s.name} ${Buffer.concat([s.id, await s.sign(Buffer.from(text))]).toString('base64')}\n`));
  return `${text}\n${lines.join('')}`;
}

/** Adds a signature (a witness's cosignature) to a signed note. */
export async function cosignNote(note: string, signer: Signer): Promise<string> {
  const { text } = splitNote(note);
  return `${note}— ${signer.name} ${Buffer.concat([signer.id, await signer.sign(Buffer.from(text))]).toString('base64')}\n`;
}

export function splitNote(note: string): { text: string; signatures: { name: string; id: Buffer; signature: Buffer }[] } {
  const at = note.lastIndexOf('\n\n');
  if (at < 0) throw new Error('not a signed note');
  const text = note.slice(0, at + 1);
  const signatures = note.slice(at + 2).split('\n').filter((l) => l.length > 0).map((line) => {
    const m = /^— (\S+) (\S+)$/.exec(line);
    if (m === null) throw new Error('malformed signature line');
    const raw = Buffer.from(m[2]!, 'base64');
    return { name: m[1]!, id: raw.subarray(0, 4), signature: raw.subarray(4) };
  });
  return { text, signatures };
}

/** A checkpoint if `verifier` signed it and it names that log as its origin, else null. */
export async function openCheckpoint(note: string, verifier: Verifier): Promise<Checkpoint | null> {
  try {
    const text = await openNote(note, verifier);
    if (text === null) return null;
    const c = parseCheckpoint(text);
    return c.origin === verifier.name ? c : null;
  } catch {
    // Not a signed note, or not a checkpoint: not this log's either way.
    return null;
  }
}

/** The note's text if `verifier` signed it, else null. */
export async function openNote(note: string, verifier: Verifier): Promise<string | null> {
  const { text, signatures } = splitNote(note);
  for (const s of signatures) {
    if (s.name === verifier.name && s.id.equals(verifier.id) && (await verifier.verify(Buffer.from(text), new Uint8Array(s.signature)))) return text;
  }
  return null;
}

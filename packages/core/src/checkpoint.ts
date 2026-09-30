import type { Checkpoint } from './vault.ts';

/** What a checkpoint's signature covers: the heads of both logs, and when. */
export function checkpointMessage(checkpoint: Omit<Checkpoint, 'signature' | 'keyId'>): Uint8Array<ArrayBuffer> {
  const { seq, headHash, vault, signedAt } = checkpoint;
  return new Uint8Array(
    new TextEncoder().encode(`coffre.checkpoint.v2|${seq}|${headHash}|${vault.seq}|${vault.hash}|${signedAt}`),
  );
}

/** Whether `checkpoint` was signed by the key whose raw public half is `publicKey`. */
export async function verifyCheckpoint(checkpoint: Checkpoint, publicKey: string): Promise<boolean> {
  const key = await crypto.subtle.importKey('raw', new Uint8Array(Buffer.from(publicKey, 'base64')), { name: 'Ed25519' }, false, ['verify']);
  return crypto.subtle.verify('Ed25519', key, new Uint8Array(Buffer.from(checkpoint.signature, 'base64')), checkpointMessage(checkpoint));
}

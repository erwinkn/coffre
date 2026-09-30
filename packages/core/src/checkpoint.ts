import type { Checkpoint } from './vault.ts';

/** What a checkpoint's signature covers. */
export function checkpointMessage(checkpoint: Omit<Checkpoint, 'signature' | 'keyId'>): Uint8Array<ArrayBuffer> {
  return new Uint8Array(
    new TextEncoder().encode(`coffre.checkpoint.v1|${checkpoint.seq}|${checkpoint.headHash}|${checkpoint.signedAt}`),
  );
}

/** Whether `checkpoint` was signed by the key whose raw public half is `publicKey`. */
export async function verifyCheckpoint(checkpoint: Checkpoint, publicKey: string): Promise<boolean> {
  const key = await crypto.subtle.importKey('raw', new Uint8Array(Buffer.from(publicKey, 'base64')), { name: 'Ed25519' }, false, ['verify']);
  return crypto.subtle.verify('Ed25519', key, new Uint8Array(Buffer.from(checkpoint.signature, 'base64')), checkpointMessage(checkpoint));
}

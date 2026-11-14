// What a vault's keys can be checked against without opening anything:
// each of its signing keys' check (`keyCheckOf`), which the vault answers
// in `about` and `coffre verify keys` computes again from an escrowed key,
// on the operator's machine, the key never sent anywhere.
import { hkdfSync } from 'node:crypto';

/** The label no other use of a vault key shares: a local vault key is otherwise only ever an AES-256-GCM key. */
const SIGNING_KEY_LABEL = 'coffre.vault.signing-key.v1';

/**
 * The signing key a local vault key stands for, when the vault is given
 * none: HKDF-SHA-256 of the key. The vault MACs its log entries and member
 * rows with what it derives from this one (`vaultLogKey` in @coffre/vault).
 */
export function derivedSigningKey(kek: Uint8Array): Buffer {
  return Buffer.from(hkdfSync('sha256', kek, new Uint8Array(0), SIGNING_KEY_LABEL, 32));
}

/**
 * A signing key's check, hex: HKDF-SHA-256 of the key under a label of its
 * own, as the vault's other keys are each derived from it under theirs
 * (`keyOf` in @coffre/vault), so the check opens, signs and names nothing.
 * Whoever holds a key tells whether it is the vault's by computing its
 * check; whoever holds only the check learns nothing of the key.
 */
export function keyCheckOf(seed: Uint8Array): string {
  return Buffer.from(hkdfSync('sha256', seed, new Uint8Array(0), 'coffre.vault.key-check.v2', 32)).toString('hex');
}

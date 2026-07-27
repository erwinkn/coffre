/**
 * The binding context for a secret's ciphertext.
 *
 * This is the AES-GCM additional authenticated data (AAD). It ties a ciphertext
 * to exactly one (project, environment, secret) triple, so a ciphertext lifted
 * out of the `dev` environment row and dropped into the `prod` row fails to
 * decrypt rather than silently succeeding.
 *
 * These are immutable UUIDs, never names. Binding to `project/environment/key`
 * names would mean that renaming an environment or a secret key makes every
 * existing ciphertext permanently undecryptable.
 */
export type SecretContext = {
  projectId: string;
  environmentId: string;
  secretId: string;
};

/**
 * Version prefix for the AAD encoding. If the encoding ever changes, this
 * changes with it, and old ciphertexts keep decrypting under the old rule.
 */
export const AAD_VERSION = 'coffre.aad.v1';

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function assertUuid(value: string, field: string): void {
  if (typeof value !== 'string' || !UUID_RE.test(value)) {
    throw new Error(`context.${field} must be a lowercase UUID, got: ${String(value)}`);
  }
}

/**
 * Encode a context into AAD bytes.
 *
 * Every field is validated as a UUID first, which is what makes joining with
 * `|` unambiguous: a UUID cannot contain the separator, so no two distinct
 * contexts can encode to the same bytes.
 */
export function encodeAad(ctx: SecretContext): Buffer {
  assertUuid(ctx.projectId, 'projectId');
  assertUuid(ctx.environmentId, 'environmentId');
  assertUuid(ctx.secretId, 'secretId');

  return Buffer.from(
    `${AAD_VERSION}|${ctx.projectId}|${ctx.environmentId}|${ctx.secretId}`,
    'utf8',
  );
}

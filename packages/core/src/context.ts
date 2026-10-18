import { createHash } from 'node:crypto';

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
 *
 * A personal config's values are bound to their owner too, `owner`, and a
 * sensitive value to being one, `sensitive`, which only the vault's wrap of
 * the data key carries (docs/design/forking.md, section 4;
 * docs/design/credential-proxy.md, section 2): a forged owner or sensitivity
 * column fails to open, rather than granting. The value's own ciphertext
 * binds the ids alone, so a version made sensitive keeps its ciphertext.
 */
export type SecretContext = {
  projectId: string;
  environmentId: string;
  secretId: string;
  /** A personal config's owner, as `ownerKey` hashes them. */
  owner?: string;
  /** A sensitive value's: never handed back to a person (`sensitive` in @coffre/core/vault). Absent otherwise, never false. */
  sensitive?: true;
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

/** Throw unless every field is a lowercase UUID, an owner a lowercase SHA-256, and `sensitive` true if there. */
export function checkContext(ctx: SecretContext): void {
  assertUuid(ctx.projectId, 'projectId');
  assertUuid(ctx.environmentId, 'environmentId');
  assertUuid(ctx.secretId, 'secretId');
  if (ctx.owner !== undefined && (typeof ctx.owner !== 'string' || !OWNER_RE.test(ctx.owner))) {
    throw new Error(`context.owner must be a lowercase SHA-256, got: ${String(ctx.owner)}`);
  }
  if (ctx.sensitive !== undefined && ctx.sensitive !== true) throw new Error(`context.sensitive is true or absent, got: ${String(ctx.sensitive)}`);
}

const OWNER_RE = /^[0-9a-f]{64}$/;

/**
 * A personal config's owner as its values' context binds them: the SHA-256
 * of the member, `user:ada@acme.example`. Hashed, so it joins the AAD as
 * unambiguously as a UUID: an email can hold the separator.
 */
export function ownerKey(member: string): string {
  return createHash('sha256').update(member, 'utf8').digest('hex');
}

/**
 * Encode a context into AAD bytes.
 *
 * Every field is validated as a UUID first, which is what makes joining with
 * `|` unambiguous: a UUID cannot contain the separator, so no two distinct
 * contexts can encode to the same bytes.
 */
export function encodeAad(ctx: SecretContext): Buffer {
  checkContext(ctx);
  return Buffer.from(
    `${AAD_VERSION}|${ctx.projectId}|${ctx.environmentId}|${ctx.secretId}${ctx.owner === undefined ? '' : `|owner:${ctx.owner}`}${ctx.sensitive === true ? '|sensitive' : ''}`,
    'utf8',
  );
}

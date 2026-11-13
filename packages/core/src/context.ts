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
 *
 * From envelope version 2 the wrap names the version's number too,
 * `version`: a version's row copied over another of the same secret, an old
 * value put back as the current one, does not open either. And whether the
 * value is plain, `plain`, as it names whether it is sensitive.
 */
export type SecretContext = {
  projectId: string;
  environmentId: string;
  secretId: string;
  /** A personal config's owner, as `ownerKey` hashes them. */
  owner?: string;
  /** A sensitive value's: never handed back to a person (`sensitive` in @coffre/core/vault). Absent otherwise, never false. */
  sensitive?: true;
  /**
   * A plain value's, one marked not secret, which whoever lists its
   * environment sees: never sensitive too. From envelope version 2, so that
   * a secret relabelled plain, to be handed to whoever reads plain values,
   * does not open. Absent otherwise, never false.
   */
  plain?: true;
  /** The version's number among its secret's, from 1. Absent in the wrap of a value written before envelope version 2. */
  version?: number;
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

/** Throw unless every field is a lowercase UUID, an owner a lowercase SHA-256, `sensitive` and `plain` true if there and never both, and a version a number from 1. */
export function checkContext(ctx: SecretContext): void {
  assertUuid(ctx.projectId, 'projectId');
  assertUuid(ctx.environmentId, 'environmentId');
  assertUuid(ctx.secretId, 'secretId');
  if (ctx.owner !== undefined && (typeof ctx.owner !== 'string' || !OWNER_RE.test(ctx.owner))) {
    throw new Error(`context.owner must be a lowercase SHA-256, got: ${String(ctx.owner)}`);
  }
  if (ctx.sensitive !== undefined && ctx.sensitive !== true) throw new Error(`context.sensitive is true or absent, got: ${String(ctx.sensitive)}`);
  if (ctx.plain !== undefined && (ctx.plain !== true || ctx.sensitive === true)) throw new Error(`context.plain is true or absent, and never with sensitive, got: ${String(ctx.plain)}`);
  if (ctx.version !== undefined && !(Number.isSafeInteger(ctx.version) && ctx.version > 0)) throw new Error(`context.version is a version's number, from 1, got: ${String(ctx.version)}`);
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
    `${AAD_VERSION}|${ctx.projectId}|${ctx.environmentId}|${ctx.secretId}${ctx.owner === undefined ? '' : `|owner:${ctx.owner}`}${ctx.sensitive === true ? '|sensitive' : ''}${ctx.plain === true ? '|plain' : ''}${ctx.version === undefined ? '' : `|version:${ctx.version}`}`,
    'utf8',
  );
}

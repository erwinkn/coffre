/** The changes of keys and their values (`packages/vault/src/ops/secrets.ts`). */
export type SecretsChanges = SecretWrite;

export type SecretsAnswers = {
  /** The version each key given a value is at now. */
  'secret.write': { versions: Record<string, number> };
};

/** How a value is kept: a secret, a sensitive one that no person is handed back, or a plain one that whoever lists its environment sees. */
export type Nature = 'secret' | 'sensitive' | 'plain';

/**
 * What a write does to one key of its environment, one thing or several:
 *
 * - `value`, with its `nature`: the key's next version, the key made if
 *   the environment has none by that name.
 * - `archived`: true archives the key, false brings it back. A key is
 *   archived with no value written.
 * - `folder`: the folder it is listed in, null for none.
 *
 * A key that gets no value is one the environment holds.
 */
export type KeyWrite = { key: string; archived?: boolean; folder?: string | null } & (
  | { value: string; nature: Nature }
  | { value?: undefined; nature?: undefined }
);

/**
 * Write keys in one environment, all of them or none. 1 to 2,000 keys,
 * each once and named as a key is (`[A-Za-z_][A-Za-z0-9_]{0,127}`); a value
 * is well-formed text with no NUL, 64 Ki characters at most, and the values
 * of one write 1 MiB of UTF-8 in all; a folder 1 to 64 UTF-16 units, with no slash or control character
 * and nothing `trim` removes at either end (`folderName`). Past any of these
 * the call is a fault, not a refusal: the app checks them first.
 */
export type SecretWrite = {
  op: 'secret.write';
  project: string;
  environment: string;
  keys: KeyWrite[];
};

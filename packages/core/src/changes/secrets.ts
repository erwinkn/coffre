/** The changes of keys and their values (`packages/vault/src/ops/secrets.ts`). */
export type SecretsChanges = SecretWrite;

export type SecretsAnswers = {
  /** The version each key is at now. */
  'secret.write': { versions: Record<string, number> };
};

/** How a value is kept: a secret, a sensitive one that no person is handed back, or a plain one that whoever lists its environment sees. */
export type Nature = 'secret' | 'sensitive' | 'plain';

/**
 * Write values in one environment: each key's next version, the key made
 * if the environment has none by that name. 1 to 2,000 keys, each once and
 * named as a key is (`[A-Za-z_][A-Za-z0-9_]{0,127}`); a value is
 * well-formed text with no NUL, 64 Ki characters at most, and the values
 * of one write 1 MiB of UTF-8 in all. Past any of these the call is a
 * fault, not a refusal: the app checks them first.
 */
export type SecretWrite = {
  op: 'secret.write';
  project: string;
  environment: string;
  values: { key: string; value: string; nature: Nature }[];
};

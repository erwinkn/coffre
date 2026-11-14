/** The changes of keys and their values (`packages/vault/src/ops/secrets.ts`). */
export type SecretsChanges = SecretWrite | SecretRefile | ReferenceBreak;

export type SecretsAnswers = {
  /** Each key given a value, written or restored: the version it is at now, and the nature it was written as. A key made a reference is given none. */
  'secret.write': { keys: Record<string, { version: number; nature: Nature }> };
  /** Where the reference read, as its source's rows say: null when the vault does not see them. */
  'reference.break': { source: SecretPath | null };
  /** The keys filed there, by name, in order. */
  'secret.refile': { moved: string[] };
};

/** A key by where it is held: `market/prod/STRIPE_KEY`. */
export type SecretPath = { project: string; environment: string; key: string };

/** How a value is kept: a secret, a sensitive one that no person is handed back, or a plain one that whoever lists its environment sees. */
export type Nature = 'secret' | 'sensitive' | 'plain';

/**
 * What a write does to one key of its environment, one thing or several:
 *
 * - `value`: the key's next version, the key made if the environment has
 *   none by that name. Its `nature` as given, or, given none, the key's
 *   own kept, or, where the environment holds none, the one it inherits,
 *   and both for an archived key brought back: sensitive stays sensitive, and anything else is written a secret, a
 *   plain one's and one inherited from nowhere included. A reference's is
 *   its source's.
 * - `restore`: the key's next version, the value of that version of its
 *   own, opened and sealed again by the vault, which never hands it out.
 *   The value comes back as it was kept, plain, a secret or sensitive, and
 *   sensitive while the key is, as a write with no nature says (above), or
 *   while the key's newest value was. Its first date is its source's (the
 *   member report's). Made by a recipe or in a pair, it comes back as typed:
 *   Regenerate makes a new value, and it pairs with nothing. Whoever restores
 *   reads the key there (`secret.read`): the value serves again.
 * - `ref`: the key made a reference to that key, which whoever reads this
 *   environment then reads through it, value and nature, as it changes. Its
 *   own value, if any, is history. The source is a key of a live project and
 *   environment, no personal config's, that the writer reads there (and
 *   uses, a sensitive one), and that is no reference itself; nor is a key
 *   other references read made one: one hop only. A workload refers only to
 *   a value it is handed back where it is held, a plain one or one its
 *   binding lists.
 * - `archived`: true archives the key, false brings it back. A key is
 *   archived with no value written.
 * - `folder`: the folder it is listed in, null for none.
 *
 * A key that gets neither a value nor a reference is one the environment
 * holds.
 */
export type KeyWrite = { key: string; archived?: boolean; folder?: string | null } & (
  | { value: string; nature?: Nature; ref?: undefined; restore?: undefined }
  | { restore: number; value?: undefined; nature?: undefined; ref?: undefined }
  | { ref: SecretPath; value?: undefined; nature?: undefined; restore?: undefined }
  | { value?: undefined; nature?: undefined; ref?: undefined; restore?: undefined }
);

/**
 * Write keys in one environment, all of them or none. 1 to 2,000 keys,
 * each once and named as a key is (`[A-Za-z_][A-Za-z0-9_]{0,127}`); a value
 * is well-formed text with no NUL, 64 Ki characters at most, and the values
 * of one write 1 MiB of UTF-8 in all; a version restored a positive integer; a reference's source named by slugs and its key's name; a folder 1 to 64 UTF-16 units, with no slash or control character
 * and nothing `trim` removes at either end (`folderName`). Past any of these
 * the call is a fault, not a refusal: the app checks them first.
 */
export type SecretWrite = {
  op: 'secret.write';
  project: string;
  environment: string;
  keys: KeyWrite[];
};

/**
 * A folder of one environment's keys renamed (`to`), or emptied (`to`
 * null): every key filed there, archived ones too, all of them or none, by
 * whoever writes keys there. A folder is a label, so renaming onto one
 * that is there merges the two. A folder no key is filed in is no folder:
 * refused `no_folder`. Folders are named as `SecretWrite`'s; past that, a
 * fault.
 */
export type SecretRefile = {
  op: 'secret.refile';
  project: string;
  environment: string;
  folder: string;
  to: string | null;
};

/**
 * End the reference a key is: whoever read through it reads nothing there,
 * until the key is given a value or made a reference again. Whoever writes
 * the key may, and whoever manages access in its source's project, who
 * need not see the key's environment at all.
 */
export type ReferenceBreak = {
  op: 'reference.break';
  project: string;
  environment: string;
  key: string;
};

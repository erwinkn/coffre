import type { Generation } from '../recipe.ts';

/** The changes of keys and their values (`packages/vault/src/ops/secrets.ts`). */
export type SecretsChanges = SecretWrite | SecretRename | SecretRefile | ReferenceBreak | MissingDismiss;

export type SecretsAnswers = {
  /**
   * Each key given a value, written or restored: the version it is at now, and the nature it was written as. A key made a
   * reference is given none. And what the write does to each key asked (`outcomes`), which a dry run tells (`weigh`).
   */
  'secret.write': { keys: Record<string, { version: number; nature: Nature }>; outcomes: Record<string, KeyOutcome> };
  /** Where the reference read, as its source's rows say: null when the vault does not see them. */
  'reference.break': { source: SecretPath | null };
  /** The key renamed, by its id. */
  'secret.rename': { id: string };
  /** The keys filed there, by name, in order. */
  'secret.refile': { moved: string[] };
  /** What the change did to each key it named: dismissed, restored, or nothing, as it was already. */
  'missing.dismiss': { keys: Record<string, 'dismissed' | 'restored' | 'unchanged'> };
};

/**
 * What a write does to one key, as 0.14's dry run said it (`DryRunOutcome`):
 * `added`, a key made, by a value or a reference; `archived`; `unchanged`,
 * nothing at all, a key archived already, filed where it is, or made a
 * reference to the source it reads; `changed`, anything else. Or, for a
 * value written over the key's own, live, of the nature it is written as,
 * typed and no reference (`compare`): the same or not only by opening that
 * version, which a decision never does. A dry run asks a use to compare
 * (purpose `compare`), which opens and logs the value as a read: the version
 * named is the one a use must hand back for the answer to stand. The write
 * itself never compares: it writes the value as a new version.
 */
export type KeyOutcome = 'added' | 'changed' | 'archived' | 'unchanged' | { compare: { secret: string; version: number } };

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
 *   `generated`: a client made it, by that recipe, which Regenerate makes
 *   the next one by (`@coffre/core/recipe`), as `formatRecipe` writes it.
 *   Never plain. A key pair's recipe writes its two keys together, each
 *   naming both, `{ private, public }`, with the same recipe: the two
 *   halves of one pair. A value typed, restored or referred to makes none.
 *   `replaces`: the version the key's value is now, by its id, as a
 *   listing gave it (`versionId`): its own live one, or in a fork that
 *   holds none, the one it inherits. Anything else, a key renamed,
 *   archived, made a reference or written since, refuses the write,
 *   `stale`: a regenerate addresses keys by name, and would otherwise
 *   write a name that no longer holds what it listed. `null`: the key
 *   reads no value now and is no reference, here or inherited (it is new,
 *   archived with none passed down, or a reference broken); `{ source }`:
 *   it reads, here or inherited, a reference to that secret, by its id (a
 *   listing's `reference.sourceId`). Anything else refuses either the same:
 *   an MCP approval's value, set over what its person read.
 * - `restore`: the key's next version, the value of that version of its
 *   own, opened and sealed again by the vault, which never hands it out.
 *   The value comes back as it was kept, plain, a secret or sensitive, and
 *   sensitive while the key is, as a write with no nature says (above), or
 *   while the key's newest value was. Its first date is its source's (the
 *   member report's). Made by a recipe or in a pair, it comes back as typed:
 *   Regenerate makes a new value, and it pairs with nothing. Whoever restores
 *   reads the key there (`secret.read`): the value serves again. And never
 *   looser than the newest copy of the same value, by its first date: a
 *   value marked sensitive comes back sensitive from a version before the
 *   mark, and one marked a secret from its plain version.
 * - `nature` alone (`coffre mark`): the key's value kept, made of that
 *   nature, as the key's next version, which the vault opens and seals
 *   again: nature and version are in what its encryption names. Its first
 *   date, recipe and pair are kept: the value is the same. Stricter only,
 *   plain to a secret or sensitive, a secret to sensitive, by whoever
 *   writes keys there (`secret.write`); a sensitive value made a secret by
 *   an Owner of the project alone, as a person on no credential's scope
 *   (`not_owner` to anyone else), and plain never: that takes the value
 *   written again (`looser`). The nature it has already writes nothing
 *   (`unchanged`). The key is the environment's own, live and holding a
 *   value: `archived`, `is_reference` (mark its source), `inherited_key`
 *   (mark it where it is held), `no_value`, or `unknown_key`. A change
 *   that makes any key looser is logged `secret.loosen`, with every key's
 *   line, and `secret.write` otherwise.
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
 * - `inherit`, alone: in a fork, true resets the key to what a parent
 *   passes down, its own row archived with its history, and false makes
 *   its own value serve over that again. Either takes `secret.write`, as
 *   writing over a parent's does, and false `secret.read` too: the value
 *   serves again. A key no parent passes down is `not_inherited`.
 *
 * A key that gets neither a value nor a reference is one the environment
 * holds. In a fork, a key reset to what it inherits is written over as if
 * it were live: it overrides its parent's again, as 0.14's did.
 */
export type KeyWrite = { key: string; archived?: boolean; folder?: string | null; inherit?: undefined } & (
  | { value: string; nature?: Nature; generated?: Generation; replaces?: string | null | { source: string }; ref?: undefined; restore?: undefined }
  | { restore: number; value?: undefined; nature?: undefined; generated?: undefined; replaces?: undefined; ref?: undefined }
  | { ref: SecretPath; value?: undefined; nature?: undefined; generated?: undefined; replaces?: undefined; restore?: undefined }
  | { value?: undefined; nature?: undefined; generated?: undefined; replaces?: undefined; ref?: undefined; restore?: undefined }
) | { key: string; nature: Nature; archived?: undefined; folder?: undefined; inherit?: undefined; value?: undefined; generated?: undefined; replaces?: undefined; ref?: undefined; restore?: undefined }
  | { key: string; inherit: boolean; archived?: undefined; folder?: undefined; value?: undefined; nature?: undefined; generated?: undefined; replaces?: undefined; ref?: undefined; restore?: undefined };

/**
 * Write keys in one environment, all of them or none. 1 to 2,000 keys,
 * each once and named as a key is (`[A-Za-z_][A-Za-z0-9_]{0,127}`); a value
 * is well-formed text with no NUL, 64 Ki characters at most, generated by a recipe as `formatRecipe` writes it, a key pair's two halves both in the write, and replacing a version named by a UUID, and the values
 * of one write 1 MiB of UTF-8 in all, each version restored counted as the most a value weighs, 192 KiB (so 5 at most), since its size is known only once the vault reads it; a version restored a positive integer; a reference's source named by slugs and its key's name; a folder 1 to 64 UTF-16 units, with no slash or control character
 * and nothing `trim` removes at either end (`folderName`); a mark one of the three natures, alone. Past any of these
 * the call is a fault, not a refusal: the app checks them first.
 *
 * In a personal config (`mine`), its owner alone writes, a person
 * (`not_a_person` to a service account), while they read or use the
 * environment it is a config of, and as far as their credential's scope
 * does there; no grant or role reaches it. It holds no reference, and a
 * value written there with no nature over a plain one stays plain: nobody
 * but its owner lists it. A write that gives a key a value makes the
 * config where they have none, as an environment of three parents at most
 * (`too_deep`); anything else asked of a config not there is asked of a
 * key not there.
 */
export type SecretWrite = {
  op: 'secret.write';
  project: string;
  environment: string;
  /** In the caller's personal config of `environment` (`dev@me`), made by this write if they have none and it gives a key a value. */
  mine?: boolean;
  keys: KeyWrite[];
};

/**
 * A key renamed (`to`), with its history, by whoever writes keys there. A
 * live key, named as `SecretWrite`'s: an archived one is brought back
 * first (`archived`), and a name the environment holds already, archived
 * or not, is `duplicate_key`. Its references read it still, by its id.
 *
 * The name carries down to every environment that inherits from it, forks
 * of forks, archived ones and personal configs included: each one's own
 * row of the key, its override, takes the new name, and so does its
 * dismissal, so each goes on overriding or doing without the key it did.
 * Where one already holds a key of the new name of its own, a shared fork
 * refuses the rename, `duplicate_key_below`; a personal config, named to
 * nobody but its owner, has its own moved out of the way, `NEW_2` (or
 * `_3`, and on). No value moves, so the renamer needs nothing in the
 * forks. Renamed onto its own name, nothing changes. In the caller's
 * personal config (`mine`), as `SecretWrite`'s: a config has no forks.
 */
export type SecretRename = {
  op: 'secret.rename';
  project: string;
  environment: string;
  /** In the caller's personal config of `environment` (`dev@me`). */
  mine?: boolean;
  key: string;
  to: string;
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
  /** In the caller's personal config of `environment` (`dev@me`). */
  mine?: boolean;
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

/**
 * Keys an environment does without (`dismissed: true`), or does again
 * (`false`), 0.14's `setDismissals`, by whoever writes keys there: the
 * team's decision, which its missing keys list leaves out until someone
 * restores it. A key named twice, or a key past 2,000 in one change, is a
 * fault and a refusal (`too_many_keys`) respectively.
 *
 * In a fork, or a personal config (`mine`), a dismissal is also a removal:
 * the environment no longer inherits the key, and a use there reads
 * nothing of it. One it holds a live row of, a value or a reference, would
 * serve whatever is dismissed, so dismissing it is refused, `held_here`:
 * reset it to what it inherits first, or archive it. Outside a fork, such a
 * dismissal is moot, and allowed, as in 0.14.7. A personal config is
 * dismissed in only by its owner, and only once they have one: a
 * dismissal makes none, `no_config`.
 */
export type MissingDismiss = {
  op: 'missing.dismiss';
  project: string;
  environment: string;
  /** In the caller's personal config of `environment` (`dev@me`). */
  mine?: boolean;
  keys: { key: string; dismissed: boolean }[];
};

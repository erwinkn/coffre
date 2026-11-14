/** The changes of projects and environments (`packages/vault/src/ops/places.ts`). */
export type PlacesChanges = ProjectCreate | EnvironmentCreate | ProjectEdit | EnvironmentEdit | FolderRefile | PlaceDelete;

/**
 * An edit answers the place as it leaves it, `archivedAt` in ISO 8601;
 * asked for what is so already, it changes nothing, and is logged all the
 * same.
 */
export type ProjectEdited = { id: string; slug: string; archivedAt: string | null; folder: string | null };
export type EnvironmentEdited = { id: string; slug: string; archivedAt: string | null; protected: boolean };

export type PlacesAnswers = {
  'project.create': { id: string };
  /**
   * Its slug is the one asked for, or, for a personal config, the one made
   * for it, which only a list for deletion shows. A personal config is
   * `protected` as the environment it is a config of is.
   */
  'environment.create': { id: string; slug: string; protected: boolean; forked?: Forked };
  /** The projects it filed, by slug. */
  'folder.refile': { moved: string[] };
  'project.delete': PlaceDeleted;
  'environment.delete': PlaceDeleted;
} & { [K in ProjectEdit['op']]: ProjectEdited } & { [K in EnvironmentEdit['op']]: EnvironmentEdited };

/**
 * Make a project, as an Admin or Owner of the instance whose scope takes in
 * new projects, on a session's credential. Its slug is free: no project has
 * it, archived ones included. A slug is 1 to 63 of `a-z`, `0-9` and `-`,
 * starting with a letter or digit; past that the call is a fault, not a
 * refusal: the app checks it first.
 */
export type ProjectCreate = {
  op: 'project.create';
  project: string;
};

/**
 * Make an environment in a live project, as one who manages its
 * environments (`environment.manage`): its slug free in the project,
 * shaped as a project's and none of a project's pages (`PROJECT_PAGES`).
 * With `parent`, a fork that inherits from that environment, live, never
 * a personal config, which the caller reads, and which inherits from two
 * at most, so that the fork inherits from three; with `copy`, a fork that
 * copies one (`EnvironmentCopy`). A fork of a protected environment is
 * protected, whatever `protected` says.
 *
 * With `mine`, the caller's personal config of `environment` instead: a
 * person's, who reads or uses it, live, never a personal config itself,
 * with two parents at most. One per person per environment. Its slug is
 * made here, and it is protected as its environment is, through it.
 */
export type EnvironmentCreate = { op: 'environment.create'; project: string; environment: string } & (
  | { mine: false; parent: string | null; protected: boolean; copy?: EnvironmentCopy }
  | { mine: true }
);

/**
 * A fork that copies (docs/design/forking.md, "Forks"): with `copy`, the
 * new environment inherits from nothing (`parent` null) and holds, made in
 * the same change, each key `from` reads now, as a use of it finds them:
 * its own and those it inherits, each from the nearest environment that
 * holds it or dismissed it, with the folder it is filed in there, and none
 * of its history. A key with no value, a reference broken, is left out.
 * Who forks manages the project's environments and reads `from`, and each
 * environment above it a key comes from (`parent_unreadable`); `from` is a
 * live environment of the project, no personal config, whose chain stands
 * (`broken_chain`).
 *
 * Each key is a copy of its value by default: the vault opens the version
 * and seals it again as the new key's first version, and nobody else holds
 * it. It is kept as it was, plain, a secret or sensitive, and its first
 * date is its source's; it has no recipe and is in no pair, as one typed.
 * With `references`, each key is a reference instead, one hop, to where its
 * value is held: the parent's key, a key it inherits, or a reference's
 * source. That is a reference made, as `secret.write` makes one: its
 * forker reads the source where it is held, by their own grants, and uses
 * it there too if it is sensitive. A key whose source they do not is
 * copied, and named in `copied`. A sensitive value reached through a
 * reference is never copied, whatever is asked: a copy would hold it under
 * this project, which another project's value is not. It stays a reference
 * to its source, which its forker must be able to make, or the fork is
 * refused, `no_access`. A workload copies or refers to no value it only
 * uses where it is held (`use_only`).
 *
 * One change opens and seals again 2,000 values at most (`too_many_keys`),
 * and 8 MiB of them as stored (`too_much_to_copy`, the vault's
 * `MOST_COPIED`, which a mark shares): past either, nothing is made, and
 * the fork is made by references or inherits instead. A fork that copies
 * by default is weighed before any value is read; one by references, by
 * what it copies.
 */
export type EnvironmentCopy = { from: string; references: boolean };

/** What a fork that copies made: how many keys, how many of them references, and those copied where references were asked for. */
export type Forked = { keys: number; references: number; copied: string[] };

/**
 * A project edited, archived or not, by whoever manages it
 * (`project.manage`), on a project there or archived: a deleted one's
 * tombstone is no project.
 *
 * - `project.update`: its slug, to one free as a new project's is.
 * - `project.archive`: refused, `referenced`, while a reference held
 *   outside it reads a value in it (D41): archiving would stop that read.
 * - `project.restore`.
 * - `project.move`: filed in a folder, 1 to 64 characters with no `/`, no
 *   control character and no space at either end, or in none.
 */
export type ProjectEdit = { project: string } & (
  | { op: 'project.update'; slug: string }
  | { op: 'project.archive' }
  | { op: 'project.restore' }
  | { op: 'project.move'; folder: string | null }
);

/**
 * An environment edited, there or archived, by whoever manages its
 * project's environments (`environment.manage`), unless said otherwise. A
 * personal config is edited by none of these: it is archived and restored
 * with its environment, and protected through it.
 *
 * - `environment.update`: its slug, to one free in the project and none of
 *   a project's pages. Scopes name environments by slug, so this moves who
 *   an instance role reaches there.
 * - `environment.archive`, with its personal configs: refused while a live
 *   fork inherits from it (`inherited`), or a reference held outside it
 *   reads a value in it (`referenced`).
 * - `environment.restore`, with its personal configs: refused while an
 *   environment it inherits from is archived or deleted (`parent_archived`),
 *   or one is not there to say (`broken_chain`).
 * - `environment.protect`: each role holds there what its protected column
 *   says, for people (docs/design/roles.md). Never by a workload's session
 *   (`workload_cannot_issue`), which changes no one's access.
 * - `environment.unprotect`: as protecting, and by an Owner of its project
 *   alone, by a grant on it or an instance role whose scope takes in all
 *   of it, on no credential's scope (`ownsProject`, R30).
 * - `upstream.freeze`: the deployment's upstream credential of that name,
 *   `stripe`, used by nobody in this live environment, by whoever writes
 *   there (`secret.write`); `upstream.thaw` lifts it, by an Owner of the
 *   project (docs/design/workload-access.md, section 8.2).
 */
export type EnvironmentEdit = { project: string; environment: string } & (
  | { op: 'environment.update'; slug: string }
  | { op: 'environment.archive' }
  | { op: 'environment.restore' }
  | { op: 'environment.protect' }
  | { op: 'environment.unprotect' }
  | { op: 'upstream.freeze'; upstream: string }
  | { op: 'upstream.thaw'; upstream: string }
);

/**
 * A folder of projects renamed, `to` a name shaped as `project.move`
 * takes one, or emptied, `to` null: every project filed there, archived
 * ones included, in one change, by whoever manages each of them
 * (`project.manage`). A folder is a label, so renaming onto one that is
 * there merges the two. A folder none of whose projects the caller may
 * file is no folder of theirs: refused as one with no project.
 */
export type FolderRefile = { op: 'folder.refile'; folder: string; to: string | null };

/**
 * A place deleted for good, as 0.14.7 deleted one (`deletePlace`), in one
 * change: every version under it erased, its ciphertext and wrapped data
 * key emptied, and a plain one's copy cleared; every grant on it revoked;
 * every reference into it or out of it ended, its holder reading nothing
 * since (a reference holds no value of its own); and its slug made a
 * tombstone, `market~deleted-2026-10-05` (`tombstoneOf`), which frees the
 * slug and is never mistaken for what takes it next. Its rows stay, names
 * and dates only, because the log names them. A copy made of one of its
 * values elsewhere, a fork's, is a value of its own and stays. Weighed
 * (`weigh`), it says what it would take, and changes nothing.
 *
 * - `project.delete`: an archived project, with every environment and
 *   personal config in it.
 * - `environment.delete`: an archived environment itself, whatever its
 *   project is, with its personal configs; refused, `inherited`, while a
 *   fork inherits from it, archived or not: deleted, it would leave the
 *   fork naming a tombstone.
 *
 * Both by an Admin or Owner of the whole instance, on no credential's
 * scope (`runsInstance`); a place there but live is `not_archived`. A
 * personal config is deleted by its owner, or by whoever manages its
 * project's environments (`environment.manage`), archived or not:
 * `environment` names it by its own slug, which only a list for deletion
 * shows, or, with `mine`, the environment it is the caller's config of.
 * A place that holds more versions with a value than one change erases
 * (`MOST_ERASED` in the vault) is refused, `too_large`, and nothing is
 * erased: its environments are deleted one at a time first.
 */
export type PlaceDelete =
  | { op: 'project.delete'; project: string }
  | { op: 'environment.delete'; project: string; environment: string; mine: boolean };

/** What deleting a place takes, or took. */
export type PlaceDeleted = {
  /** `market`, `market/prod`, or a personal config's `market/dev@ada@acme.example`. */
  path: string;
  /** The slug its tombstone keeps: `market~deleted-2026-10-05`. */
  tombstone: string;
  /** The environments it takes, personal configs too, these by their environment and owner (`dev@ada@acme.example`): a project's every one, or the one with its configs. */
  environments: string[];
  /** The keys named there, which the tombstone keeps, never their values. */
  keys: number;
  /** The versions whose values it erases. */
  versions: number;
  /** The grants on it, lapsed ones too, which it revokes. */
  grants: { member: string; place: string; role: string }[];
  /** The references into it and out of it, which it ends: each holder, and the source it read (`(gone)` for one not found). */
  references: { holder: string; source: string }[];
  /** Members who hold nothing anywhere afterwards, with no instance role: a service among them may be offboarded. */
  stranded: string[];
};

import { ACCESS_ACTIONS } from '@coffre/core/vault';
import { asc, desc, eq, sql, type SQL, type SQLWrapper } from 'drizzle-orm';

import type { Queryable } from './database.ts';
import { engineOf, type Engine } from './dialect.ts';

/**
 * The vault's allowed access entries in 0.14's log: an add, restore, role
 * change or removal of a member, a grant or a revoke, as `ACCESS_ACTIONS`
 * names them. `audit_log_access_idx` holds them alone, by principal (on
 * SQLite after `author`, as the subject index): a principal's allowed
 * access entries, or the principals that have any, read in as many steps
 * however many other entries the log holds about them, refusals included
 * (T239, R48). A read that is to use the index repeats this condition word
 * for word, with no parameter, as `recorded` does for `log_changes`:
 * Postgres proves a partial index's condition only from constants, and
 * SQLite only from the same terms.
 */
export function accessAllowed(alias?: string): SQL {
  const actions = ACCESS_ACTIONS.map((action) => `'${action}'`).join(', ');
  const column = (name: string) => (alias === undefined ? name : `${alias}.${name}`);
  return sql.raw(`${column('author')} = 'vault' AND ${column('decision')} = 'allow' AND ${column('action')} IN (${actions})`);
}

/**
 * Entries written by `author`, and with `decision` when given, as constants:
 * the condition of the audit log's partial indexes by author
 * (`audit_log_app_idx`, `audit_log_vault_idx`;
 * T245, R48). Bound as parameters, the
 * values let a plan made for them alone use those indexes: coffre's
 * statements are unnamed, each planned with its values, but a generic plan
 * (a named statement's from its sixth run, or `plan_cache_mode =
 * force_generic_plan`) could not prove the condition and would walk the
 * log by `seq` instead. As constants, every plan proves it.
 */
export function authoredBy(author: 'app' | 'vault', decision?: 'allow' | 'deny'): SQL {
  return sql.raw(`author = '${author}'${decision === undefined ? '' : ` AND decision = '${decision}'`}`);
}

/**
 * Each kind of entry a runtime read asks the newest of (or the first, or a
 * page back from the newest), and the condition of the index that holds it
 * alone (T245, R48): one place for both, so that the read and its index
 * cannot drift, as constants, which every plan proves the index's
 * condition from (`authoredBy`). Postgres walks back any index that yields
 * `seq` order (the primary key, `audit_log_vault_idx`, `audit_log_app_idx`,
 * `audit_log_action_idx`) with the rest as a filter whenever its statistics
 * hold the kind common, pricing the walk as the one row it expects to meet
 * first, however long the run of other entries since the kind's newest:
 * 140,000 rotations then 20,000 checkpoints, and the newest rotation read
 * 641 pages; 700,000 checkpoints then 100,000 unwraps, and the newest
 * checkpoint read 3,731 (Postgres 16). An index of the kind alone is
 * smaller than any of those and needs no filter, so it is cheaper by
 * Postgres's own estimate every time, and reads 4 pages. One keyed
 * `(author, action, decision, seq)` for every kind is not: larger than
 * `audit_log_vault_idx`, it lost to it once half the table was not yet
 * vacuumed, and it costs every entry written a step of its own (9% more
 * WAL an entry), where these cost an entry of another kind nothing
 * (`packages/vault/test/newest-lookups.test.ts`).
 */
export const KINDS = {
  /** The vault's checkpoints, signed or refused: whether one was written since (`newestCheckpointEntry`). */
  checkpoint: "author = 'vault' AND action = 'audit.checkpoint'",
  /** Its signed checkpoints: the newest, which a verification goes on from (`latestSigned`, `latestTallied`). */
  signed: "author = 'vault' AND action = 'audit.checkpoint' AND decision = 'allow'",
  /** Its refusals of a checkpoint for a broken log, which stand until one is signed (`newestBrokenLog`). */
  brokenLog: "author = 'vault' AND action = 'audit.checkpoint' AND decision = 'deny' AND code = 'log_broken'",
  /** Its policy changes: the newest, which every check of a member reads (`newestVaultSeq`, the uses' functions). */
  policy: "author = 'vault' AND action = 'policy.change' AND decision = 'allow'",
  /** Its settings changes: the newest, the instance's settings. */
  settings: "author = 'vault' AND action = 'settings.change' AND decision = 'allow'",
  /** Its rotations of the KEK: the newest, which the vault's start and each rotation read (`latestRotation`). */
  rotation: "author = 'vault' AND action = 'key.rotate' AND decision = 'allow'",
  /** The key services' intents: those of the last day, newest first, a page at a time (`recentIntents`). */
  intent: "author = 'vault' AND action = 'key.intent' AND decision = 'allow'",
  /** Its checks of the KEK: the oldest, which a verification reads first (`keyChecks`). */
  keyCheck: "author = 'vault' AND action = 'key.check' AND decision = 'allow'",
  /** Its reports that a member's row was changed around it, by member (`tamperReportsAbout`). */
  tamper: "author = 'vault' AND action = 'vault.tampered' AND code IN ('mac', 'stale')",
  /** The app's moves to a new key, resealed or rotated: the newest (`newestMove`). */
  moves: "author = 'app' AND action IN ('key.reseal', 'key.rotate')",
} as const;

/** A kind of entry with an index of its own (`KINDS`). */
export type Kind = keyof typeof KINDS;

/** The name of `kind`'s index: `audit_log_key_check_idx` for `keyCheck`. */
export function indexOf(kind: Kind): string {
  return `audit_log_${kind.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`)}_idx`;
}

/** The entries of `kind`, as the condition of its index, word for word (`KINDS`). */
export function entriesOf(kind: Kind): SQL {
  return sql.raw(KINDS[kind]);
}

/**
 * The entries whose `column` is one value, and the order that reads them
 * by `seq` (newest first, `desc`, or oldest first): through the index
 * keyed `(column, seq)` that holds them, whatever else the log holds
 * (T245, R48). An index keyed by a value is wider than the author's by
 * `seq` alone (`audit_log_vault_idx`, `audit_log_app_idx`), and where
 * Postgres's statistics hold the value common, as the current key's, it
 * expects to meet one at once walking the narrower index by `seq`, and
 * walks every entry of other values on the way: 557 pages behind 20,000
 * entries under another key, 956 behind 20,000 reads about a member whose
 * grants came before (Postgres 16). An equality fixes the value, and
 * Postgres drops it from the order; `= ANY` of the one value does not, so
 * only an index keyed by the value yields the order, and no walk is
 * priced against it. `values` is that one value as an array (`[value]`,
 * or a placeholder bound to one); SQLite, which takes the index keyed by
 * the value, asks it plainly, by `value`.
 */
export function keyedBy(db: Queryable, column: SQLWrapper, seq: SQLWrapper, order: 'asc' | 'desc', value: unknown, values: unknown): { where: SQL; orderBy: SQL[] } {
  const by = order === 'asc' ? asc : desc;
  if (engineOf(db) !== 'postgres') return { where: eq(column as never, value), orderBy: [by(seq as never)] };
  return { where: sql`${column} = ANY(${values}::text[])`, orderBy: [by(column as never), by(seq as never)] };
}

/**
 * One object's changes in 0.15's log (`log_changes`, as `alias`), and the
 * order that reads them by number, newest first (`desc`) or oldest:
 * through `log_changes_object_idx`, `(object, number)`, whatever else the
 * log holds (R48). `where` the condition on the object, `order` the order,
 * for `… WHERE ${where} ORDER BY ${order} LIMIT 1`. Asked plainly
 * (`object = $1 ORDER BY number DESC`), Postgres drops the object from the
 * order, which the primary key then yields, and where its statistics hold
 * the object common it walks the primary key back from the newest change,
 * every other object's on the way: 441 pages for an object's newest change
 * behind 20,000 of another's, under a plan for its value as under one for
 * any (Postgres 16; 4 by the index). `= ANY` of the one object does not
 * fix it, so only the object's index yields the order (`keyedBy`).
 * `object` is SQL that names a uuid: a column, `log_object(…)`, or a
 * value, which the cast types; `db` the database, or its engine. SQLite,
 * which takes the object's index, asks it plainly.
 */
export function changesOf(db: Queryable | Engine, alias: string, object: SQLWrapper | string, order: 'asc' | 'desc' = 'desc'): { where: SQL; order: SQL } {
  const as = sql.raw(alias);
  const by = sql.raw(order === 'asc' ? 'ASC' : 'DESC');
  if ((typeof db === 'string' ? db : engineOf(db)) !== 'postgres') return { where: sql`${as}.object = ${object}`, order: sql`${as}.number ${by}` };
  return { where: sql`${as}.object = ANY(ARRAY[CAST(${object} AS uuid)])`, order: sql`${as}.object ${by}, ${as}.number ${by}` };
}

/**
 * The change a tamper report names (its metadata's `change`, a string): a
 * report of 0.15's log, which stands while that change is its member's
 * newest; null for 0.14's, which name none. As `audit_log_tamper_idx` keys
 * it, after the member: a lookup of either kind (`tamperReportsAbout`,
 * `findingsOf`) reads its member's reports of that kind alone, never the
 * other's (T245, R48).
 */
export function changeNamed(engine: Engine, metadata: SQLWrapper): SQL<string | null> {
  return engine === 'postgres'
    ? sql`(CASE WHEN jsonb_typeof(${metadata}::jsonb -> 'change') = 'string' THEN ${metadata}::jsonb ->> 'change' END)`
    : sql`(CASE WHEN json_type(${metadata}, '$.change') = 'text' THEN json_extract(${metadata}, '$.change') END)`;
}

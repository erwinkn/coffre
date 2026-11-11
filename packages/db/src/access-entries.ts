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
 * Technical steps and sign-ins: in the log and its chain like everything
 * else, but not what someone did with secrets or access, so an audit page
 * leaves them out unless asked (`shown`). Here, beside the index of the
 * entries shown, which names them word for word.
 */
export const DETAIL_ACTIONS = [
  'sign_in',
  'sign_out',
  'token.create',
  'token.revoke',
  'device.approve',
  'device.deny',
  // An MCP client's code redeemed, or its tokens refreshed: every hour of its use.
  'mcp.token',
  // A read-only tool's call through MCP that went through. Its refusals, and every change, are `mcp.call`, shown.
  'mcp.read',
  'account.link',
  'account.unlink',
  // A touch that stepped a session up (docs/design/passkeys.md, section 6.2): one per five minutes at most, in PR 5.
  'passkey.check',
  'key.wrap',
  'key.rewrap',
  // The vault's seal of a reference: the app's `secret.reference` says it in words.
  'reference.create',
  'key.intent',
  'key.check',
  'audit.heartbeat',
  'audit.checkpoint',
  // A step of the app key's rotation, a hundred rows signed again; its `key.rotate` is shown.
  'key.reseal',
] as const;

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
  /**
   * What an audit page shows unless asked for detail (`DETAIL_ACTIONS`): a page back from the newest, past every
   * heartbeat and checkpoint since, which the primary key walked (82 pages 2,000 heartbeats in, 696 at 20,000; T248).
   * `seq >= 0`, which every entry is (the chain's first is 0) and no other read says, keeps every other read off its
   * index: a partial index on `seq` alone whose condition a read implies, Postgres may read whole as a bitmap and AND
   * with another, which a key's page, for its tokens' origins (`originsOf`, `token.create`), did through `detail`'s:
   * 1,231 pages with the history grown, 350 before (review r1 of #559).
   */
  shown: `action NOT IN (${DETAIL_ACTIONS.map((action) => `'${action}'`).join(', ')}) AND seq >= 0`,
  /**
   * The refusals it shows (`?decision=deny`): a page of them back from the newest, past every entry allowed since,
   * which `audit_log_shown_idx` walked (35 pages 4,000 allowed entries in, 334 at 40,000; T254). Not `decision = 'deny'`,
   * which a read would say too and so fix the decision: Postgres would read the refusals' index, keyed by decision then
   * `seq`, as one by `seq` alone, as every index of a kind is, and took `audit_log_shown_idx` past every entry allowed
   * (157 pages to 1,556). A read asks for the refusals as `decision = ANY('{deny}')` beside this, which implies it and
   * fixes nothing, so that only this index yields their order.
   */
  denied: `decision <> 'allow' AND action NOT IN (${DETAIL_ACTIONS.map((action) => `'${action}'`).join(', ')}) AND seq >= 0`,
  /** And what it leaves out, which it counts back from where it started, a stretch's newest at most (`auditActionCounts`); `seq >= 0` as `shown`'s. */
  detail: `action IN (${DETAIL_ACTIONS.map((action) => `'${action}'`).join(', ')}) AND seq >= 0`,
  /**
   * The reads and writes 0.14's log records of a key, by whom (`memberActivity`): a member's, through their actor,
   * where the log's whole was read for every report (2,484 pages behind 80,000 entries; T248). 0.15's log records
   * every use and key write since its cutover (R53, T179): these no longer grow.
   */
  seen: "decision = 'allow' AND action IN ('secret.read', 'secret.write')",
} as const;

/**
 * The entries a place's audit page shows, by the place (T254, R48): its
 * shown entries are a stream of an index that holds the shown entries
 * alone, keyed by the place, then `seq` (`placeStreams` in the server), so
 * that a page back from the newest steps past none of what it hides about
 * the place, nor anything about another. Through `audit_log_shown_idx` it
 * walked every shown entry about another place, through
 * `audit_log_project_idx` every one it hides about its own: 157 pages to
 * 1,555 for a project's page 4,000 and 40,000 entries in, 304 to 3,023 for
 * an environment's or a key's. As constants, as `KINDS`' (`authoredBy`):
 * the column's, `project_id IS NOT NULL AND …` for
 * `audit_log_project_shown_idx`.
 */
export const PLACE_COLUMNS = { projectId: 'project_id', environmentId: 'environment_id', secretId: 'secret_id' } as const;

/** The shown entries about a place in `column` (`PLACE_COLUMNS`), as the condition of its index, word for word. */
export function shownAt(column: (typeof PLACE_COLUMNS)[keyof typeof PLACE_COLUMNS]): SQL {
  return sql.raw(`${column} IS NOT NULL AND ${KINDS.shown}`);
}

/**
 * What a place's index of shown entries is keyed by, before `seq`: on
 * Postgres its uuid's 16 bytes (`uuid_send`), an expression no older index
 * is keyed by, so that a read of the place through it can be answered by it
 * alone. Asked plainly, `project_id = ANY(…)`, Postgres read the older index
 * by the column instead, `audit_log_project_idx`, which holds every entry
 * about the place, whenever it held few shown, from its statistics: walked
 * back past every detail entry about the place, or read whole and sorted
 * (1,059 pages for an environment's page past 20,000 of its own `mcp.read`,
 * 879 for a key's; 5 through the place's own index). The bytes, not the
 * text, as the column stores it: 16 bytes a key rather than 36, which takes
 * 5 to 6 points off what the indexes add to an insert's WAL (T254's
 * benchmark, docs/history-sweep.md). `uuid_send` never fails on a uuid.
 * SQLite, which takes the index keyed by the place, keys it by the column.
 */
export function placeKey(engine: Engine, column: SQLWrapper): SQL {
  return engine === 'postgres' ? sql`(uuid_send(${column}))` : sql`${column}`;
}

/** A place's id as `placeKey` keys it, to ask its index by: on Postgres the uuid's bytes, on SQLite the value. */
export function placeKeyOf(engine: Engine, value: string): SQL {
  return engine === 'postgres' ? sql`uuid_send(CAST(${value} AS uuid))` : sql`${value}`;
}

/**
 * And what its index of the shown entries naming it besides (`also`) is
 * keyed by: on Postgres `#>> '{also,projectId}'`, the value the older
 * `audit_log_also_*_idx` are keyed by as `-> 'also' ->> 'projectId'`, as an
 * expression none of them is (`placeKey` says why). As text, not a uuid's
 * bytes: nothing holds `also` to name uuids (no constraint does, and
 * metadata is the writer's), and an index expression that failed on one
 * (`::uuid`) would fail its insert. `#>>` fails on no JSON at all: on an
 * `also` that is no object, or a field that is no string, it answers what
 * no read asks for.
 */
export function besideKey(engine: Engine, metadata: SQLWrapper, field: keyof typeof PLACE_COLUMNS): SQL {
  return engine === 'postgres'
    ? sql`((${metadata})::jsonb #>> ${sql.raw(`'{also,${field}}'`)})`
    : sql`json_extract(${metadata}, ${sql.raw(`'$.also.${field}'`)})`;
}

/**
 * A read of several keys at one place in 0.14's log (`readsByPlace` in the
 * vault): one entry, its keys listed in its metadata's `secrets`, which no
 * index can key. `audit_log_listed_idx` holds them alone by environment, so
 * that a key's page reads its environment's reads of several keys, and no
 * other entry about it (T254). As constants.
 */
export const LISTED_READS = "action = 'secret.read' AND secret_id IS NULL";

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

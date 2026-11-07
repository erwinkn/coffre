import { personalOf } from '@coffre/core/schemas';
import { tablesOf, type Queryable } from '@coffre/db';
import { clock, engineOf, rowsOf, type Table } from '@coffre/db/dialect';
import { getTableColumns, sql } from 'drizzle-orm';

import { resolvedPlace, secretRowOf, type CredentialRead, type ResolvedPath, type SecretRow } from './queries.ts';

/**
 * What a read of values reads before anything else, in one call of
 * migration 0031's `app_read` (T135): the request's credential, as
 * `findCredential` reads it; the place, as `resolvePath` resolves a path
 * with no key; and its keys' rows, as `environmentSecrets` reads them, the
 * named ones only when `keys` names them. Each statement of the app's own
 * is planned anew for every request, which was most of a `/use`'s
 * Postgres CPU: a function's statement is planned once per backend.
 *
 * Postgres only (null on SQLite), and only where what it reads is what
 * those read: no personal config (`dev@me`), whose resolution reads by its
 * owner. Each part is undefined when not read, and the caller reads it as
 * it would; `place` null for no such project, as `resolvePath` answers;
 * `secrets` undefined, too, without an environment, for a fork, whose
 * layers are read together, and for a token that names no credential.
 *
 *   readAhead(db, { tokenHash, path: { project: 'market', environment: 'dev' }, keys: ['API_KEY'] })
 *   → { credential: { credential, identity, now, policySeq }, place: { project, environment: dev, secret: null }, secrets: [API_KEY's row] }
 */
export type ReadAhead = {
  credential?: CredentialRead | null; place?: ResolvedPath | null; secrets?: SecretRow[];
  /**
   * Of a named use's rows (`namedAhead`, T165): where the key the vault used is held, when the place inherits it (a
   * fork's parent, a personal config's dev), by id and slug; null for a key the place holds itself, or none.
   */
  held?: { environmentId: string; slug: string } | null;
};

export type ReadAsked = { tokenHash?: Buffer; path?: { project: string; environment: string }; keys?: readonly string[] | null };

export async function readAhead(db: Queryable, asked: ReadAsked): Promise<ReadAhead | null> {
  if (engineOf(db) !== 'postgres') return null;
  // A personal config is read by its owner: the caller's own statements resolve it.
  const path = asked.path !== undefined && personalOf(asked.path.environment) === null ? asked.path : undefined;
  if (asked.tokenHash === undefined && path === undefined) return null;
  const keys = asked.keys == null ? null : [...new Set(asked.keys)];
  // With the database's clock, as `credentialRow` reads it: Hyperdrive caches no statement that calls it.
  const [row] = await rowsOf<{ read: string; now: string }>(db, sql`SELECT app_read(
    ${asked.tokenHash ?? null}::bytea, ${path?.project ?? null}::text, ${path?.environment ?? null}::text, ${keys === null ? null : sql.param(keys)}::text[]
  ) AS read, ${clock(db)} AS now`);
  return readAheadOf(db, JSON.parse(row!.read) as Answer, row!.now, { tokenHash: asked.tokenHash !== undefined, path: path !== undefined });
}

/**
 * The rows the vault's named use answers (T145, PR B; `Vault.useNamed`, migration 0044's `app`): what `app_read`
 * answers, for the request's credential, place and key, read in the use's own statement, so that the app reads nothing
 * itself. Null for SQLite's vault, which answers none: the app reads its own rows there, as ever. `personal`: the
 * request named `dev@me` (T165), and the place is its caller's personal config of dev, or dev while they have none, as
 * `resolveRead` resolves it.
 */
export function namedAhead(db: Queryable, app: string | null, { personal = false }: { personal?: boolean } = {}): ReadAhead | null {
  if (app === null) return null;
  const read = JSON.parse(app) as Answer & { now: string };
  const ahead = readAheadOf(db, read, read.now, { tokenHash: true, path: true });
  const environment = ahead.place?.environment ?? null;
  // Where the key is held, a key the place inherits: the vault's own rows say, as it resolved the names (0051).
  ahead.held = read.held == null ? null : { environmentId: read.held.id, slug: read.held.slug };
  if (ahead.place != null && environment !== null && personal) {
    ahead.place = {
      ...ahead.place,
      personal: environment.owner === null
        ? { of: { id: environment.id, slug: environment.slug, archivedAt: environment.archivedAt }, fallback: true }
        : { of: { id: environment.parentId!, slug: environment.parentSlug!, archivedAt: null } },
    };
  }
  // The key it used, as `resolvePath` answers a path's key: what a reveal of `market/dev/API_KEY` says of one it finds no
  // value of. Only the place's own: a key a fork inherits is its parent's, which the path's own key is not (T165).
  const [used] = read.secrets ?? [];
  if (ahead.place != null && used !== undefined) {
    const { id, key, archivedAt, currentVersionId, currentVersion, environmentId } = rowOf(tablesOf(db).secrets, used.secret);
    if (environmentId === environment?.id) ahead.place = { ...ahead.place, secret: { id, key, archivedAt, currentVersionId, currentVersion } };
  }
  return ahead;
}

/**
 * The rows a named batch answers (T165, B2's PR 2; `Vault.useNamedMany`): the credential and the place, as its gate's
 * named call read them (`namedAhead`), and every key's rows, as each key's named call read them, in the order asked,
 * none for a key the place does not hold. Null for SQLite's vault, which answers none, or a caller who does not stand
 * at the place, of whom the vault read no key: the app reads its own rows then, as ever.
 */
export function namedManyAhead(db: Queryable, app: string | null, keys: readonly { app: string | null }[] | null, { personal = false }: { personal?: boolean } = {}): ReadAhead | null {
  const ahead = namedAhead(db, app, { personal });
  if (ahead === null || ahead.place == null) return ahead;
  ahead.held = null;
  // No key read: the place's rows only, and the read reads its keys itself.
  delete ahead.secrets;
  if (keys === null) return ahead;
  const secrets: SecretRow[] = [];
  for (const key of keys) {
    if (key.app === null) return ahead;
    const read = JSON.parse(key.app) as Answer & { now: string };
    secrets.push(...(readAheadOf(db, read, read.now, { tokenHash: false, path: true }).secrets ?? []));
  }
  ahead.secrets = secrets;
  return ahead;
}

function readAheadOf(db: Queryable, read: Answer, now: string, asked: { tokenHash: boolean; path: boolean }): ReadAhead {
  const { credentials, identities, passkeys, projects, environments, secrets, secretVersions } = tablesOf(db);
  const ahead: ReadAhead = {};
  if (asked.tokenHash) {
    ahead.credential = read.credential === null ? null : {
      credential: rowOf(credentials, read.credential),
      identity: read.identity === null ? null : rowOf(identities, read.identity),
      now,
      policySeq: read.policy,
      // What stands behind it, as the vault's call read it with it (T216): the credential's check decides on these, as on
      // its own statement's (`passkeyOf`).
      ...(read.passkey_held === undefined ? {} : { passkey: read.passkey == null ? null : rowOf(passkeys, read.passkey), passkeyHeld: read.passkey_held }),
    };
  }
  if (asked.path) {
    if (read.project === null) {
      ahead.place = null;
    } else {
      const project = rowOf(projects, read.project);
      const environment = read.environment === null ? null : rowOf(environments, read.environment);
      ahead.place = { ...resolvedPlace(project, environment, environment?.parentId == null ? null : read.parent), secret: null };
      if (read.secrets !== null) {
        ahead.secrets = read.secrets.map(({ secret, version }) => {
          const s = rowOf(secrets, secret);
          const v = version === null ? null : rowOf(secretVersions, version);
          return secretRowOf({
            id: s.id, key: s.key, folder: s.folder, archivedAt: s.archivedAt,
            versionId: v?.id ?? null, version: v?.version ?? null, createdAt: v?.createdAt ?? null, createdBy: v?.createdBy ?? null,
            envelopeVersion: v?.envelopeVersion ?? null, kekProvider: v?.kekProvider ?? null, kekId: v?.kekId ?? null, kekVersion: v?.kekVersion ?? null,
            wrappedDek: v?.wrappedDek ?? null, iv: v?.iv ?? null, authTag: v?.authTag ?? null, ciphertext: v?.ciphertext ?? null,
            recipe: v?.recipe ?? null, pairId: v?.pairId ?? null, pairHalf: v?.pairHalf ?? null, plaintext: v?.plaintext ?? null, sensitive: v?.sensitive ?? null,
          });
        });
      }
    }
  }
  return ahead;
}

/** `app_read`'s answer: each row as Postgres's `to_json` writes it, by its columns' names. */
type Json = Record<string, unknown>;
type Answer = {
  credential: Json | null;
  identity: Json | null;
  /** The newest policy change's number, as text: exact past 2^53. */
  policy: string | null;
  project: Json | null;
  environment: Json | null;
  /** The environment's parent's slug, for a fork. */
  parent: string | null;
  /** A named use's key the place inherits: where it is held (0051). */
  held?: { id: string; slug: string } | null;
  /**
   * The vault's (0073, T216), for a person's credential: the passkey it names, and whether its person holds a live one
   * at its generation (2), has rows but none live at it (1), or none ever (null), as `heldSql` answers. Absent from
   * `app_read`'s, and from a write's or an add's for a kind the check exempts; null for a named call that checked none.
   */
  passkey?: Json | null;
  passkey_held?: number | null;
  secrets: { secret: Json; version: Json | null }[] | null;
};

/**
 * A row as `to_json` wrote it, as Drizzle would have read it from the
 * table: each column by its name in TypeScript, decoded as the column
 * decodes the driver's value. Bytes come as `\x`-hex, which the driver
 * would have read as bytes; a timestamp as ISO 8601 with its offset,
 * which the column reads as the same instant.
 */
function rowOf<T extends Table>(table: T, json: Json): T['$inferSelect'] {
  const row: Record<string, unknown> = {};
  for (const [name, column] of Object.entries(getTableColumns(table))) {
    const value = json[column.name];
    if (value === undefined) throw new Error(`app_read answered no ${column.name}: the database is older than this app`);
    row[name] = value === null ? null : column.getSQLType() === 'bytea' ? Buffer.from((value as string).slice(2), 'hex') : column.mapFromDriverValue(value);
  }
  return row as T['$inferSelect'];
}

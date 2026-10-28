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
export type ReadAhead = { credential?: CredentialRead | null; place?: ResolvedPath | null; secrets?: SecretRow[] };

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
  const read = JSON.parse(row!.read) as Answer;
  const { credentials, identities, projects, environments, secrets, secretVersions } = tablesOf(db);
  const ahead: ReadAhead = {};
  if (asked.tokenHash !== undefined) {
    ahead.credential = read.credential === null ? null : {
      credential: rowOf(credentials, read.credential),
      identity: read.identity === null ? null : rowOf(identities, read.identity),
      now: row!.now,
      policySeq: read.policy,
    };
  }
  if (path !== undefined) {
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

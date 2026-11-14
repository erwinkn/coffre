import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

/**
 * A workload's session as the app routes its request (docs/design/0.16.md,
 * "What the app reads of a workload, and decides nothing on"): its id, its
 * service, whose gate takes its proofs, and the thumbprint of the key it is
 * bound to, which must have signed the proof. The row as stored, its MAC
 * unchecked: it finds a gate and turns away another key's proof before the
 * vault is asked, and decides nothing the vault does not decide again on
 * its own read.
 */
export type RoutedSession = { id: string; principal: string; jkt: string };

/** The session whose token hashes to `tokenHash`, one row by the token's unique index; null for no workload's session with a key. */
export async function routedSession(db: Queryable, tokenHash: Buffer): Promise<RoutedSession | null> {
  const [row] = await rowsOf<RoutedSession>(db, sql`
    SELECT id, principal, jkt FROM credentials
    WHERE token_hash = ${tokenHash} AND kind = 'workload' AND jkt IS NOT NULL
  `);
  return row ?? null;
}

/** A place a credential was made for, by path as it is named now (`market/dev`), and whether it is its person's own config of it (`@me`); null for one deleted. */
export type RoutedPlace = { path: string; personal: boolean } | null;

/**
 * A handle or a workload's session as the credential proxy routes its
 * request: what `RoutedSession` says, the kind, when it ends, and the
 * places it was made for, by path, in the order its row lists them (null
 * when the row lists none). Unchecked as `routedSession` is: it picks the
 * place to ask the vault about, which decides on its own rows whether the
 * credential reaches it.
 */
export type RoutedCredential = { id: string; kind: 'handle' | 'workload'; principal: string; jkt: string | null; expiresAt: Date; places: RoutedPlace[] | null };

/**
 * The handle or session whose token hashes to `tokenHash`, one row by the
 * token's unique index, its places named by the environments' and
 * projects' primary keys. A `places` that is no JSON array, or an entry
 * that names no environment by a UUID, names none: a row written behind
 * the vault routes nowhere rather than failing the statement.
 */
export async function routedCredential(db: Queryable, tokenHash: Buffer): Promise<RoutedCredential | null> {
  const [row] = await rowsOf<Omit<RoutedCredential, 'expiresAt'> & { expiresAt: Date | string }>(db, sql`
    SELECT c.id, c.kind, c.principal, c.jkt, c.expires_at AS "expiresAt",
      CASE WHEN c.places IS JSON ARRAY THEN (
        SELECT coalesce(json_agg(
          CASE WHEN p.id IS NULL THEN NULL ELSE json_build_object('path', p.slug || '/' || e.slug, 'personal', coalesce(x.place -> 'personal' = 'true'::jsonb, false)) END
          ORDER BY x.n), '[]'::json)
        FROM jsonb_array_elements(c.places::jsonb) WITH ORDINALITY AS x(place, n)
        LEFT JOIN environments e ON e.id = CASE WHEN jsonb_typeof(x.place) = 'object' AND x.place ->> 'environmentId' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (x.place ->> 'environmentId')::uuid END
          AND e.slug NOT LIKE '%~%'
        LEFT JOIN projects p ON p.id = e.project_id AND p.slug NOT LIKE '%~%'
      ) END AS places
    FROM credentials c
    WHERE c.token_hash = ${tokenHash} AND c.kind IN ('handle', 'workload')
  `);
  return row === undefined ? null : { ...row, expiresAt: new Date(row.expiresAt) };
}

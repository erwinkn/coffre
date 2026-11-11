// The world route uses run in (use-route.test.ts, use-route-cost.test.ts; T186 PR C): a sealed world whose handle's
// token is known, members who save UI definitions as the vault's `proxy.save` makes them, and the changes of their
// standing and of a key's nature, each as the vault logs it.
import { randomUUID } from 'node:crypto';

import type { Holdings } from '@coffre/core/access';
import { definitionKeys, type ProxyDefinition, type RouteUseInput } from '@coffre/core/vault';
import { tablesOf } from '@coffre/db';
import { sql } from 'drizzle-orm';

import type { Reader } from '../src/decide.ts';
import { applyOp, indexBytes, type Input, type Op, type ProxyInput, type ProxyItem, type Ref } from '../src/inputs.ts';
import { frozenHoldings } from '../src/proxy.ts';
import { rows, run, type TestDatabase } from './database.ts';
import { namedWorld } from './named-world.ts';
import { change, genesis, onePeriod, ROOT, seal } from './use-world.ts';

/** A change's op as the vault logs it: naming its object, which the log's replay reads it by (`loggedChange`). */
const named = (ref: Ref, op: Op): Op => ({ ...op, ref }) as unknown as Op;

/** The world's caller, a Developer on dev: a handle (its token known), whose keys a route sends. */
export async function routeWorld(db: TestDatabase) {
  const w = await namedWorld(db, { role: 'developer', caller: 'person' });
  /** A member who saves definitions: their row, grants and object, sealed; and what a save of theirs freezes. */
  const member = async (grants: { environmentId: string | null; role: string }[]) => {
    const principal = `user:${randomUUID()}@acme.example`;
    const now = Date.now();
    const t = tablesOf(db.owner);
    await db.owner.insert(t.principals).values({
      principal, status: 'active', role: null, scope: null, generation: 0, createdAt: now, createdBy: ROOT, statusChangedAt: now, statusChangedBy: ROOT, accessSeq: 0n, mac: Buffer.alloc(32),
    });
    for (const grant of grants) {
      await db.owner.insert(t.grants).values({ principal, projectId: grant.environmentId === null ? w.project : null, environmentId: grant.environmentId, environmentSlug: null, role: grant.role, grantedAt: now, grantedBy: ROOT });
    }
    const object: Extract<Input, { kind: 'principal' }> = {
      kind: 'principal', principal, status: 'active', generation: 0, role: 'member', scope: { projects: 'all', environments: 'all' },
      grants: grants.map((grant) => ({ projectId: w.project, environmentId: grant.environmentId, environmentSlug: null, role: grant.role, expiresAt: null })),
    };
    await genesis({ kind: 'principal', id: principal }, object);
    const live: Holdings = { role: 'member', scope: { projects: 'all', environments: 'all' }, grants: grants.map((grant) => ({ projectId: w.project, environmentId: grant.environmentId, role: grant.role })) };
    const frozen = frozenHoldings({ status: 'active', live, all: live } as Reader);
    return { principal, object, frozen };
  };
  type Editor = Awaited<ReturnType<typeof member>>;
  /**
   * An editor's standing changed: their grants made `grants` (each grant revoked or made, `access.revoke`,
   * `access.grant`), then, `removed`, their membership ended (`member.remove`): each a change of their object as the
   * vault makes it, their rows written to match.
   */
  const restand = async (editor: Editor, grants: { environmentId: string | null; role: string }[], removed = false) => {
    const ref: Ref = { kind: 'principal', id: editor.principal };
    const placeOf = (environmentId: string | null) => ({ projectId: w.project, environmentId, environmentSlug: null });
    const ops: Op[] = [
      ...editor.object.grants.map((grant): Op => ({ op: 'access.revoke', place: placeOf(grant.environmentId) })),
      ...grants.map((grant): Op => ({ op: 'access.grant', grant: { ...placeOf(grant.environmentId), role: grant.role, expiresAt: null } })),
      ...(removed ? [{ op: 'member.remove' } as Op] : []),
    ];
    for (const op of ops) {
      const after = applyOp(editor.object, ref, op) as Extract<Input, { kind: 'principal' }>;
      await change(ref, named(ref, op), after, async (tx, value) => {
        await run(tx, sql`DELETE FROM grants WHERE principal = ${editor.principal}`);
        const now = Date.now();
        for (const grant of after.grants) {
          await run(tx, sql`INSERT INTO grants (principal, project_id, environment_id, environment_slug, role, granted_at, granted_by)
            VALUES (${editor.principal}, ${grant.environmentId === null ? w.project : null}, ${grant.environmentId}, NULL, ${grant.role}, ${now}, ${ROOT})`);
        }
        await run(tx, sql`UPDATE principals SET status = ${after.status}, generation = ${after.generation} WHERE principal = ${editor.principal}`);
        await seal('principals', 'principal', editor.principal)(tx, value);
      });
      editor.object = after;
    }
  };
  /** The environment's proxy row as stored, its items by name. */
  const stored = async (environment: string): Promise<{ items: Record<string, ProxyItem>; digests: Buffer; seal: Buffer } | null> => {
    const [row] = await rows<{ items: unknown; digests: Buffer; seal: Buffer }>(db.owner, sql`SELECT items, digests, seal FROM proxy_definitions WHERE environment_id = ${environment}`);
    if (row === undefined) return null;
    return { items: (typeof row.items === 'string' ? JSON.parse(row.items) : row.items) as Record<string, ProxyItem>, digests: Buffer.from(row.digests), seal: Buffer.from(row.seal) };
  };
  /** A save of `items` in `environment` (`dev`), each by its editor, as the vault's `proxy.save` makes it: the row and its entry. */
  const save = async (items: Record<string, { definition: ProxyDefinition; editor: Editor } | null>, environment = w.dev) => {
    const before = (await stored(environment))?.items ?? {};
    const changed: Record<string, ProxyItem | null> = {};
    for (const [name, one] of Object.entries(items)) {
      changed[name] = one === null ? null : { definition: one.definition, keys: definitionKeys(one.definition), savedBy: one.editor.principal, savedAt: Date.now(), holdings: one.editor.frozen };
    }
    const next: Record<string, ProxyItem> = { ...before };
    for (const [name, one] of Object.entries(changed)) {
      if (one === null) delete next[name];
      else next[name] = one;
    }
    const after: ProxyInput = { kind: 'proxy', id: environment, items: next };
    const ref: Ref = { kind: 'proxy', id: environment };
    await change(ref, named(ref, { op: 'proxy.save', items: changed, replace: false, loaded: null }), after, async (tx, value) => {
      const json = JSON.stringify(next);
      const digests = indexBytes(next);
      await run(tx, sql`INSERT INTO proxy_definitions (environment_id, items, digests, seal) VALUES (${environment}, ${json}::jsonb, ${digests}, ${value})
        ON CONFLICT (environment_id) DO UPDATE SET items = excluded.items, digests = excluded.digests, seal = excluded.seal`);
    });
    return next;
  };
  /** A key made sensitive, as an Owner's mark makes it: a new version of its value, sensitive, and a change to its object. */
  const markSensitive = async (id: string) => {
    const made = w.keys.find((key) => key.id === id)!;
    const was = made.object as Extract<Input, { kind: 'secret' }>;
    const version = randomUUID();
    await run(db.owner, sql`INSERT INTO secret_versions (id, secret_id, version, envelope_version, ciphertext, iv, auth_tag, wrapped_dek, kek_provider, kek_id, kek_version, created_by, sensitive)
      SELECT ${version}, secret_id, 2, envelope_version, ciphertext, iv, auth_tag, wrapped_dek, kek_provider, kek_id, kek_version, created_by, true
        FROM secret_versions WHERE id = ${was.version}`);
    const object = { ...was, version, nature: 'sensitive' as const };
    const { projectId, environmentId, key, digest, source, reference } = object;
    const ref: Ref = { kind: 'secret', id };
    await change(ref, named(ref, { op: 'secret.write', projectId, environmentId, version, nature: 'sensitive', key, digest, source, reference }), object, async (tx, value) => {
      await run(tx, sql`UPDATE secrets SET current_version_id = ${version}, current_version = 2 WHERE id = ${id}`);
      await seal('secrets', 'id', id)(tx, value);
    });
    made.object = object;
  };
  /**
   * The time of the world's uses, fixed by the first: all of a test's uses fall in one refresh period of the cap (a minute),
   * as `use-world`'s do (`onePeriod`). A clock read for each would let a cold and a warm use land either side of a minute's
   * turn, where the key's bulk row belongs to an earlier period and the warm use decides again (T236).
   */
  let period: number | null = null;
  /** A route use of `route` at dev's place reading, as the handle asks it. */
  const ask = (route: string, extra: Partial<RouteUseInput> = {}): RouteUseInput => {
    const at = (period ??= onePeriod());
    return {
      caller: { kind: 'handle', tokenHash: w.tokenHash.toString('base64'), accepts: { signin: true, issuers: [], passkeys: 'off' as const } },
      named: { place: { project: w.slug, environment: 'dev' }, route }, stable: null, digests: [], purpose: 'use', at, deadline: at + 3000, ...extra,
    };
  };
  return { ...w, member, restand, save, stored, markSensitive, askRoute: ask };
}

/** A route, `name`, sending `keys` in a header each to `host`. */
export function route(name: string, keys: readonly string[], host = 'api.openai.com'): ProxyDefinition {
  return {
    kind: 'route', name, upstream: `https://${host}/v1`,
    inject: keys.map((key, i) => ({ kind: 'header' as const, name: `x-key-${i}`, template: `Bearer {${key}}` })),
    allow: null, limit: { perMinute: null, perDay: null }, placeholder: null, egress: null,
  };
}


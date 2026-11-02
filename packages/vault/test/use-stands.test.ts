// The named statement's gate, `use_stands` (0045, W268), is the vault's own rule on the rows as read (`namedStanding`,
// decide.ts): a caller it finds standing nowhere is answered on the place alone, before any key is read
// (formal/Probing.tla, StandingFirst). So the two must agree on every caller a release writes: one the gate refuses
// and the rule allows would be refused a key they may use; one the gate lets through and the rule refuses would have
// a key read for them. Generated worlds, each in a transaction rolled back, hold the one to the other; on a value no
// release writes, the gate stands where the rule refuses, never the other way.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';

import type { Permission } from '@coffre/core/access';
import { postgresClient } from '@coffre/db/connect';

import { GATE_ROLES, namedStanding } from '../src/decide.ts';
import { noEdits, type RolesInput } from '../src/inputs.ts';
import { PURPOSES, purposeCode } from '../src/log-replay.ts';
import { configObject, credentialObject, environmentObject, memberStanding, principalObject } from '../src/objects.ts';
import { OWNER_URL, openTestDatabase, postgresOnly, type TestDatabase } from './database.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());

/** mulberry32: a seeded generator, so that a case that fails is made again from its seed. */
function generator(seed: number) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const pick = <T>(items: readonly T[]): T => items[Math.floor(next() * items.length)]!;
  const chance = (p: number) => next() < p;
  const subset = <T>(items: readonly T[]): T[] => items.filter(() => chance(0.5));
  return { pick, chance, subset };
}

const SECRET_PERMISSIONS: Permission[] = ['secret.read', 'secret.use', 'secret.write'];
const GRANT_ROLES = ['viewer', 'contributor', 'developer', 'maintainer', 'owner', 'access-manager', 'auditor', 'custom-a', 'custom-b', 'unmade'] as const;

/** One caller, generated: everything `use_stands` reads, as rows, and the request. */
function caller(seed: number) {
  const { pick, chance, subset } = generator(seed);
  const at = 1_800_000_000_000 + Math.floor(seed * 7919);
  const project = randomUUID();
  const other = randomUUID();
  const place = randomUUID();
  const sibling = randomUUID();
  const slug = pick(['dev', 'prod', 'qa']);
  const person = chance(0.6);
  const principal = `${person ? 'user' : 'token'}:${randomUUID()}`;
  // The place (T165): an environment of its own; a fork of the sibling, weighed as any (R18); or a personal config of
  // the sibling, its owner's while they read or use it, mostly the caller's, weighed with it (`use_stands_personal`).
  const kind = pick(['own', 'own', 'fork', 'personal'] as const);
  const owner = kind !== 'personal' ? null : person && chance(0.85) ? principal : `user:${randomUUID()}`;
  const definition = () => ({ name: 'Edited', description: '', permissions: subset(SECRET_PERMISSIONS), protected: subset(SECRET_PERMISSIONS) });
  const edits = chance(0.5)
    ? JSON.stringify({
      kind: 'roles',
      roles: Object.fromEntries(subset(['viewer', 'contributor', 'developer', 'custom-a', 'custom-b']).map((name) => [name, definition()])),
      instanceRoles: Object.fromEntries(subset(['developer', 'auditor', 'admin', 'owner']).map((name) => [name, definition()])),
    })
    : null;
  const scopes = [
    null,
    JSON.stringify({ projects: 'all', environments: { only: ['dev'] } }),
    JSON.stringify({ projects: 'all', environments: { except: ['prod'] } }),
    JSON.stringify({ projects: { only: [project] }, environments: 'all' }),
    JSON.stringify({ projects: { except: [project] }, environments: 'all' }),
    JSON.stringify({ projects: { only: [other] }, environments: { only: ['dev', 'qa'] } }),
    JSON.stringify({ projects: { only: [] }, environments: { only: [] } }),
    'not a scope',
  ];
  const status = chance(0.92) ? 'active' : 'removed';
  // Every credential is a member's (`credentials`' foreign key), removed or not.
  const member = {
    status,
    // As the table holds it: only an active person is ever an owner of 0.4.
    owner: person && status === 'active' ? pick([true, false]) : false,
    role: pick([null, 'member', 'auditor', 'developer', 'admin', 'owner', 'bogus']),
    scope: pick(scopes),
  };
  const generation = pick([0, 1]);
  const memberGeneration = chance(0.95) ? generation : 1 - generation;
  // Grants: on the place's project or another, on the place or a sibling, each live, lapsed at `at`, or never ending.
  const grants: { project: string | null; environment: string | null; role: string; expires: number | null }[] = [];
  const targets = [{ project, environment: null }, { project: other, environment: null }, { project: null, environment: place }, { project: null, environment: sibling }];
  for (const target of targets.filter(() => chance(0.6))) grants.push({ ...target, role: pick(GRANT_ROLES), expires: pick([null, null, at - 1, at, at + 1, at + 60_000]) });
  // The credential's scope: none (a session's), grants as issued (both columns) or as kept before 0.10 (a built-in's
  // name), or none that parses, which reaches nothing.
  const scopeGrant = (target: { project: string; environment: string | null }) => {
    const role = pick(['viewer', 'contributor', 'developer', 'custom-a']);
    const issued = role === 'custom-a' || chance(0.6);
    return { projectId: target.project, environmentId: target.environment, role, ...(issued ? { permissions: { normal: subset(SECRET_PERMISSIONS), protected: subset(SECRET_PERMISSIONS) } } : {}) };
  };
  const credentialScope = pick([
    null, null, null, null,
    () => JSON.stringify(subset([{ project, environment: null }, { project, environment: place }, { project: other, environment: null }, { project, environment: sibling }]).map(scopeGrant)),
    () => JSON.stringify([scopeGrant({ project, environment: place })]),
    () => 'not json',
    () => '{}',
  ]);
  const expires = at + pick([-1000, 0, 1, 120_000, 120_000, 120_000]);
  return {
    at, project, other, place, sibling, slug, protected: pick([null, false, true]), siblingProtected: pick([null, false, true]), kind, owner, principal, edits, member, generation, memberGeneration, grants,
    credential: {
      id: randomUUID(), revoked: chance(0.06), expires, notAfter: chance(0.2) ? expires + pick([-2000, 5000]) : null,
      scope: typeof credentialScope === 'function' ? credentialScope() : credentialScope, kind: person ? pick(['browser', 'cli', 'personal', 'handle']) : pick(['service', 'workload']),
    },
    purpose: pick(PURPOSES), keepsSensitive: chance(0.2),
  };
}

type Caller = ReturnType<typeof caller>;

/** What the vault's rule says of `c`: `namedStanding` on the objects its rows make, null if they stand. */
function ruled(c: Caller): string | null {
  const credential = credentialObject({
    id: c.credential.id, principal: c.principal, kind: c.credential.kind, scope: c.credential.scope, revoked: c.credential.revoked,
    expiresAt: Math.min(c.credential.expires, c.credential.notAfter ?? Infinity), generation: c.generation,
  });
  const projectOf = (grant: Caller['grants'][number]) => grant.project ?? (grant.environment === c.place || grant.environment === c.sibling ? c.project : null);
  const principal = principalObject(
    { principal: c.principal, status: c.member.status, generation: c.memberGeneration, ...memberStanding({ owner: c.member.owner === true, role: c.member.role, scope: c.member.scope }) },
    c.grants.map((grant) => ({ projectId: projectOf(grant), environmentId: grant.environment, environmentSlug: null, role: grant.role, expiresAt: grant.expires })),
  );
  const environment = environmentObject({
    id: c.place, projectId: c.project, slug: c.slug, owner: c.owner, parentId: c.kind === 'own' ? null : c.sibling, protected: c.protected, archived: false, projectArchived: false,
  });
  const sibling = environmentObject({ id: c.sibling, projectId: c.project, slug: 'sibling', owner: null, parentId: null, protected: c.siblingProtected, archived: false, projectArchived: false });
  const roles = c.edits === null ? noEdits() : configObject(c.edits) as RolesInput;
  return namedStanding(principal, credential, roles, environment, { purpose: c.purpose, at: c.at }, c.kind === 'personal' ? [sibling] : []);
}

const CASES = 3000;

test(`the named statement's gate stands a caller exactly where the vault's rule does, on ${CASES} generated callers, at an environment, a fork or a personal config (W268, T165; Probing.tla, StandingFirst, GateWeighsParent)`, { ...postgresOnly('use_stands is a Postgres function'), timeout: 600_000 }, async () => {
  const client = postgresClient(OWNER_URL, { max: 1 });
  const differing: string[] = [];
  const tally = { stands: 0, personal: 0, refused: new Map<string, number>() };
  try {
    for (let seed = 1; seed <= CASES; seed += 1) {
      const c = caller(seed);
      const expected = ruled(c);
      const stands = await client.begin(async (tx) => {
        const q = (text: string, params: unknown[] = []) => tx.unsafe(text, params as never[]);
        await q(`INSERT INTO projects (id, slug, name) VALUES ($1, $2, 'p'), ($3, $4, 'o')`, [c.project, `p-${c.project}`, c.other, `o-${c.other}`]);
        await q(`INSERT INTO environments (id, project_id, slug, name, protected) VALUES ($1, $2, 'sibling', 's', $3)`, [c.sibling, c.project, c.siblingProtected]);
        await q(`INSERT INTO environments (id, project_id, slug, name, protected, parent_id, owner) VALUES ($1, $2, $3, 'e', $4, $5, $6)`,
          [c.place, c.project, c.slug, c.protected, c.kind === 'own' ? null : c.sibling, c.owner]);
        {
          await q(`INSERT INTO vault_members (principal, status, owner, generation, created_at, created_by, status_changed_at, status_changed_by, access_seq, mac, role, scope)
                   VALUES ($1, $2, $3, $4, 0, 'test', 0, 'test', 0, $7, $5, $6)`, [c.principal, c.member.status, c.member.owner, c.memberGeneration, c.member.role, c.member.scope, Buffer.alloc(32)]);
        }
        for (const grant of c.grants) {
          await q(`INSERT INTO vault_grants (principal, project_id, environment_id, role, expires_at, granted_at, granted_by) VALUES ($1, $2, $3, $4, $5, 0, 'test')`,
            [c.principal, grant.project, grant.environment, grant.role, grant.expires === null ? null : String(grant.expires)]);
        }
        await q(`DELETE FROM log_config WHERE name = 'roles'`);
        if (c.edits !== null) await q(`INSERT INTO log_config (name, value) VALUES ('roles', $1)`, [c.edits]);
        await q(`INSERT INTO credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, created_by, expires_at, not_after, revoked_at, scope, jkt)
                 VALUES ($1, $2, $10, $3, 'h', $4, $5, 'test', $6, $7, $8, $9, CASE WHEN $2 = 'workload' THEN 'jkt' END)`, [
          c.credential.id, c.credential.kind, createHash('sha256').update(c.credential.id).digest(), c.generation, c.principal, new Date(c.credential.expires),
          c.credential.notAfter === null ? null : new Date(c.credential.notAfter), c.credential.revoked ? new Date(c.at - 5000) : null, c.credential.scope, Buffer.alloc(32),
        ]);
        const [row] = await (c.kind === 'personal'
          ? q('SELECT use_stands_personal($1::uuid, $2::uuid, $3::bigint, $4::jsonb) AS stands', [c.credential.id, c.place, String(c.at), GATE_ROLES])
          : q('SELECT use_stands($1::uuid, $2::uuid, $3::smallint, $4::bigint, $5::jsonb) AS stands', [c.credential.id, c.place, purposeCode(c), String(c.at), GATE_ROLES])) as unknown as { stands: boolean }[];
        throw new RolledBack(row!.stands);
      }).then(() => null as never, (error: unknown) => {
        if (error instanceof RolledBack) return error.stands;
        throw error;
      });
      // On what a release writes, alike; on a value no release writes (a scope that does not parse), the gate may stand
      // a caller the rule refuses, never refuse one it stands.
      const malformed = c.member.scope === 'not a scope' || c.credential.scope === 'not json' || c.credential.scope === '{}';
      if (malformed ? !stands && expected === null : stands !== (expected === null)) {
        differing.push(`seed ${seed}: the gate ${stands ? 'stands' : 'refuses'}, the rule ${expected ?? 'stands'}: ${JSON.stringify(c)}`);
      }
      if (expected === null) tally.stands += 1;
      else tally.refused.set(expected, (tally.refused.get(expected) ?? 0) + 1);
      if (expected === null && c.kind === 'personal') tally.personal += 1;
    }
  } finally {
    await client.end();
  }
  console.log(`of ${CASES} callers, ${tally.stands} stand (${tally.personal} at a personal config); refused: ${JSON.stringify(Object.fromEntries(tally.refused))}`);
  assert.deepEqual(differing.slice(0, 5), []);
  // The generated callers stand, and are refused for each reason the gate must weigh, often enough to mean something.
  assert.ok(tally.stands >= CASES / 12, `${tally.stands} of ${CASES} stand`);
  assert.ok(tally.personal >= CASES / 100, `${tally.personal} of ${CASES} stand at a personal config`);
  for (const code of ['credential', 'no_grant', 'expired', 'removed', 'personal']) assert.ok((tally.refused.get(code) ?? 0) >= CASES / 100, `${code}: ${tally.refused.get(code) ?? 0}`);
});

class RolledBack extends Error {
  readonly stands: boolean;

  constructor(stands: boolean) {
    super('rolled back');
    this.stands = stands;
  }
}

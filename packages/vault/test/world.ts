import { createHash, randomUUID } from 'node:crypto';

import { ownerKey, seal } from '@coffre/core/envelope';
import { bindings, credentials, dismissedKeys, environments, grants, identities, policy, principals, projects, roles, secrets, secretVersions } from '@coffre/db/schema';
import { sql, type SQL } from 'drizzle-orm';

import { change, put, part, type Write } from '../src/change.ts';
import type { Fresh } from '../src/rows.ts';
import type { Ask } from '../src/use.ts';
import type { TestVault } from './database.ts';

/**
 * A small instance for the use's tests, written as the vault writes: every
 * sealed row by a change, every value sealed under the test vault's key.
 * Each helper returns a write, and `World.write` makes them one change.
 */
const at = new Date(Date.UTC(2026, 10, 13, 9));
const root = 'user:root@acme.example';

export const user = (name: string) => `user:${name}@acme.example`;
export const tokenOf = (label: string) => createHash('sha256').update(label).digest();

export function project(slug: string, more: Partial<Fresh<typeof projects>> = {}): Fresh<typeof projects> {
  return { id: randomUUID(), slug, name: slug, createdAt: at, archivedAt: null, folder: null, ...more };
}

export function environment(of: { id: string }, slug: string, more: Partial<Fresh<typeof environments>> = {}): Fresh<typeof environments> {
  return { id: randomUUID(), projectId: of.id, slug, name: slug, createdAt: at, archivedAt: null, parentId: null, owner: null, protected: false, frozenCredentials: [], ...more };
}

export function secret(of: { id: string; projectId: string }, key: string, more: Partial<Fresh<typeof secrets>> = {}): Fresh<typeof secrets> {
  return { id: randomUUID(), projectId: of.projectId, environmentId: of.id, key, createdAt: at, updatedAt: at, versions: 0, currentVersion: null, archivedAt: null, folder: null, sourceId: null, ...more };
}

export function principal(id: string, more: Partial<Fresh<typeof principals>> = {}): Fresh<typeof principals> {
  return { id, status: 'active', role: 'member', scope: null, generation: 0, createdAt: at, createdBy: root, statusChangedAt: at, statusChangedBy: root, frozenAt: null, ...more };
}

export function grant(to: string, role: string, on: { project?: { id: string }; environment?: { id: string } }, more: Partial<Fresh<typeof grants>> = {}): Fresh<typeof grants> {
  return { id: randomUUID(), principal: to, projectId: on.project?.id ?? null, environmentId: on.environment?.id ?? null, role, expiresAt: null, grantedAt: at, grantedBy: root, ...more };
}

export function role(instance: boolean, id: string, permissions: string[], guarded: string[] = permissions): Fresh<typeof roles> {
  return { instance, id, name: id, description: '', permissions, protected: guarded };
}

/** A credential whose token is `tokenOf(label)`: a CLI session unless told. */
export function credential(label: string, of: string, more: Partial<Fresh<typeof credentials>> = {}): Fresh<typeof credentials> {
  return {
    id: randomUUID(), kind: of.startsWith('token:') ? 'service' : 'cli', tokenHash: tokenOf(label), tokenHint: null, previousTokenHash: null, generation: 0, principal: of, identityId: null,
    scope: null, places: null, label, createdAt: at, createdBy: of, expiresAt: new Date(Date.UTC(2027, 0, 1)), lastUsedAt: null, lastUsedIp: null, frozenAt: null, revokedAt: null, revokedBy: null,
    jkt: null, notAfter: null, ancestors: null, constraints: null, enrollmentId: null, approvedAt: null, approvedBy: null, run: null, client: null, challenge: null, ...more,
  };
}

/** A trust binding of a service: one `/api/auth/oidc` takes, unless given a policy, which makes it a workload's. */
export function binding(of: string, more: Partial<Fresh<typeof bindings>> = {}): Fresh<typeof bindings> {
  return {
    id: randomUUID(), principal: of, generation: 0, profile: 'github', issuer: 'https://token.actions.githubusercontent.com', jwksUri: 'https://token.actions.githubusercontent.com/.well-known/jwks', jwks: null,
    claims: '{}', scope: null, policy: null, label: null, createdAt: at, createdBy: root, lastUsedAt: null, frozenAt: null, revokedAt: null, revokedBy: null, ...more,
  };
}

/** A workload's session a binding issued. Its key's thumbprint is its label, so `ask(label, …, { proof: label })` is the session used with its key. */
export function session(label: string, by: Fresh<typeof bindings>, more: Partial<Fresh<typeof credentials>> = {}): Fresh<typeof credentials> {
  return credential(label, by.principal, { kind: 'workload', createdBy: `binding:${by.id}`, jkt: label, notAfter: new Date(Date.UTC(2027, 0, 1)), ...more });
}

/** The instance's one policy row. */
export function instance(more: Partial<Fresh<typeof policy>> = {}): Fresh<typeof policy> {
  return { onlyRow: true, serviceAccounts: '{"projects":"all","environments":"all"}', workloadsFrozenAt: null, changedAt: at, changedBy: root, ...more };
}

export function identity(of: string, more: Partial<Fresh<typeof identities>> = {}): Fresh<typeof identities> {
  return { id: randomUUID(), provider: 'github', subject: randomUUID(), issuerHash: 'x', generation: 0, principal: of, email: null, createdAt: at, createdBy: of, lastSignInAt: null, revokedAt: null, revokedBy: null, ...more };
}

export function dismissed(of: { id: string }, key: string): Fresh<typeof dismissedKeys> {
  return { environmentId: of.id, key, dismissedAt: at, dismissedBy: root, restoredAt: null, restoredBy: null };
}

export const TABLES = { projects, environments, secrets, principals, grants, roles, credentials, identities, dismissedKeys, bindings, policy };

/** Rows of one table, as writes of a change. */
export const rows = <K extends keyof typeof TABLES>(table: K, ...of: Fresh<(typeof TABLES)[K]>[]): Write[] => of.map((row) => put(TABLES[table], row as never));

/** Versions sealed and not yet stored: a version's row points at its secret's, which the next `write` makes. */
const sealed: (typeof secretVersions.$inferInsert)[] = [];

/** One change that writes them all, then the versions sealed for them. */
export async function write(vault: TestVault, ...writes: Write[]): Promise<void> {
  const result = await change(vault, { read: { none: part(principals, sql`false`) }, decide: () => ({ writes, entry: { kept: true, action: 'test.write', actor: null, credential: null, request: null, ip: null, objects: [], detail: {} }, answer: null }) });
  if ('refused' in result) throw new Error(result.refused);
  if (sealed.length > 0) await vault.owner.insert(secretVersions).values(sealed.splice(0));
}

/** One change that puts `more` on the rows of a table a condition finds: a revocation, a freeze, an approval. */
export async function amend<K extends keyof typeof TABLES>(vault: TestVault, table: K, where: SQL, more: Partial<Fresh<(typeof TABLES)[K]>>): Promise<void> {
  const result = await change(vault, {
    read: { found: part(TABLES[table], where) },
    decide: ({ found }) => ({ writes: found.map((row) => put(TABLES[table], { ...row, ...more } as never, row as never)), entry: { kept: true, action: 'test.write', actor: null, credential: null, request: null, ip: null, objects: [], detail: {} }, answer: null }),
  });
  if ('refused' in result) throw new Error(result.refused);
}

/**
 * A secret with its next version, as the vault will write one: the value
 * sealed under its secret, number and sensitivity, and the secret's row
 * moved on to it. The version is stored by the next `write`.
 */
export async function value(vault: TestVault, of: Fresh<typeof secrets>, text: string, more: { sensitive?: boolean; plain?: boolean; owner?: string } = {}): Promise<Fresh<typeof secrets>> {
  const version = of.versions + 1;
  const sensitive = more.sensitive === true;
  const nature = sensitive ? { sensitive: true as const } : more.plain === true ? { plain: true as const } : {};
  const envelope = await seal(Buffer.from(text), { projectId: of.projectId, environmentId: of.environmentId, secretId: of.id, version, ...nature, ...(more.owner === undefined ? {} : { owner: ownerKey(more.owner) }) }, vault.keks);
  sealed.push({ id: randomUUID(), secretId: of.id, version, ...envelope, createdAt: at, createdBy: root, recipe: null, pairId: null, pairHalf: null, plaintext: more.plain === true ? text : null, sensitive });
  return { ...of, versions: version, currentVersion: version };
}

export const ask = (label: string, place: string, keys: readonly string[] | null, more: Partial<Ask> = {}): Ask => {
  const [projectSlug, environmentSlug] = place.split('/') as [string, string];
  return { token: tokenOf(label), project: projectSlug, environment: environmentSlug, mine: false, keys, purpose: 'reveal', upstream: null, proof: null, request: 'req-1', ip: '192.0.2.7', ...more };
};

import { tablesOf, type Queryable } from '@coffre/db';
import { and, desc, eq, gt, inArray, isNull, sql } from 'drizzle-orm';

import type { Answer, IssueCall, RevokeCall, SignInCall } from './credentials.ts';
import { objectKey } from './inputs.ts';

/**
 * `sign_in` on SQLite, step for step, in one transaction: SQLite runs one
 * writer at a time, so its locks are implicit, and an entry's number is
 * one past the log's highest.
 */
export async function signInOnSqlite(tx: Queryable, c: SignInCall): Promise<Answer> {
  const { auditLog, consumedTokens, credentials, logChanges, serviceBindings, vaultMembers } = tablesOf(tx);
  const target = objectKey({ kind: 'credential', id: c.credential.id });
  const k = c.credential;
  const [member] = await tx.select({ status: vaultMembers.status, generation: vaultMembers.generation, seal: vaultMembers.seal }).from(vaultMembers).where(eq(vaultMembers.principal, c.principal));
  if (member?.status !== 'active' || member.generation !== c.binding.generation) return { state: 'unbound' };
  // Its row as its newest change sealed it, or 0.14's with neither: a row put back is none.
  const [sealedAs] = await tx.select({ seal: logChanges.seal }).from(logChanges).where(eq(logChanges.object, objectKey({ kind: 'principal', id: c.principal }))).orderBy(desc(logChanges.number)).limit(1);
  if (!same(member.seal ?? null, sealedAs?.seal ?? null)) return { state: 'unbound' };
  const [binding] = await tx.select().from(serviceBindings).where(eq(serviceBindings.id, c.binding.id));
  if (binding === undefined || binding.principal !== c.principal || binding.generation !== c.binding.generation || binding.revokedAt !== null || binding.profile !== c.binding.profile
    || binding.scope !== c.binding.scope || binding.policy !== c.binding.policy) {
    return { state: 'unbound' };
  }
  const [moved] = await tx.select({ seq: auditLog.seq }).from(auditLog)
    .where(and(eq(auditLog.author, 'app'), eq(auditLog.subjectPrincipal, c.appKey), inArray(auditLog.action, ['key.reseal', 'key.rotate']))).limit(1);
  if (moved !== undefined) return { state: 'retired' };
  const named = (key: string) => sql`json_extract(${auditLog.metadata}, ${`$.${key}`})`;
  const [tomb] = await tx.select({ seq: auditLog.seq }).from(auditLog)
    .where(and(eq(auditLog.author, 'app'), eq(auditLog.action, 'token.unbind'), eq(auditLog.decision, 'allow'), eq(named('bindingId'), c.binding.id))).limit(1);
  if (tomb !== undefined) return { state: 'unbound' };
  if (c.frozen) {
    for (const target of ['instance', c.principal, `binding:${c.binding.id}`]) {
      const [newest] = await tx.select({ action: auditLog.action }).from(auditLog)
        .where(and(eq(auditLog.author, 'app'), inArray(auditLog.action, ['workload.freeze', 'workload.unfreeze']), eq(auditLog.decision, 'allow'), eq(named('target'), target)))
        .orderBy(desc(auditLog.seq)).limit(1);
      if (newest?.action === 'workload.freeze') return { state: 'frozen' };
    }
  }
  const now = Date.now();
  const recent = await tx.select({ id: credentials.id }).from(credentials)
    .where(and(eq(credentials.principal, c.principal), eq(credentials.createdBy, k.createdBy), gt(credentials.createdAt, new Date(now - c.window))))
    .limit(c.rate);
  if (recent.length >= c.rate) return { state: 'busy' };
  if ((c.validUntil !== null && c.validUntil <= now) || k.expiresAt <= now || k.expiresAt > now + c.longest + 60_000 || (k.notAfter !== null && (k.notAfter <= now || k.expiresAt > k.notAfter))) return { state: 'expired' };
  if (c.spent !== null) {
    const spent = await tx.insert(consumedTokens).values({ hash: c.spent }).onConflictDoNothing().returning({ hash: consumedTokens.hash });
    if (spent.length === 0) return { state: 'replayed' };
  }
  await tx.insert(credentials).values({
    id: k.id, kind: k.kind, authMac: k.authMacBytes, tokenHash: k.tokenHashBytes, tokenHint: k.tokenHint, generation: c.binding.generation,
    principal: c.principal, identityId: null, scope: k.scope, places: k.places, label: k.label, createdBy: k.createdBy,
    expiresAt: new Date(k.expiresAt), revokedAt: null, jkt: k.jkt, notAfter: k.notAfter === null ? null : new Date(k.notAfter), seal: c.seal,
  });
  await tx.update(serviceBindings).set({ lastUsedAt: new Date(now) }).where(eq(serviceBindings.id, c.binding.id));
  const number = await nextNumber(tx);
  await tx.insert(logChanges).values({ number, at: c.at, requestId: c.requestId, object: target, actor: c.actor, payload: c.payload, seal: c.seal, mac: c.mac });
  return { number: number.toString() };
}

/** `revoke_credential` on SQLite, step for step, in one transaction. */
export async function revokeOnSqlite(tx: Queryable, c: RevokeCall): Promise<Answer> {
  const { auditLog, credentials, environments, logChanges, projects } = tablesOf(tx);
  const { change, policy } = c;
  const [row] = await tx.select({ seal: credentials.seal, authMac: credentials.authMac, revokedAt: credentials.revokedAt }).from(credentials).where(eq(credentials.id, c.ref.id));
  if (row === undefined || row.revokedAt !== null || !same(row.authMac, c.macFrom) || !same(row.seal ?? null, change.sealFrom)) return { state: 'moved' };
  const [newest] = await tx.select({ seal: logChanges.seal }).from(logChanges).where(eq(logChanges.object, change.object)).orderBy(desc(logChanges.number)).limit(1);
  if (!same(newest?.seal ?? null, change.sealFrom)) return { state: 'stale' };
  if (policy !== null) {
    const [changed] = await tx.select({ seq: auditLog.seq }).from(auditLog)
      .where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, 'policy.change'), eq(auditLog.decision, 'allow'))).orderBy(desc(auditLog.seq)).limit(1);
    if ((changed === undefined ? null : String(changed.seq)) !== policy.seq) return { state: 'policy' };
    for (const { environmentId, slug } of policy.protected) {
      const [place] = await tx.select({ slug: environments.slug, project: projects.slug }).from(environments)
        .innerJoin(projects, eq(projects.id, environments.projectId)).where(eq(environments.id, environmentId));
      const standing = place === undefined || place.slug.includes('~') || place.project.includes('~') ? null : place.slug;
      if (standing !== slug) return { state: 'policy' };
    }
  }
  await tx.update(credentials).set({ revokedAt: new Date(c.revokedAt), revokedBy: c.revokedBy, authMac: c.mac, seal: change.seal })
    .where(and(eq(credentials.id, c.ref.id), isNull(credentials.revokedAt)));
  const number = await nextNumber(tx);
  await tx.insert(logChanges).values({ number, at: change.at, requestId: change.requestId, object: change.object, actor: change.actor, payload: change.payload, seal: change.seal, mac: change.mac });
  return { number: number.toString() };
}

/** `issue_token` on SQLite, step for step, in one transaction: its one writer holds every row as read. */
export async function issueOnSqlite(tx: Queryable, c: IssueCall): Promise<Answer> {
  const { auditLog, credentials, environments, logChanges, projects, vaultMembers } = tablesOf(tx);
  const { change, input, read } = c;
  const k = input.credential;
  const standing = async (principal: string, generation: number, accessSeq: bigint) => {
    const [row] = await tx.select({ status: vaultMembers.status, generation: vaultMembers.generation, accessSeq: vaultMembers.accessSeq }).from(vaultMembers).where(eq(vaultMembers.principal, principal));
    return row?.status === 'active' && row.generation === generation && BigInt(row.accessSeq) === accessSeq;
  };
  if (!(await standing(input.actor, read.actor.generation, read.actor.accessSeq)) || !(await standing(input.principal, input.generation, read.principal.accessSeq))) return { state: 'moved' };
  const now = Date.now();
  if (input.via !== null) {
    const [via] = await tx.select({ principal: credentials.principal, revokedAt: credentials.revokedAt, seal: credentials.seal, expiresAt: credentials.expiresAt, notAfter: credentials.notAfter })
      .from(credentials).where(eq(credentials.id, input.via));
    const [newest] = await tx.select({ seal: logChanges.seal }).from(logChanges).where(eq(logChanges.object, objectKey({ kind: 'credential', id: input.via }))).orderBy(desc(logChanges.number)).limit(1);
    // Its end as the vault authenticated it, still the columns' and still ahead (as `issue_token`).
    const sealedAs = read.via?.seal ?? null;
    const end = read.via?.columns.expiresAt ?? null;
    const ends = via === undefined ? null : Math.min(via.expiresAt.getTime(), via.notAfter?.getTime() ?? Infinity);
    if (via === undefined || via.principal !== input.actor || via.revokedAt !== null || sealedAs === null || end === null || ends !== end || end <= now
      || !same(via.seal ?? null, sealedAs) || !same(newest?.seal ?? null, sealedAs)) {
      return { state: 'ended' };
    }
  }
  const [changed] = await tx.select({ seq: auditLog.seq }).from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, 'policy.change'), eq(auditLog.decision, 'allow'))).orderBy(desc(auditLog.seq)).limit(1);
  if ((changed === undefined ? null : String(changed.seq)) !== input.policy.seq) return { state: 'policy' };
  for (const { environmentId, slug } of read.slugs) {
    const [place] = await tx.select({ slug: environments.slug, project: projects.slug }).from(environments).innerJoin(projects, eq(projects.id, environments.projectId)).where(eq(environments.id, environmentId));
    if ((place === undefined || place.slug.includes('~') || place.project.includes('~') ? null : place.slug) !== slug) return { state: 'policy' };
  }
  const [moved] = await tx.select({ seq: auditLog.seq }).from(auditLog)
    .where(and(eq(auditLog.author, 'app'), eq(auditLog.subjectPrincipal, input.appKey), inArray(auditLog.action, ['key.reseal', 'key.rotate']))).limit(1);
  if (moved !== undefined) return { state: 'retired' };
  if (k.expiresAt <= now) return { state: 'expired' };
  await tx.insert(credentials).values({
    id: k.id, kind: k.kind, authMac: c.authMac, tokenHash: c.tokenHash, tokenHint: k.tokenHint, generation: input.generation, principal: input.principal,
    identityId: null, scope: k.scope, places: k.places, label: k.label, createdBy: k.createdBy, expiresAt: new Date(k.expiresAt), revokedAt: null, seal: change.seal,
  });
  const number = await nextNumber(tx);
  await tx.insert(logChanges).values({ number, at: change.at, requestId: change.requestId, object: change.object, actor: change.actor, payload: change.payload, seal: change.seal, mac: change.mac });
  return { number: number.toString() };
}

/** One past the log's highest number, both tables' (store.ts's `changeOnSqlite` says why). */
async function nextNumber(tx: Queryable): Promise<bigint> {
  const { logChanges, logUses } = tablesOf(tx);
  const [{ last }] = await tx.select({ last: sql<number | string | null>`max(n)` }).from(
    sql`(SELECT max(${logChanges.number}) AS n FROM ${logChanges} UNION ALL SELECT max(${logUses.number}) FROM ${logUses})`,
  );
  return BigInt(last ?? 0) + 1n;
}

function same(a: Uint8Array | null, b: Uint8Array | null): boolean {
  return a === null || b === null ? a === b : Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
}

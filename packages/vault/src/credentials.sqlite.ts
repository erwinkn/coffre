import { tablesOf, type Queryable } from '@coffre/db';
import { and, desc, eq, gt, inArray, isNull, sql } from 'drizzle-orm';

import type { Answer, RevokeCall, SignInCall } from './credentials.ts';
import { objectKey } from './inputs.ts';

/**
 * `sign_in` on SQLite, step for step, in one transaction: SQLite runs one
 * writer at a time, so its locks are implicit, and an entry's number is
 * one past the log's highest.
 */
export async function signInOnSqlite(tx: Queryable, c: SignInCall): Promise<Answer> {
  const { auditLog, consumedTokens, credentials, logChanges, serviceBindings, vaultMembers } = tablesOf(tx);
  const target = objectKey({ kind: 'credential', id: c.credential.id });
  const prior = await priorChange(tx, c.requestId, target, c.payload, c.seal);
  if (prior !== undefined) return { number: prior };
  const k = c.credential;
  const [member] = await tx.select({ status: vaultMembers.status, generation: vaultMembers.generation }).from(vaultMembers).where(eq(vaultMembers.principal, c.principal));
  if (member?.status !== 'active' || member.generation !== c.binding.generation) return { state: 'unbound' };
  const [binding] = await tx.select().from(serviceBindings).where(eq(serviceBindings.id, c.binding.id));
  if (binding === undefined || binding.principal !== c.principal || binding.generation !== c.binding.generation || binding.revokedAt !== null
    || binding.scope !== c.binding.scope || binding.policy !== c.binding.policy) {
    return { state: 'unbound' };
  }
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
  const { credentials, logChanges } = tablesOf(tx);
  const target = objectKey(c.ref);
  if (c.change !== null) {
    const prior = await priorChange(tx, c.change.requestId, target, c.change.payload, c.change.seal);
    if (prior !== undefined) return { number: prior };
  }
  const [row] = await tx.select({ seal: credentials.seal, authMac: credentials.authMac, revokedAt: credentials.revokedAt }).from(credentials).where(eq(credentials.id, c.ref.id));
  if (row === undefined || row.revokedAt !== null || !same(row.authMac, c.macFrom) || !same(row.seal ?? null, c.change?.sealFrom ?? null)) return { state: 'moved' };
  const [newest] = await tx.select({ seal: logChanges.seal }).from(logChanges).where(eq(logChanges.object, target)).orderBy(desc(logChanges.number)).limit(1);
  if (!same(newest?.seal ?? null, c.change?.sealFrom ?? null)) return { state: 'stale' };
  await tx.update(credentials).set({ revokedAt: new Date(c.revokedAt), revokedBy: c.revokedBy, authMac: c.mac, seal: c.change?.seal ?? null })
    .where(and(eq(credentials.id, c.ref.id), isNull(credentials.revokedAt)));
  if (c.change === null) return { number: null };
  const number = await nextNumber(tx);
  await tx.insert(logChanges).values({ number, at: c.at, requestId: c.change.requestId, object: target, actor: c.actor, payload: c.change.payload, seal: c.change.seal, mac: c.change.mac });
  return { number: number.toString() };
}

/** A change this request committed already, by its request id: its number, if it is this one; another under it is refused. */
async function priorChange(tx: Queryable, requestId: string, target: string, payload: string, seal: Buffer): Promise<string | undefined> {
  const { logChanges } = tablesOf(tx);
  const [prior] = await tx.select({ number: logChanges.number, object: logChanges.object, payload: logChanges.payload, seal: logChanges.seal }).from(logChanges).where(eq(logChanges.requestId, requestId));
  if (prior === undefined) return undefined;
  if (prior.object !== target || prior.payload !== payload || !same(prior.seal ?? null, seal)) {
    throw Object.assign(new Error(`request ${requestId} names another change`), { code: 'SQLITE_CONSTRAINT_UNIQUE' });
  }
  return String(prior.number);
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

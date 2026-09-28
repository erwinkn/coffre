import { randomUUID } from 'node:crypto';

import { and, asc, desc, eq, inArray, isNull, max } from 'drizzle-orm';

import type { Permission } from '../../../../../packages/core/src/access.ts';
import { open, seal, type Envelope } from '../../../../../packages/core/src/envelope.ts';
import type { Queryable, Transaction } from '../../../../../packages/db/src/database.ts';
import { forUpdate, insertSecretIfAbsent } from '../../../../../packages/db/src/dialect.ts';
import { secrets, secretVersions } from '../../../../../packages/db/src/schema.ts';
import { permissionsAt } from './caller.ts';
import { allowed, audited, denied, need, Refusal, type ApiContext } from './context.ts';
import { conflict, notFound } from './errors.ts';
import { formatPath, resolvePath, type Path, type ResolvedPath } from './paths.ts';

export type SecretKey = {
  key: string;
  archived: boolean;
  version: number | null;
  updatedAt: string | null;
  updatedBy: string | null;
};

export type SecretVersion = {
  version: number;
  createdAt: string;
  createdBy: string;
  current: boolean;
  kek: string;
};

/** What `PATCH /secrets/:project/:environment` did to each key it named. */
export type SetOutcome = { version: number } | { archived: true };

type Environment = { projectId: string; environmentId: string };

/**
 * The environment a secrets call works in. An archived project or
 * environment serves nothing, exactly as if it did not exist.
 */
function liveEnvironment(place: ResolvedPath): Environment | null {
  if (place.project.archived || place.environment === null || place.environment.archived) {
    return null;
  }
  return { projectId: place.project.id, environmentId: place.environment.id };
}

function requireLive(place: ResolvedPath): Environment {
  const environment = liveEnvironment(place);
  if (environment === null) throw notFound('unknown project or environment');
  return environment;
}

/** Tell the environment's syncs to push, once the change has committed. */
function changed(ctx: ApiContext, environmentId: string): void {
  try {
    ctx.onChange(environmentId);
  } catch (error) {
    // The write has committed; a sync that cannot start now is picked up by the scheduler.
    console.error('sync notification failed', error);
  }
}

const envelopeColumns = {
  envelopeVersion: secretVersions.envelopeVersion,
  kekProvider: secretVersions.kekProvider,
  kekId: secretVersions.kekId,
  kekVersion: secretVersions.kekVersion,
  wrappedDek: secretVersions.wrappedDek,
  iv: secretVersions.iv,
  authTag: secretVersions.authTag,
  ciphertext: secretVersions.ciphertext,
};

function envelopeOf(row: Envelope): Envelope {
  return {
    envelopeVersion: row.envelopeVersion,
    kekProvider: row.kekProvider,
    kekId: row.kekId,
    kekVersion: row.kekVersion,
    wrappedDek: row.wrappedDek,
    iv: row.iv,
    authTag: row.authTag,
    ciphertext: row.ciphertext,
  };
}

/**
 * The current ciphertext of every live secret in an environment, or of one
 * secret. What reveals and syncs decrypt.
 */
export async function currentEnvelopes(
  db: Queryable,
  environmentId: string,
  secretId?: string,
): Promise<{ secretId: string; secretVersionId: string; key: string; version: number; envelope: Envelope }[]> {
  const rows = await db
    .select({
      secretId: secrets.id,
      secretVersionId: secretVersions.id,
      key: secrets.key,
      version: secretVersions.version,
      ...envelopeColumns,
    })
    .from(secrets)
    .innerJoin(secretVersions, eq(secretVersions.id, secrets.currentVersionId))
    .where(
      and(
        eq(secrets.environmentId, environmentId),
        isNull(secrets.archivedAt),
        secretId === undefined ? undefined : eq(secrets.id, secretId),
      ),
    )
    .orderBy(asc(secrets.key));
  return rows.map((row) => ({
    secretId: row.secretId,
    secretVersionId: row.secretVersionId,
    key: row.key,
    version: row.version,
    envelope: envelopeOf(row),
  }));
}

/** Secret names and who last changed them, never values. */
export async function listSecrets(
  ctx: ApiContext,
  place: ResolvedPath,
): Promise<{ permissions: Permission[]; keys: SecretKey[] }> {
  const environment = requireLive(place);
  const rows = await ctx.db
    .select({
      key: secrets.key,
      archivedAt: secrets.archivedAt,
      version: secretVersions.version,
      createdAt: secretVersions.createdAt,
      createdBy: secretVersions.createdBy,
    })
    .from(secrets)
    .leftJoin(secretVersions, eq(secretVersions.id, secrets.currentVersionId))
    .where(eq(secrets.environmentId, environment.environmentId))
    .orderBy(asc(secrets.key));

  return {
    permissions: permissionsAt(ctx.caller, environment),
    keys: rows.map((row) => ({
      key: row.key,
      archived: row.archivedAt !== null,
      version: row.version,
      updatedAt: row.createdAt?.toISOString() ?? null,
      updatedBy: row.createdBy,
    })),
  };
}

/** The next version number of each secret: one more than the highest so far. */
async function nextVersions(tx: Transaction, secretIds: string[]): Promise<Map<string, number>> {
  const next = new Map(secretIds.map((id) => [id, 1]));
  if (secretIds.length === 0) return next;
  const rows = await tx
    .select({ secretId: secretVersions.secretId, latest: max(secretVersions.version) })
    .from(secretVersions)
    .where(inArray(secretVersions.secretId, secretIds))
    .groupBy(secretVersions.secretId);
  for (const row of rows) next.set(row.secretId, (row.latest ?? 0) + 1);
  return next;
}

/** Append a version and make it current. Versions are never rewritten. */
async function appendVersion(
  tx: Transaction,
  secretId: string,
  version: number,
  envelope: Envelope,
  createdBy: string,
): Promise<string> {
  const id = randomUUID();
  await tx.insert(secretVersions).values({ id, secretId, version, ...envelope, createdBy });
  await tx
    .update(secrets)
    .set({ currentVersionId: id, updatedAt: new Date() })
    .where(eq(secrets.id, secretId));
  return id;
}

/**
 * The only way to write. A string sets a key, adding it if it is new; `null`
 * archives it. One transaction, one version and one audit entry per key, so
 * fifty keys from an `.env` file land together or not at all.
 */
export async function setSecrets(
  ctx: ApiContext,
  place: ResolvedPath,
  patch: Record<string, string | null>,
): Promise<{ bundleId: string; keys: Record<string, SetOutcome> }> {
  const environment = requireLive(place);
  const writes = Object.entries(patch).filter((entry): entry is [string, string] => entry[1] !== null);
  const archives = Object.keys(patch).filter((key) => patch[key] === null);
  const bundleId = randomUUID();

  const result = await audited(ctx, async (tx, log) => {
    for (const [key] of writes) {
      await insertSecretIfAbsent(tx, { id: randomUUID(), ...environment, key });
    }
    // Lock every named row, so a racing archive or write waits for this one.
    const rows = await forUpdate(
      tx
        .select({ id: secrets.id, key: secrets.key, archivedAt: secrets.archivedAt })
        .from(secrets)
        .where(
          and(eq(secrets.environmentId, environment.environmentId), inArray(secrets.key, Object.keys(patch))),
        ),
    );
    const byKey = new Map(rows.map((row) => [row.key, row]));
    const next = await nextVersions(tx, writes.map(([key]) => byKey.get(key)!.id));

    const keys: Record<string, SetOutcome> = {};
    for (const [key, value] of writes) {
      const secret = byKey.get(key)!;
      if (secret.archivedAt !== null) {
        throw new Refusal(
          conflict(`${key} is archived; unarchive it before writing a new version`),
          denied(ctx, 'secret.write', 'secret_archived', {
            ...environment,
            secretId: secret.id,
            bundleId,
            metadata: { key },
          }),
        );
      }
      const version = next.get(secret.id)!;
      const envelope = await seal(
        Buffer.from(value, 'utf8'),
        { ...environment, secretId: secret.id },
        ctx.keks,
      );
      await appendVersion(tx, secret.id, version, envelope, ctx.caller.principal.id);
      // The value is never logged. The log answers who and what, not what it was.
      log.push(allowed(ctx, 'secret.write', {
        ...environment,
        secretId: secret.id,
        bundleId,
        metadata: { key, version },
      }));
      keys[key] = { version };
    }

    const now = new Date();
    for (const key of archives) {
      const secret = byKey.get(key);
      keys[key] = { archived: true };
      // Archiving what is already gone is a no-op, the way a merge patch's null is.
      if (secret === undefined || secret.archivedAt !== null) continue;
      await tx.update(secrets).set({ archivedAt: now }).where(eq(secrets.id, secret.id));
      log.push(allowed(ctx, 'secret.archive', {
        ...environment,
        secretId: secret.id,
        bundleId,
        metadata: { key },
      }));
    }
    return { bundleId, keys };
  });
  if (Object.keys(patch).length > 0) changed(ctx, environment.environmentId);
  return result;
}

/** Rename a secret, or archive or unarchive it. Its versions are untouched. */
export async function patchSecret(
  ctx: ApiContext,
  place: ResolvedPath,
  patch: { key?: string; archived?: boolean },
): Promise<{ key: string; archived: boolean }> {
  const environment = requireLive(place);
  const secret = place.secret;
  if (secret === null) throw notFound('unknown secret');
  const renaming = patch.key !== undefined && patch.key !== secret.key;
  const archiving = patch.archived !== undefined && patch.archived !== secret.archived;
  const archived = patch.archived ?? secret.archived;
  const where = { ...environment, secretId: secret.id };

  const result = await audited(ctx, async (tx, log) => {
    if (renaming && archived) {
      throw conflict(`${secret.key} is archived; unarchive it before renaming it`);
    }
    if (archiving) {
      await tx
        .update(secrets)
        .set({ archivedAt: archived ? new Date() : null })
        .where(eq(secrets.id, secret.id));
      log.push(allowed(ctx, archived ? 'secret.archive' : 'secret.restore', {
        ...where,
        metadata: { key: secret.key },
      }));
    }
    if (renaming) {
      const nextKey = patch.key!;
      const [taken] = await tx
        .select({ id: secrets.id })
        .from(secrets)
        .where(and(eq(secrets.environmentId, environment.environmentId), eq(secrets.key, nextKey)));
      if (taken !== undefined) {
        throw new Refusal(
          conflict(`a secret named "${nextKey}" already exists`),
          denied(ctx, 'secret.rename', 'duplicate_key', { ...where, metadata: { key: secret.key, nextKey } }),
        );
      }
      await tx.update(secrets).set({ key: nextKey, updatedAt: new Date() }).where(eq(secrets.id, secret.id));
      log.push(allowed(ctx, 'secret.rename', { ...where, metadata: { key: secret.key, nextKey } }));
    }
    return { key: renaming ? patch.key! : secret.key, archived };
  });
  if (renaming || archiving) changed(ctx, environment.environmentId);
  return result;
}

/**
 * Who wrote each version and when, never values. Needs `secret.read`: the
 * shape of a history says something about the secret too.
 */
export async function listVersions(
  ctx: ApiContext,
  place: ResolvedPath,
): Promise<{ key: string; archived: boolean; versions: SecretVersion[] }> {
  requireLive(place);
  const secret = place.secret;
  if (secret === null) throw notFound('unknown secret');

  const rows = await ctx.db
    .select({
      id: secretVersions.id,
      version: secretVersions.version,
      createdAt: secretVersions.createdAt,
      createdBy: secretVersions.createdBy,
      kekProvider: secretVersions.kekProvider,
      kekId: secretVersions.kekId,
    })
    .from(secretVersions)
    .where(eq(secretVersions.secretId, secret.id))
    .orderBy(desc(secretVersions.version));

  return {
    key: secret.key,
    archived: secret.archived,
    versions: rows.map((row) => ({
      version: row.version,
      createdAt: row.createdAt.toISOString(),
      createdBy: row.createdBy,
      current: row.id === secret.currentVersionId,
      kek: `${row.kekProvider}:${row.kekId}`,
    })),
  };
}

/**
 * Bring back an old value as a new version. The old envelope is copied as it
 * is: it is bound to the secret, not to a version number, so it still opens.
 */
export async function restoreVersion(
  ctx: ApiContext,
  place: ResolvedPath,
  toVersion: number,
): Promise<{ key: string; version: number }> {
  const environment = requireLive(place);
  const secret = place.secret;
  if (secret === null) throw notFound('unknown secret');
  const where = { ...environment, secretId: secret.id };

  const result = await audited(ctx, async (tx, log) => {
    const [locked] = await forUpdate(
      tx
        .select({ archivedAt: secrets.archivedAt, currentVersionId: secrets.currentVersionId })
        .from(secrets)
        .where(eq(secrets.id, secret.id)),
    );
    if (locked.archivedAt !== null) {
      throw conflict(`${secret.key} is archived; unarchive it before restoring a version`);
    }
    const versions = await tx
      .select({ id: secretVersions.id, version: secretVersions.version, ...envelopeColumns })
      .from(secretVersions)
      .where(eq(secretVersions.secretId, secret.id));
    const target = versions.find((row) => row.version === toVersion);
    if (target === undefined) {
      throw new Refusal(
        notFound(`${secret.key} has no version ${toVersion}`),
        denied(ctx, 'secret.rollback', 'unknown_version', { ...where, metadata: { key: secret.key, toVersion } }),
      );
    }
    const fromVersion = versions.find((row) => row.id === locked.currentVersionId)?.version ?? null;
    const version = Math.max(...versions.map((row) => row.version)) + 1;
    await appendVersion(tx, secret.id, version, envelopeOf(target), ctx.caller.principal.id);
    log.push(allowed(ctx, 'secret.rollback', {
      ...where,
      metadata: { key: secret.key, fromVersion, toVersion, version },
    }));
    return { key: secret.key, version };
  });
  changed(ctx, environment.environmentId);
  return result;
}

/**
 * The only way to decrypt, and a POST so nothing can trigger it by
 * prefetching. One audit row per secret, sharing a bundle id: "they read the
 * whole environment" is true but useless, "they read these nine keys at these
 * versions" is what an investigation needs. Refusals are logged too.
 */
export async function reveal(
  ctx: ApiContext,
  path: Path,
): Promise<{ bundleId: string; values: Record<string, string> }> {
  const bundleId = randomUUID();
  return audited(ctx, async (tx, log) => {
    const place = await resolvePath(tx, path);
    const environment = place === null ? null : liveEnvironment(place);
    if (place === null || environment === null) {
      throw new Refusal(
        notFound('unknown project or environment'),
        denied(ctx, 'secret.read', 'unknown_environment', {
          projectId: place?.project.id ?? null,
          bundleId,
          metadata: { path: formatPath(path) },
        }),
      );
    }
    need(ctx, 'secret.read', environment, 'secret.read', {
      bundleId,
      metadata: path.key === undefined ? {} : { key: path.key },
    });
    if (path.key !== undefined && (place.secret === null || place.secret.archived)) {
      throw new Refusal(
        notFound('unknown secret'),
        denied(ctx, 'secret.read', 'unknown_secret', { ...environment, bundleId, metadata: { key: path.key } }),
      );
    }

    const rows = await currentEnvelopes(tx, environment.environmentId, place.secret?.id);
    // A null-prototype record: a key named __proto__ is a key like any other.
    const values: Record<string, string> = Object.create(null);
    for (const row of rows) {
      const plaintext = await open(row.envelope, { ...environment, secretId: row.secretId }, ctx.keks);
      values[row.key] = plaintext.toString('utf8');
      log.push(allowed(ctx, 'secret.read', {
        ...environment,
        secretId: row.secretId,
        bundleId,
        metadata: { key: row.key, version: row.version },
      }));
    }
    if (log.length === 0) {
      // An empty environment still produced a read. Log the attempt rather than nothing.
      log.push(allowed(ctx, 'secret.read', { ...environment, bundleId, metadata: { reason: 'empty_environment' } }));
    }
    return { bundleId, values: { ...values } };
  });
}

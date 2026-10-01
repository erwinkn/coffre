import { randomUUID } from 'node:crypto';

import type { Permission } from '../../../core/src/access.ts';
import type { Envelope } from '../../../core/src/envelope.ts';
import type { Queryable, Transaction } from '../db/database.ts';
import { isUniqueViolation } from '../db/dialect.ts';
import {
  environmentSecrets,
  insert,
  insertIfAbsent,
  lock,
  resolvePath,
  secretHistory,
  update,
  type ResolvedPath,
} from '../db/queries.ts';
import { secrets, secretVersions } from '../db/schema.ts';
import type { SecretRef } from '../../../vault/src/types.ts';
import { permissionsAt } from './caller.ts';
import { allowed, asking, audited, denied, need, Refusal, vaultRefusal, type ApiContext } from './context.ts';
import { conflict, notFound } from './errors.ts';
import { openValues, rewrapValue, sealValues } from './keys.ts';
import { formatPath, type Path } from './paths.ts';

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
export type SetResult = { bundleId: string; keys: Record<string, SetOutcome> };

type Environment = { projectId: string; environmentId: string };

/**
 * The environment a secrets call works in. An archived project or
 * environment serves nothing, exactly as if it did not exist.
 */
function liveEnvironment(place: ResolvedPath): Environment | null {
  if (place.project.archivedAt !== null || place.environment === null || place.environment.archivedAt !== null) {
    return null;
  }
  return { projectId: place.project.id, environmentId: place.environment.id };
}

function requireLive(place: ResolvedPath): Environment {
  const environment = liveEnvironment(place);
  if (environment === null) throw notFound('unknown project or environment');
  return environment;
}

/** One version of a secret, as the vault names it: bound to its ids, labelled with its path. */
export function secretRef(
  place: { project: { slug: string }; environment: { slug: string } | null },
  environment: Environment,
  secret: { id: string; key: string },
  version: number,
): SecretRef {
  return {
    ...environment,
    secretId: secret.id,
    version,
    path: `${place.project.slug}/${place.environment!.slug}/${secret.key}`,
  };
}

/** Tell the environment's syncs to push, once the change has committed. */
function changed(ctx: ApiContext, environmentId: string): void {
  // Never throws: the write has committed, and the scheduler picks up any run missed here.
  ctx.waitUntil(ctx.syncs.runForEnvironment(environmentId));
}

/**
 * The current value of every live secret in an environment, or of one
 * secret. What reveals and syncs decrypt.
 */
export async function currentEnvelopes(
  db: Queryable,
  environmentId: string,
  secretId?: string,
): Promise<{ secretId: string; secretVersionId: string; key: string; version: number; envelope: Envelope }[]> {
  return (await environmentSecrets(db, environmentId, secretId)).flatMap((secret) =>
    secret.archivedAt === null && secret.current !== null
      ? [{
          secretId: secret.id,
          secretVersionId: secret.current.id,
          key: secret.key,
          version: secret.current.version,
          envelope: secret.current.envelope,
        }]
      : [],
  );
}

/** Secret names and who last changed them, never values. */
export async function listSecrets(
  ctx: ApiContext,
  place: ResolvedPath,
): Promise<{ permissions: Permission[]; keys: SecretKey[] }> {
  const environment = requireLive(place);
  const rows = await environmentSecrets(ctx.db, environment.environmentId);
  return {
    permissions: permissionsAt(ctx.caller, environment),
    keys: rows.map((row) => ({
      key: row.key,
      archived: row.archivedAt !== null,
      version: row.current?.version ?? null,
      updatedAt: row.current?.createdAt.toISOString() ?? null,
      updatedBy: row.current?.createdBy ?? null,
    })),
  };
}

/**
 * Append a version and make it current. Versions are never rewritten. The
 * caller holds the secret's row lock, which is what makes `version` its own.
 */
async function appendVersion(
  tx: Transaction,
  secretId: string,
  version: number,
  envelope: Envelope,
  createdBy: string,
): Promise<void> {
  const id = randomUUID();
  await insert(tx, secretVersions, { id, secretId, version, ...envelope, createdBy });
  await update(tx, secrets, { id: secretId }, { currentVersionId: id, currentVersion: version, updatedAt: new Date() });
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
): Promise<SetResult> {
  const environment = requireLive(place);
  const writes = Object.entries(patch).filter((entry): entry is [string, string] => entry[1] !== null);
  const archives = Object.keys(patch).filter((key) => patch[key] === null);
  const bundleId = randomUUID();

  const result = await audited(ctx, async (tx, log) => {
    await insertIfAbsent(tx, secrets, writes.map(([key]) => ({ id: randomUUID(), ...environment, key })));
    // Lock every named row: a racing write or archive waits for this one,
    // and the version counter each row carries is ours until commit.
    const rows = await lock(tx, secrets, { environmentId: environment.environmentId, key: Object.keys(patch) });
    const byKey = new Map(rows.map((row) => [row.key, row]));

    const keys: Record<string, SetOutcome> = {};
    const items: { key: string; secret: SecretRef; value: string }[] = [];
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
      items.push({ key, secret: secretRef(place, environment, secret, secret.currentVersion + 1), value });
    }
    // One vault call wraps every new key, or refuses them all.
    const sealed = await sealValues(ctx.vault, asking(ctx), items);
    if (!sealed.ok) throw vaultRefusal(ctx, sealed.refusal, 'secret.write', { ...environment, bundleId });
    const versions = items.map(({ key, secret }, i) => {
      // The value is never logged. The log answers who and what, not what it was.
      log.push(allowed(ctx, 'secret.write', {
        ...environment,
        secretId: secret.secretId,
        bundleId,
        metadata: { key, version: secret.version },
      }));
      keys[key] = { version: secret.version };
      return {
        id: randomUUID(),
        secretId: secret.secretId,
        version: secret.version,
        ...sealed.values[i],
        createdBy: ctx.caller.principal.id,
      };
    });
    await insert(tx, secretVersions, versions);
    const now = new Date();
    for (const { id, secretId, version } of versions) {
      await update(tx, secrets, { id: secretId }, { currentVersionId: id, currentVersion: version, updatedAt: now });
    }

    const archiving: string[] = [];
    for (const key of archives) {
      const secret = byKey.get(key);
      keys[key] = { archived: true };
      // Archiving what is already gone is a no-op, the way a merge patch's null is.
      if (secret === undefined || secret.archivedAt !== null) continue;
      archiving.push(secret.id);
      log.push(allowed(ctx, 'secret.archive', {
        ...environment,
        secretId: secret.id,
        bundleId,
        metadata: { key },
      }));
    }
    if (archiving.length > 0) await update(tx, secrets, { id: archiving }, { archivedAt: now });
    return { bundleId, keys };
  });
  if (Object.keys(patch).length > 0) changed(ctx, environment.environmentId);
  return result;
}

/** What a merge patch would do to a key: the answer to `?dryRun=1`. */
export type DryRunOutcome = 'added' | 'changed' | 'unchanged' | 'archived';
export type DryRunResult = { dryRun: true; keys: Record<string, DryRunOutcome> };

/**
 * `setSecrets` without the write: what each key in the patch would become,
 * as an outcome, never a value. Nothing is written but the audit entries.
 *
 * Telling `changed` from `unchanged` decrypts the current value, and the
 * answer tells whoever sent the patch whether their guess was right: a read.
 * So a dry run needs secret.read, and every value it opens is logged as a
 * `secret.read` marked `dryRun`, one bundle per call, the way a reveal logs
 * the values it opens. Keys that are new or being archived open nothing.
 */
export async function dryRunSecrets(
  ctx: ApiContext,
  place: ResolvedPath,
  patch: Record<string, string | null>,
): Promise<DryRunResult> {
  const environment = requireLive(place);
  const bundleId = randomUUID();
  return audited(ctx, async (tx, log) => {
    need(ctx, 'secret.read', environment, 'secret.read', { bundleId, metadata: { dryRun: true } });
    const rows = new Map((await environmentSecrets(tx, environment.environmentId)).map((row) => [row.key, row]));
    // Refuse what the write would refuse before opening anything.
    for (const [key, value] of Object.entries(patch)) {
      if (value !== null && rows.get(key)?.archivedAt != null) {
        throw conflict(`${key} is archived; unarchive it before writing a new version`);
      }
    }

    // A null-prototype record: a key named __proto__ is a key like any other.
    const keys: Record<string, DryRunOutcome> = Object.create(null);
    const comparing: { key: string; value: string; secret: SecretRef; envelope: Envelope }[] = [];
    for (const [key, value] of Object.entries(patch)) {
      const secret = rows.get(key);
      if (value === null) {
        // Archiving what is already gone changes nothing, as in setSecrets.
        keys[key] = secret === undefined || secret.archivedAt !== null ? 'unchanged' : 'archived';
        continue;
      }
      if (secret === undefined || secret.current === null) {
        keys[key] = 'added';
        continue;
      }
      const { version, envelope } = secret.current;
      comparing.push({ key, value, secret: secretRef(place, environment, secret, version), envelope });
    }
    const opened = await openValues(ctx.vault, { ...asking(ctx), purpose: 'compare' }, comparing);
    if (!opened.ok) {
      throw vaultRefusal(ctx, opened.refusal, 'secret.read', { ...environment, bundleId, metadata: { dryRun: true } });
    }
    comparing.forEach(({ key, value, secret }, i) => {
      keys[key] = opened.values[i] === value ? 'unchanged' : 'changed';
      log.push(allowed(ctx, 'secret.read', {
        ...environment,
        secretId: secret.secretId,
        bundleId,
        metadata: { key, version: secret.version, dryRun: true },
      }));
    });
    return { dryRun: true as const, keys: { ...keys } };
  });
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
  const wasArchived = secret.archivedAt !== null;
  const renaming = patch.key !== undefined && patch.key !== secret.key;
  const archiving = patch.archived !== undefined && patch.archived !== wasArchived;
  const archived = patch.archived ?? wasArchived;
  const where = { ...environment, secretId: secret.id };
  if (renaming && archived) {
    throw conflict(`${secret.key} is archived; unarchive it before renaming it`);
  }
  if (!renaming && !archiving) return { key: secret.key, archived };

  const nextKey = patch.key!;
  const result = await audited(ctx, async (tx, log) => {
    try {
      await update(tx, secrets, { id: secret.id }, {
        ...(archiving ? { archivedAt: archived ? new Date() : null } : {}),
        ...(renaming ? { key: nextKey, updatedAt: new Date() } : {}),
      });
    } catch (error) {
      if (!renaming || !isUniqueViolation(error)) throw error;
      throw new Refusal(
        conflict(`a secret named "${nextKey}" already exists`),
        denied(ctx, 'secret.rename', 'duplicate_key', { ...where, metadata: { key: secret.key, nextKey } }),
      );
    }
    if (archiving) {
      log.push(allowed(ctx, archived ? 'secret.archive' : 'secret.restore', {
        ...where,
        metadata: { key: secret.key },
      }));
    }
    if (renaming) log.push(allowed(ctx, 'secret.rename', { ...where, metadata: { key: secret.key, nextKey } }));
    return { key: renaming ? nextKey : secret.key, archived };
  });
  changed(ctx, environment.environmentId);
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
  const versions = await secretHistory(ctx.db, secret.id);
  return {
    key: secret.key,
    archived: secret.archivedAt !== null,
    versions: versions.map((row) => ({
      version: row.version,
      createdAt: row.createdAt.toISOString(),
      createdBy: row.createdBy,
      current: row.id === secret.currentVersionId,
      kek: `${row.envelope.kekProvider}:${row.envelope.kekId}`,
    })),
  };
}

/**
 * Bring back an old value as a new version. The old ciphertext is copied as
 * it is: it is bound to the secret, not to a version number, so it still
 * opens. The vault wraps its data key again under the current key, which
 * takes a write grant and never opens the value.
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
    // The lock makes the next version number ours, as in setSecrets.
    const [locked] = await lock(tx, secrets, { id: secret.id });
    if (locked.archivedAt !== null) {
      throw conflict(`${secret.key} is archived; unarchive it before restoring a version`);
    }
    const target = (await secretHistory(tx, secret.id)).find((row) => row.version === toVersion);
    if (target === undefined) {
      throw new Refusal(
        notFound(`${secret.key} has no version ${toVersion}`),
        denied(ctx, 'secret.rollback', 'unknown_version', { ...where, metadata: { key: secret.key, toVersion } }),
      );
    }
    const fromVersion = locked.currentVersion;
    const version = fromVersion + 1;
    const rewrapped = await rewrapValue(ctx.vault, asking(ctx), secretRef(place, environment, secret, version), target);
    if (!rewrapped.ok) {
      throw vaultRefusal(ctx, rewrapped.refusal, 'secret.rollback', { ...where, metadata: { key: secret.key, toVersion } });
    }
    await appendVersion(tx, secret.id, version, rewrapped.values[0], ctx.caller.principal.id);
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
    if (path.key !== undefined && (place.secret === null || place.secret.archivedAt !== null)) {
      throw new Refusal(
        notFound('unknown secret'),
        denied(ctx, 'secret.read', 'unknown_secret', { ...environment, bundleId, metadata: { key: path.key } }),
      );
    }

    const rows = await currentEnvelopes(tx, environment.environmentId, place.secret?.id);
    const opened = await openValues(
      ctx.vault,
      { ...asking(ctx), purpose: path.key === undefined ? 'run' : 'reveal' },
      rows.map((row) => ({
        secret: secretRef(place, environment, { id: row.secretId, key: row.key }, row.version),
        envelope: row.envelope,
      })),
    );
    if (!opened.ok) {
      throw vaultRefusal(ctx, opened.refusal, 'secret.read', {
        ...environment,
        bundleId,
        metadata: path.key === undefined ? {} : { key: path.key },
      });
    }
    // A null-prototype record: a key named __proto__ is a key like any other.
    const values: Record<string, string> = Object.create(null);
    for (const [i, row] of rows.entries()) {
      values[row.key] = opened.values[i];
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

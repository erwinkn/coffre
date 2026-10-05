import { randomUUID } from 'node:crypto';

import type { Permission } from '@coffre/core/access';
import type { Envelope } from '@coffre/core/envelope';
import { isTombstone } from '@coffre/core/schemas';
import type { HolderRef, SecretRef } from '@coffre/core/vault';
import type { Queryable, Transaction } from '@coffre/db';
import { isUniqueViolation } from '@coffre/db/dialect';
import { secretReferences, secrets, secretVersions } from '@coffre/db/schema';

import {
  environmentSecrets,
  insert,
  insertIfAbsent,
  lock,
  referenceRows,
  resolvePath,
  secretHeads,
  secretPlaces,
  secretHistory,
  update,
  type ResolvedPath,
  type SecretPlaceRow,
} from '../db/queries.ts';
import { can, permissionsAt, placeOf } from './caller.ts';
import { allowed, asking, audited, denied, need, recorded, Refusal, vaultRefusal, withRefusals, type ApiContext } from './context.ts';
import { conflict, notFound, vaultRefused } from './errors.ts';
import { fileSecrets, requireFolders, secretFoldersIn } from './folders.ts';
import { openValues, rewrapValue, sealValues } from './keys.ts';
import { formatMember, formatPath, type Path } from './paths.ts';
import { currentReferences, placeOfRow, readableValues, readersOf, referencesReady, refuseIfRead, requireReferences, type ReferenceView, type Resolved } from './references.ts';

export type SecretKey = {
  key: string;
  /**
   * The reference it is, when it has no value of its own: what it reads,
   * whether it does, and whether you could open its source where it is.
   */
  reference: (ReferenceView & { canOpenSource: boolean }) | null;
  /** The folder it is listed in within this environment, or null for none. */
  folder: string | null;
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
/** A value, or a reference to another secret by path. */
export type SecretValue = string | { ref: string };

export type SetOutcome = { version: number } | { archived: true } | { reference: string };
export type SetResult = { operationId: string; keys: Record<string, SetOutcome> };

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

/**
 * The current value of every live secret in an environment, or of one
 * secret. What reveals decrypt.
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
  const [rows, folders] = await Promise.all([
    environmentSecrets(ctx.db, environment.environmentId),
    secretFoldersIn(ctx.db, environment.environmentId),
  ]);
  const references = await currentReferences(ctx.db, rows.filter((row) => row.current === null).map((row) => row.id));
  const referenceOf = (secretId: string): SecretKey['reference'] => {
    const reference = references.get(secretId);
    if (reference === undefined) return null;
    const { source } = reference;
    const canOpenSource = source !== null && can(ctx.caller, 'secret.read', placeOfRow(source));
    return { ...reference.view, canOpenSource };
  };
  return {
    permissions: permissionsAt(ctx.caller, placeOf(place.project, place.environment)),
    keys: rows.map((row) => ({
      key: row.key,
      reference: referenceOf(row.id),
      folder: folders.get(row.id) ?? null,
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

/** A competing write invalidated the keys prepared outside the transaction. */
class PrepareAgain extends Error {}

async function optimistic<T>(ctx: ApiContext, work: () => Promise<T>): Promise<T> {
  return withRefusals(ctx, async () => {
    // Bound the work under sustained contention; an ordinary burst can retry.
    for (let attempt = 0; attempt < 16; attempt++) {
      try {
        return await work();
      } catch (error) {
        if (!(error instanceof PrepareAgain)) throw error;
      }
    }
    throw conflict('the secrets kept changing; try again');
  });
}

/**
 * The place as it is under the log's head, which every write to a place
 * takes first: archived or deleted since the router found it, it takes no
 * write. The head is held, so an archive or a deletion cannot commit until we do.
 */
export async function checkEnvironment(tx: Transaction, place: ResolvedPath, expected: Environment): Promise<void> {
  const current = await resolvePath(tx, { project: place.project.slug, environment: place.environment!.slug });
  if (current === null) throw notFound('unknown project or environment');
  const live = requireLive(current);
  if (live.projectId !== expected.projectId || live.environmentId !== expected.environmentId) throw notFound('unknown project or environment');
}

/**
 * The only way to write. A string sets a key, adding it if it is new;
 * `{ ref }` makes it a reference to another secret, by path; `null`
 * archives it. One transaction, one version or reference and one audit
 * entry per key, so fifty keys from an `.env` file land together or not at
 * all.
 *
 * A key that is a reference stops being one when it gets a value or
 * another reference: the vault ends it first, `replaced`, before anything
 * is written, so a write that then fails leaves a key with no value, never
 * one still reading the source it was moved off.
 *
 * The operation id is drawn inside the retried preparation: an attempt that
 * prepares again leaves the vault's `key.wrap` entries for keys nothing
 * stored, and a fresh id keeps them out of the write that did land.
 */
export async function setSecrets(
  ctx: ApiContext,
  place: ResolvedPath,
  patch: Record<string, SecretValue | null>,
): Promise<SetResult> {
  const environment = requireLive(place);
  const keysIn = Object.keys(patch);
  const writes = Object.entries(patch).filter((entry): entry is [string, string] => typeof entry[1] === 'string');
  const refs = Object.entries(patch).flatMap(([key, value]) => (value !== null && typeof value === 'object' ? [{ key, ref: value.ref }] : []));
  const archives = keysIn.filter((key) => patch[key] === null);
  if (refs.length > 0) await requireReferences(ctx.db);
  const result = await optimistic(ctx, async () => {
    const operationId = randomUUID();
    const heads = await secretHeads(ctx.db, environment.environmentId, { keys: keysIn });
    const prepared = new Map(heads.map((row) => [row.key, row]));
    const ready = await referencesReady(ctx.db);
    const currently = await currentReferences(ctx.db, heads.filter((row) => row.currentVersionId === null).map((row) => row.id));
    // Each key's newest reference, which the transaction checks no write replaced meanwhile.
    const newestBefore = ready ? newestReferences(await referenceRows(ctx.db, { holderSecretIds: heads.map((row) => row.id) })) : new Map<string, string>();
    const archived = (key: string) => {
      const row = prepared.get(key);
      if (row?.archivedAt == null) return;
      throw new Refusal(
        conflict(`${key} is archived; unarchive it before writing a new version`),
        denied(ctx, 'secret.write', 'secret_archived', { ...environment, secretId: row.id, operationId, metadata: { key } }),
      );
    };
    const items = writes.map(([key, value]) => {
      archived(key);
      const row = prepared.get(key);
      const secret = { id: row?.id ?? randomUUID(), key };
      return { key, secret: secretRef(place, environment, secret, (row?.currentVersion ?? 0) + 1), value };
    });
    const references = (await referenceTargets(ctx, place, environment, refs, prepared, currently, operationId)).filter((item) => {
      archived(item.key);
      return !item.unchanged;
    });
    // What gets a value or another reference stops being the reference it is.
    const replaced = [...items.map((item) => item.secret.secretId), ...references.map((item) => item.holder.secretId)]
      .flatMap((secretId) => {
        const reference = currently.get(secretId);
        return reference === undefined || reference.row.ended !== null ? [] : [reference.row];
      });

    // IDs and versions are provisional until the transaction checks them.
    const sealed = await sealValues(ctx.vault, asking(ctx, operationId), items);
    if (!sealed.ok) throw vaultRefusal(ctx, sealed.refusal, 'secret.write', { ...environment, operationId });
    // Vault calls only for what there is: most writes make and end no reference.
    const made = references.length === 0 ? { ok: true as const, seqs: [] } : await ctx.vault.reference({
      ...asking(ctx, operationId),
      items: references.map(({ id, holder, source }) => ({ id, holder, source: { secretId: source.id } })),
    });
    if (!made.ok) throw vaultRefusal(ctx, made.refusal, 'secret.reference', { ...environment, operationId });
    if (replaced.length > 0) {
      const ended = await ctx.vault.endReferences({
        ...asking(ctx, operationId),
        reason: 'replaced',
        items: replaced.map((row) => ({ reference: row.id, seq: Number(row.createdSeq) })),
      });
      if (!ended.ok) {
        await abandon(ctx, operationId, references, made.seqs);
        throw vaultRefusal(ctx, ended.refusal, 'secret.write', { ...environment, operationId });
      }
    }

    return audited(ctx, async (tx, log) => {
      await checkEnvironment(tx, place, environment);
      // Each source again under the head: archived or deleted since it was checked, it is no source (D41).
      if (references.length > 0) {
        const sources = await secretPlaces(tx, references.map((item) => item.source.id));
        for (const { key, source } of references) {
          const now = sources.get(source.id);
          if (now !== undefined && now.archivedAt === null && now.environmentArchivedAt === null && now.projectArchivedAt === null
            && !isTombstone(now.project) && !isTombstone(now.environment)) continue;
          throw new Refusal(
            notFound(`${sourcePath(source)} was archived or deleted meanwhile: it is no live secret to refer to`),
            denied(ctx, 'secret.reference', 'source_archived', { ...environment, operationId, metadata: { key, source: sourcePath(source) } }),
          );
        }
      }
      await insertIfAbsent(tx, secrets, [
        ...items.map(({ key, secret }) => ({ key, id: secret.secretId })),
        ...references.map(({ key, holder }) => ({ key, id: holder.secretId })),
      ].filter(({ key }) => !prepared.has(key)).map(({ key, id }) => ({ id, ...environment, key })));
      const rows = await lock(tx, secrets, { environmentId: environment.environmentId, key: keysIn });
      const byKey = new Map(rows.map((row) => [row.key, row]));
      const created = new Map([
        ...items.map((item) => [item.key, item.secret.secretId] as const),
        ...references.map((item) => [item.key, item.holder.secretId] as const),
      ]);
      for (const key of keysIn) {
        const before = prepared.get(key);
        const current = byKey.get(key);
        if (before === undefined) {
          if (current?.id !== created.get(key) || (current !== undefined && (current.currentVersion !== 0 || current.archivedAt !== null))) {
            throw new PrepareAgain();
          }
        } else if (current === undefined || current.id !== before.id
          || current.currentVersion !== before.currentVersion
          || current.currentVersionId !== before.currentVersionId
          || current.archivedAt?.getTime() !== before.archivedAt?.getTime()) {
          throw new PrepareAgain();
        }
      }
      // A reference made meanwhile, to a key this write prepared without it.
      if (ready) {
        const newest = newestReferences(await referenceRows(tx, { holderSecretIds: rows.map((row) => row.id) }));
        if (rows.some((row) => newest.get(row.id) !== newestBefore.get(row.id))) throw new PrepareAgain();
      }

      const keys: Record<string, SetOutcome> = {};
      const versions = items.map(({ key, secret }, i) => {
        log.push(allowed(ctx, 'secret.write', {
          ...environment, secretId: secret.secretId, operationId, relatedSeq: sealed.seqs[i], metadata: { key, version: secret.version },
        }));
        keys[key] = { version: secret.version };
        return { id: randomUUID(), secretId: secret.secretId, version: secret.version, ...sealed.values[i], createdBy: ctx.caller.principal.id };
      });
      await insert(tx, secretVersions, versions);
      const now = new Date();
      for (const { id, secretId, version } of versions) {
        await update(tx, secrets, { id: secretId }, { currentVersionId: id, currentVersion: version, updatedAt: now });
      }
      for (const [i, { key, id, holder, source }] of references.entries()) {
        await update(tx, secrets, { id: holder.secretId }, { currentVersionId: null, updatedAt: now });
        await insert(tx, secretReferences, {
          id,
          projectId: holder.projectId,
          environmentId: holder.environmentId,
          secretId: holder.secretId,
          sourceProjectId: source.projectId,
          sourceEnvironmentId: source.environmentId,
          sourceSecretId: source.id,
          createdSeq: BigInt(made.seqs[i]!),
          // The member, as the vault's entry names them. Provenance only: lists and the offboarding report read the maker from the entry.
          createdBy: formatMember(ctx.caller.principal),
        });
        log.push(allowed(ctx, 'secret.reference', {
          ...environment, secretId: holder.secretId, operationId, relatedSeq: made.seqs[i], metadata: {
            key, source: sourcePath(source), also: { projectId: source.projectId, environmentId: source.environmentId, secretId: source.id },
          },
        }));
        keys[key] = { reference: sourcePath(source) };
      }
      for (const { key, source } of refs.map((ref) => ({ key: ref.key, source: ref.ref }))) keys[key] ??= { reference: source };
      const archiving = archives.map((key) => byKey.get(key)).filter((secret) => secret !== undefined && secret.archivedAt === null);
      if (archiving.length > 0) {
        await refuseIfRead(ctx, tx, `${place.project.slug}/${place.environment!.slug}`, { ...environment, secretIds: archiving.map((secret) => secret!.id) }, 'secret.archive', { ...environment, operationId });
      }
      for (const key of archives) {
        const secret = byKey.get(key);
        keys[key] = { archived: true };
        if (secret === undefined || secret.archivedAt !== null) continue;
        await update(tx, secrets, { id: secret.id }, { archivedAt: now });
        log.push(allowed(ctx, 'secret.archive', { ...environment, secretId: secret.id, operationId, metadata: { key } }));
      }
      return { operationId, keys };
    }).catch(async (error: unknown) => {
      await abandon(ctx, operationId, references, made.seqs);
      throw error;
    });
  });
  return result;
}

/**
 * End, `abandoned`, the references the vault sealed for a write that stored
 * none of them: refused, failed, or prepared again under fresh ids. Then a
 * row written later around the app, naming one, reads nothing. Best effort,
 * and after the write's own answer: meanwhile a seal no row names is no
 * reference, and the write's error is the one to answer with.
 */
async function abandon(ctx: ApiContext, operationId: string, references: readonly { id: string }[], seqs: readonly number[]): Promise<void> {
  if (seqs.length === 0) return;
  await ctx.vault.endReferences({
    ...asking(ctx, operationId),
    reason: 'abandoned',
    items: references.map(({ id }, i) => ({ reference: id, seq: seqs[i]! })),
  }).catch(() => undefined);
}

/** Each holder's newest reference's id, from rows oldest first. */
function newestReferences(rows: readonly { id: string; holder: { secretId: string } }[]): Map<string, string> {
  return new Map(rows.map((row) => [row.holder.secretId, row.id]));
}

const sourcePath = (source: SecretPlaceRow) => `${source.project}/${source.environment}/${source.key}`;

/** A reference a write makes: its id, holder and source; `unchanged` when the key already reads that source. */
type ReferenceTarget = { key: string; id: string; holder: HolderRef; source: SecretPlaceRow; unchanged: boolean };

/**
 * The references a patch makes, checked: each source a live secret the
 * caller reads by their own grants, not the holder, and not itself a
 * reference (one hop); and no holder a source others read through, since
 * they would then read through two. The vault checks the grants again, and
 * reads only the source its entry names, whatever the app decided.
 */
async function referenceTargets(
  ctx: ApiContext,
  place: ResolvedPath,
  environment: Environment,
  refs: { key: string; ref: string }[],
  prepared: Map<string, { id: string; key: string }>,
  currently: Map<string, Resolved>,
  operationId: string,
): Promise<ReferenceTarget[]> {
  if (refs.length === 0) return [];
  const refused = (key: string, message: string, reason: string) =>
    new Refusal(conflict(message), denied(ctx, 'secret.reference', reason, { ...environment, operationId, metadata: { key } }));
  const resolved = await Promise.all(refs.map(async ({ key, ref }) => {
    const parts = ref.split('/');
    const found = parts.length === 3 ? await resolvePath(ctx.db, { project: parts[0]!, environment: parts[1]!, key: parts[2]! }) : null;
    if (found?.environment == null || found.secret === null || found.project.archivedAt !== null || found.environment.archivedAt !== null || found.secret.archivedAt !== null) {
      throw new Refusal(notFound(`${ref} is no live secret to refer to`), denied(ctx, 'secret.reference', 'unknown_source', { ...environment, operationId, metadata: { key, source: ref } }));
    }
    need(ctx, 'secret.read', placeOf(found.project, found.environment), 'secret.reference', { operationId, metadata: { key, source: ref } });
    return { key, secretId: found.secret.id };
  }));
  const holders = refs.map(({ key }) => prepared.get(key)?.id ?? randomUUID());
  const [sources, sourceReferences, readers] = await Promise.all([
    secretPlaces(ctx.db, resolved.map((source) => source.secretId)),
    currentReferences(ctx.db, resolved.map((source) => source.secretId)),
    readersOf(ctx.db, holders),
  ]);
  return refs.map(({ key }, i) => {
    const source = sources.get(resolved[i]!.secretId)!;
    const holderId = holders[i]!;
    if (source.id === holderId) throw refused(key, `${key} cannot be a reference to itself`, 'reference_to_itself');
    if (sourceReferences.has(source.id)) {
      const via = sourceReferences.get(source.id);
      throw refused(key, `${sourcePath(source)} is itself a reference${via === undefined ? '' : ` to ${via.view.source}`}: point ${key} at its source instead`, 'reference_to_reference');
    }
    const pointing = readers.filter((reader) => reader.row.source.secretId === holderId);
    if (pointing.length > 0) {
      throw refused(key, `${pointing.length} reference${pointing.length === 1 ? '' : 's'} read ${key} (${pointing.map((reader) => reader.view.holder).join(', ')}): a reference cannot point at a reference, so break ${pointing.length === 1 ? 'it' : 'them'} first`, 'referenced_holder');
    }
    const now = currently.get(holderId);
    return {
      key,
      id: randomUUID(),
      holder: { ...environment, secretId: holderId, path: `${place.project.slug}/${place.environment!.slug}/${key}` },
      source,
      unchanged: now !== undefined && now.row.ended === null && now.row.source.secretId === source.id,
    };
  });
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
 * So a dry run needs secret.read, and the vault logs every value it opens as
 * a `secret.read` for the purpose `compare`, one operation per call, the way
 * it logs a reveal's. Keys that are new or being archived open nothing.
 */
export async function dryRunSecrets(
  ctx: ApiContext,
  place: ResolvedPath,
  patch: Record<string, SecretValue | null>,
): Promise<DryRunResult> {
  const environment = requireLive(place);
  const operationId = randomUUID();
  return withRefusals(ctx, async () => {
    need(ctx, 'secret.read', placeOf(place.project, place.environment), 'secret.read', { operationId, metadata: { dryRun: true } });
    const rows = new Map((await environmentSecrets(ctx.db, environment.environmentId)).map((row) => [row.key, row]));
    // Refuse what the write would refuse before opening anything.
    for (const [key, value] of Object.entries(patch)) {
      if (value !== null && rows.get(key)?.archivedAt != null) {
        throw conflict(`${key} is archived; unarchive it before writing a new version`);
      }
    }

    // A null-prototype record: a key named __proto__ is a key like any other.
    const keys: Record<string, DryRunOutcome> = Object.create(null);
    const comparing: { key: string; value: string; secretVersionId: string; secret: SecretRef; envelope: Envelope }[] = [];
    for (const [key, value] of Object.entries(patch)) {
      const secret = rows.get(key);
      if (value === null) {
        // Archiving what is already gone changes nothing, as in setSecrets.
        keys[key] = secret === undefined || secret.archivedAt !== null ? 'unchanged' : 'archived';
        continue;
      }
      if (secret === undefined) {
        keys[key] = 'added';
        continue;
      }
      // A reference, or a value over a reference: what it is now is not a value to compare.
      if (typeof value !== 'string' || secret.current === null) {
        keys[key] = 'changed';
        continue;
      }
      const { version, envelope } = secret.current;
      comparing.push({ key, value, secretVersionId: secret.current.id, secret: secretRef(place, environment, secret, version), envelope });
    }
    const opened = await openValues(ctx.vault, { ...asking(ctx, operationId), purpose: 'compare' }, comparing);
    if (!opened.ok) throw vaultRefused(opened.refusal);
    comparing.forEach(({ key, value }, i) => {
      keys[key] = opened.values[i] === value ? 'unchanged' : 'changed';
    });
    return { dryRun: true as const, keys: { ...keys } };
  });
}

/** Rename a secret, archive or unarchive it, or move it to a folder. Its versions are untouched. */
export async function patchSecret(
  ctx: ApiContext,
  place: ResolvedPath,
  patch: { key?: string; archived?: boolean; folder?: string | null },
): Promise<{ key: string; archived: boolean; folder: string | null }> {
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
  if (patch.folder !== undefined) await requireFolders(ctx.db);
  const before = (await secretFoldersIn(ctx.db, environment.environmentId)).get(secret.id) ?? null;
  const moving = patch.folder !== undefined && patch.folder !== before;
  const folder = moving ? patch.folder! : before;
  if (!renaming && !archiving && !moving) return { key: secret.key, archived, folder };

  const nextKey = patch.key!;
  const result = await audited(ctx, async (tx, log) => {
    // Under the head, as every write to a place: one deleted since the router found it is not written to, nor filed.
    await checkEnvironment(tx, place, environment);
    if (archiving && archived) {
      await refuseIfRead(ctx, tx, `${place.project.slug}/${place.environment!.slug}`, { ...environment, secretIds: [secret.id] }, 'secret.archive', where);
    }
    if (renaming || archiving) {
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
    }
    if (archiving) {
      log.push(allowed(ctx, archived ? 'secret.archive' : 'secret.unarchive', {
        ...where,
        metadata: { key: secret.key },
      }));
    }
    if (renaming) log.push(allowed(ctx, 'secret.rename', { ...where, metadata: { key: secret.key, nextKey } }));
    if (moving) {
      await fileSecrets(tx, [{ secretId: secret.id, folder }], ctx.caller.principal.id);
      log.push(allowed(ctx, 'secret.move', { ...where, metadata: { key: renaming ? nextKey : secret.key, from: before, to: folder } }));
    }
    return { key: renaming ? nextKey : secret.key, archived, folder };
  });
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

  const result = await optimistic(ctx, async () => {
    // Inside the retried preparation, as in setSecrets: a rewrap the retry discards keeps its own id.
    const operationId = randomUUID();
    const [prepared] = await secretHeads(ctx.db, environment.environmentId, { id: secret.id });
    if (prepared === undefined) throw notFound('unknown secret');
    if (prepared.archivedAt !== null) throw conflict(`${secret.key} is archived; unarchive it before restoring a version`);
    const target = (await secretHistory(ctx.db, secret.id)).find((row) => row.version === toVersion);
    if (target === undefined) {
      throw new Refusal(
        notFound(`${secret.key} has no version ${toVersion}`),
        denied(ctx, 'secret.restore', 'unknown_version', { ...where, operationId, metadata: { key: secret.key, from: toVersion } }),
      );
    }
    const fromVersion = prepared.currentVersion;
    const version = fromVersion + 1;
    const rewrapped = await rewrapValue(ctx.vault, asking(ctx, operationId), secretRef(place, environment, prepared, version), target);
    if (!rewrapped.ok) {
      throw vaultRefusal(ctx, rewrapped.refusal, 'secret.restore', { ...where, operationId, metadata: { key: prepared.key, from: toVersion } });
    }
    // An old value brought back ends the reference the key is now.
    const reference = prepared.currentVersionId === null ? (await currentReferences(ctx.db, [secret.id])).get(secret.id) : undefined;
    if (reference !== undefined && reference.row.ended === null) {
      const ended = await ctx.vault.endReferences({
        ...asking(ctx, operationId), reason: 'replaced', items: [{ reference: reference.row.id, seq: Number(reference.row.createdSeq) }],
      });
      if (!ended.ok) throw vaultRefusal(ctx, ended.refusal, 'secret.restore', { ...where, operationId, metadata: { key: prepared.key, from: toVersion } });
    }
    return audited(ctx, async (tx, log) => {
      await checkEnvironment(tx, place, environment);
      const [current] = await lock(tx, secrets, { id: secret.id });
      if (current === undefined || current.currentVersion !== fromVersion || current.currentVersionId !== prepared.currentVersionId
        || current.archivedAt !== null || current.key !== prepared.key) throw new PrepareAgain();
      await appendVersion(tx, secret.id, version, rewrapped.values[0], ctx.caller.principal.id);
      log.push(allowed(ctx, 'secret.restore', {
        ...where, operationId, relatedSeq: rewrapped.seqs[0], metadata: { key: prepared.key, version, from: toVersion },
      }));
      return { key: prepared.key, version };
    });
  });
  return result;
}

/**
 * The only way to decrypt, and a POST so nothing can trigger it by
 * prefetching. The vault logs one `secret.read` per secret it releases,
 * sharing the operation id: "they read the whole environment" is true but
 * useless, "they read these nine keys at these versions" is what an
 * investigation needs. Refusals are logged too, by whichever of the app and
 * the vault refused.
 */
export async function reveal(
  ctx: ApiContext,
  path: Path,
): Promise<{ operationId: string; values: Record<string, string> }> {
  const operationId = randomUUID();
  return recorded(ctx, async (log) => {
    const place = await resolvePath(ctx.db, path);
    const environment = place === null ? null : liveEnvironment(place);
    if (place === null || environment === null) {
      throw new Refusal(
        notFound('unknown project or environment'),
        denied(ctx, 'secret.read', 'unknown_environment', {
          projectId: place?.project.id ?? null,
          operationId,
          metadata: { path: formatPath(path) },
        }),
      );
    }
    need(ctx, 'secret.read', placeOf(place.project, place.environment), 'secret.read', {
      operationId,
      metadata: path.key === undefined ? {} : { key: path.key },
    });
    if (path.key !== undefined && (place.secret === null || place.secret.archivedAt !== null)) {
      throw new Refusal(
        notFound('unknown secret'),
        denied(ctx, 'secret.read', 'unknown_secret', { ...environment, operationId, metadata: { key: path.key } }),
      );
    }

    const { items: rows, unreadable } = await readableValues(ctx.db, place, environment, place.secret?.id);
    // A reference that cannot be read stops the whole read, saying why, rather than run without it.
    if (unreadable.length > 0) {
      throw new Refusal(
        conflict(unreadable.join('; ')),
        denied(ctx, 'secret.read', 'reference_unreadable', { ...environment, operationId, metadata: { references: unreadable.length } }),
      );
    }
    // A key with nothing to read, no version of its own and no reference the vault sealed, as a row written around it: no value.
    if (path.key !== undefined && rows.length === 0) {
      throw new Refusal(
        notFound(`${formatPath(path)} holds no value`),
        denied(ctx, 'secret.read', 'no_value', { ...environment, operationId, metadata: { key: path.key } }),
      );
    }
    const opened = await openValues(ctx.vault, { ...asking(ctx, operationId), purpose: path.key === undefined ? 'run' : 'reveal' }, rows);
    if (!opened.ok) throw vaultRefused(opened.refusal);
    // A null-prototype record: a key named __proto__ is a key like any other.
    const values: Record<string, string> = Object.create(null);
    for (const [i, row] of rows.entries()) values[row.key] = opened.values[i];
    if (rows.length === 0) {
      // An empty environment still produced a read. Log the attempt rather than nothing.
      log.push(allowed(ctx, 'secret.read', { ...environment, operationId, metadata: { reason: 'empty_environment' } }));
    }
    return { operationId, values: { ...values } };
  });
}

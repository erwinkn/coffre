import type { Queryable, Transaction } from '@coffre/db';
import { projectFolders, secretFolders } from '@coffre/db/schema';
import { applied } from '@coffre/db/schema-version';

import { projectFolderOf, secretFolderOf, upsert } from '../db/queries.ts';
import { ApiError } from './errors.ts';

/**
 * Folders: one level, for projects and for an environment's secrets, which
 * arrange lists and do nothing else (docs/design/environments.md). They
 * live in tables this release's migration adds; until it runs, everything
 * lists in no folder and moving answers 503.
 */
export const FOLDERS_MIGRATION = '0007_folders';

/** Each project's folder, or none before the migration. */
export async function projectFoldersOf(db: Queryable): Promise<Map<string, string>> {
  return (await applied(db, FOLDERS_MIGRATION)) ? projectFolderOf(db) : new Map();
}

/** Each of an environment's secrets' folder, or none before the migration. */
export async function secretFoldersIn(db: Queryable, environmentId: string): Promise<Map<string, string>> {
  return (await applied(db, FOLDERS_MIGRATION)) ? secretFolderOf(db, environmentId) : new Map();
}

/** Refuse a move before the migration that makes folders. */
export async function requireFolders(db: Queryable): Promise<void> {
  if (!(await applied(db, FOLDERS_MIGRATION))) {
    throw new ApiError('unavailable', "folders need this release's database migration: an owner runs `coffre migrate`");
  }
}

/** File a project in `folder`, or in none. */
export async function fileProject(tx: Transaction, projectId: string, folder: string | null, by: string): Promise<void> {
  await upsert(tx, projectFolders, [{ projectId, folder, movedAt: new Date(), movedBy: by }], {
    target: ['projectId'],
    columns: ['folder', 'movedAt', 'movedBy'],
  });
}

/** File secrets in folders, or in none. */
export async function fileSecrets(tx: Transaction, rows: { secretId: string; folder: string | null }[], by: string): Promise<void> {
  const movedAt = new Date();
  await upsert(tx, secretFolders, rows.map((row) => ({ ...row, movedAt, movedBy: by })), {
    target: ['secretId'],
    columns: ['folder', 'movedAt', 'movedBy'],
  });
}

import { randomBytes } from 'node:crypto';

import type { Database } from '@coffre/db';
import { openDatabase } from '@coffre/db/connect';
import * as schema from '@coffre/db/schema';
import { getTableName, is, sql } from 'drizzle-orm';
import { PgTable } from 'drizzle-orm/pg-core';

import type { Running } from '../src/change.ts';
import { keyOf } from '../src/rows.ts';

/**
 * The suite's database, which scripts/test-suite.sh prepares, opened twice:
 * as the vault, through the vault's own login, and as its owner, to play
 * someone who writes rows behind the vault.
 */
const name = process.env.COFFRE_TEST_DATABASE ?? 'coffre_test';
const url = (login: string) => `postgresql://${login}@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${name}`;

export type TestVault = Running & {
  owner: Database;
  /** The hashes the signer was woken with, oldest first. */
  woken: Buffer[];
  /** Move the vault's clock on. */
  tick(ms: number): void;
  close(): Promise<void>;
};

export async function openTestVault(): Promise<TestVault> {
  const [owner, vault] = await Promise.all([openDatabase(url('coffre_owner:local-dev-only')), openDatabase(url('coffre_vault_runtime:local-vault-only'))]);
  const woken: Buffer[] = [];
  let now = Date.UTC(2026, 10, 13, 12);
  return {
    db: vault.db,
    owner: owner.db,
    keys: [keyOf(randomBytes(32))],
    now: () => now,
    tick: (ms) => void (now += ms),
    wake: (hash) => void woken.push(hash),
    woken,
    close: async () => void (await Promise.all([owner.close(), vault.close()])),
  };
}

const TABLES = Object.values(schema).filter((value): value is PgTable => is(value, PgTable));

/** Every table emptied. */
export async function emptyDatabase(owner: Database): Promise<void> {
  await owner.execute(sql`TRUNCATE ${sql.join(TABLES.map((table) => sql.identifier(getTableName(table))), sql`, `)} RESTART IDENTITY CASCADE`);
}

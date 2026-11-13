import { randomBytes } from 'node:crypto';

import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { Database } from '@coffre/db';
import { openDatabase } from '@coffre/db/connect';
import * as schema from '@coffre/db/schema';
import { getTableName, is, sql } from 'drizzle-orm';
import { PgTable } from 'drizzle-orm/pg-core';

import { keyOf } from '../src/rows.ts';
import { memoryOf, type Serving } from '../src/use.ts';

/**
 * The suite's database, which scripts/test-suite.sh prepares, opened twice:
 * as the vault, through the vault's own login, and as its owner, to play
 * someone who writes rows behind the vault.
 */
const name = process.env.COFFRE_TEST_DATABASE ?? 'coffre_test';
const url = (login: string) => `postgresql://${login}@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${name}`;

export type TestVault = Serving & {
  owner: Database;
  /** The hashes the signer was woken with, oldest first. */
  woken: Buffer[];
  /** Move the vault's clock on. */
  tick(ms: number): void;
  close(): Promise<void>;
};

/** The vault's own login's connection string. */
export const VAULT_URL = url('coffre_vault_runtime:local-vault-only');

export async function openTestVault(): Promise<TestVault> {
  const [owner, vault] = await Promise.all([openDatabase(url('coffre_owner:local-dev-only')), openDatabase(VAULT_URL)]);
  const woken: Buffer[] = [];
  let now = Date.UTC(2026, 10, 13, 12);
  return {
    db: vault.db,
    owner: owner.db,
    keys: [keyOf(randomBytes(32))],
    keks: new KekRegistry(LocalKekProvider.generate('test')),
    cap: { count: 1000, windowMs: 15 * 60_000 },
    workloads: { noReads: false, useOnly: false },
    memory: memoryOf(2),
    now: () => now,
    tick: (ms) => void (now += ms),
    wake: (hash) => void woken.push(hash),
    woken,
    close: async () => void (await Promise.all([owner.close(), vault.close()])),
  };
}

const TABLES = Object.values(schema).filter((value: unknown): value is PgTable => is(value, PgTable));

/** Every table emptied. */
export async function emptyDatabase(owner: Database): Promise<void> {
  await owner.execute(sql`TRUNCATE ${sql.join(TABLES.map((table) => sql.identifier(getTableName(table))), sql`, `)} RESTART IDENTITY CASCADE`);
}

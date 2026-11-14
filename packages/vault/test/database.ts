import { randomBytes } from 'node:crypto';
import { connect, createServer, type Server } from 'node:net';

import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { Database } from '@coffre/db';
import { openDatabase } from '@coffre/db/connect';
import * as schema from '@coffre/db/schema';
import { getTableName, is, sql } from 'drizzle-orm';
import { PgTable } from 'drizzle-orm/pg-core';

import { keyOf } from '../src/rows.ts';
import type { Store } from '../src/signer.ts';
import type { Storage } from '../src/signer-host.ts';
import { memoryOf, type Serving } from '../src/use.ts';

/**
 * The suite's database, which scripts/test-suite.sh prepares, opened twice:
 * as the vault, through the vault's own login, and as its owner, to play
 * someone who writes rows behind the vault.
 */
const name = process.env.COFFRE_TEST_DATABASE ?? 'coffre_test';
const url = (login: string) => `postgresql://${login}@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${name}`;

export type TestVault = Serving & {
  /** The Owners the deployment names, by email: none, unless told. */
  owners: readonly string[];
  owner: Database;
  /** The hashes the signer was woken with, oldest first. */
  woken: Buffer[];
  /** Move the vault's clock on. */
  tick(ms: number): void;
  close(): Promise<void>;
};

/** The vault's own login's connection string. */
export const VAULT_URL = url('coffre_vault_runtime:local-vault-only');
/** The app's own login's: it reads the tables a page lists, and writes none the vault seals. */
export const APP_URL = url('coffre_runtime:local-runtime-only');

/** `more` replaces what it names: the keys a deployment's configuration makes, or the clock, where another process reads what this one writes. */
export async function openTestVault(more: Partial<Serving & { owners: readonly string[] }> = {}): Promise<TestVault> {
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
    refused: new Map(),
    owners: [],
    now: () => now,
    tick: (ms) => void (now += ms),
    wake: (hash) => void woken.push(hash),
    woken,
    ...more,
    close: async () => void (await Promise.all([owner.close(), vault.close()])),
  };
}

/** The signer's storage, in memory: what a Durable Object's is in a deployment. `down` makes its writes fail. */
export function memoryStore() {
  const kept = new Map<string, unknown>();
  return {
    kept,
    down: false,
    read: async () => structuredClone(kept),
    async write(changes: ReadonlyMap<string, unknown>) {
      if (this.down) throw new Error('storage is down');
      for (const [key, value] of structuredClone(changes)) if (value === undefined) kept.delete(key);
      else kept.set(key, value);
    },
  } satisfies Store & Record<string, unknown>;
}

/**
 * A Durable Object's storage, in memory, as the signer's host uses it
 * (`Storage` in signer-host.ts). `down` makes its writes fail, `refuses` a
 * write to one key, `noAlarm` the setting of its alarm; `alarm` is when its alarm is set for, `sets` how often
 * it was set, and `syncs` how often it was asked to be on disk.
 */
export function objectStorage() {
  const kept = new Map<string, unknown>();
  const storage = {
    kept,
    down: false,
    refuses: null as string | null,
    noAlarm: false,
    alarm: null as number | null,
    sets: 0,
    syncs: 0,
    kv: {
      get: (key: string): unknown => structuredClone(kept.get(key)),
      list: (): [string, unknown][] => structuredClone([...kept]),
      put(key: string, value: unknown): void {
        if (key === storage.refuses) throw new Error(`storage refuses ${key}`);
        kept.set(key, structuredClone(value));
      },
      delete: (key: string): boolean => kept.delete(key),
    },
    transactionSync<T>(run: () => T): T {
      if (storage.down) throw new Error('storage is down');
      const before = new Map(kept);
      try {
        return run();
      } catch (error) {
        kept.clear();
        for (const [key, value] of before) kept.set(key, value);
        throw error;
      }
    },
    async sync(): Promise<void> {
      if (storage.down) throw new Error('storage is down');
      storage.syncs += 1;
    },
    getAlarm: async (): Promise<number | null> => storage.alarm,
    async setAlarm(at: number): Promise<void> {
      if (storage.noAlarm) throw new Error('the alarm cannot be set');
      storage.alarm = at;
      storage.sets += 1;
    },
  };
  return storage satisfies Storage;
}

const TABLES = (Object.values(schema) as unknown[]).filter((value): value is PgTable => is(value, PgTable));

/** Every table emptied. */
export async function emptyDatabase(owner: Database): Promise<void> {
  await owner.execute(sql`TRUNCATE ${sql.join(TABLES.map((table) => sql.identifier(getTableName(table))), sql`, `)} RESTART IDENTITY CASCADE`);
}

/**
 * Postgres as Hyperdrive serves it from far away: each chunk either way
 * delayed by `ms`. Locally a query answers in well under a millisecond,
 * which hides calls waiting on each other's I/O. `opened` counts the
 * connections made to it.
 */
export async function slowPostgres(ms: number, to: string = VAULT_URL): Promise<{ url: string; readonly opened: number; close(): Promise<void> }> {
  const target = new URL(to);
  let opened = 0;
  const server: Server = createServer((client) => {
    opened += 1;
    const upstream = connect(Number(target.port), target.hostname);
    const relay = (from: NodeJS.ReadableStream, to: NodeJS.WritableStream) =>
      from.on('data', (chunk) => setTimeout(() => to.write(chunk), ms));
    relay(client, upstream);
    relay(upstream, client);
    const end = () => {
      client.destroy();
      upstream.destroy();
    };
    client.on('close', end).on('error', end);
    upstream.on('close', end).on('error', end);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as { port: number };
  const url = new URL(to);
  url.port = String(address.port);
  return {
    url: url.href,
    get opened() {
      return opened;
    },
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

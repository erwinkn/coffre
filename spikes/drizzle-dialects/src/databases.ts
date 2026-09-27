import { fileURLToPath } from 'node:url';

import { createClient } from '@libsql/client';
import { eq } from 'drizzle-orm';
import { drizzle as drizzleLibsql } from 'drizzle-orm/libsql';
import { migrate as migrateLibsql } from 'drizzle-orm/libsql/migrator';
import { drizzle as drizzleMysql } from 'drizzle-orm/mysql2';
import { migrate as migrateMysql } from 'drizzle-orm/mysql2/migrator';
import { drizzle as drizzlePostgres } from 'drizzle-orm/node-postgres';
import { migrate as migratePostgres } from 'drizzle-orm/node-postgres/migrator';
import mysql from 'mysql2/promise';
import pg from 'pg';

import type { AuditHead, NewProject } from './model.ts';
import {
  asLogicalDatabase,
  asLogicalSchema,
  asLogicalTransaction,
  type LogicalTransaction,
} from './portable.ts';
import type { DialectOperations } from './queries.ts';
import * as mysqlSchema from './schema.mysql.ts';
import * as postgresSchema from './schema.postgres.ts';
import * as sqliteSchema from './schema.sqlite.ts';

const spikeRoot = fileURLToPath(new URL('..', import.meta.url));

async function lockedHead(
  tx: LogicalTransaction,
  schema: ReturnType<typeof asLogicalSchema>,
): Promise<AuditHead> {
  const rows = await tx
    .select({ nextSeq: schema.auditChainHead.nextSeq, headHash: schema.auditChainHead.headHash })
    .from(schema.auditChainHead)
    .where(eq(schema.auditChainHead.onlyRow, 1))
    .for('update');
  if (!rows[0]) throw new Error('audit chain head is missing');
  return rows[0];
}

function sqliteHead(
  tx: LogicalTransaction,
  schema: ReturnType<typeof asLogicalSchema>,
): Promise<AuditHead> {
  return tx
    .select({ nextSeq: schema.auditChainHead.nextSeq, headHash: schema.auditChainHead.headHash })
    .from(schema.auditChainHead)
    .where(eq(schema.auditChainHead.onlyRow, 1))
    .then((rows) => {
      if (!rows[0]) throw new Error('audit chain head is missing');
      return rows[0];
    });
}

export async function connectPostgres(): Promise<DialectOperations> {
  const pool = new pg.Pool({
    connectionString: process.env.SPIKE_POSTGRES_URL
      ?? 'postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/coffre_spike_drizzle',
    max: 12,
  });
  const actual = drizzlePostgres(pool, { schema: postgresSchema });
  await migratePostgres(actual, { migrationsFolder: `${spikeRoot}/migrations/postgres` });

  return {
    name: 'postgres',
    database: actual,
    schema: postgresSchema,
    transaction: (callback) => actual.transaction((tx) => callback(asLogicalTransaction(tx))),
    lockAuditHead: (tx) => lockedHead(tx, postgresSchema),
    async upsertProject(project) {
      await actual
        .insert(postgresSchema.projects)
        .values(project)
        .onConflictDoUpdate({
          target: postgresSchema.projects.slug,
          set: { name: project.name },
        });
    },
    close: () => pool.end(),
  };
}

export async function connectMysql(): Promise<DialectOperations> {
  const pool = mysql.createPool({
    uri: process.env.SPIKE_MYSQL_URL
      ?? 'mysql://root:coffre-spike-only@127.0.0.1:53306/coffre_spike_drizzle',
    connectionLimit: 12,
    timezone: 'Z',
  });
  const actual = drizzleMysql(pool, { schema: mysqlSchema, mode: 'default' });
  await migrateMysql(actual, { migrationsFolder: `${spikeRoot}/migrations/mysql` });

  const schema = asLogicalSchema(mysqlSchema);
  return {
    name: 'mysql',
    database: asLogicalDatabase(actual),
    schema,
    transaction: (callback) => actual.transaction((tx) => callback(asLogicalTransaction(tx))),
    lockAuditHead: (tx) => lockedHead(tx, schema),
    async upsertProject(project: NewProject) {
      await actual
        .insert(mysqlSchema.projects)
        .values(project)
        .onDuplicateKeyUpdate({ set: { name: project.name } });
    },
    close: () => pool.end(),
  };
}

export async function connectSqlite(): Promise<DialectOperations> {
  const client = createClient({ url: `file:${spikeRoot}/prototype.sqlite` });
  const actual = drizzleLibsql(client, { schema: sqliteSchema });
  await migrateLibsql(actual, { migrationsFolder: `${spikeRoot}/migrations/sqlite` });

  const schema = asLogicalSchema(sqliteSchema);
  let writer = Promise.resolve();

  async function transaction<T>(callback: (tx: LogicalTransaction) => Promise<T>): Promise<T> {
    const previous = writer;
    let release = () => {};
    writer = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await actual.transaction((tx) => callback(asLogicalTransaction(tx)));
    } finally {
      release();
    }
  }

  return {
    name: 'sqlite',
    database: asLogicalDatabase(actual),
    schema,
    transaction,
    lockAuditHead: (tx) => sqliteHead(tx, schema),
    async upsertProject(project: NewProject) {
      await actual
        .insert(sqliteSchema.projects)
        .values(project)
        .onConflictDoUpdate({
          target: sqliteSchema.projects.slug,
          set: { name: project.name },
        });
    },
    async close() {
      client.close();
    },
  };
}

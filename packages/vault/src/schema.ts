import { sql } from 'drizzle-orm';
import { index, integer, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core';

/**
 * The vault's store: who is in, what they hold, what it signed, and its log.
 * One SQLite database the app has no credentials for: a Durable Object's on
 * Workers, a file of the vault's own in a Node process.
 *
 * Times are milliseconds since the epoch. Principals are the strings the
 * app writes in URLs: `user:ada@acme.example`, `token:ci-deploy`, and
 * `sync:<id>` for a sync.
 */

/** Everyone the vault has admitted. A principal with no row is no member. */
export const principals = sqliteTable('principals', {
  principal: text('principal').primaryKey(),
  status: text('status', { enum: ['active', 'removed'] }).notNull(),
  /** An instance owner: manages every project and every member. Users only. */
  owner: integer('owner', { mode: 'boolean' }).notNull().default(false),
  /** When the status last changed, and who changed it. */
  since: integer('since').notNull(),
  by: text('by').notNull(),
});

/**
 * One role per principal per place: a project (`environment_id` null) or one
 * of its environments. A revoked grant is deleted; an expired one stays until
 * the place is granted again, so the members page can say it lapsed.
 */
export const grants = sqliteTable(
  'grants',
  {
    principal: text('principal').notNull(),
    projectId: text('project_id').notNull(),
    environmentId: text('environment_id'),
    role: text('role').notNull(),
    expiresAt: integer('expires_at'),
    grantedAt: integer('granted_at').notNull(),
    grantedBy: text('granted_by').notNull(),
  },
  (table) => [
    uniqueIndex('grants_on_project')
      .on(table.principal, table.projectId)
      .where(sql`${table.environmentId} IS NULL`),
    uniqueIndex('grants_on_environment')
      .on(table.principal, table.environmentId)
      .where(sql`${table.environmentId} IS NOT NULL`),
  ],
);

/**
 * The vault's log. Each row commits to the one before it (`hash` is
 * SHA-256 over `prev_hash` and the row), and the only code that touches
 * this table appends. Triggers refuse UPDATE and DELETE besides, so a bug
 * cannot rewrite it either; only someone holding the raw storage can, and
 * the chain shows it.
 */
export const log = sqliteTable(
  'log',
  {
    seq: integer('seq').primaryKey(),
    at: integer('at').notNull(),
    /** Who asked: the principal an unwrap is for, or who changed access. */
    actor: text('actor').notNull(),
    action: text('action').notNull(),
    outcome: text('outcome', { enum: ['allow', 'refuse'] }).notNull(),
    /** Why a refusal was one. */
    code: text('code'),
    /** What it was about: a secret's path, a principal, the app's log. */
    subject: text('subject'),
    /** Everything else, as JSON: ids, roles, the purpose of a read. */
    detail: text('detail').notNull(),
    prevHash: text('prev_hash').notNull(),
    hash: text('hash').notNull(),
  },
  // The bulk limit counts one principal's recent unwraps.
  (table) => [index('log_by_actor').on(table.actor, table.action, table.at)],
);

/** Heads of the app's audit log the vault has signed, newest last. */
export const checkpoints = sqliteTable('checkpoints', {
  /** The app log's last sequence number at this head. */
  seq: integer('seq').primaryKey(),
  headHash: text('head_hash').notNull(),
  signedAt: integer('signed_at').notNull(),
  keyId: text('key_id').notNull(),
  signature: text('signature').notNull(),
});

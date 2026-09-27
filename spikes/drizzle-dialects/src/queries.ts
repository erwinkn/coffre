import { createHash } from 'node:crypto';

import { and, count, desc, eq, isNull } from 'drizzle-orm';

import type { AuditHead, AuditInput, NewProject } from './model.ts';
import type {
  LogicalDatabase,
  LogicalSchema,
  LogicalTransaction,
} from './portable.ts';

export type DialectOperations = {
  readonly name: 'postgres' | 'mysql' | 'sqlite';
  readonly database: LogicalDatabase;
  readonly schema: LogicalSchema;
  transaction<T>(callback: (tx: LogicalTransaction) => Promise<T>): Promise<T>;
  lockAuditHead(tx: LogicalTransaction): Promise<AuditHead>;
  upsertProject(project: NewProject): Promise<void>;
  close(): Promise<void>;
};

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`);
  return `{${entries.join(',')}}`;
}

function auditHash(previous: Buffer, row: {
  seq: number;
  occurredAt: Date;
  actorId: string;
  action: string;
  metadata: Record<string, unknown>;
}): Buffer {
  return createHash('sha256')
    .update(previous)
    .update(canonicalJson({
      seq: row.seq,
      occurredAt: row.occurredAt.toISOString(),
      actorId: row.actorId,
      action: row.action,
      metadata: row.metadata,
    }))
    .digest();
}

export function createQueries(operations: DialectOperations) {
  const { database, schema } = operations;

  return {
    async reset(): Promise<void> {
      await database.delete(schema.auditLog);
      await database.delete(schema.auditChainHead);
      await database.delete(schema.secretVersions);
      await database.delete(schema.secrets);
      await database.delete(schema.environments);
      await database.delete(schema.projects);
    },

    async initializeAuditHead(): Promise<void> {
      await database.insert(schema.auditChainHead).values({
        onlyRow: 1,
        nextSeq: 0,
        headHash: Buffer.alloc(32),
        updatedAt: new Date(),
      });
    },

    async insertProject(project: NewProject): Promise<string> {
      await database.insert(schema.projects).values(project);
      return project.id;
    },

    async insertFixture(input: {
      environment: {
        id: string;
        projectId: string;
        slug: string;
        name: string;
        createdAt: Date;
      };
      secret: {
        id: string;
        projectId: string;
        environmentId: string;
        key: string;
        createdAt: Date;
      };
      version: {
        id: string;
        secretId: string;
        version: number;
        ciphertext: Buffer;
        wrappedDek: Buffer;
        createdAt: Date;
      };
    }): Promise<void> {
      await operations.transaction(async (tx) => {
        await tx.insert(schema.environments).values(input.environment);
        await tx.insert(schema.secrets).values(input.secret);
        await tx.insert(schema.secretVersions).values(input.version);
        await tx
          .update(schema.secrets)
          .set({ currentVersionId: input.version.id })
          .where(eq(schema.secrets.id, input.secret.id));
      });
    },

    async findCurrentSecret(projectSlug: string, environmentSlug: string, key: string) {
      const rows = await database
        .select({
          project: schema.projects.slug,
          environment: schema.environments.slug,
          key: schema.secrets.key,
          version: schema.secretVersions.version,
          ciphertext: schema.secretVersions.ciphertext,
        })
        .from(schema.projects)
        .innerJoin(schema.environments, eq(schema.environments.projectId, schema.projects.id))
        .innerJoin(schema.secrets, eq(schema.secrets.environmentId, schema.environments.id))
        .innerJoin(
          schema.secretVersions,
          eq(schema.secretVersions.id, schema.secrets.currentVersionId),
        )
        .where(and(
          eq(schema.projects.slug, projectSlug),
          eq(schema.environments.slug, environmentSlug),
          eq(schema.secrets.key, key),
          isNull(schema.projects.archivedAt),
          isNull(schema.environments.archivedAt),
          isNull(schema.secrets.archivedAt),
        ));

      return rows[0] ?? null;
    },

    async countSecrets(environmentId: string): Promise<number> {
      const rows = await database
        .select({ total: count() })
        .from(schema.secrets)
        .where(and(
          eq(schema.secrets.environmentId, environmentId),
          isNull(schema.secrets.archivedAt),
        ));
      return rows[0]?.total ?? 0;
    },

    upsertProject(project: NewProject): Promise<void> {
      return operations.upsertProject(project);
    },

    async appendAudit(input: AuditInput): Promise<{ seq: number; hash: Buffer }> {
      return operations.transaction(async (tx) => {
        const head = await operations.lockAuditHead(tx);
        const occurredAt = new Date();
        const hash = auditHash(head.headHash, {
          seq: head.nextSeq,
          occurredAt,
          actorId: input.actorId,
          action: input.action,
          metadata: input.metadata,
        });

        await tx.insert(schema.auditLog).values({
          seq: head.nextSeq,
          id: input.id,
          occurredAt,
          actorId: input.actorId,
          action: input.action,
          metadata: input.metadata,
          prevHash: head.headHash,
          hash,
        });
        await tx
          .update(schema.auditChainHead)
          .set({ nextSeq: head.nextSeq + 1, headHash: hash, updatedAt: occurredAt })
          .where(eq(schema.auditChainHead.onlyRow, 1));

        return { seq: head.nextSeq, hash };
      });
    },

    async readAudit() {
      return database
        .select()
        .from(schema.auditLog)
        .orderBy(schema.auditLog.seq);
    },

    async readAuditNewestFirst() {
      return database
        .select({ seq: schema.auditLog.seq, metadata: schema.auditLog.metadata })
        .from(schema.auditLog)
        .orderBy(desc(schema.auditLog.seq));
    },
  };
}

export function verifyLinearChain(rows: Awaited<ReturnType<ReturnType<typeof createQueries>['readAudit']>>): boolean {
  let expectedPrevious: Buffer = Buffer.alloc(32);
  for (const [index, row] of rows.entries()) {
    if (row.seq !== index || !row.prevHash.equals(expectedPrevious)) return false;
    const expectedHash = auditHash(expectedPrevious, row);
    if (!row.hash.equals(expectedHash)) return false;
    expectedPrevious = row.hash;
  }
  return true;
}

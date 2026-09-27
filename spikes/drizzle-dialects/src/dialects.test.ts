import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';

import {
  connectMysql,
  connectPostgres,
  connectSqlite,
} from './databases.ts';
import { createQueries, verifyLinearChain, type DialectOperations } from './queries.ts';

const connectors = [connectPostgres, connectMysql, connectSqlite] as const;

for (const connect of connectors) {
  test(`${connect.name.replace('connect', '').toLowerCase()}: the shared queries and concurrent audit append work`, async () => {
    const operations: DialectOperations = await connect();
    const queries = createQueries(operations);
    try {
      await queries.reset();
      await queries.initializeAuditHead();

      const createdAt = new Date('2026-09-27T12:00:00.000Z');
      const projectId = randomUUID();
      const environmentId = randomUUID();
      const secretId = randomUUID();
      const versionId = randomUUID();
      // Larger than MySQL BLOB's 65,535-byte ceiling. Coffre accepts a 64 KiB
      // string before UTF-8 encoding and encryption overhead.
      const ciphertext = Buffer.alloc(70 * 1024, 0x63);

      assert.equal(await queries.insertProject({
        id: projectId,
        slug: 'market',
        name: 'Market',
        createdAt,
      }), projectId);

      await queries.insertFixture({
        environment: {
          id: environmentId,
          projectId,
          slug: 'prod',
          name: 'Production',
          createdAt,
        },
        secret: {
          id: secretId,
          projectId,
          environmentId,
          key: 'DATABASE_URL',
          createdAt,
        },
        version: {
          id: versionId,
          secretId,
          version: 1,
          ciphertext,
          wrappedDek: Buffer.from('wrapped-dek'),
          createdAt,
        },
      });

      assert.deepEqual(await queries.findCurrentSecret('market', 'prod', 'DATABASE_URL'), {
        project: 'market',
        environment: 'prod',
        key: 'DATABASE_URL',
        version: 1,
        ciphertext,
      });
      assert.equal(await queries.countSecrets(environmentId), 1);

      await queries.upsertProject({
        id: randomUUID(),
        slug: 'market',
        name: 'Market renamed',
        createdAt,
      });
      assert.equal(
        (await operations.database
          .select({ name: operations.schema.projects.name })
          .from(operations.schema.projects))[0]?.name,
        'Market renamed',
      );

      const appends = Array.from({ length: 24 }, (_, index) => queries.appendAudit({
        id: randomUUID(),
        actorId: `user:${index % 3}`,
        action: 'secret.read',
        // Deliberately not key-sorted: PostgreSQL jsonb and MySQL JSON may
        // return a different object order than the application supplied.
        metadata: { z: index, nested: { dialect: operations.name }, a: 'first' },
      }));
      await Promise.all(appends);

      const audit = await queries.readAudit();
      assert.equal(audit.length, 24);
      assert.equal(verifyLinearChain(audit), true);
      const newest = (await queries.readAuditNewestFirst())[0];
      assert.equal(newest?.seq, 23);
      assert.equal((newest?.metadata.nested as { dialect?: unknown }).dialect, operations.name);
    } finally {
      await operations.close();
    }
  });
}

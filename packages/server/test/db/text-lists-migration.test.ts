import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { deriveKey } from '@coffre/core/identity';
import { postgresClient } from '@coffre/db/connect';
import { migrateDatabase, migrationsFolder } from '@coffre/db/migrate';

import { signedBy } from '../../src/auth-rows.ts';
import { TEST_OWNER_DATABASE_URL } from './connections.ts';

/**
 * 0084_text_lists (T278): a client's redirects and a passkey's transports, JSON text before, are text[] after, the
 * same strings in the same order, and a client registered before still carries its MAC: the app signs the list as the
 * JSON text the column held.
 */

const TAG = '0084_text_lists';
const CLIENT = '77777777-7777-4777-8777-777777777777';
const REDIRECTS = ['https://claude.ai/api/mcp/auth_callback', 'http://127.0.0.1:33418/'];

/** The three columns as 0083 left them, and the ledger without 0084: what `coffre migrate` finds on 0.15.0's schema. */
const BEFORE = [
  `DELETE FROM drizzle.__drizzle_migrations WHERE created_at = ${JSON.parse(readFileSync(join(migrationsFolder(), 'meta/_journal.json'), 'utf8')).entries.find((entry: { tag: string }) => entry.tag === TAG).when}`,
  `ALTER TABLE oauth_clients ALTER COLUMN redirect_uris TYPE text USING to_jsonb(redirect_uris)::text`,
  `ALTER TABLE oauth_clients ADD CONSTRAINT oauth_clients_redirect_uris_check CHECK (redirect_uris::jsonb IS NOT NULL)`,
  `ALTER TABLE passkeys ALTER COLUMN transports DROP DEFAULT`,
  `ALTER TABLE passkeys ALTER COLUMN transports TYPE text USING to_jsonb(transports)::text`,
  `ALTER TABLE passkeys ALTER COLUMN transports SET DEFAULT '[]'`,
  `ALTER TABLE passkeys ADD CONSTRAINT passkeys_transports_check CHECK (jsonb_typeof(transports::jsonb) = 'array')`,
  `ALTER TABLE proxy_reserved ALTER COLUMN names TYPE jsonb USING to_jsonb(names)`,
  `ALTER TABLE proxy_reserved ADD CONSTRAINT proxy_reserved_names_check CHECK (jsonb_typeof(names) = 'array')`,
];

/** A client's MAC as 0.15.0 made it, by hand: its redirects the column's JSON text, inside the tuple's JSON. */
function macBefore(chainKey: Buffer, redirects: string): Buffer {
  const tuple = JSON.stringify(['coffre.auth.v2', 'oauth_clients', CLIENT, 'Claude', redirects, null]);
  return createHmac('sha256', deriveKey(chainKey, 'signin-rows/v1')).update(tuple).digest();
}

test(`${TAG} turns the JSON lists into text[], and a client registered before keeps its MAC`, async (t) => {
  const db = postgresClient(TEST_OWNER_DATABASE_URL, { max: 1 });
  t.after(() => db.end());
  const chainKey = randomBytes(32);

  for (const statement of BEFORE) await db.unsafe(statement);
  const redirects = JSON.stringify(REDIRECTS);
  await db.unsafe(`INSERT INTO oauth_clients (id, auth_mac, name, redirect_uris) VALUES ($1, $2, 'Claude', $3)`, [CLIENT, macBefore(chainKey, redirects), redirects]);
  await db.unsafe(`INSERT INTO principals (principal, status, owner, generation, created_at, created_by, status_changed_at, status_changed_by, access_seq, mac)
    VALUES ('user:ada@acme.example', 'active', true, 1, 1, 'setup', 1, 'setup', 1, $1)`, [randomBytes(32)]);
  const passkey = (id: string, byte: number) => db.unsafe(`
    INSERT INTO passkeys (id, auth_mac, principal, generation, user_handle, credential_id, public_key, algorithm, synced, name, created_by)
    VALUES ($1, $2, 'user:ada@acme.example', 1, $3, $3, $4, -7, true, 'Key', 'system:signin')`, [id, randomBytes(32), Buffer.alloc(16, byte), Buffer.alloc(8, byte)]);
  await passkey('88888888-8888-4888-8888-888888888881', 1);
  await passkey('88888888-8888-4888-8888-888888888882', 2);
  await db.unsafe(`UPDATE passkeys SET transports = '["hybrid","internal"]' WHERE id = '88888888-8888-4888-8888-888888888882'`);

  await migrateDatabase(TEST_OWNER_DATABASE_URL);

  const [client] = await db.unsafe(`SELECT id, name, redirect_uris, auth_mac FROM oauth_clients`);
  assert.deepEqual(client!.redirect_uris, REDIRECTS);
  const row = { id: client!.id as string, name: client!.name as string, redirectUris: client!.redirect_uris as string[], revokedAt: null, authMac: Buffer.from(client!.auth_mac as Uint8Array) };
  assert.ok(signedBy(chainKey, 'oauth_clients', row), 'the client signed before checks after');
  assert.equal(signedBy(chainKey, 'oauth_clients', { ...row, redirectUris: [...REDIRECTS, 'https://evil.example/cb'] }), false);

  const keys = await db.unsafe(`SELECT transports FROM passkeys ORDER BY id`);
  assert.deepEqual(keys.map((key) => key.transports), [[], ['hybrid', 'internal']]);
});

// upgrade-check.mjs's `lists`: on a 0.15.0 database, the OAuth clients whose redirects 0084 would cut, by id.
import test from 'node:test';
import assert from 'node:assert/strict';

import { postgresSession } from '@coffre/db/connect';

import { brokenLists } from './upgrade-check.mjs';

const url = `postgresql://coffre_owner:local-dev-only@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${process.env.COFFRE_TEST_DATABASE ?? 'coffre_test'}`;

test('a client whose redirects are not a JSON array of strings is named; an array of strings, empty or not, passes', async () => {
    const sql = postgresSession(url);
    try {
        // 0.15.0's column, JSON as text, in a schema of the test's own: this database is already past 0084.
        await sql.unsafe('CREATE SCHEMA upgrade_lists');
        await sql.unsafe('SET search_path TO upgrade_lists');
        await sql.unsafe('CREATE TABLE oauth_clients (id text PRIMARY KEY, redirect_uris text NOT NULL)');
        const rows = {
            mixed: '["https://a.example/cb", 1]',
            object: '{"a": 1}',
            string: '"https://a.example/cb"',
            empty: '[]',
            strings: '["https://a.example/cb", "https://b.example/cb"]',
        };
        for (const [id, redirects] of Object.entries(rows)) {
            await sql.unsafe('INSERT INTO oauth_clients VALUES ($1, $2)', [id, redirects]);
        }
        assert.deepEqual(await brokenLists(sql), ['mixed', 'object', 'string']);
        await sql.unsafe("DELETE FROM oauth_clients WHERE id IN ('mixed', 'object', 'string')");
        assert.deepEqual(await brokenLists(sql), []);
    } finally {
        await sql.unsafe('DROP SCHEMA IF EXISTS upgrade_lists CASCADE');
        await sql.end();
    }
});

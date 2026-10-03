import assert from 'node:assert/strict';
import test from 'node:test';
import pg from 'pg';
import { cloneDatabase, removeDatabases } from './test-databases.mjs';

function owner(t, databases = []) {
    const queries = [];
    let closed = false;
    t.mock.method(pg.Client.prototype, 'connect', async () => {});
    t.mock.method(pg.Client.prototype, 'end', async () => { closed = true; });
    t.mock.method(pg.Client.prototype, 'query', async (sql) => {
        queries.push(sql);
        return { rows: databases.map((datname) => ({ datname })) };
    });
    return { queries, closed: () => closed };
}

test('a clone preserves schema grants and restricts its new database ACL', async (t) => {
    const { queries, closed } = owner(t);
    await cloneDatabase('coffre_template', 'coffre_worker');
    assert.deepEqual(queries, [
        'CREATE DATABASE "coffre_worker" TEMPLATE "coffre_template"',
        'REVOKE CREATE, TEMPORARY ON DATABASE "coffre_worker" FROM PUBLIC, coffre_app, coffre_runtime, coffre_vault, coffre_vault_runtime',
    ]);
    assert.ok(closed());
});

test('cleanup removes only this random run and its numeric worker suffixes', async (t) => {
    const template = 'coffre_other_checkout_0123456789abcdef';
    const { queries, closed } = owner(t, [
        'coffre', 'coffre_test', template, `${template}_123`,
        `${template}_123_other`, `${template}0`, 'coffre_other_checkout_fedcba9876543210_123',
    ]);
    await removeDatabases(template);
    assert.deepEqual(queries.slice(1), [
        `DROP DATABASE "${template}" WITH (FORCE)`,
        `DROP DATABASE "${template}_123" WITH (FORCE)`,
    ]);
    assert.ok(closed());
});

test('cleanup refuses an ordinary database name before connecting', async (t) => {
    const { queries } = owner(t);
    await assert.rejects(removeDatabases('coffre_test'), /not a test run template/);
    assert.deepEqual(queries, []);
});

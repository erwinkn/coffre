import assert from 'node:assert/strict';
import test from 'node:test';
import pg from 'pg';
import { restrictDatabase } from '@coffre/db/migrate';
import { cloneDatabase, removeDatabases } from './test-databases.mjs';

function owner(t, databases = []) {
    const queries = [];
    const connected = [];
    const closed = [];
    t.mock.method(pg.Client.prototype, 'connect', async function () { connected.push(this.database); });
    t.mock.method(pg.Client.prototype, 'end', async function () { closed.push(this.database); });
    t.mock.method(pg.Client.prototype, 'query', async (sql) => {
        queries.push(sql);
        return { rows: databases.map((datname) => ({ datname })) };
    });
    return { queries, connected, closed };
}

test('a clone preserves schema grants and restricts its new database ACL', async (t) => {
    const { queries, connected, closed } = owner(t);
    const restriction = [];
    await restrictDatabase({ query: async (sql) => { restriction.push(sql); } });
    assert.equal(restriction.length, 1);
    await cloneDatabase('coffre_template', 'coffre_worker');
    assert.deepEqual(queries, [
        'CREATE DATABASE "coffre_worker" TEMPLATE "coffre_template"',
        ...restriction,
    ]);
    assert.deepEqual(connected, ['postgres', 'coffre_worker']);
    assert.deepEqual(closed, connected);
});

test('cleanup removes only this random run and its numeric worker suffixes', async (t) => {
    const template = 'coffre_other_checkout_0123456789abcdef';
    const { queries, connected, closed } = owner(t, [
        'coffre', 'coffre_test', template, `${template}_123`,
        `${template}_123_other`, `${template}0`, 'coffre_other_checkout_fedcba9876543210_123',
    ]);
    await removeDatabases(template);
    assert.deepEqual(queries.slice(1), [
        `DROP DATABASE "${template}" WITH (FORCE)`,
        `DROP DATABASE "${template}_123" WITH (FORCE)`,
    ]);
    assert.deepEqual(closed, connected);
});

test('cleanup refuses an ordinary database name before connecting', async (t) => {
    const { queries } = owner(t);
    await assert.rejects(removeDatabases('coffre_test'), /not a test run template/);
    assert.deepEqual(queries, []);
});

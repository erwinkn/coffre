// upgrade-check.mjs's `refusals`, on a 0.15.0 database: the OAuth clients whose redirects 0084 would cut, by id, and
// the losses the log accepted, by seq, the members a tamper finding stands for, and the environments the newest
// policy.change and their rows disagree on protecting, and the trust bindings 0.14's tombstone and 0.16's log disagree on.
import test from 'node:test';
import assert from 'node:assert/strict';

import { postgresSession } from '@coffre/db/connect';

import { acceptedLosses, bindingsDiffer, brokenLists, disagreeing, standingFindings } from './upgrade-check.mjs';

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

test('the losses the log accepted are named by seq; other entries pass', async () => {
    const sql = postgresSession(url);
    try {
        // The columns the check reads, in a schema of the test's own.
        await sql.unsafe('CREATE SCHEMA upgrade_losses');
        await sql.unsafe('SET search_path TO upgrade_losses');
        await sql.unsafe('CREATE TABLE audit_log (seq bigint PRIMARY KEY, action text NOT NULL)');
        await sql.unsafe("INSERT INTO audit_log VALUES (1, 'secret.write'), (2, 'audit.heartbeat'), (3, 'audit.finding'), (4, 'audit.loss_unapplied')");
        assert.deepEqual(await acceptedLosses(sql), []);
        await sql.unsafe("INSERT INTO audit_log VALUES (10, 'audit.loss_accepted'), (9, 'audit.loss_accepted')");
        assert.deepEqual(await acceptedLosses(sql), ['9', '10']);
    } finally {
        await sql.unsafe('DROP SCHEMA IF EXISTS upgrade_losses CASCADE');
        await sql.end();
    }
});

test('the members a tamper finding stands for are named; one settled by a later change of theirs is not', async () => {
    const sql = postgresSession(url);
    try {
        // 0.15.0's columns the rule reads, in a schema of the test's own; 0.15.0 writes 0.14's findings, which name no change.
        await sql.unsafe('CREATE SCHEMA upgrade_findings');
        await sql.unsafe('SET search_path TO upgrade_findings');
        await sql.unsafe('CREATE TABLE audit_log (seq bigint PRIMARY KEY, author text, action text, decision text, code text, metadata text, subject_principal text)');
        await sql.unsafe('CREATE TABLE log_changes (number bigint PRIMARY KEY, object uuid NOT NULL, mac bytea NOT NULL)');
        const entry = (seq, action, principal, code = null) => sql.unsafe(
            "INSERT INTO audit_log VALUES ($1, 'vault', $2, 'allow', $3, NULL, $4)", [seq, action, code, principal]);
        assert.deepEqual(await standingFindings(sql), []);
        await entry(1, 'member.add', 'user:olga@acme.example');
        await entry(2, 'member.add', 'user:piet@acme.example');
        await entry(3, 'vault.tampered', 'user:olga@acme.example', 'mac');
        await entry(4, 'vault.tampered', 'user:piet@acme.example', 'stale');
        await entry(5, 'member.role', 'user:piet@acme.example');
        assert.deepEqual(await standingFindings(sql), ['user:olga@acme.example']);
    } finally {
        await sql.unsafe('DROP SCHEMA IF EXISTS upgrade_findings CASCADE');
        await sql.end();
    }
});

test('the environments the newest policy.change and their rows disagree on protecting are named; a fork never written or a deleted one is not', async () => {
    const sql = postgresSession(url);
    const id = (n) => `00000000-0000-4000-8000-00000000000${n}`;
    try {
        await sql.unsafe('CREATE SCHEMA upgrade_policy');
        await sql.unsafe('SET search_path TO upgrade_policy');
        await sql.unsafe('CREATE TABLE audit_log (seq bigint PRIMARY KEY, author text, action text, decision text, metadata text)');
        await sql.unsafe('CREATE TABLE projects (id uuid PRIMARY KEY, slug text)');
        await sql.unsafe('CREATE TABLE environments (id uuid PRIMARY KEY, project_id uuid, slug text, protected boolean)');
        await sql.unsafe(`INSERT INTO projects VALUES ('${id(0)}', 'market'), ('${id(9)}', 'old~1')`);
        // 1 protected by both; 2 by the entry alone; 3 by its row alone; 4 a fork's id, no row; 5 deleted; 6 in a deleted project.
        await sql.unsafe(`INSERT INTO environments VALUES ('${id(1)}', '${id(0)}', 'prod', true), ('${id(2)}', '${id(0)}', 'staging', false),
            ('${id(3)}', '${id(0)}', 'dev', true), ('${id(5)}', '${id(0)}', 'qa~1', false), ('${id(6)}', '${id(9)}', 'prod', NULL)`);
        assert.deepEqual(await disagreeing(sql), [id(1), id(3)], 'no entry protects nothing');
        const listed = [1, 2, 4, 5, 6].map((n) => ({ projectId: id(n === 6 ? 9 : 0), environmentId: id(n), at: 1 }));
        const entry = (seq, metadata) => sql.unsafe("INSERT INTO audit_log VALUES ($1, 'vault', 'policy.change', 'allow', $2)", [seq, metadata]);
        await entry(1, JSON.stringify({ policy: { roles: {}, instanceRoles: {}, protected: listed } }));
        assert.deepEqual(await disagreeing(sql), [id(2), id(3)]);
        await entry(2, '{"policy":{"protected":"all"}}');
        assert.equal(await disagreeing(sql), null);
    } finally {
        await sql.unsafe('DROP SCHEMA IF EXISTS upgrade_policy CASCADE');
        await sql.end();
    }
});

test('a binding 0.14 ended that the log calls live is revived; one live on 0.15.0 the log ends is dropped; the four ordinary lives are neither', async () => {
    const sql = postgresSession(url);
    const id = (n) => `00000000-0000-4000-8000-00000000000${n}`;
    const seal = (n) => Buffer.alloc(16, n);
    try {
        await sql.unsafe('CREATE SCHEMA upgrade_bindings');
        await sql.unsafe('SET search_path TO upgrade_bindings');
        await sql.unsafe('CREATE TABLE audit_log (seq bigserial, author text, action text, decision text, metadata text)');
        await sql.unsafe('CREATE TABLE log_changes (number bigserial, object uuid, payload text, seal bytea)');
        await sql.unsafe('CREATE TABLE service_bindings (id uuid, seal bytea, revoked_at timestamptz)');
        // 0.15.0's own, 0022_log_015.
        await sql.unsafe(`CREATE FUNCTION log_object(p_kind text, p_id text) RETURNS uuid LANGUAGE sql AS $$ SELECT encode(substr(sha256(
            '\\x636f666672652e6f626a6563742e763100'::bytea || convert_to(p_kind, 'UTF8') || '\\x00'::bytea || convert_to(p_id, 'UTF8')), 1, 16), 'hex')::uuid $$`);
        const binding = (n, sealed, revoked) => sql.unsafe('INSERT INTO service_bindings VALUES ($1, $2, $3)', [id(n), sealed, revoked ? new Date() : null]);
        const unbind = (n) => sql.unsafe("INSERT INTO audit_log (author, action, decision, metadata) VALUES ('app', 'token.unbind', 'allow', $1)", [JSON.stringify({ bindingId: id(n) })]);
        const change = (n, op, sealed) => sql.unsafe("INSERT INTO log_changes (object, payload, seal) VALUES (log_object('binding', $1), $2, $3)", [id(n), JSON.stringify({ op }), sealed]);
        await binding(1, null, true); await unbind(1); // ended by 0.14: its tombstone, no seal
        await binding(2, seal(2), true); await change(2, 'genesis', seal(1)); await change(2, 'binding.revoke', seal(2)); // ended by 0.15
        await binding(3, seal(3), false); await change(3, 'genesis', seal(3)); // born on 0.14, sealed by the cutover
        await binding(4, seal(4), false); await change(4, 'binding.make', seal(4)); // born on 0.15
        assert.deepEqual(await bindingsDiffer(sql), { revived: [], dropped: [] });
        await binding(5, seal(5), false); await unbind(5); await change(5, 'genesis', seal(5)); // tombstoned, yet sealed as live
        await binding(6, seal(6), false); await change(6, 'genesis', seal(7)); // its seal not its newest change's: a rotation's?
        assert.deepEqual(await bindingsDiffer(sql), { revived: [id(5)], dropped: [id(6)] });
    } finally {
        await sql.unsafe('DROP SCHEMA IF EXISTS upgrade_bindings CASCADE');
        await sql.end();
    }
});

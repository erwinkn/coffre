#!/usr/bin/env node
// The steps of `pnpm upgrade:check` (upgrade-check.sh) that are not a shell's:
//
//   fill <conformance's dist/main.js> <database> <state>
//               0.14.5's conformance made to fill a database and leave it:
//               it makes <database>, keeps it and its Durable Objects'
//               storage in <state>, and stops before the checks that tamper
//               with the log for good.
//   before <origin> <idp> <out.json> -- <cli…>
//               on 0.15.0, as its Owner: the log verified by `coffre verify
//               log`, a beat, then the audit API's pages and every removed
//               member's offboarding report, saved.
//   after <origin> <idp> <before.json> -- <cli…>
//               on this checkout, as its Owner: the same entries in the
//               same order, the same reports, a use through the credential
//               proxy, a change, a beat, and `coffre verify log` green.
//   lists <owner's URL of the database>
//               on 0.15.0's database, before this checkout's migrate: no
//               OAuth client's redirects that 0084 would cut (`brokenLists`).
//
// <cli…> is the CLI of the version serving, as a command line; it runs in a
// home of its own, given as HOME, and is told the instance with --url.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';

const OWNER = 'root@conformance.example';
// conformance's DEV (checks/people.ts), where its people read and write.
const DEV = 'conformance/dev';
// What the audit page leaves out of the comparison: the log's own beats, which 0.16 no longer lists (state-rows.md,
// section 6) and which go on being written between the two snapshots.
const BEATS = new Set(['audit.heartbeat', 'audit.checkpoint']);

const say = (line) => process.stderr.write(`    ${line}\n`);
if (import.meta.main) {
    const [command, ...args] = process.argv.slice(2);
    if (command === 'fill') fill(args[0], args[1], args[2]);
    else if (command === 'lists') await lists(args[0]);
    else if (command === 'before' || command === 'after') {
        const split = args.indexOf('--');
        const [origin, idp, file] = args.slice(0, split);
        await (command === 'before' ? before : after)(origin, idp, file, args.slice(split + 1));
    } else {
        console.error('usage: upgrade-check.mjs fill|lists|before|after …');
        process.exit(2);
    }
}

/**
 * Each edit must match the release's bundle exactly once, or this fails, as scripts/compat/renamed-tables.mjs does.
 * The file is moved aside and a new one takes its place, never written through: pnpm links it from its store.
 */
function fill(file, database, state) {
    assert.match(database, /^coffre_[a-z0-9_]+$/);
    assert.ok(state?.startsWith('/'), 'fill takes the Durable Objects\' storage as an absolute path');
    const edits = [
        // The harness's own scratch database, by the name given.
        ['const name = `coffre_conformance_${randomBytes(4).toString("hex")}`;', `const name = ${JSON.stringify(database)};`],
        // Kept when the run ends.
        ['sql.exec(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`)', 'Promise.resolve()'],
        // The Durable Objects' storage where the next versions find it, not in the scratch directory it removes.
        ['const state = join(scratch, "state");', `const state = ${JSON.stringify(state)};`],
        // The suite stops after the beats it runs and its look at the writes: what follows deletes, forges and cuts
        // entries, and the log stays broken for good.
        ['\tawait report.check("no audit, no value",', '\treturn report.failed;\n\tawait report.check("no audit, no value",'],
    ];
    let text = readFileSync(file, 'utf8');
    for (const [from, to] of edits) {
        assert.equal(text.split(from).length - 1, 1, `0.14.5's conformance does not read once as expected: ${from}`);
        text = text.replace(from, () => to);
    }
    renameSync(file, `${file}.release`);
    writeFileSync(file, text);
}

async function before(origin, idp, out, cli) {
    const owner = await ownerOf(origin, idp);
    await verifyLog(owner, cli);
    await owner.beat();
    const saved = await snapshot(owner);
    writeFileSync(out, JSON.stringify(saved));
    say(`saved ${saved.entries.length} entries and the reports of ${Object.keys(saved.reports).join(', ') || 'nobody'}`);
}

async function after(origin, idp, file, cli) {
    const saved = JSON.parse(readFileSync(file, 'utf8'));
    assert.ok(Object.keys(saved.reports).length > 0, '0.15.0 listed no removed member');
    const owner = await ownerOf(origin, idp);
    const now = await snapshot(owner);
    sameEntries(saved.entries, now.entries);
    say(`the same ${saved.entries.length} entries, in the same order`);
    assert.deepEqual(Object.keys(now.reports).sort(), Object.keys(saved.reports).sort(), 'not the same members removed');
    for (const [member, report] of Object.entries(saved.reports)) {
        assert.deepEqual(sameAs(now.reports[member], report), report, `${member}'s offboarding report is not the one 0.15.0 gave`);
    }
    say(`the same offboarding reports, of ${Object.keys(saved.reports).join(', ')}`);

    // A use through the credential proxy: the plan `coffre run` builds an app's environment from, for a handle. Every
    // key the Owner lists is in it, given or left out by name; no value is printed.
    const { keys } = await owner.call('GET', `/api/secrets/${DEV}`);
    const { token } = await owner.call('POST', '/api/handles', { label: 'upgrade check', expiresInMinutes: 10, paths: [DEV] });
    const response = await fetch(`${origin}/use/${DEV}`, { headers: { authorization: `Bearer ${token}` } });
    assert.equal(response.status, 200, `a use of ${DEV} through the proxy answered ${response.status}: ${await response.text()}`);
    const plan = await response.json();
    const given = Object.keys(plan.env);
    const missing = keys.map(({ key }) => key).filter((key) => !given.includes(key) && !plan.left.includes(key));
    assert.ok(given.length > 0, `the plan for ${DEV} gives no key; it leaves out ${plan.left.join(', ') || 'none'}`);
    assert.deepEqual(missing, [], `the plan for ${DEV} neither gives nor leaves out ${missing.join(', ')}`);
    say(`a handle's use of ${DEV} through the proxy gives ${given.length} keys and leaves out ${plan.left.length}`);

    // A change, read back.
    const value = randomBytes(18).toString('base64url');
    await owner.call('PATCH', `/api/secrets/${DEV}`, { UPGRADE_CHECK: value });
    const { values } = await owner.call('POST', '/api/reveals', { path: `${DEV}/UPGRADE_CHECK` });
    assert.equal(values.UPGRADE_CHECK, value, 'the value written after the upgrade does not read back');
    say(`a value written to ${DEV} reads back`);

    await owner.beat();
    await verifyLog(owner, cli);
}

/** The Owner, signed in through the dev IdP once the instance opens its door: 503 while it cuts over or upgrades. */
async function ownerOf(origin, idp) {
    const { browser } = await import('../dev/browser.mjs');
    const { signIn, call, touched } = browser(origin, idp);
    let session;
    for (let tries = 0; session === undefined; tries += 1) {
        try {
            session = await signIn(OWNER);
        } catch (error) {
            if (tries >= 60) throw error;
            await new Promise((resolve) => setTimeout(resolve, 1000));
        }
    }
    return {
        call: (method, path, body) => call(session, method, path, body),
        touched: (method, path, body) => touched(session, OWNER, method, path, body),
        /** What the Cron trigger does every five minutes: a heartbeat, and the vault's checkpoint. */
        async beat() {
            const response = await fetch(`${origin}/cdn-cgi/local/scheduled?cron=*/5+*+*+*+*`);
            assert.ok(response.ok, `the scheduled handler answered ${response.status}: ${await response.text()}`);
        },
        origin,
    };
}

/** The audit API's pages, every entry with sign-ins and 0.15's sealed records, beats left out; and every removed member's report. */
async function snapshot(owner) {
    const entries = [];
    for (let next = null; ; ) {
        const page = await owner.call('GET', `/api/audit?detail=1&sealed=1&limit=500${next === null ? '' : `&before=${encodeURIComponent(next)}`}`);
        entries.push(...page.entries.filter((entry) => !BEATS.has(entry.action)));
        if (!page.more || page.next === null) break;
        next = page.next;
    }
    const { removed } = await owner.call('GET', '/api/members');
    const reports = {};
    for (const { principalType, principalId } of removed) {
        const member = `${principalType === 'service' ? 'token' : principalType}:${principalId}`;
        reports[member] = await owner.call('GET', `/api/members/${encodeURIComponent(member)}`);
    }
    return { entries, reports };
}

/**
 * 0.15.0's entries, newest first, are the tail of what this checkout lists: what it lists above them is what was
 * written since (this run's sign-ins and reads).
 */
function sameEntries(saved, now) {
    assert.ok(saved.length > 0, '0.15.0 listed no entries');
    const top = now.findIndex((entry) => isDeepStrictEqual(entry, saved[0]));
    assert.ok(top >= 0, `0.15.0's newest entry is not listed after the upgrade:\n${JSON.stringify(saved[0], null, 2)}`);
    const tail = now.slice(top);
    for (let at = 0; at < Math.max(saved.length, tail.length); at += 1) {
        if (isDeepStrictEqual(saved[at], tail[at])) continue;
        assert.fail(`entry ${at} of ${saved.length}, newest first, differs:\n0.15.0: ${JSON.stringify(saved[at], null, 2)}\nnow: ${JSON.stringify(tail[at], null, 2)}`);
    }
}

/**
 * This checkout's report, held to 0.15.0's where they differ by more than content: `reads.through`, how far sealed
 * reads are listed, moves on with every seal since (the beats), and must not go back; `proxy`, the proxy items a
 * member saved (0.16), is a field 0.15.0 has not, and nobody saved one. The rest is compared as it is.
 */
function sameAs(now, saved) {
    const { proxy, ...report } = now;
    assert.deepEqual(proxy, [], `${now.principalId} has proxy items nobody saved`);
    if (saved.reads === undefined) return report;
    assert.ok(saved.reads.through === null || report.reads.through >= saved.reads.through, `reads listed through ${report.reads.through}, before 0.15.0's ${saved.reads.through}`);
    return { ...report, reads: { ...report.reads, through: saved.reads.through } };
}

/** `coffre login`, approved by the Owner, then `coffre verify log`, green: each in the CLI's own home, told the instance. */
async function verifyLog(owner, cli) {
    const [program, ...rest] = cli;
    const run = (argv) => spawn(program, [...rest, ...argv], { cwd: process.env.HOME, stdio: ['ignore', 'pipe', 'pipe'] });
    const output = (child) => {
        let text = '';
        child.stdout.on('data', (chunk) => (text += chunk));
        child.stderr.on('data', (chunk) => (text += chunk));
        const done = new Promise((resolve, reject) => {
            child.once('error', reject);
            child.once('exit', (code) => resolve({ code, text }));
        });
        return { done, text: () => text };
    };

    const login = run(['login', owner.origin]);
    const watched = output(login);
    let code;
    for (let tries = 0; code === undefined; tries += 1) {
        code = /shows the code\s+(\S+)/.exec(watched.text())?.[1];
        assert.ok(tries < 100, `coffre login printed no code:\n${watched.text()}`);
        if (code === undefined) await new Promise((resolve) => setTimeout(resolve, 100));
    }
    await owner.touched('POST', `/api/device-logins/${encodeURIComponent(code)}`, { approve: true });
    const signedIn = await watched.done;
    assert.equal(signedIn.code, 0, `coffre login failed:\n${signedIn.text}`);

    const verified = await output(run(['--url', owner.origin, 'verify', 'log'])).done;
    assert.equal(verified.code, 0, `coffre verify log failed:\n${verified.text}`);
    say(`coffre verify log: ${verified.text.trim().split('\n').at(-1)}`);
    const out = await output(run(['logout', owner.origin])).done;
    assert.equal(out.code, 0, `coffre logout failed:\n${out.text}`);
}

/**
 * 0084 makes `oauth_clients.redirect_uris`, JSON text on 0.15.0, a text[]: the strings of an array, in order. It would
 * drop anything else without a word (a non-string element; all of a non-array), so a client whose redirects are
 * anything else stops the upgrade here, by id. The other two lists 0084 converts have no table on 0.15.0.
 */
export async function brokenLists(sql) {
    const rows = await sql.unsafe(`
        SELECT id::text FROM oauth_clients
        WHERE CASE WHEN jsonb_typeof(redirect_uris::jsonb) = 'array'
            THEN EXISTS (SELECT FROM jsonb_array_elements(redirect_uris::jsonb) AS e WHERE jsonb_typeof(e) <> 'string')
            ELSE true END
        ORDER BY id`);
    return rows.map(({ id }) => id);
}

async function lists(url) {
    const { postgresSession } = await import('@coffre/db/connect');
    const sql = postgresSession(url);
    try {
        const broken = await brokenLists(sql);
        assert.deepEqual(broken, [], `0084 would cut the redirects of the OAuth clients ${broken.join(', ')}: they are not a JSON array of strings`);
    } finally {
        await sql.end();
    }
    say('every OAuth client\'s redirects are a JSON array of strings, as 0084 converts them');
}

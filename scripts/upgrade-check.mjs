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
//               log`, a beat, then an environment's values (`held`), the
//               audit API's pages and every removed member's offboarding
//               report, saved.
//   after <origin> <idp> <before.json> -- <cli…>
//               on this checkout, as its Owner: the same entries in the
//               same order, the same reports, the same values, a use of
//               them through the credential proxy (newer than 0.15.0), a
//               change, a beat, and `coffre verify log` green.
//   refusals <owner's URL of the database>
//               on 0.15.0's database, before this checkout's migrate: no
//               OAuth client's redirects that 0084 would cut
//               (`brokenLists`), no loss the log accepted
//               (`acceptedLosses`), no tamper finding standing
//               (`standingFindings`), and the policy and the rows
//               agreeing on what is protected (`disagreeing`), and no
//               trust binding 0.14 ended alive by the log (`bindingsDiffer`).
//
// <cli…> is the CLI of the version serving, as a command line; it runs in a
// home of its own, given as HOME, and is told the instance with --url.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { setTimeout as sleep } from 'node:timers/promises';

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
    else if (command === 'refusals') await refusals(args[0]);
    else if (command === 'before' || command === 'after') {
        const split = args.indexOf('--');
        const [origin, idp, file] = args.slice(0, split);
        await (command === 'before' ? before : after)(origin, idp, file, args.slice(split + 1));
    } else {
        console.error('usage: upgrade-check.mjs fill|refusals|before|after …');
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
    const saved = { held: await held(owner), ...(await snapshot(owner)) };
    writeFileSync(out, JSON.stringify(saved));
    say(`saved ${Object.keys(saved.held.values).length} values of ${DEV}, ${saved.entries.length} entries and the reports of ${Object.keys(saved.reports).join(', ') || 'nobody'}`);
}

async function after(origin, idp, file, cli) {
    const saved = JSON.parse(readFileSync(file, 'utf8'));
    assert.ok(Object.keys(saved.reports).length > 0, '0.15.0 listed no removed member');
    const owner = await ownerOf(origin, idp);
    const now = await snapshot(owner);
    const since = sameEntries(saved.entries, now.entries);
    say(`the same ${saved.entries.length} entries, in the same order; since: ${since}`);
    assert.deepEqual(Object.keys(now.reports).sort(), Object.keys(saved.reports).sort(), 'not the same members removed');
    for (const [member, report] of Object.entries(saved.reports)) {
        assert.deepEqual(sameAs(now.reports[member], report), report, `${member}'s offboarding report is not the one 0.15.0 gave`);
    }
    say(`the same offboarding reports, of ${Object.keys(saved.reports).join(', ')}`);

    const { values } = await held(owner);
    for (const [key, hash] of Object.entries(saved.held.values)) assert.equal(values[key], hash, `${DEV}'s ${key} does not read back as 0.15.0 read it`);
    assert.deepEqual(Object.keys(values), Object.keys(saved.held.values), `${DEV} does not hold the keys it held on 0.15.0`);
    const { given, left } = await use(owner);
    say(`${DEV}'s ${Object.keys(values).length} values read back as 0.15.0 read them; a use through the proxy gives ${given.length} keys and leaves out ${left.length}`);

    // A change, read back.
    const value = randomBytes(18).toString('base64url');
    await owner.call('PATCH', `/api/secrets/${DEV}`, { UPGRADE_CHECK: value });
    const { values: read } = await owner.call('POST', '/api/reveals', { path: `${DEV}/UPGRADE_CHECK` });
    assert.equal(read.UPGRADE_CHECK, value, 'the value written after the upgrade does not read back');
    say(`a value written to ${DEV} reads back`);

    await owner.beat();
    await verifyLog(owner, cli);
}

/**
 * The Owner, signed in through the dev IdP once the instance opens its door: 503 while it cuts over or upgrades, or
 * no answer yet. Any other failure is final.
 */
async function ownerOf(origin, idp) {
    const { browser } = await import('../dev/browser.mjs');
    const { signIn, call, touched } = browser(origin, idp);
    let session;
    for (let tries = 0; session === undefined; tries += 1) {
        try {
            session = await signIn(OWNER);
        } catch (error) {
            const opening = error instanceof TypeError || /\b503\b/.test(error.message);
            if (!opening || tries >= 60) throw error;
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

/** What DEV holds, as the Owner reads it, each value as its SHA-256, never printed. */
async function held(owner) {
    const { values } = await owner.call('POST', '/api/reveals', { path: DEV });
    const hashes = Object.fromEntries(Object.keys(values).sort().map((key) => [key, createHash('sha256').update(values[key]).digest('hex')]));
    assert.ok(Object.keys(hashes).length > 0, `the Owner reads no value of ${DEV}`);
    return { values: hashes };
}

/**
 * A handle's use of DEV through the credential proxy, which 0.15.0 does not have: the plan `coffre run` builds an
 * app's environment from. Every key the Owner lists, archived ones aside, is in it, given or left out by name.
 */
async function use(owner) {
    const { keys } = await owner.call('GET', `/api/secrets/${DEV}`);
    const { token } = await owner.call('POST', '/api/handles', { label: 'upgrade check', expiresInMinutes: 10, paths: [DEV] });
    const response = await fetch(`${owner.origin}/use/${DEV}`, { headers: { authorization: `Bearer ${token}` } });
    const body = await response.text();
    assert.equal(response.status, 200, `a use of ${DEV} through the proxy answered ${response.status}: ${body}`);
    const plan = JSON.parse(body);
    // A key behind a tunnel leaves `env` for the tunnel's entry: given too.
    const given = [...Object.keys(plan.env), ...Object.values(plan.tunnels ?? {}).map(({ key }) => key)];
    const missing = keys.filter(({ archived }) => !archived).map(({ key }) => key).filter((key) => !given.includes(key) && !plan.left.includes(key));
    assert.ok(given.length > 0, `the plan for ${DEV} gives no key; it leaves out ${plan.left.join(', ') || 'none'}`);
    assert.deepEqual(missing, [], `the plan for ${DEV} neither gives nor leaves out ${missing.join(', ')}`);
    return { given, left: plan.left };
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
    // A report lists the reads the projector has written, and says `behind` while it has some left: compared only
    // once it has none, so that two reports differ by what they hold, not by when the projector last ran.
    for (const deadline = Date.now() + 30_000; ; await sleep(1_000)) {
        const reports = {};
        for (const { principalType, principalId } of removed) {
            const member = `${principalType === 'service' ? 'token' : principalType}:${principalId}`;
            reports[member] = await owner.call('GET', `/api/members/${encodeURIComponent(member)}`);
        }
        const behind = Object.keys(reports).filter((member) => reports[member].reads?.behind);
        if (behind.length === 0) return { entries, reports };
        assert.ok(Date.now() < deadline, `the reads of ${behind.join(', ')} still wait to be listed after 30 s`);
    }
}

/**
 * 0.15.0's entries, newest first, are the tail of what this checkout lists: what it lists above them is what was
 * written since (this run's sign-ins and reads), which it returns, counted by action.
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
    const counts = {};
    for (const { action } of now.slice(0, top)) counts[action] = (counts[action] ?? 0) + 1;
    return Object.entries(counts).map(([action, count]) => `${count} ${action}`).join(', ') || 'nothing';
}

/**
 * This checkout's report, held to 0.15.0's where they differ by more than content: `reads.through`, how far sealed
 * reads are listed, moves on with every seal since (the beats), and must not go back; `proxy`, the proxy items a
 * member saved (0.16), is a field 0.15.0 has not, and nobody saved one; `readsFrom`, the day retention keeps reads
 * from (0.16), is null, since retention has dropped none. The rest is compared as it is.
 */
function sameAs(now, saved) {
    const { proxy, readsFrom, ...report } = now;
    assert.deepEqual(proxy, [], `${now.principalId} has proxy items nobody saved`);
    assert.equal(readsFrom, null, `${now.principalId}'s reads are weighed from ${readsFrom}, though retention has dropped none`);
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

/**
 * A loss the log accepted (`audit.loss_accepted`, which 0.15's watch writes when an Owner accepts a gap) is a break
 * in its hashes, where 0.16's projector, walking the log back, stops: below it is not designed, and will be only for a
 * real database that has one (state-rows.md, section 6). The entry is the barrier, not the break: one a later
 * `audit.loss_unapplied` says did not take stops the upgrade too, since whether its range still breaks the hashes is
 * the walk's to judge, not this check's. Such a log stops the upgrade here, with the entries' seqs.
 */
export async function acceptedLosses(sql) {
    const rows = await sql.unsafe(`SELECT seq::text AS seq FROM audit_log WHERE action = 'audit.loss_accepted' ORDER BY audit_log.seq`);
    return rows.map(({ seq }) => seq);
}

/**
 * The members a tamper finding stands for (their row changed around the vault, or an older one put back), by the rule
 * the members page marks them with (`tamperedMembers`, `findingStands`), which reads nothing 0.15.0 lacks. 0.16
 * carries no finding over (state-rows.md, section 6), so one that stands stops the upgrade here, by member; an
 * Owner's change to the member, on 0.15.0, settles it.
 */
export async function standingFindings(sql) {
    const [{ createDatabase }, { tamperedMembers }] = await Promise.all([import('@coffre/db'), import('@coffre/db/grants')]);
    return [...(await tamperedMembers(createDatabase(sql)))].sort();
}

/**
 * The environments the newest `policy.change` and their rows disagree on protecting (`protectionDisagrees`, the rule
 * the vault's step refuses on), by id; null when that entry's edits do not read. 0.16 fills the policy's protected list
 * from the entry, so either stops the upgrade here. On 0.15.0, an Owner turns the environment's protection off and on
 * again, or on and off, to end where it should: each turn writes the entry and the row together.
 */
export async function disagreeing(sql) {
    const [{ readEdits, NO_EDITS, protectionDisagrees }, { KINDS }, { TOMBSTONE }] = await Promise.all([import('@coffre/core/vault'), import('@coffre/db/log'), import('@coffre/core/schemas')]);
    const [entry] = await sql.unsafe(`SELECT metadata FROM audit_log WHERE ${KINDS.policy} ORDER BY seq DESC LIMIT 1`);
    let edits = NO_EDITS;
    if (entry !== undefined) try { edits = readEdits(JSON.parse(entry.metadata)); } catch { edits = null; }
    if (edits === null) return null;
    const rows = await sql.unsafe('SELECT e.id::text AS id, e.protected, strpos(e.slug, $1) > 0 OR strpos(p.slug, $1) > 0 AS deleted FROM environments e JOIN projects p ON p.id = e.project_id', [TOMBSTONE]);
    return protectionDisagrees(edits, new Map(rows.map((row) => [row.id, row])));
}

/**
 * The trust bindings whose life 0.16's rule (the log's: sealed by its newest change, no `binding.revoke` among them)
 * and 0.14's tombstone (an allowed app `token.unbind`) disagree on, in plain SQL on 0.15.0's tables, apart from either
 * release's code. `revived`, live by the log though tombstoned, would come back: they stop the upgrade, by id. `dropped`,
 * live by 0.15.0 (not revoked, no tombstone, sealed) but dead by the log, ends no more than it should, and is reported:
 * only a write around the vault makes one, since every 0.15.0 change moves a binding's seal and logs its change in one
 * statement (`change_input`, `change_bindings`) and the app key's rotation re-signs `auth_mac` alone.
 */
export async function bindingsDiffer(sql) {
    const rows = await sql.unsafe(`
        SELECT id, live AND tombstoned AS revived, NOT live AND unrevoked AND NOT tombstoned AND sealed AS dropped FROM (
            SELECT s.id::text AS id, s.revoked_at IS NULL AS unrevoked, s.seal IS NOT NULL AS sealed,
                EXISTS (SELECT FROM audit_log t WHERE t.author = 'app' AND t.action = 'token.unbind' AND t.decision = 'allow' AND t.metadata::jsonb ->> 'bindingId' = s.id::text) AS tombstoned,
                coalesce(s.seal = (SELECT c.seal FROM log_changes c WHERE c.object = log_object('binding', s.id::text) ORDER BY c.number DESC LIMIT 1), false)
                    AND NOT EXISTS (SELECT FROM log_changes e WHERE e.object = log_object('binding', s.id::text) AND e.payload::jsonb ->> 'op' = 'binding.revoke') AS live
            FROM service_bindings s) AS b
        ORDER BY id`);
    return { revived: rows.filter((row) => row.revived).map(({ id }) => id), dropped: rows.filter((row) => row.dropped).map(({ id }) => id) };
}

async function refusals(url) {
    const { postgresSession } = await import('@coffre/db/connect');
    const sql = postgresSession(url);
    let broken, losses, tampered, protection, bindings;
    try {
        [broken, losses, tampered] = [await brokenLists(sql), await acceptedLosses(sql), await standingFindings(sql)];
        [protection, bindings] = [await disagreeing(sql), await bindingsDiffer(sql)];
    } finally {
        await sql.end();
    }
    const refused = [
        broken.length > 0 && `0084 would cut the redirects of the OAuth clients ${broken.join(', ')}: they are not a JSON array of strings`,
        losses.length > 0 && `the log accepted ${losses.length} loss${losses.length === 1 ? '' : 'es'}, at seq ${losses.join(', ')}: 0.16's projector stops at one, so stop and ask coffre's maintainers`,
        tampered.length > 0 && `a tamper finding stands for ${tampered.join(', ')}: 0.16 carries none over, and an Owner's change to each, on 0.15.0, settles it`,
        protection === null && 'the newest policy.change does not read: 0.16 fills the protected environments from it, and an Owner\'s change of the policy, on 0.15.0, writes one that does',
        protection?.length > 0 && `the newest policy.change and the rows disagree on protecting ${protection.join(', ')}: an Owner turns each off and on again (or on and off), on 0.15.0, to end where it should`,
        bindings.revived.length > 0 && `0.14 ended the trust bindings ${bindings.revived.join(', ')}, which 0.16, reading the log, would bring back: no change on 0.15.0 is known to settle it, so stop and ask coffre's maintainers`,
    ].filter(Boolean);
    assert.deepEqual(refused, [], `the upgrade is refused:\n${refused.join('\n')}`);
    if (bindings.dropped.length > 0) say(`${bindings.dropped.length} trust binding${bindings.dropped.length === 1 ? '' : 's'} sign${bindings.dropped.length === 1 ? 's' : ''} in on 0.15.0 but not on 0.16, whose log ends ${bindings.dropped.length === 1 ? 'it' : 'them'}: ${bindings.dropped.join(', ')}. A write around the vault made ${bindings.dropped.length === 1 ? 'it' : 'them'}; an Owner creates ${bindings.dropped.length === 1 ? 'it' : 'them'} again on 0.16`);
    say('every OAuth client\'s redirects are a JSON array of strings, as 0084 converts them; the log accepted no loss; no tamper finding stands; the policy and the rows agree on what is protected; no binding 0.14 ended comes back');
}

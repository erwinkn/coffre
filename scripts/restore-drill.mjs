#!/usr/bin/env node
// The restore drill's steps at the API, run by restore-drill.sh against a
// local stack, as its Owner through the dev IdP:
//
//   prepare     before the backup: a canary, a grant, a removal whose
//               session is kept, a token, and checkpoints, 0.15's sealed
//               too. Prints what the checks after need, as JSON.
//   check       after the restore, with the same keys and a checkpointer
//               with no memory: everything is back, and 0.15's log verifies
//               from its newest checkpoint and seals what comes after.
//   wrong-kek   after the restore, with another KEK: nobody signs in, reads
//               and writes answer 503, and readiness goes red.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { browser } from '../dev/browser.mjs';

const API = process.env.COFFRE_DEV_URL;
const ADMIN = 'admin@acme.example';
const LEAVER = 'dev@acme.example';
const CANARY = 'market/prod/DRILL_CANARY';
const { trySignIn, signIn, send, call } = browser(API, process.env.COFFRE_DEV_IDP_URL);

const say = (line) => process.stderr.write(`    ${line}\n`);
const member = (principal) => `/api/members/${encodeURIComponent(principal)}`;

/** What the Cron trigger does every five minutes: a heartbeat, and the vault's checkpoint. */
async function beat() {
    const response = await fetch(`${API}/cdn-cgi/handler/scheduled?cron=*/5+*+*+*+*`);
    assert.ok(response.ok, `the scheduled handler answered ${response.status}`);
    const ready = await (await fetch(`${API}/readyz`)).json();
    assert.deepEqual([ready.ok, ready.checkpointed], [true, true], `not ready after a beat: ${JSON.stringify(ready)}`);
}

async function verified(admin) {
    const verification = await call(admin, 'GET', '/api/audit/verification');
    assert.ok(verification.ok, `verification failed: ${JSON.stringify(verification)}`);
    return verification;
}

/**
 * 0.15's log, from its newest checkpoint: verified, and sealed past `upto`, which the checkpointer, ticking every
 * half second, reaches within a few ticks of the last change.
 */
async function sealed(admin, upto = 0n) {
    for (let tries = 0; ; tries += 1) {
        const trees = await call(admin, 'GET', '/api/audit/trees');
        assert.ok(trees.kept && trees.problems.length === 0, `0.15's log does not verify: ${JSON.stringify(trees)}`);
        if (trees.ok && trees.checkpoint !== null && BigInt(trees.checkpoint.upto) > upto) return trees;
        assert.ok(tries < 20, `0.15's log is not sealed past ${upto}: ${JSON.stringify(trees)}`);
        await new Promise((resolve) => setTimeout(resolve, 250));
    }
}

async function reveal(session, path) {
    return (await call(session, 'POST', '/api/reveals', { path })).values;
}

async function prepare() {
    const admin = await signIn(ADMIN);
    const canary = randomBytes(18).toString('base64url');
    await call(admin, 'PATCH', '/api/secrets/market/prod', { DRILL_CANARY: canary });
    say(`wrote ${CANARY}`);

    // Access changes, so members, grants and generations are not the seed's.
    await call(admin, 'PATCH', `/api/access/${encodeURIComponent('user:outsider@acme.example')}`, { 'market/dev': 'viewer' });
    const leaver = await signIn(LEAVER);
    assert.equal((await send(leaver, 'GET', '/api/me')).status, 200);
    await call(admin, 'DELETE', member(`user:${LEAVER}`));
    const refused = (await send(leaver, 'GET', '/api/me')).status;
    assert.notEqual(refused, 200, 'a removed member’s session still works');
    say(`granted outsider viewer on market/dev; removed ${LEAVER}, whose session now answers ${refused}`);

    // A token for `coffre verify instance`: it reads the canary's environment, and audits its project.
    await call(admin, 'PATCH', `/api/access/${encodeURIComponent('token:ci-deploy')}`, { market: 'auditor' });
    const { token } = await call(admin, 'POST', `${member('token:ci-deploy')}/tokens`, { label: 'drill', expiresInDays: 1 });

    await beat();
    await beat();
    const verification = await verified(admin);
    const members = await call(admin, 'GET', '/api/members');
    const trees = await sealed(admin);
    say(`verified through ${verification.through}, checkpointed at ${verification.checkpoint.seq}; 0.15's log sealed up to ${trees.checkpoint.upto}`);
    process.stdout.write(JSON.stringify({ canary, leaver, token, verification, members, trees }));
}

async function check(before) {
    const admin = await signIn(ADMIN);
    const verification = await verified(admin);
    assert.ok(verification.through > before.verification.through, 'verification stopped short of the restored log');
    assert.deepEqual(verification.checkpoint, before.verification.checkpoint, 'the newest checkpoint is not the one backed up');
    say(`verified through ${verification.through}, the backup's checkpoint at ${verification.checkpoint.seq} still holding`);
    // A checkpointer with no memory, as after its reset (docs/restore.md, "On 0.15's log"): it takes the restored log's newest pair.
    const trees = await sealed(admin, BigInt(before.trees.checkpoint.upto) - 1n);
    say(`0.15's log verifies from its newest checkpoint, up to ${trees.checkpoint.upto}`);

    // The directory as backed up; how far its reads are listed (T166) moves on with this sign-in's seal, so it is held
    // apart: there as it was, and vouched for.
    const { reads, ...directory } = await call(admin, 'GET', '/api/members');
    const { reads: readsBefore, ...directoryBefore } = before.members;
    assert.deepEqual(directory, directoryBefore, 'members or grants differ from the backup');
    assert.equal(reads === undefined, readsBefore === undefined, 'the directory says how far reads are listed, or not, unlike the backup');
    assert.equal(reads?.forged, undefined, 'the restored reads listing is not vouched for');
    say('members, owners, grants and the removed are as backed up');

    assert.equal((await reveal(admin, CANARY)).DRILL_CANARY, before.canary);
    say(`${CANARY} reveals`);

    const stale = (await send(before.leaver, 'GET', '/api/me')).status;
    assert.notEqual(stale, 200, 'the removed member’s old session works again');
    assert.equal(await trySignIn(LEAVER), null, 'the removed member signs in again');
    say(`${LEAVER} stays removed: the old session answers ${stale}, and a new sign-in is turned away`);

    await call(admin, 'PATCH', '/api/secrets/market/dev', { DRILL_AFTER: 'written after the restore' });
    assert.equal((await reveal(admin, 'market/dev/DRILL_AFTER')).DRILL_AFTER, 'written after the restore');
    await beat();
    const after = await verified(admin);
    assert.ok(after.checkpoint.seq > before.verification.checkpoint.seq);
    const resealed = await sealed(admin, BigInt(trees.checkpoint.upto));
    say(`a new write reads back; the next beat checkpoints at ${after.checkpoint.seq}, the log verifies through ${after.through}, and 0.15's seals it, up to ${resealed.checkpoint.upto}`);
}

async function wrongKek(before) {
    // The vault's keys come from its KEK: under another, its checkpointer refuses the log's checkpoints ("not a pair
    // signed by this log"), so the app's door, which asks whether 0.15's log is cut over, holds every request at 503,
    // sign-in's first step included, and the vault decides nothing: an outage, never a verdict.
    const leave = await fetch(`${API}/auth/signin/github`, { redirect: 'manual' });
    assert.equal(leave.status, 503, `sign-in under the wrong KEK answered ${leave.status}`);
    say(`${ADMIN} cannot sign in: coffre answers ${leave.status} from the first step`);
    const asToken = (method, path, body) => fetch(`${API}${path}`, {
        method,
        headers: { authorization: `Bearer ${before.token}`, 'content-type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    const response = await asToken('POST', '/api/reveals', { path: CANARY });
    const answer = await response.text();
    assert.equal(response.status, 503, answer);
    assert.ok(!answer.includes(before.canary), 'a value opened under the wrong KEK');
    say(`revealing ${CANARY} with the drill's token answers ${response.status}: ${answer}`);
    const write = await asToken('PATCH', '/api/secrets/market/dev', { DRILL_WRONG: 'never stored' });
    assert.equal(write.status, 503, 'a value was written under the wrong KEK');
    say(`writing answers ${write.status} too: nothing is wrapped under the wrong KEK`);

    await fetch(`${API}/cdn-cgi/handler/scheduled?cron=*/5+*+*+*+*`);
    const ready = await (await fetch(`${API}/readyz`)).json();
    assert.equal(ready.ok, false, 'ready under the wrong KEK');
    assert.notEqual(ready.checkpointed, true, 'the vault checkpointed under the wrong KEK');
    say(`and /readyz turns red: ${JSON.stringify(ready)}`);
}

const [step, state] = process.argv.slice(2);
const before = state === undefined ? null : JSON.parse(readFileSync(state, 'utf8'));
if (step === 'prepare') await prepare();
else if (step === 'check') await check(before);
else if (step === 'wrong-kek') await wrongKek(before);
else throw new Error('usage: restore-drill.mjs prepare | check <state> | wrong-kek <state>');

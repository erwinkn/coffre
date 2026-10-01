#!/usr/bin/env node
// The restore drill's steps at the API, run by restore-drill.sh against a
// local stack, as the root admin through the dev IdP:
//
//   prepare     before the backup: a canary, a grant, a removal whose
//               session is kept, a token, and checkpoints. Prints what the
//               checks after need, as JSON.
//   check       after the restore, with the same keys: everything is back.
//   wrong-kek   after the restore, with another KEK: values fail closed,
//               and the log still verifies.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { browser } from '../dev/browser.mjs';

const API = process.env.COFFRE_API_URL;
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

    // A token for the probe: it reads the canary's environment, and audits its project.
    await call(admin, 'PATCH', `/api/access/${encodeURIComponent('token:ci-deploy')}`, { market: 'auditor' });
    const { token } = await call(admin, 'POST', `${member('token:ci-deploy')}/tokens`, { label: 'drill', expiresInDays: 1 });

    await beat();
    await beat();
    const verification = await verified(admin);
    const members = await call(admin, 'GET', '/api/members');
    say(`verified through ${verification.through}, checkpointed at ${verification.checkpoint.seq}`);
    process.stdout.write(JSON.stringify({ canary, leaver, token, verification, members }));
}

async function check(before) {
    const admin = await signIn(ADMIN);
    const verification = await verified(admin);
    assert.ok(verification.through > before.verification.through, 'verification stopped short of the restored log');
    assert.deepEqual(verification.checkpoint, before.verification.checkpoint, 'the newest checkpoint is not the one backed up');
    say(`verified through ${verification.through}, the backup's checkpoint at ${verification.checkpoint.seq} still holding`);

    assert.deepEqual(await call(admin, 'GET', '/api/members'), before.members, 'members or grants differ from the backup');
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
    say(`a new write reads back; the next beat checkpoints at ${after.checkpoint.seq}, and the log verifies through ${after.through}`);
}

async function wrongKek(before) {
    const admin = await signIn(ADMIN);
    const response = await send(admin, 'POST', '/api/reveals', { path: CANARY });
    const answer = await response.text();
    assert.ok(!response.ok && !answer.includes(before.canary), 'a value opened under the wrong KEK');
    say(`revealing ${CANARY} answers ${response.status}: ${answer}`);

    const verification = await verified(admin);
    await beat();
    say(`the log still verifies through ${verification.through}, and checkpoints: it needs the signing and audit keys, not the KEK`);
}

const [step, state] = process.argv.slice(2);
const before = state === undefined ? null : JSON.parse(readFileSync(state, 'utf8'));
if (step === 'prepare') await prepare();
else if (step === 'check') await check(before);
else if (step === 'wrong-kek') await wrongKek(before);
else throw new Error('usage: restore-drill.mjs prepare | check <state> | wrong-kek <state>');

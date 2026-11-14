#!/usr/bin/env node
// The restore drill's steps at the API, run by restore-drill.sh against a
// local stack, as its Owner through the dev IdP:
//
//   prepare     before the backup: a canary, a grant, a removal whose
//               session is kept, and a token. Prints what the checks after
//               need, as JSON.
//   check       after the restore, with the same keys: everything is back,
//               and a new write reads back.
//   wrong-kek   after the restore, with another KEK: the signer cannot take
//               the database's head as the vault's, so nobody signs in, and
//               reads and writes answer 503.
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

async function reveal(session, path) {
    return (await call(session, 'POST', '/api/reveals', { path })).values;
}

async function prepare() {
    const admin = await signIn(ADMIN);
    const canary = randomBytes(18).toString('base64url');
    await call(admin, 'PATCH', '/api/secrets/market/prod', { DRILL_CANARY: canary });
    say(`wrote ${CANARY}`);

    // Access changes, so members and grants are not the seed's.
    await call(admin, 'PATCH', `/api/access/${encodeURIComponent('user:outsider@acme.example')}`, { 'market/dev': 'viewer' });
    const leaver = await signIn(LEAVER);
    assert.equal((await send(leaver, 'GET', '/api/me')).status, 200);
    await call(admin, 'DELETE', member(`user:${LEAVER}`));
    // An instance remembers a caller's rows for `memorySeconds`, 2 by default: what a revocation waits at most.
    await new Promise((resolve) => setTimeout(resolve, 3000));
    const refused = (await send(leaver, 'GET', '/api/me')).status;
    assert.notEqual(refused, 200, 'a removed member’s session still works');
    say(`granted outsider viewer on market/dev; removed ${LEAVER}, whose session now answers ${refused}`);

    // A token of ci-deploy's, which reads market/prod (the seed's grant).
    const { token } = await call(admin, 'POST', `${member('token:ci-deploy')}/tokens`, { label: 'drill', expiresInDays: 1 });
    const members = await call(admin, 'GET', '/api/members');
    process.stdout.write(JSON.stringify({ canary, leaver, token, members }));
}

async function check(before) {
    const admin = await signIn(ADMIN);
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
    say('a new write reads back');
}

async function wrongKek(before) {
    // The vault's keys come from its KEK: under another, the database's head is no word of the vault's, and the new
    // signer goes on from no head it cannot vouch for. The vault serves nothing, so nothing opens and nothing is written.
    assert.equal(await trySignIn(ADMIN), null, 'signed in under the wrong KEK');
    say(`${ADMIN} cannot sign in`);
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
    say(`writing answers ${write.status} too`);
}

const [step, state] = process.argv.slice(2);
const before = state === undefined ? null : JSON.parse(readFileSync(state, 'utf8'));
if (step === 'prepare') await prepare();
else if (step === 'check') await check(before);
else if (step === 'wrong-kek') await wrongKek(before);
else throw new Error('usage: restore-drill.mjs prepare | check <state> | wrong-kek <state>');

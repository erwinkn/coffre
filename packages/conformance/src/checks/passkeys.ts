// Passkeys (docs/design/passkeys.md, section 13): what a deployment must never do with them, whatever code it runs. The
// numbers in the comments are that section's checks. The deployment runs as booted, `optional` as `coffre init` writes
// it; the checks that need `required` restart it so (`PASSKEYS`), and back.
import { CoffreError } from '@coffre/client';

import { FLAGS, SoftAuthenticator, type Tweak } from '../authenticator.ts';
import { bearer, Browser } from '../browser.ts';
import { using } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect } from '../report.ts';
import { connect, discovers, modern, redeem, refused, register } from './mcp.ts';
import { BULK, canary, ceremonyOf, deviceLogin, DEV, keepPasskey, passkeyOf, personaOn, PROJECT, provider, signIn, signInAdmin, stepUp, touching, withPasskey, type Canaries, type People, type Person, type Touch } from './people.ts';
import { pollDevice, startDevice } from './signin.ts';
import { query } from './storage.ts';

/** How long a touch keeps a session fresh: five minutes (D170), which a session left alone outlives. */
const FRESH_MS = 5 * 60 * 1000;

type Body = Record<string, unknown> & { error?: string };

async function bodyOf(response: Response): Promise<Body> {
  return (await response.clone().json().catch(() => ({}))) as Body;
}

/** `401 passkey_failed`, and the like: what a refusal said, for a failure's detail. */
async function said(response: Response): Promise<string> {
  return `${response.status} ${(await bodyOf(response)).error ?? (await response.clone().text())}`;
}

/** Whether the answer is this refusal exactly: `401 passkey_failed`, and the like. */
async function refusedAs(response: Response, status: number, error: string): Promise<boolean> {
  return response.status === status && (await bodyOf(response)).error === error;
}

/** A call the client made that must be refused: the error it threw. */
async function refusal(call: Promise<unknown>): Promise<CoffreError> {
  const outcome = await call.then(() => null, (error: unknown) => error);
  expect(outcome instanceof CoffreError, 'a call that must be refused went through', outcome);
  return outcome as CoffreError;
}

/** The sign-in's passkey page, as coffre's page reads it: what to ask the authenticator, and the sealed state. */
async function passkeyPage(browser: Browser, query = ''): Promise<{ purpose: string; options: { challenge: string; user?: { id: string } } | null; state?: string }> {
  const asked = await browser.fetch(`/api/auth/passkey${query}`);
  expect(asked.ok, `the passkey page${query} had nothing to ask: ${asked.status}`, await asked.clone().text());
  return (await asked.json()) as { purpose: string; options: { challenge: string; user?: { id: string } } | null; state?: string };
}

/** The answer the page sends, from this browser. */
function answer(browser: Browser, body: Record<string, unknown>): Promise<Response> {
  return browser.send('POST', '/api/auth/passkey', body);
}

/** A step-up's options and an assertion of `key` for them, tweaked or not: what the dialog sends, unsent. */
async function stepUpAnswer(deployment: Deployment, browser: Browser, key: SoftAuthenticator, tweak: Tweak = {}): Promise<{ state: string; response: unknown }> {
  const page = await passkeyPage(browser, '?step-up=1&next=/projects');
  return { state: page.state!, response: await key.assert(ceremonyOf(deployment, page.options!.challenge), tweak) };
}

/** Whether the browser's session reaches the API. */
async function signedIn(browser: Browser): Promise<boolean> {
  return (await browser.fetch('/api/projects')).status === 200;
}

/** A person admitted with this access, signed in, holding a passkey they signed in with, a moment ago. */
async function keyHolder(deployment: Deployment, admin: Person, name: string, access: Record<string, 'viewer' | 'developer' | 'maintainer'>): Promise<Person & { key: SoftAuthenticator }> {
  const person = await personaOn(deployment, admin, name, access);
  await withPasskey(deployment, person);
  return { ...person, key: passkeyOf(person.email)! };
}

/** Another passkey of the person's, from Account → Passkeys: the key, and its id there. */
async function addPasskey(deployment: Deployment, person: Person, kind: { synced?: boolean } = {}): Promise<{ key: SoftAuthenticator; id: string }> {
  const before = new Set((await person.api.passkeys.list(person.member)).passkeys.map((passkey) => passkey.id));
  const { options, state } = await person.api.passkeys.options(person.member);
  const key = await SoftAuthenticator.create('ES256', kind);
  const response = await key.register({ ...ceremonyOf(deployment, options.challenge), userHandle: new Uint8Array(Buffer.from(options.user.id, 'base64url')) });
  await person.api.passkeys.add(person.member, { state, response: response as unknown as Record<string, unknown> });
  const added = (await person.api.passkeys.list(person.member)).passkeys.find((passkey) => !before.has(passkey.id));
  expect(added !== undefined, 'a passkey added in Account → Passkeys is not listed there');
  return { key, id: added!.id };
}

/** A passkey removed in Account → Passkeys, with a touch of `touched`: the browser's session replaced by the answer. */
function removePasskey(deployment: Deployment, browser: Browser, id: string, touched: SoftAuthenticator): Promise<Response> {
  return passkeyPage(browser, `?remove=${encodeURIComponent(id)}`).then(async (step) => {
    const response = step.options === null ? undefined : await touched.assert(ceremonyOf(deployment, step.options.challenge));
    return answer(browser, { state: step.state, ...(response === undefined ? {} : { response }) });
  });
}

/** A one-act touch, as `touching` makes it: the refusal's challenge, signed by `key`. */
async function touchOf(deployment: Deployment, refused: CoffreError, key: SoftAuthenticator): Promise<Touch> {
  expect(refused.code === 'touch_required' && refused.touch !== undefined, `an act asked no touch of its own: ${refused.status} ${refused.code}`, refused);
  const { challenge } = refused.touch!.options as { challenge: string };
  return { state: refused.touch!.state, response: (await key.assert(ceremonyOf(deployment, challenge))) as unknown as Record<string, unknown> };
}

/** A terminal's code, polled: 200 with a token, or the refusal it answered. */
async function polled(deployment: Deployment, code: string): Promise<string> {
  const answered = await pollDevice(deployment, code);
  return answered.ok ? 'token' : String((await bodyOf(answered)).error ?? answered.status);
}

/** A handle's plan at /use, as `coffre run` asks it: its status. */
async function used(deployment: Deployment, token: string, path = DEV): Promise<number> {
  return (await fetch(`${deployment.origin}/use/${path}`, { headers: { authorization: `Bearer ${token}` } })).status;
}

/** The rows a sign-in would make, by table: a person, an account, a credential, a passkey, a terminal's code. */
async function signinRows(deployment: Deployment): Promise<Record<string, number>> {
  return using(deployment.database(), async (sql) => {
    const counts: Record<string, number> = {};
    for (const table of ['principals', 'identities', 'credentials', 'passkeys', 'device_logins']) {
      const [row] = await query<{ n: number | string }>(sql, `SELECT COUNT(*) AS n FROM ${table}`);
      counts[table] = Number(row?.n ?? 0);
    }
    return counts;
  });
}

/**
 * 22, 7 and 27: under `required`, on the empty database the deployment booted on and a cold vault (restarted so),
 * through its real entry: a provider sign-in that stops at the passkey sets no session and leaves no row of its own;
 * then the Owner the config names signs in, adds a passkey and lands, and signs in again with it. The deployment goes
 * back to `optional` after, for the checks that follow, the admin's passkey kept.
 */
export async function requiredFromCold(deployment: Deployment) {
  await deployment.restart({ PASSKEYS: 'required' });
  const before = await signinRows(deployment);
  const stopped = new Browser(deployment.origin);
  const at = await provider(deployment, stopped, deployment.owner);
  expect(at.pathname === '/auth/passkey', `under required, the Owner's provider sign-in went to ${at.pathname}, not to the passkey`, at.href);
  // 7: what the stopped sign-in set is no session.
  for (const path of ['/api/me', '/api/projects']) {
    const answered = await stopped.fetch(path);
    expect(answered.status === 401, `a sign-in stopped at the passkey reached ${path}: ${answered.status}`, await answered.text());
  }
  const after = await signinRows(deployment);
  expect(JSON.stringify(after) === JSON.stringify(before), 'a sign-in stopped at the passkey wrote rows of its own', { before, after });

  const { value: admin } = await signInAdmin(deployment);
  const key = passkeyOf(deployment.owner);
  expect(key !== undefined, 'under required, the configured Owner signed in without adding a passkey');
  // 27: again, with the passkey added there, and asked for no other.
  const again = new Browser(deployment.origin);
  const signed = await signIn(deployment, again, deployment.owner);
  expect(signed.ok && passkeyOf(deployment.owner) === key && (await signedIn(again)), `the Owner did not sign in again with the passkey added: ${'error' in signed ? signed.error : ''}`);
  await deployment.restart({ PASSKEYS: 'optional' });
  return { detail: `under required, from cold: a stopped sign-in left no session and no row (${Object.entries(before).map(([table, n]) => `${table} ${n}`).join(', ')}); the configured Owner added a passkey, landed, and signed in again with it`, value: admin };
}

/**
 * The ceremonies themselves (1 to 6, 10, 13, 20, 21, 29): each answer bound to its origin, RP ID, user verification,
 * backup flags, passkey, purpose and state, used once; a touch that opens a window ends the session it came in on and
 * keeps its expiry; an enroll's state adds one passkey, never two, and none after a reset.
 */
export async function ceremonies(deployment: Deployment, { admin }: People): Promise<string> {
  const ada = await keyHolder(deployment, admin, 'ada', { [DEV]: 'developer' });
  const adminKey = passkeyOf(admin.email)!;
  const tweaks: [string, Tweak][] = [
    ['for another origin', { clientData: { origin: 'https://secrets-evil.example' } }],
    ["for another RP ID's hash", { rpId: 'evil.example' }],
    ['without user verification', { flags: FLAGS.UP }],
    ['backed up but not backup-eligible', { flags: FLAGS.UP | FLAGS.UV | FLAGS.BS }],
  ];

  // 1, 2, 6 at the step-up, and 4: refused, and the session stays as it was.
  for (const [what, tweak] of [...tweaks, ['by another member\'s passkey', {}] as [string, Tweak]]) {
    const signer = what.startsWith('by another') ? adminKey : ada.key;
    const refused = await answer(ada.browser, await stepUpAnswer(deployment, ada.browser, signer, tweak));
    expect(await refusedAs(refused, 401, 'passkey_failed'), `a step-up assertion ${what} answered ${await said(refused)}, not 401 passkey_failed`);
  }
  expect(await signedIn(ada.browser), 'a refused step-up ended the session it came in on');

  // Added before the sign-in below starts: a passkey's replay mark starts at its own ceremony, which a challenge drawn
  // before it would not pass.
  const synced = await addPasskey(deployment, ada, { synced: true });
  // 1, 4, 6 at a sign-in: refused, then the honest answer signs in.
  const signing = new Browser(deployment.origin);
  expect((await provider(deployment, signing, ada.email)).pathname === '/auth/passkey', "ada's sign-in asked no passkey");
  for (const [what, tweak] of [tweaks[0]!, tweaks[2]!, ['by another member\'s passkey', {}] as [string, Tweak]]) {
    const page = await passkeyPage(signing);
    const signer = what.startsWith('by another') ? adminKey : ada.key;
    const refused = await answer(signing, { response: await signer.assert(ceremonyOf(deployment, page.options!.challenge), tweak) });
    expect((await refusedAs(refused, 401, 'passkey_failed')) && !(await signedIn(signing)), `a sign-in assertion ${what} answered ${await said(refused)}, not 401 passkey_failed`);
  }

  // 3 at a sign-in: the same assertion, sent again with the same sealed state from a copy, signs in once. Signed by a
  // synced passkey, whose counter stays 0: only the replay mark (section 7.3) refuses it, not a counter standing still.
  const page = await passkeyPage(signing);
  const thief = signing.copy();
  const response = await synced.key.assert(ceremonyOf(deployment, page.options!.challenge));
  const first = await answer(signing, { response });
  expect(first.ok && (await signedIn(signing)), `the honest sign-in assertion answered ${await said(first)}`);
  const replayed = await answer(thief, { response });
  expect(replayed.status === 400 && (await bodyOf(replayed)).error === 'state_mismatch' && !(await signedIn(thief)),
    `a synced passkey's sign-in assertion sent twice answered ${await said(replayed)}, not 400 state_mismatch`);

  // 10 and 21: a fresh check ends the session it came in on, and the new one expires when that one would have.
  const expiry = async (browser: Browser) => (await browser.client().sessions.list()).sessions.find((session) => session.current)?.expiresAt;
  const was = await expiry(ada.browser);
  const old = ada.browser.copy();
  await stepUp(deployment, ada.browser, ada.email);
  expect((await old.fetch('/api/projects')).status === 401, 'after a fresh check, the session it came in on still answers');
  const now = await expiry(ada.browser);
  expect(was !== undefined && now !== undefined && Math.abs(Date.parse(now) - Date.parse(was)) < 1000,
    `the session a fresh check made expires at ${now}, not when the one before it would have, ${was}`);
  // 3 at a step-up: the same answer again, from a copy of the session it ended, is refused.
  const step = await stepUpAnswer(deployment, ada.browser, ada.key);
  const before = ada.browser.copy();
  expect((await answer(ada.browser, step)).ok, 'an honest step-up was refused');
  const stepReplayed = await answer(before, step);
  expect((await refusedAs(stepReplayed, 401, 'session_ended')) && !(await signedIn(before)), `a step-up answer sent twice, from the session it ended, answered ${await said(stepReplayed)}, not 401 session_ended`);

  // 20: two fresh checks on one session, at once: one new session, one 401.
  const [one, two] = [await stepUpAnswer(deployment, ada.browser, ada.key), await stepUpAnswer(deployment, ada.browser, ada.key)];
  const copies = [ada.browser.copy(), ada.browser.copy()];
  const raced = await Promise.all([answer(copies[0]!, one), answer(copies[1]!, two)]);
  const won = raced.filter((each) => each.ok).length;
  expect(won === 1 && raced.some((each) => each.status === 401), `two fresh checks on one session answered ${raced.map((each) => each.status).join(' and ')}, not one session and one 401`);
  // Ada signs in again for what follows: the session the browser held ended with the race.
  expect((await signIn(deployment, ada.browser, ada.email)).ok, 'ada could not sign in again');

  // 5: one purpose's state completes no other. A sign-in's sealed cookie, as a step-up's state:
  const pending = new Browser(deployment.origin);
  await provider(deployment, pending, ada.email);
  const pendingPage = await passkeyPage(pending);
  const sealed = pending.cookies().find(([name]) => name.includes('passkey'))?.[1];
  expect(sealed !== undefined, 'a sign-in stopped at the passkey left no sealed cookie', pending.cookies().map(([name]) => name));
  const crossed = await answer(ada.browser, { state: decodeURIComponent(sealed!), response: await ada.key.assert(ceremonyOf(deployment, pendingPage.options!.challenge)) });
  // A state that opens as no step-up of this session's is answered as one whose session ended: `401 session_ended`.
  expect((await refusedAs(crossed, 401, 'session_ended')) && (await signedIn(ada.browser)),
    `a sign-in's state, as a step-up's, answered ${await said(crossed)}, not 401 session_ended, or ended the session it came in on`);
  // A touch for another act, or no act's, counts as none: `403 touch_required`, with a challenge for this one.
  // a step-up's state and answer, as a terminal's approval:
  const terminal = await startDevice(deployment);
  const asStepUp = await stepUpAnswer(deployment, ada.browser, ada.key);
  const crossedDevice = await refusal(ada.api.deviceLogins.decide(terminal.user_code, true, asStepUp as Touch));
  expect(crossedDevice.status === 403 && crossedDevice.code === 'touch_required', `a step-up's answer, as a terminal's touch, answered ${crossedDevice.status} ${crossedDevice.code}, not 403 touch_required`);
  // and one terminal's touch, as another's:
  const other = await startDevice(deployment);
  const touch = await touchOf(deployment, await refusal(ada.api.deviceLogins.decide(terminal.user_code, true)), ada.key);
  const crossedCode = await refusal(ada.api.deviceLogins.decide(other.user_code, true, touch));
  expect(crossedCode.status === 403 && crossedCode.code === 'touch_required', `one terminal's touch, as another's, answered ${crossedCode.status} ${crossedCode.code}, not 403 touch_required`);
  expect((await polled(deployment, other.device_code)) === 'authorization_pending', 'a terminal approved with another\'s touch is not pending');
  await ada.api.deviceLogins.decide(terminal.user_code, true, touch);
  expect((await polled(deployment, terminal.device_code)) === 'token', 'the touch for its own terminal did not approve it');

  // 13, 6 at an enroll, and 29: an enroll's state adds one passkey; again, none; after a reset, none.
  const cy = await personaOn(deployment, admin, 'cy', { [DEV]: 'viewer' });
  expect((await provider(deployment, cy.browser, cy.email, '/auth/signin/github?passkey=add')).pathname === '/auth/passkey', 'adding a first passkey asked none');
  const enroll = await passkeyPage(cy.browser);
  expect(enroll.purpose === 'enroll' && enroll.state !== undefined, 'adding a first passkey was not an enroll', enroll);
  const [later, afterReset] = [cy.browser.copy(), cy.browser.copy()];
  const register = async (key: SoftAuthenticator, tweak: Tweak = {}) =>
    key.register({ ...ceremonyOf(deployment, enroll.options!.challenge), userHandle: new Uint8Array(Buffer.from(enroll.options!.user!.id, 'base64url')) }, tweak);
  const unverified = await answer(cy.browser, { state: enroll.state, response: await register(await SoftAuthenticator.create(), { flags: FLAGS.UP }) });
  expect(await refusedAs(unverified, 401, 'passkey_failed'), `an enroll without user verification answered ${await said(unverified)}, not 401 passkey_failed`);
  const cyKey = await SoftAuthenticator.create();
  const enrolled = await answer(cy.browser, { state: enroll.state, response: await register(cyKey) });
  expect(enrolled.ok, `the honest enroll was refused: ${await said(enrolled)}`);
  keepPasskey(cy.email, cyKey);
  const held = async () => (await admin.api.passkeys.list(cy.member)).passkeys.length;
  // A first passkey's enroll holds only while the person has never had one (section 3.2): `400 passkey_exists` after.
  const spent = async (answered: Response) => answered.status === 400 && (await bodyOf(answered)).error === 'passkey_exists';
  const second = await answer(later, { state: enroll.state, response: await register(await SoftAuthenticator.create()) });
  expect((await spent(second)) && (await held()) === 1, `a second enroll with the same state answered ${await said(second)}, not 400 passkey_exists, or added a passkey`);
  await admin.api.passkeys.reset(cy.member);
  const reused = await answer(afterReset, { state: enroll.state, response: await register(await SoftAuthenticator.create()) });
  expect((await spent(reused)) && (await held()) === 0, `an enroll's state used again after a reset answered ${await said(reused)}, not 400 passkey_exists, or enrolled`);

  return `refused at the step-up and at sign-in: an assertion for another origin, another RP ID, without UV, backed up but not eligible, by another member's passkey; ` +
    `an answer sent twice taken once, at sign-in and at the step-up; a fresh check ends its session and keeps its expiry; two at once, one session and one 401; ` +
    `a sign-in's state completes no step-up, a step-up's no terminal, a terminal's touch no other; an enroll's state adds one passkey, and none again, after a reset too`;
}

/**
 * What a change to someone's passkeys ends, and what a touch for one act carries (11, 12, 15, 17, 18, 23, 25, 30, 31,
 * 34, 35): a first passkey ends what none confirmed; a removal everything else; a reset too, for good; an approval or a
 * consent needs its own touch, which approves that act alone.
 */
export async function passkeyChanges(deployment: Deployment, { admin }: People): Promise<string> {
  // 17, 18, 23: what a person made before their first passkey ends with it, and a reset brings none of it back.
  const dee = await personaOn(deployment, admin, 'dee', { [DEV]: 'developer' });
  const cli = bearer(deployment.origin, await deviceLogin(deployment, dee.browser));
  const approved = await startDevice(deployment);
  await dee.api.deviceLogins.decide(approved.user_code, true);
  // Approved too, left unpolled through the first passkey and the reset: denied by the first, and still after (23).
  const unpolled = await startDevice(deployment);
  await dee.api.deviceLogins.decide(unpolled.user_code, true);
  const handle = await dee.api.handles.create({ label: 'conformance', paths: [DEV] });
  expect((await used(deployment, handle.token)) === 200, 'a handle made before any passkey does not reach /use');
  await withPasskey(deployment, dee);
  // Denied for good by the first passkey itself, unpolled: a poll now would be refused anyway while Dee holds one, and
  // a reset denies what is left, so only the row shows it (a later `off` would let an approval still standing redeem).
  const decision = await using(deployment.database(), async (sql) =>
    (await query<{ decision: string }>(sql, 'SELECT decision FROM device_logins WHERE user_code = $1', [unpolled.user_code]))[0]?.decision);
  expect(decision === 'denied', `a terminal approved before the first passkey is ${decision} after it, not denied`);
  expect((await refusal(cli.me())).status === 401, "a CLI session made before the person's first passkey still answers");
  const deniedFirst = await polled(deployment, approved.device_code);
  expect(deniedFirst === 'access_denied', `a terminal approved before the first passkey answered ${deniedFirst} after it, not access_denied`);
  expect((await used(deployment, handle.token)) === 401, 'a handle made before the first passkey still reaches /use');
  await admin.api.passkeys.reset(dee.member);
  expect((await refusal(cli.me())).status === 401, 'a CLI session made before the first passkey answers again once that passkey is reset');
  const deniedAfter = await polled(deployment, unpolled.device_code);
  expect(deniedAfter === 'access_denied', `a terminal approved before the first passkey, polled once it was reset, answered ${deniedAfter}, not access_denied`);
  expect((await used(deployment, handle.token)) === 401, 'a handle made before the first passkey reaches /use again once that passkey is reset');

  // 30: under optional, an unscoped Owner without a passkey adds one at sign-in; a Developer does not.
  const deeAgain = new Browser(deployment.origin);
  expect((await provider(deployment, deeAgain, dee.email)).pathname !== '/auth/passkey', 'a Developer whose passkeys were reset was asked for one at sign-in');
  const eve = 'user:eve@conformance.example';
  await admin.api.members.add(eve, { role: 'owner' });
  const eveBrowser = new Browser(deployment.origin);
  expect((await provider(deployment, eveBrowser, 'eve@conformance.example')).pathname === '/auth/passkey', 'an unscoped Owner with no passkey signed in without adding one');
  expect((await passkeyPage(eveBrowser)).purpose === 'enroll', "an unscoped Owner's first sign-in was asked no new passkey");
  await admin.api.members.remove(eve);

  // 11: a session confirmed a moment ago approves no terminal without that terminal's own touch.
  const fay = await keyHolder(deployment, admin, 'fay', { [DEV]: 'developer' });
  const waiting = await startDevice(deployment);
  const untouched = await refusal(fay.api.deviceLogins.decide(waiting.user_code, true));
  expect(untouched.status === 403 && untouched.code === 'touch_required', `a fresh session approved a terminal without its touch: ${untouched.status} ${untouched.code}`);
  expect((await polled(deployment, waiting.device_code)) === 'authorization_pending', 'a terminal refused its approval is not pending');

  // 12, 15, 18: what the first passkey confirmed, once it is removed, with a touch of the second.
  const second = await addPasskey(deployment, fay);
  const first = (await fay.api.passkeys.list(fay.member)).passkeys.find((passkey) => passkey.id !== second.id)!;
  const fayCli = bearer(deployment.origin, await deviceLogin(deployment, fay.browser));
  const personal = bearer(deployment.origin, (await fay.api.tokens.issue(fay.member, { label: 'conformance', expiresInMinutes: 60, scope: { [DEV]: 'viewer' } })).token);
  const elsewhere = new Browser(deployment.origin);
  expect((await signIn(deployment, elsewhere, fay.email)).ok, 'fay could not sign in elsewhere');
  const fayHandle = await fay.api.handles.create({ label: 'conformance', paths: [DEV] });
  // An MCP client connected with the first passkey's touch: its access token and its refresh token end with it too.
  const fayClient = await register(deployment);
  const fayApp = await redeem(deployment, fayClient, await connect(deployment, fay, fayClient));
  expect(await discovers(deployment, fayApp.access_token), "fay's MCP client does not reach /mcp before the removal");
  const pendingCode = await startDevice(deployment);
  await fay.api.deviceLogins.decide(pendingCode.user_code, true, await touchOf(deployment, await refusal(fay.api.deviceLogins.decide(pendingCode.user_code, true)), fay.key));
  const removed = await removePasskey(deployment, fay.browser, first.id, second.key);
  expect(removed.ok && (await signedIn(fay.browser)), `removing a passkey with a touch of another answered ${await said(removed)}`);
  const deniedRemoved = await polled(deployment, pendingCode.device_code);
  expect(deniedRemoved === 'access_denied', `a terminal approved with a passkey since removed answered ${deniedRemoved}, not access_denied`);
  const elsewhereAnswered = await elsewhere.fetch('/api/projects');
  expect((await refusal(fayCli.me())).status === 401 && (await refusal(personal.me())).status === 401 && elsewhereAnswered.status === 401,
    `a credential the removed passkey confirmed still answers, or answers other than 401 (the browser elsewhere: ${await said(elsewhereAnswered)})`);
  expect((await used(deployment, fayHandle.token)) === 401, 'a handle still reaches /use after its person removed a passkey');
  expect(!(await discovers(deployment, fayApp.access_token)), 'an MCP client connected before a passkey was removed still reaches /mcp');
  await refused(deployment, "an MCP client's refresh token, after a passkey was removed", { grant_type: 'refresh_token', refresh_token: fayApp.refresh_token, client_id: fayClient });
  const withRemoved = new Browser(deployment.origin);
  await provider(deployment, withRemoved, fay.email);
  const removedPage = await passkeyPage(withRemoved);
  const signedRemoved = await answer(withRemoved, { response: await fay.key.assert(ceremonyOf(deployment, removedPage.options!.challenge)) });
  expect((await refusedAs(signedRemoved, 401, 'passkey_failed')) && !(await signedIn(withRemoved)), `a removed passkey's sign-in answered ${await said(signedRemoved)}, not 401 passkey_failed`);
  keepPasskey(fay.email, second.key);

  // 35: a handle issued while a removal runs is refused, or revoked with the rest: never live after.
  let raced = 0;
  for (let round = 0; round < 3; round++) {
    const doomed = await addPasskey(deployment, fay);
    const racer = new Browser(deployment.origin);
    expect((await signIn(deployment, racer, fay.email)).ok, 'fay could not sign in to race');
    // Refused only as a source the removal ended is: 401 once it is revoked, 403 when it ended under the issue's lock.
    const [issued, gone] = await Promise.all([
      racer.client().handles.create({ label: 'conformance race', paths: [DEV] }).catch((error: unknown) => {
        if (error instanceof CoffreError && (error.status === 401 || (error.status === 403 && error.code === 'forbidden' && /session has ended/.test(error.message)))) return null;
        throw error;
      }),
      removePasskey(deployment, fay.browser, doomed.id, second.key),
    ]);
    expect(gone.ok, `the raced removal answered ${await said(gone)}`);
    if (issued !== null) {
      raced++;
      expect((await used(deployment, issued.token)) === 401, 'a handle issued while a removal ran is live after it');
    }
  }

  // 31 and 34: an MCP client's approval, and its consent, need a touch of their own, which approves that act alone.
  const clientId = await register(deployment);
  const { access_token: managing } = await redeem(deployment, clientId, await connect(deployment, admin, clientId, 'read', ['manage-access']));
  const ask = async (service: string) => {
    const { body } = await modern(deployment, managing, 'tools/call', { name: 'issue_service_token', arguments: { service, expiresInDays: 1 } }, 'issue_service_token');
    const id = (body.result as { structuredContent?: { approval?: { id: string } } } | undefined)?.structuredContent?.approval?.id;
    expect(id !== undefined, 'issue_service_token asked no approval', body);
    return (await admin.api.approvals.get(id!)).approval;
  };
  const shown = await ask('conformance-ci');
  const bare = await refusal(admin.api.approvals.decide(shown.id, { approve: true, digest: shown.digest, basis: shown.basis }));
  expect(bare.status === 403 && bare.code === 'touch_required', `an MCP approval without its own touch answered ${bare.status} ${bare.code}`);
  expect((await admin.api.approvals.get(shown.id)).approval.status === 'pending', 'an approval refused for want of a touch is not pending');
  const touch = await touchOf(deployment, bare, passkeyOf(admin.email)!);
  const decided = await admin.api.approvals.decide(shown.id, { approve: true, digest: shown.digest, basis: shown.basis, touch });
  expect(decided.status === 'approved', 'the approval with its touch issued no token', decided);
  // Another service's, whose page the first token's issue left as it showed: the touch is all that is weighed.
  await admin.api.members.add('token:conformance-touched');
  await admin.api.access.set('token:conformance-touched', { [DEV]: 'viewer' });
  const next = await ask('conformance-touched');
  const reused = await refusal(admin.api.approvals.decide(next.id, { approve: true, digest: next.digest, basis: next.basis, touch }));
  // Counted as no touch: `403 touch_required`, asking one for this approval.
  expect(reused.status === 403 && reused.code === 'touch_required' && (await admin.api.approvals.get(next.id)).approval.status === 'pending',
    `one approval's touch approved another: ${reused.status} ${reused.code} ${reused.message}`);
  await admin.api.approvals.decide(next.id, { approve: false, digest: next.digest, basis: next.basis });
  const apps = async () => (await admin.api.apps.list()).apps.length;
  const appsBefore = await apps();
  const consent = consentRequest(deployment, await register(deployment));
  const unconsented = await refusal(admin.api.oauth.decide({ request: consent, approve: true, scopes: ['read'] }));
  expect(unconsented.status === 403 && (await apps()) === appsBefore, `an MCP consent without its own touch answered ${unconsented.status} ${unconsented.code}, or connected`);

  // 25: a consent whose session a removal ended meanwhile connects nothing.
  const doomed = await addPasskey(deployment, fay);
  const consenting = new Browser(deployment.origin);
  expect((await signIn(deployment, consenting, fay.email)).ok, 'fay could not sign in to consent');
  const request = consentRequest(deployment, await register(deployment));
  const view = await consenting.client().oauth.describe(request);
  expect(view.status === 'ready', 'the consent page refused a good request', view);
  const askedTouch = await refusal(consenting.client().oauth.decide({ request, approve: true, scopes: ['read'] }));
  const consentTouch = await touchOf(deployment, askedTouch, second.key);
  expect((await removePasskey(deployment, fay.browser, doomed.id, second.key)).ok, 'the removal during a consent was refused');
  const ended = await refusal(consenting.client().oauth.decide({ request, approve: true, scopes: ['read'], touch: consentTouch }));
  expect(ended.status === 401 && ended.code === 'unauthenticated', `a consent whose session a removal ended answered ${ended.status} ${ended.code}, not 401 unauthenticated`);
  expect((await fay.api.apps.list()).apps.length === 0, 'a consent whose session a removal ended connected a client');

  return 'a first passkey ended the CLI session, the approved terminal and the handle no passkey confirmed, and a reset brought none back; ' +
    'an unscoped Owner adds one at sign-in, a Developer does not; a terminal, an MCP approval and a consent each need a touch of their own, which approves that act alone; ' +
    `a removal ends every credential the passkey confirmed, its terminal's code, its handles, its MCP client's tokens, and it signs nobody in; ${3 - raced} of 3 handles raced against a removal refused, the rest revoked; a consent a removal ended connects nothing`;
}

/** An MCP client's authorization request, as the consent page reads it. */
function consentRequest(deployment: Deployment, clientId: string) {
  return {
    client_id: clientId,
    redirect_uri: 'http://127.0.0.1:33418/callback',
    response_type: 'code',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    code_challenge_method: 'S256',
    state: '1e5',
    scope: 'read',
    resource: `${deployment.origin}/mcp`,
  };
}

/**
 * A browser session of the admin's, touched now and left alone, and a link to another account it started meanwhile:
 * where its callback, called once the session went stale, sent the browser, or why it could not be called.
 */
export type LeftAlone = { browser: Browser; at: number; linked: Promise<{ status: number; location: string } | { failed: string }> };

/** The account the left-alone session links, which no identity may name after. */
const ELSEWHERE = 'root-elsewhere@conformance.example';

/**
 * The admin, signed in in a browser of their own and then left alone, for 9, 14, 24 and 32: its session is fresh
 * now, and stale once five minutes pass. A link to another GitHub account starts while it is fresh, and calls back
 * five minutes and five seconds on, on a timer of its own, whatever check runs then: its pending state lasts ten
 * minutes, which the checks between here and `stale session` may outlast. A restart then (a scheduled job's, on Node)
 * is waited out, a minute at most.
 */
export async function leaveAlone(deployment: Deployment, admin: Person) {
  const browser = new Browser(deployment.origin);
  const signed = await signIn(deployment, browser, admin.email);
  expect(signed.ok, 'the admin could not sign in a second browser');
  const at = Date.now();
  const leave = await browser.fetch('/auth/signin/github?link=1');
  const authorize = new URL(leave.headers.get('location') ?? '', deployment.origin);
  expect(leave.status === 302 && authorize.origin === deployment.idp.origin, 'a link from a fresh session did not go to GitHub', `${leave.status} ${leave.headers.get('location')}`);
  const form = new URLSearchParams(authorize.searchParams);
  form.set('email', ELSEWHERE);
  const approve = await fetch(authorize.origin + authorize.pathname, { method: 'POST', body: form, redirect: 'manual' });
  const callback = approve.headers.get('location') ?? '';
  expect(callback.startsWith(`${deployment.origin}/auth/callback/github?`), 'GitHub did not send the link back', callback);
  const linked = new Promise<{ status: number; location: string } | { failed: string }>((done) => {
    const call = async (until: number): Promise<void> => {
      try {
        const back = await browser.fetch(callback);
        if (back.status < 500) return done({ status: back.status, location: back.headers.get('location') ?? '' });
        if (Date.now() > until) return done({ failed: `${back.status} ${await back.text()}` });
      } catch (error) {
        if (Date.now() > until) return done({ failed: String(error) });
      }
      setTimeout(() => void call(until), 1000).unref();
    };
    setTimeout(() => void call(Date.now() + 60_000), at + FRESH_MS + 5_000 - Date.now()).unref();
  });
  return { detail: 'the admin, in a browser left alone from now on, a link to another account started', value: { browser, at, linked } satisfies LeftAlone };
}

/**
 * 9, 14, 24, 32: from the session left alone, now more than five minutes after its touch: every **always** route
 * answers `403 fresh_check_required` and changes nothing, `?dryRun=1` where a route takes none too; the link started
 * while it was fresh is refused at its callback, and another at its start; a write that loosens a key's nature is
 * refused, the same write keeping it goes.
 */
export async function staleSession(deployment: Deployment, people: People, alone: LeftAlone, canaries: Canaries): Promise<string> {
  const { admin, reader } = people;
  const left = alone.at + FRESH_MS + 5_000 - Date.now();
  if (left > 0) await new Promise((done) => setTimeout(done, left));
  const { browser } = alone;
  expect(await signedIn(browser), 'the session left alone was signed out');

  // 14: the link, at its callback (called on its timer) and at a start.
  const back = await alone.linked;
  expect(!('failed' in back), `the link's callback could not be called: ${'failed' in back ? back.failed : ''}`);
  const { status, location } = back as { status: number; location: string };
  const landed = new URL(location, deployment.origin);
  expect(landed.searchParams.get('error') === 'link_stale', `a link whose session went stale was answered ${status} ${landed.pathname}${landed.search}`);
  const { identities } = await admin.api.identities.list();
  expect(!identities.some((identity) => identity.email === ELSEWHERE), 'a link refused at its callback linked an account', identities);
  const start = await browser.fetch('/auth/signin/github?link=1');
  expect(start.status === 302 && new URL(start.headers.get('location') ?? '', deployment.origin).origin === deployment.origin,
    `a link from a stale session was not sent to a fresh check: ${start.status} ${start.headers.get('location')}`);

  // 32 first, whose key is made by the admin's own, fresh, browser.
  const loose = canaries[`${DEV}/STALE_LOOSE`] = canary();
  await admin.api.secrets.set(DEV, { STALE_LOOSE: { value: loose, sensitivity: 'sensitive' } });
  const loosened = await browser.send('PATCH', `/api/secrets/${DEV}`, { STALE_LOOSE: { sensitivity: 'secret' } });
  expect(loosened.status === 403 && (await bodyOf(loosened)).error === 'fresh_check_required', `a stale session made a sensitive value a secret: ${await said(loosened)}`);
  const kept = (await admin.api.secrets.list(DEV)).keys.find((key) => key.key === 'STALE_LOOSE');
  expect(kept?.sensitivity === 'sensitive', 'a refused loosening loosened', kept);
  const same = await browser.send('PATCH', `/api/secrets/${DEV}`, { STALE_LOOSE: { sensitivity: 'sensitive' } });
  expect(same.ok, `a write keeping a key's nature was refused a stale session: ${await said(same)}`);

  // 9 and 24: every always route. The workloads' on a service of its own, with bodies the routes take, so that each
  // would change something were it let through; ids no row has where a row must exist first (a 404 then).
  const service = 'token:conformance-stale';
  await admin.api.members.add(service);
  const { keys: jwks } = (await (await fetch(deployment.idp.workloads.jwksUrl)).json()) as { keys: Record<string, unknown>[] };
  const issuer = 'https://stale.cluster.local';
  const placeholder = await SoftAuthenticator.create();
  const registration = await placeholder.register({ ...ceremonyOf(deployment, Buffer.alloc(32).toString('base64url')), userHandle: new Uint8Array(32) });
  const [project, environment] = DEV.split('/') as [string, string];
  // What the acts below would change, read by the admin's own browser before and after: the members, the reader's
  // grants, both people's passkeys, the service's tokens and bindings (where the deployment trusts workloads), the
  // settings, the roles, the projects and their environments, the freezes.
  const workloads = (await admin.api.me()).features.workloads;
  const reads = [
    '/api/members', `/api/members/${reader.member}/access`, `/api/members/${admin.member}/passkeys`, `/api/members/${reader.member}/passkeys`,
    `/api/members/${service}/tokens`, ...(workloads ? [`/api/members/${service}/bindings`] : []), '/api/settings', '/api/roles', '/api/projects', '/api/freezes',
  ];
  // A read this deployment does not serve (`501 not_implemented`: freezes, on Node) has nothing to change.
  const served = await Promise.all(reads.map(async (path) => ((await admin.browser.fetch(path)).status === 501 ? null : path)));
  const watched = served.filter((path) => path !== null);
  const snapshot = async () => Promise.all(watched.map(async (path) => {
    const read = await admin.browser.fetch(path);
    expect(read.status === 200, `the admin could not read ${path}: ${await said(read)}`);
    // The members list's `reads` says how far the instance has counted reads, which moves on its own.
    const { reads: _counted, ...body } = (await read.json()) as Record<string, unknown>;
    return [path, JSON.stringify(body)] as const;
  }));
  const was = await snapshot();
  const acts: [string, string, unknown?][] = [
    ['PUT', '/api/members/user:stale-new@conformance.example', {}],
    ['PUT', '/api/members/user:stale-new@conformance.example?dryRun=1', {}],
    ['DELETE', `/api/members/${reader.member}`],
    ['PATCH', `/api/access/${reader.member}`, { [BULK]: 'viewer' }],
    ['PATCH', `/api/access/${reader.member}?dryRun=1`, { [BULK]: 'viewer' }],
    ['POST', `/api/members/${admin.member}/passkeys/options`],
    ['POST', `/api/members/${admin.member}/passkeys`, { state: 'stale', response: registration }],
    ['DELETE', `/api/members/${reader.member}/passkeys`],
    ['POST', `/api/members/${service}/tokens`, { label: 'stale', expiresInDays: 1 }],
    ['POST', `/api/members/${service}/bindings`, { profile: 'custom', issuer, claims: { sub: 'stale' }, jwks: { keys: jwks } }],
    ['POST', `/api/members/${service}/bindings/keys`, { issuer, jwks: { keys: jwks } }],
    ['POST', `/api/members/${service}/bindings/${crypto.randomUUID()}/enrollments`, {}],
    ['POST', `/api/members/${service}/bindings/${crypto.randomUUID()}/enrollments/${crypto.randomUUID()}/promote`, {}],
    ['POST', `/api/members/${service}/tokens/${crypto.randomUUID()}/approve`],
    ['PUT', '/api/settings', { serviceAccounts: { projects: 'all' } }],
    ['POST', '/api/audit/loss', { from: 1, to: 1 }],
    ['DELETE', `/api/projects/${project}`],
    ['DELETE', `/api/projects/${project}/${environment}`],
    ['PATCH', `/api/projects/${project}/${environment}`, { protected: false }],
    ['PUT', '/api/roles/stale-role', { name: 'Stale', description: 'never made', permissions: ['secret.read'], protected: [] }],
    ['DELETE', '/api/roles/developer'],
    ['PUT', '/api/instance-roles/stale-role', { name: 'Stale', description: 'never made', permissions: ['audit.read'], protected: [] }],
    ['DELETE', '/api/instance-roles/stale-role'],
    ['DELETE', `/api/freezes/${encodeURIComponent(DEV)}`],
  ];
  const answered: string[] = [];
  for (const [method, path, body] of acts) {
    const response = await browser.send(method, path, body);
    const error = (await bodyOf(response)).error;
    if (response.status !== 403 || error !== 'fresh_check_required') answered.push(`${method} ${path}: ${await said(response)}`);
  }
  expect(answered.length === 0, 'a route that takes a fresh check let a stale session through', answered);

  const now = await snapshot();
  const changed = now.filter(([, read], at) => read !== was[at]![1]).map(([path, read]) => ({ path, was: was.find(([each]) => each === path)![1], now: read }));
  expect(changed.length === 0, `a route refused a stale session changed what ${changed.map(({ path }) => path).join(', ')} reads`, changed);
  expect((await admin.api.secrets.list(DEV)).keys.some((key) => key.key === 'STALE_LOOSE'), 'a refused erase erased an environment');
  return `${acts.length} acts of routes that take a fresh check, ?dryRun=1 on two that take none, refused a session touched over five minutes ago, changing nothing ${watched.length} reads show; ` +
    'a link it started while fresh refused at its callback, and another sent to a fresh check; a loosening refused, the same write keeping the nature taken';
}

/**
 * 26: a role that may use a protected environment's keys but not read them reveals no value there, from a browser
 * session confirmed a moment ago as from a personal token: a passkey widens no read.
 */
export async function readsStayReads(deployment: Deployment, { admin }: People, canaries: Canaries): Promise<string> {
  const place = `${PROJECT}/vaulted`;
  await admin.api.environments.create(place, { name: 'Vaulted' });
  const value = canary();
  canaries[`${place}/USED`] = value;
  await admin.api.secrets.set(place, { USED: value });
  await admin.api.environments.protect(place);
  const hal = await personaOn(deployment, admin, 'hal', {});
  await admin.api.access.set(hal.member, { [place]: 'contributor' });
  await withPasskey(deployment, hal);
  const fresh = await refusal(hal.api.secrets.reveal(place));
  const pat = bearer(deployment.origin, (await hal.api.tokens.issue(hal.member, { label: 'conformance', expiresInMinutes: 60, scope: { [place]: 'contributor' } })).token);
  const token = await refusal(pat.secrets.reveal(place));
  expect(fresh.status === 403 && token.status === 403, `a use-only role revealed a protected value: ${fresh.status} from a fresh session, ${token.status} from a personal token`);

  // Through MCP, connected with Reveal values and Hal's touch: neither into the conversation nor on coffre's page.
  const clientId = await register(deployment);
  const { access_token: access } = await redeem(deployment, clientId, await connect(deployment, hal, clientId, 'read reveal'));
  const answers: string[] = [];
  const call = async (tool: string, args: Record<string, unknown>) => {
    const { body } = await modern(deployment, access, 'tools/call', { name: tool, arguments: args }, tool);
    answers.push(JSON.stringify(body));
    return body.result as { isError?: boolean; structuredContent?: { status?: string; approval?: { id: string } } } | undefined;
  };
  const revealed = await call('reveal_secret_values', { path: place });
  expect(revealed?.isError === true, `a use-only role's MCP client was not refused reveal_secret_values on ${place}`, revealed);
  const shown = await call('show_secret_value', { secret: `${place}/USED` });
  const id = shown?.structuredContent?.approval?.id;
  let page = 'refused at the tool';
  if (id !== undefined) {
    // An approval opened: pressing Reveal on it, with Hal's touch, shows no value either. Each answer is read whole,
    // the page's GET and every decision's, a refusal's body too, before anything reads what it says.
    const whole = async (method: string, path: string, body?: unknown) => {
      const response = await hal.browser.send(method, path, body);
      const text = await response.text();
      answers.push(text);
      let parsed: { error?: string; touch?: { options: unknown; state: string }; approval?: { digest: string; basis: string } } | null = null;
      try { parsed = JSON.parse(text); } catch { /* said as it came, in `answers` */ }
      return { status: response.status, body: parsed };
    };
    const opened = await whole('GET', `/api/approvals/${encodeURIComponent(id)}`);
    const approval = opened.body?.approval;
    expect(opened.status === 200 && approval !== undefined, `Hal's approval page for show_secret_value answered ${opened.status}`, opened.body);
    const decided = await touching(hal.browser, async (touch) => {
      const sent = await whole('POST', `/api/approvals/${encodeURIComponent(id)}`, { approve: true, digest: approval!.digest, basis: approval!.basis, ...(touch === undefined ? {} : { touch }) });
      if (sent.status === 403 && sent.body?.error === 'touch_required' && sent.body.touch !== undefined) throw new CoffreError(403, 'touch_required', 'touch required', undefined, undefined, sent.body.touch, 'POST');
      return sent.status < 400 ? `${sent.status}` : `${sent.status} ${sent.body?.error ?? 'unreadable'}`;
    });
    page = `its approval, pressed, answered ${decided}, without the value`;
  } else {
    expect(shown?.isError === true, `show_secret_value on ${place}/USED neither refused nor opened an approval`, shown);
  }
  expect(!answers.some((each) => each.includes(value)), `a use-only role's MCP client, or its approval page, held ${place}/USED's value`);
  return `a contributor on ${place}, protected, reveals nothing there, from a session touched a moment ago, a personal token, or an MCP client with Reveal values (show_secret_value ${page})`;
}

/**
 * 8, 16 and 19, under `required`: a browser session no passkey stands behind reaches nothing but its way out; a
 * one-key reveal it asks is refused alike whether the key exists, is sensitive or was never made, and logs no use;
 * services read as they did. The deployment stays `required` for the workload checks after, until `backToOptional`.
 * The way out is shown from a second session of the bulk reader's, so that `bulk.browser` stays signed in for the
 * canary scan's signed-in viewer once `backToOptional` lets it read again.
 */
export async function passkeysRequired(deployment: Deployment, { admin, bulk }: People, live: { token: string; canary: { project: string; environment: string; key: string; value: string } }, canaries: Canaries): Promise<string> {
  const sensitive = canaries[`${BULK}/REQUIRED_SENSITIVE`] = canary();
  const write = canaries[`${BULK}/REQUIRED_WRITE`] = canary();
  await admin.api.secrets.set(BULK, { REQUIRED_SENSITIVE: { value: sensitive, sensitivity: 'sensitive' } });
  const existing = (await admin.api.secrets.list(BULK)).keys.find((key) => key.key !== 'REQUIRED_SENSITIVE')?.key;
  expect(existing !== undefined, `${BULK} holds no key to ask for`);
  // 16: a handle of a person with no passkey, made under `optional`, which `/use` takes the same under `required`.
  const ivy = await personaOn(deployment, admin, 'ivy', { [DEV]: 'viewer' });
  const handle = await ivy.api.handles.create({ label: 'conformance required', paths: [DEV] });
  const usedFirst = await used(deployment, handle.token);
  expect(usedFirst === 200, `a handle made under optional answered ${usedFirst} at /use, not 200`);
  // Bulk holds no passkey: GitHub alone signs this second session in, under optional.
  const leaving = new Browser(deployment.origin);
  expect((await signIn(deployment, leaving, bulk.email)).ok, 'the bulk reader could not sign in a second session');
  const since = new Date().toISOString();
  await deployment.restart({ PASSKEYS: 'required' });

  // 8: nothing but the way out, `GET /api/me` included: `401 passkey_required` to each.
  const required = async (response: Response) => response.status === 401 && (await bodyOf(response)).error === 'passkey_required';
  const reached: string[] = [];
  for (const [method, path, body] of [
    ['GET', '/api/me'], ['GET', '/api/projects'], ['GET', '/api/members'], ['GET', '/api/sessions'], ['GET', `/api/secrets/${BULK}`],
    ['PATCH', `/api/secrets/${BULK}`, { REQUIRED_WRITE: { value: write } }], ['POST', '/api/handles', { label: 'x', paths: [BULK] }],
  ] as [string, string, unknown?][]) {
    const response = await bulk.browser.send(method, path, body);
    if (!(await required(response))) reached.push(`${method} ${path}: ${await said(response)}`);
  }
  expect(reached.length === 0, 'under required, a session no passkey stands behind was not answered 401 passkey_required', reached);

  // 19: one key, alike whatever it is.
  const reveal = async (key: string) => {
    const response = await bulk.browser.send('POST', '/api/reveals', { path: `${BULK}/${key}` });
    return { required: await required(response), said: `${response.status} ${await response.text()}` };
  };
  const answers = [await reveal(existing!), await reveal('REQUIRED_SENSITIVE'), await reveal('NEVER_MADE')];
  expect(answers.every((each) => each.required && each.said === answers[0]!.said), 'a refused credential told keys apart, or was not answered 401 passkey_required', answers.map((each) => each.said));
  const { entries } = await admin.api.audit.list({ actor: bulk.member, limit: 100 });
  const uses = entries.filter((entry) => entry.occurredAt >= since && entry.action.startsWith('secret.') && entry.decision === 'allow');
  expect(uses.length === 0, 'a refused credential has a use of a key in the log', uses);

  const out = await leaving.send('POST', '/auth/signout');
  expect(out.status === 303 || out.status === 302, `signing out a session no passkey stands behind answered ${out.status}`);
  expect(!(await signedIn(leaving)), 'a session no passkey stands behind, signed out, still read', await said(await leaving.fetch('/api/projects')));

  // 16: a service, with no passkey anywhere, reads as it did; the handle reaches /use as it did.
  const read = await bearer(deployment.origin, live.token).secrets.reveal(`${live.canary.project}/${live.canary.environment}`);
  expect(read.values[live.canary.key] === live.canary.value, "under required, a service's token did not read its value");
  const usedThen = await used(deployment, handle.token);
  expect(usedThen === 200, `under required, a handle made under optional answered ${usedThen} at /use, not 200 as before`);
  return 'under required, a session no passkey stands behind answered 401 passkey_required to every call, /api/me too, but signing out; a one-key reveal refused alike for a key that exists, a sensitive one and one never made, no use logged; a service read as before, and a handle reached /use as before';
}

/** The deployment back to `optional`, after the workload checks ran under `required` (16): the session `required` refused reads again. */
export async function backToOptional(deployment: Deployment, { bulk }: People): Promise<string> {
  await deployment.restart({ PASSKEYS: 'optional' });
  expect(await signedIn(bulk.browser), "back under optional, the bulk reader's session, refused under required, did not read", await said(await bulk.browser.fetch('/api/projects')));
  return "restarted under optional; the bulk reader's session, refused under required, reads again";
}

/**
 * 28: a sign-in pending at the passkey whose provider's issuer the deployment replaced, under the same provider ID,
 * before the passkey answered, completes nothing. GitHub's issuer is its API's URL: the same stand-in, by another name.
 */
export async function issuerReplaced(deployment: Deployment, { admin }: People): Promise<string> {
  const pending = new Browser(deployment.origin);
  expect((await provider(deployment, pending, admin.email)).pathname === '/auth/passkey', "the admin's sign-in asked no passkey");
  const page = await passkeyPage(pending);
  const response = await passkeyOf(admin.email)!.assert(ceremonyOf(deployment, page.options!.challenge));
  const idp = new URL(deployment.idp.origin);
  idp.hostname = idp.hostname === 'localhost' ? '127.0.0.1' : 'localhost';
  await deployment.restart({ PASSKEYS: 'optional', GITHUB_API_URL: `${idp.origin}/github/api` });
  try {
    const answered = await answer(pending, { response });
    expect(answered.status === 400 && (await bodyOf(answered)).error === 'state_mismatch' && !(await signedIn(pending)),
      `a sign-in whose issuer was replaced answered ${await said(answered)}, not 400 state_mismatch`);
  } finally {
    await deployment.restart({ PASSKEYS: 'optional' });
  }
  const again = new Browser(deployment.origin);
  expect((await signIn(deployment, again, admin.email)).ok, 'the admin could not sign in once the issuer was put back');
  return 'a sign-in pending at the passkey, its issuer replaced meanwhile, completed nothing';
}

/** 33: a deployment whose public URL is an IP address, with passkeys not off, does not start. */
export async function ipPublicUrl(deployment: Deployment): Promise<string> {
  const port = new URL(deployment.origin).port;
  const said = await deployment.refusesToStart({ PASSKEYS: 'optional', PUBLIC_URL: `http://127.0.0.1:${port}` });
  expect(/browsers make no passkey there|passkeys need a public URL/.test(said), 'a deployment at an IP address did not say why it refused to start', said);
  return 'at http://127.0.0.1, with passkeys optional, it refused to start, and said why';
}

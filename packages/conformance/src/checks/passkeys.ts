// Passkeys (docs/design/passkeys.md, section 13): what a deployment must never do with them, whatever code it runs. The
// numbers in the comments are that section's checks. The deployment runs as booted, `optional` as `coffre init` writes
// it; the checks that need `required` restart it so (`PASSKEYS`), and back.
import { CoffreError } from '@coffre/client';

import { FLAGS, SoftAuthenticator, type Tweak } from '../authenticator.ts';
import { bearer, Browser } from '../browser.ts';
import { using } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect } from '../report.ts';
import { connect, modern, redeem, register } from './mcp.ts';
import { BULK, canary, ceremonyOf, deviceLogin, DEV, keepPasskey, passkeyOf, personaOn, PROJECT, provider, signIn, signInAdmin, stepUp, withPasskey, type Canaries, type People, type Person, type Touch } from './people.ts';
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
async function addPasskey(deployment: Deployment, person: Person): Promise<{ key: SoftAuthenticator; id: string }> {
  const before = new Set((await person.api.passkeys.list(person.member)).passkeys.map((passkey) => passkey.id));
  const { options, state } = await person.api.passkeys.options(person.member);
  const key = await SoftAuthenticator.create('ES256');
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
  await deployment.restart();
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
    expect(refused.status === 401, `a step-up assertion ${what} answered ${await said(refused)}, not 401`);
  }
  expect(await signedIn(ada.browser), 'a refused step-up ended the session it came in on');

  // 1, 4, 6 at a sign-in: refused, then the honest answer signs in.
  const signing = new Browser(deployment.origin);
  expect((await provider(deployment, signing, ada.email)).pathname === '/auth/passkey', "ada's sign-in asked no passkey");
  for (const [what, tweak] of [tweaks[0]!, tweaks[2]!, ['by another member\'s passkey', {}] as [string, Tweak]]) {
    const page = await passkeyPage(signing);
    const signer = what.startsWith('by another') ? adminKey : ada.key;
    const refused = await answer(signing, { response: await signer.assert(ceremonyOf(deployment, page.options!.challenge), tweak) });
    expect(refused.status === 401 && !(await signedIn(signing)), `a sign-in assertion ${what} answered ${await said(refused)}, not 401`);
  }

  // 3 at a sign-in: the same assertion, sent again with the same sealed state from a copy, signs in once.
  const page = await passkeyPage(signing);
  const thief = signing.copy();
  const response = await ada.key.assert(ceremonyOf(deployment, page.options!.challenge));
  const first = await answer(signing, { response });
  expect(first.ok && (await signedIn(signing)), `the honest sign-in assertion answered ${await said(first)}`);
  const replayed = await answer(thief, { response });
  expect(!replayed.ok && !(await signedIn(thief)), `a sign-in assertion sent twice signed in twice: ${await said(replayed)}`);

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
  expect(!stepReplayed.ok && !(await signedIn(before)), `a step-up answer sent twice was taken twice: ${await said(stepReplayed)}`);

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
  expect(!crossed.ok, `a sign-in's state completed a step-up: ${await said(crossed)}`);
  // a step-up's state and answer, as a terminal's approval:
  const terminal = await startDevice(deployment);
  const asStepUp = await stepUpAnswer(deployment, ada.browser, ada.key);
  const crossedDevice = await refusal(ada.api.deviceLogins.decide(terminal.user_code, true, asStepUp as Touch));
  expect(crossedDevice.status === 403, `a step-up's answer approved a terminal: ${crossedDevice.status} ${crossedDevice.code}`);
  // and one terminal's touch, as another's:
  const other = await startDevice(deployment);
  const touch = await touchOf(deployment, await refusal(ada.api.deviceLogins.decide(terminal.user_code, true)), ada.key);
  const crossedCode = await refusal(ada.api.deviceLogins.decide(other.user_code, true, touch));
  expect(crossedCode.status === 403, `one terminal's touch approved another: ${crossedCode.status} ${crossedCode.code}`);
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
  expect(unverified.status === 401, `an enroll without user verification answered ${await said(unverified)}, not 401`);
  const cyKey = await SoftAuthenticator.create();
  const enrolled = await answer(cy.browser, { state: enroll.state, response: await register(cyKey) });
  expect(enrolled.ok, `the honest enroll was refused: ${await said(enrolled)}`);
  keepPasskey(cy.email, cyKey);
  const held = async () => (await admin.api.passkeys.list(cy.member)).passkeys.length;
  const second = await answer(later, { state: enroll.state, response: await register(await SoftAuthenticator.create()) });
  expect(!second.ok && (await held()) === 1, `a second enroll with the same state added a passkey: ${await said(second)}`);
  await admin.api.passkeys.reset(cy.member);
  const reused = await answer(afterReset, { state: enroll.state, response: await register(await SoftAuthenticator.create()) });
  expect(!reused.ok && (await held()) === 0, `an enroll's state used again after a reset enrolled: ${await said(reused)}`);

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
  const handle = await dee.api.handles.create({ label: 'conformance', paths: [DEV] });
  expect((await used(deployment, handle.token)) === 200, 'a handle made before any passkey does not reach /use');
  await withPasskey(deployment, dee);
  expect((await refusal(cli.me())).status === 401, "a CLI session made before the person's first passkey still answers");
  expect((await polled(deployment, approved.device_code)) !== 'token', 'a terminal approved before the first passkey redeemed a token after it');
  expect((await used(deployment, handle.token)) === 401, 'a handle made before the first passkey still reaches /use');
  await admin.api.passkeys.reset(dee.member);
  expect((await refusal(cli.me())).status === 401, 'a CLI session made before the first passkey answers again once that passkey is reset');

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
  const pendingCode = await startDevice(deployment);
  await fay.api.deviceLogins.decide(pendingCode.user_code, true, await touchOf(deployment, await refusal(fay.api.deviceLogins.decide(pendingCode.user_code, true)), fay.key));
  const removed = await removePasskey(deployment, fay.browser, first.id, second.key);
  expect(removed.ok && (await signedIn(fay.browser)), `removing a passkey with a touch of another answered ${await said(removed)}`);
  expect((await polled(deployment, pendingCode.device_code)) !== 'token', 'a terminal approved with a passkey redeemed a token after it was removed');
  expect((await refusal(fayCli.me())).status === 401 && (await refusal(personal.me())).status === 401 && !(await signedIn(elsewhere)),
    'a credential the removed passkey confirmed still answers');
  expect((await used(deployment, fayHandle.token)) === 401, 'a handle still reaches /use after its person removed a passkey');
  const withRemoved = new Browser(deployment.origin);
  await provider(deployment, withRemoved, fay.email);
  const removedPage = await passkeyPage(withRemoved);
  const signedRemoved = await answer(withRemoved, { response: await fay.key.assert(ceremonyOf(deployment, removedPage.options!.challenge)) });
  expect(signedRemoved.status === 401 && !(await signedIn(withRemoved)), `a removed passkey signed its person in: ${await said(signedRemoved)}`);
  keepPasskey(fay.email, second.key);

  // 35: a handle issued while a removal runs is refused, or revoked with the rest: never live after.
  let raced = 0;
  for (let round = 0; round < 3; round++) {
    const doomed = await addPasskey(deployment, fay);
    const racer = new Browser(deployment.origin);
    expect((await signIn(deployment, racer, fay.email)).ok, 'fay could not sign in to race');
    const [issued, gone] = await Promise.all([
      racer.client().handles.create({ label: 'conformance race', paths: [DEV] }).catch(() => null),
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
  expect(reused.status === 403 && (await admin.api.approvals.get(next.id)).approval.status === 'pending',
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
  expect(ended.status === 401 || ended.status === 403, `a consent whose session a removal ended answered ${ended.status} ${ended.code}`);
  expect((await fay.api.apps.list()).apps.length === 0, 'a consent whose session a removal ended connected a client');

  return 'a first passkey ended the CLI session, the approved terminal and the handle no passkey confirmed, and a reset brought none back; ' +
    'an unscoped Owner adds one at sign-in, a Developer does not; a terminal, an MCP approval and a consent each need a touch of their own, which approves that act alone; ' +
    `a removal ends every credential the passkey confirmed, its terminal's code, its handles, and it signs nobody in; ${3 - raced} of 3 handles raced against a removal refused, the rest revoked; a consent a removal ended connects nothing`;
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

/** A browser session of the admin's, touched now and left alone, and a link to another account it started meanwhile. */
export type LeftAlone = { browser: Browser; at: number; callback: string };

/**
 * The admin, signed in in a browser of their own and then left alone, for 9, 14, 24 and 32: its session is fresh
 * now, and stale once five minutes pass. A link to another GitHub account starts while it is fresh, and calls back
 * once it is not.
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
  form.set('email', 'root-elsewhere@conformance.example');
  const approve = await fetch(authorize.origin + authorize.pathname, { method: 'POST', body: form, redirect: 'manual' });
  const callback = approve.headers.get('location') ?? '';
  expect(callback.startsWith(`${deployment.origin}/auth/callback/github?`), 'GitHub did not send the link back', callback);
  return { detail: "the admin, in a browser left alone from now on, a link to another account started", value: { browser, at, callback } satisfies LeftAlone };
}

/**
 * 9, 14, 24, 32: from the session left alone, now more than five minutes after its touch: every **always** route
 * answers `403 fresh_check_required` and changes nothing, `?dryRun=1` where a route takes none too; the link started
 * while it was fresh is refused at its callback, and another at its start; a write that loosens a key's nature is
 * refused, the same write keeping it goes.
 */
export async function staleSession(deployment: Deployment, people: People, alone: LeftAlone): Promise<string> {
  const { admin, reader } = people;
  const left = alone.at + FRESH_MS + 5_000 - Date.now();
  if (left > 0) await new Promise((done) => setTimeout(done, left));
  const { browser } = alone;
  expect(await signedIn(browser), 'the session left alone was signed out');

  // 14: the link, at its callback and at a start.
  const identities = (await admin.api.identities.list()).identities.length;
  const back = await browser.fetch(alone.callback);
  const landed = new URL(back.headers.get('location') ?? '', deployment.origin);
  expect(landed.searchParams.get('error') === 'link_stale', `a link whose session went stale was answered ${back.status} ${landed.pathname}${landed.search}`);
  expect((await admin.api.identities.list()).identities.length === identities, 'a link refused at its callback linked an account');
  const start = await browser.fetch('/auth/signin/github?link=1');
  expect(start.status === 302 && new URL(start.headers.get('location') ?? '', deployment.origin).origin === deployment.origin,
    `a link from a stale session was not sent to a fresh check: ${start.status} ${start.headers.get('location')}`);

  // 32 first, whose key is made by the admin's own, fresh, browser.
  await admin.api.secrets.set(DEV, { STALE_LOOSE: { value: canary(), sensitivity: 'sensitive' } });
  const loosened = await browser.send('PATCH', `/api/secrets/${DEV}`, { STALE_LOOSE: { sensitivity: 'secret' } });
  expect(loosened.status === 403 && (await bodyOf(loosened)).error === 'fresh_check_required', `a stale session made a sensitive value a secret: ${await said(loosened)}`);
  const kept = (await admin.api.secrets.list(DEV)).keys.find((key) => key.key === 'STALE_LOOSE');
  expect(kept?.sensitivity === 'sensitive', 'a refused loosening loosened', kept);
  const same = await browser.send('PATCH', `/api/secrets/${DEV}`, { STALE_LOOSE: { sensitivity: 'sensitive' } });
  expect(same.ok, `a write keeping a key's nature was refused a stale session: ${await said(same)}`);

  // 9 and 24: every always route.
  const placeholder = await SoftAuthenticator.create();
  const registration = await placeholder.register({ ...ceremonyOf(deployment, Buffer.alloc(32).toString('base64url')), userHandle: new Uint8Array(32) });
  const [project, environment] = DEV.split('/') as [string, string];
  const acts: [string, string, unknown?][] = [
    ['PUT', '/api/members/user:stale-new@conformance.example', {}],
    ['PUT', '/api/members/user:stale-new@conformance.example?dryRun=1', {}],
    ['DELETE', `/api/members/${reader.member}`],
    ['PATCH', `/api/access/${reader.member}`, { [BULK]: 'viewer' }],
    ['PATCH', `/api/access/${reader.member}?dryRun=1`, { [BULK]: 'viewer' }],
    ['POST', `/api/members/${admin.member}/passkeys/options`],
    ['POST', `/api/members/${admin.member}/passkeys`, { state: 'stale', response: registration }],
    ['DELETE', `/api/members/${reader.member}/passkeys`],
    ['POST', '/api/members/token:conformance-stale/tokens', { label: 'stale', expiresInDays: 1 }],
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

  const members = (await admin.api.members.list()).members.map((member) => member.member);
  expect(!members.some((id) => id.includes('stale-new')) && members.includes(reader.member),
    'a refused member change changed the members', members);
  expect((await admin.api.passkeys.list(reader.member)).passkeys.length > 0, "a refused reset removed the reader's passkeys");
  expect((await admin.api.secrets.list(DEV)).keys.some((key) => key.key === 'STALE_LOOSE'), 'a refused erase erased an environment');
  return `${acts.length} acts of routes that take a fresh check, ?dryRun=1 on two that take none, refused a session touched over five minutes ago, changing nothing; ` +
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
  return `a contributor on ${place}, protected, reveals nothing there, from a session touched a moment ago or a personal token`;
}

/**
 * 8, 16 and 19, under `required`: a browser session no passkey stands behind reaches nothing but its way out; a
 * one-key reveal it asks is refused alike whether the key exists, is sensitive or was never made, and logs no use;
 * services read as they did. The deployment stays `required` for the workload checks after, until `backToOptional`.
 */
export async function passkeysRequired(deployment: Deployment, { admin, bulk }: People, live: { token: string; canary: { project: string; environment: string; key: string; value: string } }): Promise<string> {
  await admin.api.secrets.set(BULK, { REQUIRED_SENSITIVE: { value: canary(), sensitivity: 'sensitive' } });
  const existing = (await admin.api.secrets.list(BULK)).keys.find((key) => key.key !== 'REQUIRED_SENSITIVE')?.key;
  expect(existing !== undefined, `${BULK} holds no key to ask for`);
  const since = new Date().toISOString();
  await deployment.restart({ PASSKEYS: 'required' });

  // 8: nothing but the way out.
  const reached: string[] = [];
  for (const [method, path, body] of [
    ['GET', '/api/projects'], ['GET', '/api/members'], ['GET', '/api/sessions'], ['GET', `/api/secrets/${BULK}`],
    ['PATCH', `/api/secrets/${BULK}`, { REQUIRED_WRITE: { value: canary() } }], ['POST', '/api/handles', { label: 'x', paths: [BULK] }],
  ] as [string, string, unknown?][]) {
    const response = await bulk.browser.send(method, path, body);
    if (response.status !== 401) reached.push(`${method} ${path}: ${await said(response)}`);
  }
  expect(reached.length === 0, 'under required, a session no passkey stands behind reached the API', reached);

  // 19: one key, alike whatever it is.
  const reveal = async (key: string) => {
    const response = await bulk.browser.send('POST', '/api/reveals', { path: `${BULK}/${key}` });
    return `${response.status} ${await response.text()}`;
  };
  const answers = [await reveal(existing!), await reveal('REQUIRED_SENSITIVE'), await reveal('NEVER_MADE')];
  expect(answers.every((each) => each === answers[0]) && answers[0]!.startsWith('401'), 'a refused credential told keys apart', answers);
  const { entries } = await admin.api.audit.list({ actor: bulk.member, limit: 100 });
  const uses = entries.filter((entry) => entry.occurredAt >= since && entry.action.startsWith('secret.') && entry.decision === 'allow');
  expect(uses.length === 0, 'a refused credential has a use of a key in the log', uses);

  const out = await bulk.browser.send('POST', '/auth/signout');
  expect(out.status === 303 || out.status === 302, `signing out a session no passkey stands behind answered ${out.status}`);

  // 16: a service, with no passkey anywhere, reads as it did.
  const read = await bearer(deployment.origin, live.token).secrets.reveal(`${live.canary.project}/${live.canary.environment}`);
  expect(read.values[live.canary.key] === live.canary.value, "under required, a service's token did not read its value");
  return 'under required, a session no passkey stands behind answered 401 to every call but signing out; a one-key reveal refused alike for a key that exists, a sensitive one and one never made, no use logged; a service read as before';
}

/** The deployment back to `optional`, after the workload checks ran under `required` (16). */
export async function backToOptional(deployment: Deployment): Promise<string> {
  await deployment.restart();
  return 'restarted as booted';
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
  await deployment.restart({ GITHUB_API_URL: `${idp.origin}/github/api` });
  try {
    const answered = await answer(pending, { response });
    expect(answered.status === 400 && (await bodyOf(answered)).error === 'state_mismatch' && !(await signedIn(pending)),
      `a sign-in whose issuer was replaced answered ${await said(answered)}, not 400 state_mismatch`);
  } finally {
    await deployment.restart();
  }
  const again = new Browser(deployment.origin);
  expect((await signIn(deployment, again, admin.email)).ok, 'the admin could not sign in once the issuer was put back');
  return 'a sign-in pending at the passkey, its issuer replaced meanwhile, completed nothing';
}

/** 33: a deployment whose public URL is an IP address, with passkeys not off, does not start. */
export async function ipPublicUrl(deployment: Deployment): Promise<string> {
  const port = new URL(deployment.origin).port;
  const said = await deployment.refusesToStart({ PUBLIC_URL: `http://127.0.0.1:${port}` });
  expect(/browsers make no passkey there|passkeys need a public URL/.test(said), 'a deployment at an IP address did not say why it refused to start', said);
  return 'at http://127.0.0.1, with passkeys optional, it refused to start, and said why';
}

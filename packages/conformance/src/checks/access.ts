// Who reaches what: members only, each to the places granted, from coffre's
// own pages, until they leave, and never too much at once.
import { bearer } from '../browser.ts';
import type { Deployment } from '../harness.ts';
import { expect, refused } from '../report.ts';
import { BULK, canary, DEV, PROD, PROJECT, signIn, valuesIn, type Canaries, type People } from './people.ts';
import { connectedApp, discovers } from './mcp.ts';
import { pollDevice, startDevice } from './signin.ts';

export async function membersOnly(deployment: Deployment, { stranger }: People): Promise<string> {
  const attempt = await signIn(deployment, stranger.browser, stranger.email);
  expect(!attempt.ok, 'someone never admitted signed in');
  expect(!stranger.browser.hasCookies, 'the refused sign-in left the browser a cookie');
  expect((await stranger.browser.fetch('/api/me')).status === 401, 'the refused sign-in left a session');

  const nobody = bearer(deployment.origin, 'coffre_cli_conformanceforgedtokenconformanceforged');
  await refused('a made-up token read secrets', nobody.secrets.list(DEV));
  for (const [method, path, body] of [
    ['GET', `/api/secrets/${DEV}`, undefined],
    ['POST', '/api/reveals', { path: DEV }],
    ['PATCH', `/api/secrets/${DEV}`, { API_KEY: 'from nobody' }],
    ['GET', '/api/audit', undefined],
  ] as const) {
    const response = await fetch(`${deployment.origin}${path}`, {
      method,
      headers: { origin: deployment.origin, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    expect(response.status === 401, `${method} ${path} answered ${response.status} to no one`);
  }
  return `a stranger's sign-in is ${attempt.ok ? 'let' : attempt.error}; no one and a made-up token get 401`;
}

export async function grantScoping({ reader, service, bulk }: People, canaries: Canaries): Promise<string> {
  const read = await reader.api.secrets.reveal(DEV);
  expect(same(read.values, valuesIn(canaries, DEV)), "a viewer on dev did not get dev's values", read.values);
  await refused('a viewer on dev revealed prod', reader.api.secrets.reveal(PROD));
  await refused('a viewer on dev listed prod', reader.api.secrets.list(PROD));
  await refused('a viewer wrote a value', reader.api.secrets.set(DEV, { API_KEY: 'from the reader' }));
  await refused('a viewer granted themselves more', reader.api.access.set(reader.member, { [PROD]: 'owner' }));
  await refused('a viewer added a member', reader.api.members.add('user:friend@conformance.example'));
  // A service account is set up by whoever holds all it holds: a viewer on bulk, who holds nothing on dev, may not.
  await refused("a viewer on bulk issued a token for a service on dev", bulk.api.tokens.issue(service.member, { expiresInDays: 1 }));
  await refused('a viewer on bulk gave a service dev', bulk.api.access.set(service.member, { [DEV]: 'viewer' }));
  await refused('a viewer on dev gave a service prod', reader.api.access.set(service.member, { [PROD]: 'viewer' }));
  const me = await reader.api.me();
  const places = me.environments.map((place) => `${place.project}/${place.environment}`);
  expect(places.length === 1 && places[0] === DEV, 'a viewer on dev is told of other places', places);

  const served = await service.api.secrets.reveal(DEV);
  expect(same(served.values, valuesIn(canaries, DEV)), "a service viewer on dev did not get dev's values", served.values);
  await refused('a service viewer on dev revealed prod', service.api.secrets.reveal(PROD));
  await refused('a viewer on bulk revealed dev', bulk.api.secrets.reveal(DEV));
  return 'a viewer on dev reads dev and nothing else, in a browser or with a token, and changes nothing; nobody gives a service account, or a token for one, beyond what they hold';
}

/**
 * A change sent with the session cookie from another site's page, or from
 * no page coffre can vouch for, is refused (CSRF), and so is a reveal.
 */
export async function crossSite({ admin }: People, canaries: Canaries): Promise<string> {
  const foreign: Record<string, string>[] = [
    { origin: 'https://attacker.example', 'sec-fetch-site': 'cross-site' },
    { origin: 'https://attacker.example' },
    { 'sec-fetch-site': 'same-site' },
    {},
  ];
  for (const headers of foreign) {
    for (const [method, path, body] of [
      ['PATCH', `/api/secrets/${DEV}`, { API_KEY: 'from another site' }],
      ['POST', '/api/reveals', { path: DEV }],
      ['PUT', '/api/members/user:mallory@attacker.example', {}],
      ['POST', '/auth/signout', undefined],
    ] as const) {
      const response = await admin.browser.fetch(path, {
        method,
        headers: { ...headers, 'content-type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const text = await response.text();
      expect(response.status === 403, `${method} ${path} with ${JSON.stringify(headers)} answered ${response.status}`, text);
      expect(!Object.values(canaries).some((value) => text.includes(value)), `${method} ${path} from another site carried a value`);
    }
  }
  const after = await admin.api.secrets.reveal(DEV);
  expect(after.values.API_KEY === canaries[`${DEV}/API_KEY`], 'a value changed from another site', after.values);
  const members = await admin.api.members.list();
  expect(!members.members.some((entry) => entry.member.includes('mallory')), 'a member was added from another site');
  return 'writes, reveals and sign-out with the cookie, from another site or no page at all: 403';
}

export async function offboarding(deployment: Deployment, { admin, leaver, service }: People, canaries: Canaries) {
  const device = await startDevice(deployment);
  await leaver.api.deviceLogins.decide(device.user_code, true);
  // What they saw is what to rotate once they are gone.
  await leaver.cli.secrets.reveal(DEV);
  // An app they connected is listed to an owner, and removal disconnects it.
  const app = await connectedApp(deployment, leaver);
  const before = await admin.api.members.get(leaver.member);
  expect(before.live.apps === 1 && before.apps.length === 1, "the owner's report does not list the app the leaver connected", before.apps);
  const { revoked, report } = await admin.api.members.remove(leaver.member);
  expect(report !== null, "an owner's removal does not answer with the leaver's report");
  expect(revoked.apps === 1 && report.live.apps === 0 && report.apps.length === 0, 'removal does not say it disconnected their app', { revoked, apps: report.apps });
  expect(!(await discovers(deployment, app)), "a removed member's app still reaches /mcp");
  const exposed = report.exposed.map((entry) => `${entry.project}/${entry.environment}/${entry.key}`).sort();
  const expected = Object.keys(valuesIn(canaries, DEV)).map((key) => `${DEV}/${key}`).sort();
  expect(same(exposed, expected), 'the offboarding report does not name what they read', report.exposed);

  expect((await leaver.browser.fetch('/api/me')).status === 401, "a removed member's browser session still works");
  await refused("a removed member's CLI session read secrets", leaver.cli.secrets.list(DEV));
  const again = await signIn(deployment, leaver.browser, leaver.email);
  expect(!again.ok, 'a removed member signed in again');

  await admin.api.members.remove(service.member);
  await refused("a removed service's token read secrets", service.api.secrets.reveal(DEV));
  await admin.api.members.add(leaver.member);
  await admin.api.access.set(leaver.member, { [DEV]: 'developer' });
  await admin.api.members.add(service.member);
  await admin.api.access.set(service.member, { [DEV]: 'viewer' });
  expect((await leaver.browser.fetch('/api/me')).status === 401, 're-admission revived the browser session');
  await refused('re-admission revived the CLI session', leaver.cli.secrets.reveal(DEV));
  await refused('re-admission revived the service token', service.api.secrets.reveal(DEV));
  expect(!(await pollDevice(deployment, device.device_code)).ok, 're-admission revived the old device approval');
  const fresh = await signIn(deployment, leaver.browser, leaver.email);
  expect(fresh.ok, 'a fresh provider callback could not sign the re-admitted member in');
  await admin.api.members.remove(leaver.member);
  await admin.api.members.remove(service.member);
  return `the report names ${exposed.length} values and their connected app, which removal disconnects; re-admission revives no old session, token or approval; a fresh provider callback works`;
}

/**
 * Instance roles: a Developer scoped to dev reads and writes the dev of a
 * project made after it, and no prod; an Admin scoped to one environment
 * grants there and nowhere else, and sets no role, its own or anyone's;
 * and no grant is on every project. The reader is a member again as it
 * ends, its service removed, its project archived.
 */
export async function instanceRoles(deployment: Deployment, { admin, reader }: People, canaries: Canaries): Promise<string> {
  const scoped = 'token:conformance-scoped';
  await admin.api.members.add(scoped);
  await refused('a grant on every project was given', admin.api.access.set(scoped, { '*': 'viewer' }));
  await refused('a grant on dev in every project was given', admin.api.access.set(scoped, { '*/dev': 'viewer' }));
  await refused('a service account was given an instance role', admin.api.members.add(scoped, { role: 'developer' }));
  await refused('a viewer gave themselves an instance role', reader.api.members.add(reader.member, { role: 'owner' }));

  // Made after the role: a project with a dev and a prod.
  await admin.api.members.add(reader.member, { role: 'developer', scope: { environments: { only: ['dev'] } } });
  const later = `${PROJECT}-roles`;
  await admin.api.projects.create(later, { name: 'Made later' });
  for (const environment of ['dev', 'prod']) {
    const path = `${later}/${environment}`;
    await admin.api.environments.create(path, { name: environment });
    canaries[`${path}/API_KEY`] = canary();
    await admin.api.secrets.set(path, valuesIn(canaries, path));
  }
  const read = await reader.api.secrets.reveal(`${later}/dev`);
  expect(read.values.API_KEY === canaries[`${later}/dev/API_KEY`], 'a Developer scoped to dev could not read a dev made later', read.values);
  await reader.api.secrets.set(`${later}/dev`, { API_KEY: canaries[`${later}/dev/API_KEY`]! });
  await refused('a Developer scoped to dev read a prod made later', reader.api.secrets.reveal(`${later}/prod`));
  await refused('a Developer scoped to dev read prod', reader.api.secrets.reveal(PROD));

  // An admin scoped to one environment manages it alone.
  await admin.api.members.add(reader.member, { role: 'admin', scope: { projects: { only: [PROJECT] }, environments: { only: ['dev'] } } });
  await reader.api.access.set(scoped, { [DEV]: 'viewer' });
  await refused('a scoped admin granted outside its scope', reader.api.access.set(scoped, { [PROD]: 'viewer' }));
  await refused('a scoped admin granted on the project around its scope', reader.api.access.set(scoped, { [PROJECT]: 'viewer' }));
  await refused('a scoped admin widened its own role', reader.api.members.add(reader.member, { role: 'admin' }));
  await refused('a scoped admin promoted someone', reader.api.members.add(scoped, { role: 'member' }));
  await refused('a scoped admin made a project', reader.api.projects.create(`${PROJECT}-scoped`, { name: 'Scoped' }));
  await refused('a scoped admin read a value no grant of its gives', reader.api.secrets.reveal(PROD));
  // Nor does an admin of the whole instance set its own.
  await admin.api.members.add(reader.member, { role: 'admin' });
  await refused('an admin made itself an owner', reader.api.members.add(reader.member, { role: 'owner' }));

  // As it was: a member, with its viewer on dev; the service and the project gone.
  await admin.api.members.add(reader.member, { role: 'member' });
  await admin.api.members.remove(scoped);
  await admin.api.projects.update(later, { archived: true });
  const me = await reader.api.me();
  expect(me.instanceRole === 'member' && me.environments.length === 1, 'the reader is not back as it was', me);
  return 'a Developer scoped to dev reaches a dev made later and no prod; a scoped admin grants only inside its scope and sets no role; no grant is on every project';
}

/** Reading more values at once than the vault allows in its window is refused. */
export async function bulkLimit({ admin, bulk }: People, limit: number): Promise<string> {
  const values: Record<string, string> = {};
  for (let i = 0; i <= limit; i++) values[`BULK_${i}`] = `bulk-${i}`;
  await admin.api.secrets.set(BULK, values);
  const refusal = await refused(`${limit + 1} values were revealed at once`, bulk.api.secrets.reveal(BULK));
  expect(refusal.status === 403 && refusal.code === 'bulk_limit' && refusal.reason === 'bulk_limit',
    'the bulk read was not refused as bulk_limit', refusal);
  // Refused for how many, not for where: one of them still opens.
  const one = await bulk.api.secrets.reveal(`${BULK}/BULK_0`);
  expect(one.values.BULK_0 === 'bulk-0', 'a viewer on bulk could not read one of its values', one.values);
  return `${limit + 1} values at once: ${refusal.status} ${refusal.reason ?? refusal.code}; one still opens`;
}

function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(sorted(a)) === JSON.stringify(sorted(b));
}

function sorted(value: unknown): unknown {
  if (Array.isArray(value) || value === null || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).sort(([a], [b]) => (a < b ? -1 : 1)));
}

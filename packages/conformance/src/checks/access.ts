// Who reaches what: members only, each to the places granted, from coffre's
// own pages, until they leave, and never too much at once.
import { bearer } from '../browser.ts';
import type { Deployment } from '../harness.ts';
import { expect, refused } from '../report.ts';
import { BULK, DEV, PROD, signIn, valuesIn, type Canaries, type People } from './people.ts';
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
  await refused('a viewer issued a service token', reader.api.tokens.issue(service.member, { expiresInDays: 1 }));
  const me = await reader.api.me();
  const places = me.environments.map((place) => `${place.project}/${place.environment}`);
  expect(places.length === 1 && places[0] === DEV, 'a viewer on dev is told of other places', places);

  const served = await service.api.secrets.reveal(DEV);
  expect(same(served.values, valuesIn(canaries, DEV)), "a service viewer on dev did not get dev's values", served.values);
  await refused('a service viewer on dev revealed prod', service.api.secrets.reveal(PROD));
  await refused('a viewer on bulk revealed dev', bulk.api.secrets.reveal(DEV));
  return 'a viewer on dev reads dev and nothing else, in a browser or with a token, and changes nothing';
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
  const { report } = await admin.api.members.remove(leaver.member);
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
  return `the report names ${exposed.length} values; re-admission revives no old session, token or approval; a fresh provider callback works`;
}

/** Reading more values at once than the vault allows in its window is refused. */
export async function bulkLimit({ admin, bulk }: People, limit: number): Promise<string> {
  const values: Record<string, string> = {};
  for (let i = 0; i <= limit; i++) values[`BULK_${i}`] = `bulk-${i}`;
  await admin.api.secrets.set(BULK, values);
  const refusal = await refused(`${limit + 1} values were revealed at once`, bulk.api.secrets.reveal(BULK));
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

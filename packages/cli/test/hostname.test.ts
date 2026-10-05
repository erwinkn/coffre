// An address whose DNS is elsewhere, served through one of the account's
// zones with Cloudflare for SaaS: against a stand-in for Cloudflare's API,
// whose custom hostnames go active as the records they ask for appear.
import test from 'node:test';
import assert from 'node:assert/strict';

import { CloudflareApi } from '../src/cloudflare.ts';
import { recordLines, recordsToAdd, Refused, saasZone, serveThrough, standing, tokenNeeded, waitForRecords, zoneOf } from '../src/hostname.ts';
import { fakeCloudflare, type FakeHostname } from './fakes.ts';

const TOKEN = `cf-api-${'t'.repeat(40)}`;
const LIMIT = { timeout: 30_000 };
const ADDRESS = 'secrets.example.org';

async function cloudflare(zones: { id: string; name: string }[]) {
  const fake = await fakeCloudflare(TOKEN);
  fake.state.zones['acc-acme'] = zones.map((zone) => ({ ...zone, status: 'active' }));
  for (const { id } of zones) fake.state.saas.add(id);
  return { fake, api: new CloudflareApi(TOKEN, fake.url) };
}

const never = async (): Promise<number> => assert.fail('asked which domain');
const changes = (requests: { method: string; path: string }[]) => requests.filter(({ method }) => method !== 'GET').map(({ method, path }) => `${method} ${path}`);

test("the zone an address is under: the longest of the account's, or none", () => {
  const zones = [
    { id: 'z1', name: 'acme.test' },
    { id: 'z2', name: 'eu.acme.test' },
  ];
  assert.equal(zoneOf('secrets.eu.acme.test', zones)?.id, 'z2');
  assert.equal(zoneOf('acme.test', zones)?.id, 'z1');
  assert.equal(zoneOf('notacme.test', zones), undefined);
  assert.equal(zoneOf(ADDRESS, zones), undefined);
});

test('the records to add: the CNAME always, each TXT record until Cloudflare has seen it, in columns to copy', () => {
  const hostname = {
    id: 'ch-1',
    hostname: ADDRESS,
    status: 'pending',
    ownership_verification: { type: 'txt', name: `_cf-custom-hostname.${ADDRESS}`, value: '5e1f' },
    ssl: { status: 'pending_validation', validation_records: [{ txt_name: `_acme-challenge.${ADDRESS}`, txt_value: 'ca-1' }] },
  };
  assert.deepEqual(recordLines(recordsToAdd(hostname, 'coffre-fallback.acme.test')), [
    'CNAME  secrets.example.org                      →  coffre-fallback.acme.test',
    'TXT    _cf-custom-hostname.secrets.example.org  "5e1f"',
    'TXT    _acme-challenge.secrets.example.org      "ca-1"',
  ]);
  assert.deepEqual(recordsToAdd({ ...hostname, status: 'active', ssl: { ...hostname.ssl, status: 'active' } }, 'fb.acme.test'), [
    { type: 'CNAME', name: ADDRESS, value: 'fb.acme.test' },
  ]);
  assert.deepEqual(standing(hostname), { done: false, stopped: null, text: 'hostname pending, certificate pending validation', why: [] });
  assert.match(standing({ ...hostname, ssl: { status: 'validation_timed_out' } }).stopped!, /stopped waiting for secrets\.example\.org's records/);
  assert.match(standing({ ...hostname, status: 'moved' }).stopped!, /run setup again: it asks Cloudflare to validate again/);
  assert.match(standing({ ...hostname, status: 'blocked' }).stopped!, /marked secrets\.example\.org blocked/);
  assert.deepEqual(standing({ ...hostname, verification_errors: ['custom hostname does not CNAME to this zone.'] }).why, ['custom hostname does not CNAME to this zone.']);
});

test("one domain on the account: its fallback origin made, the custom hostname made; a run after keeps both", LIMIT, async () => {
  const { fake, api } = await cloudflare([{ id: 'zone-1', name: 'acme.test' }]);
  try {
    const zone = await saasZone(api, 'acc-acme', fake.state.zones['acc-acme']!, ADDRESS, never);
    const served = await serveThrough(api, zone, ADDRESS, 0);
    assert.equal(served.target, 'coffre-fallback.acme.test');
    assert.deepEqual(served.details, ['fallback origin  coffre-fallback.acme.test, made', 'custom hostname  secrets.example.org, made']);
    assert.deepEqual(fake.state.dns.get('zone-1'), [
      { type: 'AAAA', name: 'coffre-fallback.acme.test', content: '100::', proxied: true, comment: "coffre's fallback origin: its Worker answers there" },
    ]);
    assert.deepEqual(fake.state.fallback.get('zone-1'), { origin: 'coffre-fallback.acme.test', status: 'pending_deployment' });
    const posted = fake.state.requests.find(({ method, path }) => method === 'POST' && path === '/client/v4/zones/zone-1/custom_hostnames')!;
    assert.deepEqual(JSON.parse(posted.body), { hostname: ADDRESS, ssl: { method: 'txt', type: 'dv' } });
    // Read again after its creation: the certificate's records, which the POST's answer lacks, are in.
    assert.deepEqual(recordsToAdd(served.hostname, served.target).map(({ name }) => name), [ADDRESS, `_cf-custom-hostname.${ADDRESS}`, `_acme-challenge.${ADDRESS}`, `_acme-challenge.${ADDRESS}`]);

    fake.state.requests.length = 0;
    const again = await serveThrough(api, await saasZone(api, 'acc-acme', fake.state.zones['acc-acme']!, ADDRESS, never), ADDRESS, 0);
    assert.deepEqual(again.details, ['fallback origin  coffre-fallback.acme.test, kept', 'custom hostname  secrets.example.org, kept']);
    assert.equal(again.hostname.id, served.hostname.id);
    assert.deepEqual(changes(fake.state.requests), [], 'a run after changes nothing');
  } finally {
    fake.close();
  }
});

test("a zone's own fallback origin is kept, for the custom hostnames it serves already: the CNAME points there", LIMIT, async () => {
  const { fake, api } = await cloudflare([{ id: 'zone-1', name: 'acme.test' }]);
  try {
    fake.state.fallback.set('zone-1', { origin: 'proxy-fallback.acme.test', status: 'active' });
    const served = await serveThrough(api, fake.state.zones['acc-acme']![0]!, ADDRESS, 0);
    assert.equal(served.target, 'proxy-fallback.acme.test');
    assert.deepEqual(changes(fake.state.requests), ['POST /client/v4/zones/zone-1/custom_hostnames']);
  } finally {
    fake.close();
  }
});

test('several domains: setup asks which, unless a run before made the custom hostname on one', LIMIT, async () => {
  const { fake, api } = await cloudflare([
    { id: 'zone-1', name: 'acme.test' },
    { id: 'zone-2', name: 'acme.dev' },
  ]);
  try {
    const asked: string[][] = [];
    const zone = await saasZone(api, 'acc-acme', fake.state.zones['acc-acme']!, ADDRESS, async (question, options) => {
      asked.push([question, ...options]);
      return 1;
    });
    assert.deepEqual(asked, [[`Which of your domains serves ${ADDRESS}?`, 'acme.test', 'acme.dev']]);
    assert.equal(zone.name, 'acme.dev');
    await serveThrough(api, zone, ADDRESS, 0);
    assert.equal((await saasZone(api, 'acc-acme', fake.state.zones['acc-acme']!, ADDRESS, never)).name, 'acme.dev');
  } finally {
    fake.close();
  }
});

test("a login that may not manage custom hostnames, as wrangler's may not: refused, for setup to ask for a token, before anything is made", LIMIT, async () => {
  const { fake, api } = await cloudflare([{ id: 'zone-1', name: 'acme.test' }]);
  try {
    fake.state.denied.add('ssl');
    await assert.rejects(saasZone(api, 'acc-acme', fake.state.zones['acc-acme']!, ADDRESS, never), (error: unknown) => {
      assert.ok(error instanceof Refused);
      assert.deepEqual(error.zones, ['acme.test']);
      return true;
    });
    const why = tokenNeeded(['acme.test']);
    assert.match(why, /Cloudflare refused this login the custom hostnames of acme\.test: wrangler's login may not manage them, and has no scope for DNS records/);
    assert.match(why, /and Zone, for acme\.test: Zone Read, Workers Routes Edit, SSL and Certificates Edit and DNS Edit\. Setup goes on under it, and so does each wrangler it runs\./);
    assert.match(tokenNeeded(['acme.test', 'acme.dev']), /of acme\.test and acme\.dev: [\s\S]*and Zone, for the domain coffre goes through:/);
    // DNS refused, custom hostnames not: refused at the fallback origin's record, before the custom hostname.
    fake.state.denied.clear();
    fake.state.denied.add('dns');
    await assert.rejects(serveThrough(api, fake.state.zones['acc-acme']![0]!, ADDRESS, 0), Refused);
    assert.deepEqual(changes(fake.state.requests), []);
    // Under a token that may, the same goes through.
    fake.state.apiTokens.add('cf-dashboard-token-with-all-of-it');
    api.use('cf-dashboard-token-with-all-of-it');
    assert.equal((await serveThrough(api, fake.state.zones['acc-acme']![0]!, ADDRESS, 0)).target, 'coffre-fallback.acme.test');
  } finally {
    fake.close();
  }
});

test('a run stopped between the fallback origin\'s record and the origin: the next sets the origin, and makes no second record', LIMIT, async () => {
  const { fake, api } = await cloudflare([{ id: 'zone-1', name: 'acme.test' }]);
  try {
    fake.state.dns.set('zone-1', [{ type: 'AAAA', name: 'coffre-fallback.acme.test', content: '100::', proxied: true }]);
    const served = await serveThrough(api, fake.state.zones['acc-acme']![0]!, ADDRESS, 0);
    assert.equal(served.details[0], 'fallback origin  coffre-fallback.acme.test, made');
    assert.equal(fake.state.dns.get('zone-1')!.length, 1);
    assert.deepEqual(changes(fake.state.requests).slice(0, 1), ['PUT /client/v4/zones/zone-1/custom_hostnames/fallback_origin']);
  } finally {
    fake.close();
  }
});

test('no fallback origin, however Cloudflare says so: a 404, an empty answer, or its error 1551', LIMIT, async () => {
  const { fake, api } = await cloudflare([{ id: 'zone-1', name: 'acme.test' }]);
  try {
    for (const answer of ['404', 'empty', '1551'] as const) {
      fake.state.noFallback = answer;
      assert.equal(await api.fallbackOrigin('zone-1'), null, answer);
    }
    fake.state.noFallback = '1551';
    assert.equal((await serveThrough(api, fake.state.zones['acc-acme']![0]!, ADDRESS, 0)).details[0], 'fallback origin  coffre-fallback.acme.test, made');
  } finally {
    fake.close();
  }
});

test('Cloudflare for SaaS off on the zone: where to turn it on, and that it asks for a payment method', LIMIT, async () => {
  const { fake, api } = await cloudflare([{ id: 'zone-1', name: 'acme.test' }]);
  try {
    fake.state.saas.clear();
    await assert.rejects(
      saasZone(api, 'acc-acme', fake.state.zones['acc-acme']!, ADDRESS, never),
      /Cloudflare for SaaS isn't enabled on acme\.test\. Enable it at https:\/\/dash\.cloudflare\.com\/acc-acme\/acme\.test\/ssl-tls\/custom-hostnames: Cloudflare asks for a payment method/,
    );
  } finally {
    fake.close();
  }
});

test("the wait: the records shown, and shown again when Cloudflare's change; done once it has seen them", LIMIT, async () => {
  const { fake, api } = await cloudflare([{ id: 'zone-1', name: 'acme.test' }]);
  try {
    const served = await serveThrough(api, fake.state.zones['acc-acme']![0]!, ADDRESS, 0);
    const stored = () => fake.state.hostnames.get('zone-1')![0]!;
    const shown: string[][] = [];
    const notes: string[] = [];
    await waitForRecords(
      api,
      served,
      {
        records: (lines) => {
          shown.push(lines);
          // A certificate record Cloudflare issues anew; then all of them added, as their user would.
          if (shown.length === 1) stored().ssl.validation_records![1]!.txt_value = 'reissued';
          else for (const line of lines) fake.state.published.add(line.split(/\s+/)[1]!);
        },
        note: (text) => notes.push(text),
        under: () => {},
      },
      10,
    );
    const names = [`CNAME ${ADDRESS}`, `TXT _cf-custom-hostname.${ADDRESS}`, `TXT _acme-challenge.${ADDRESS}`, `TXT _acme-challenge.${ADDRESS}`];
    assert.deepEqual(shown.map((lines) => lines.map((line) => line.split(/\s+/).slice(0, 2).join(' '))), [names, names]);
    assert.match(shown[1]!.at(-1)!, /"reissued"$/);
    assert.match(notes[0]!, /^Wait for the DNS records: hostname pending, certificate pending validation \(0s\)$/);
    assert.equal(standing(await api.customHostnameById('zone-1', served.hostname.id)).done, true);
  } finally {
    fake.close();
  }
});

for (const [gave, up] of [
  ['its certificate timed out', (hostname: FakeHostname) => (hostname.ssl.status = 'validation_timed_out')],
  ['the hostname moved', (hostname: FakeHostname) => (hostname.status = 'moved')],
] as const) {
  test(`Cloudflare gave up waiting, ${gave}: the wait says so; a run after asks it to validate again`, LIMIT, async () => {
    const { fake, api } = await cloudflare([{ id: 'zone-1', name: 'acme.test' }]);
    try {
      const served = await serveThrough(api, fake.state.zones['acc-acme']![0]!, ADDRESS, 0);
      up(fake.state.hostnames.get('zone-1')![0]!);
      await assert.rejects(
        waitForRecords(api, served, { records() {}, note() {}, under() {} }, 10),
        /Cloudflare stopped waiting for secrets\.example\.org's records\. Once they are in, run setup again: it asks Cloudflare to validate again/,
      );
      const again = await serveThrough(api, fake.state.zones['acc-acme']![0]!, ADDRESS, 0);
      assert.equal(again.details.at(-1), 'custom hostname  secrets.example.org, kept, asked to validate again');
      assert.deepEqual([again.hostname.status, again.hostname.ssl?.status], ['pending', 'pending_validation']);
      assert.equal(standing(again.hostname).stopped, null, 'waiting again');
    } finally {
      fake.close();
    }
  });
}

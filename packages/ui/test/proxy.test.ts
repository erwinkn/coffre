// The Proxy tab (0.16, T186; docs/design/proxy-ui.md): what it lists, code's
// items locked beside the environment's own and those its fork inherits; what
// a save sends; what discarding leaves; what the review says after another
// save came first (409); and a reader's page, every field inert. The rows'
// state is what the sheet renders from (components/proxy-sheet.tsx).
import test from 'node:test';
import assert from 'node:assert/strict';
import type { ProxyPage, SecretKey } from '@coffre/client';

import {
  blockedInWords,
  changedSince,
  codeOf,
  copiedInWords,
  diffOf,
  fieldOf,
  inheritanceOf,
  itemsOf,
  keyStanding,
  methodChoices,
  methodsLabel,
  NO_DRAFTS,
  notClearedInWords,
  pageState,
  parentsOf,
  redirects,
  routedInWords,
  rowsOf,
  sampleCall,
  saveOf,
  type Drafts,
  type ProxyDefinition,
  type ProxyItem,
  type ProxyRoute,
} from '../src/lib/proxy.ts';

const DEV = { project: 'market', environment: 'dev' };
const NONE = { perMinute: null, perDay: null };

function route(name: string, keys: readonly string[] = ['OPENAI_API_KEY'], host = 'api.openai.com'): ProxyRoute {
  return {
    kind: 'route', name, upstream: `https://${host}/v1`,
    inject: keys.map((key, i) => ({ kind: 'header' as const, name: i === 0 ? 'authorization' : `x-key-${i}`, template: i === 0 ? `Bearer {${key}}` : `{${key}}` })),
    allow: null, limit: NONE, placeholder: null, egress: null,
  };
}

function key(name: string, over: Partial<SecretKey> = {}): SecretKey {
  return {
    key: name, reference: null, folder: null, archived: false, version: 1, updatedAt: null, updatedBy: null, versionId: null,
    generated: null, value: null, sensitivity: 'secret', readable: true, parent: null, ...over,
  };
}

const KEYS = [key('OPENAI_API_KEY'), key('STRIPE_KEY', { sensitivity: 'sensitive', readable: false }), key('PARTNER_KEY', { readable: false }), key('MAPS_API_KEY')];

/** A page as `GET …/proxy` answers it: Ada's, an Owner of market, unless `over` says. */
function page(items: readonly ProxyDefinition[], over: Partial<ProxyPage> = {}): ProxyPage {
  return {
    environmentId: '00000000-0000-4000-8000-000000000001', seal: 'c2VhbHNlYWxzZWFsc2VhbA==', state: 'ok',
    items: items.map((definition, i) => ({ definition, keys: [], savedBy: 'user:ada@acme.example', savedAt: 1_700_000_000_000 + i, routesSensitive: true })),
    reserved: ['maps'], reservedState: 'ok', editable: true, readOnly: null,
    code: [{ definition: route('maps', ['MAPS_API_KEY'], 'maps.googleapis.com'), environments: null, limitPerService: true, bound: false }],
    routesSensitive: true, releases: true, useUrl: 'https://secrets.acme.example/use', windowSeconds: 60, insecureUpstreams: false,
    ...over,
  } as ProxyPage;
}

const state = (proxy: ProxyPage, drafts: Drafts = NO_DRAFTS, tried = false, keys = KEYS) => pageState({ page: proxy, place: DEV, parents: [], keys, drafts, tried });

test("the list: code's items locked, the environment's own, then what its fork inherits and does not override, none whose name code takes", () => {
  const dev = page([route('openai'), route('stripe', ['STRIPE_KEY'], 'api.stripe.com')]);
  const fork = page([route('openai', ['OPENAI_API_KEY'], 'eu.api.openai.com'), route('maps')]);
  const items = itemsOf(fork, { project: 'market', environment: 'dev-eu' }, [{ path: 'market/dev', page: dev }]);
  assert.deepEqual(items.map((item) => [item.id, item.source, item.from]), [
    ['code:route:maps', 'code', null],
    ['own:openai', 'own', 'market/dev'],
    ['from:stripe', 'inherited', 'market/dev'],
  ]);
  // A code item scoped elsewhere takes its name here and serves nothing.
  const scoped = page([], { code: [{ definition: { kind: 'tunnel', name: 'replica', key: 'REPLICA_URL', hosts: ['10.0.1.5'], network: null }, environments: ['market/prod'], limitPerService: false, bound: true }] });
  assert.deepEqual(itemsOf(scoped, DEV).map((item) => [item.id, item.serves]), [['code:tunnel:replica', false]]);
  assert.deepEqual(parentsOf([{ slug: 'dev', parent: null }, { slug: 'dev-eu', parent: 'dev' }, { slug: 'x', parent: 'dev-eu' }], { project: 'market', environment: 'x' }), ['market/dev-eu', 'market/dev']);
});

test('a save sends each changed item by name: a rename removes the old name, a deletion is null, an override is the place\'s own', () => {
  const proxy = page([route('openai'), route('partner', ['PARTNER_KEY'], 'api.partner.example'), route('old')]);
  const parentPage = page([route('stripe', ['OPENAI_API_KEY'], 'api.stripe.com')]);
  const drafts: Drafts = {
    ...NO_DRAFTS,
    edits: { 'own:openai': { ...route('gpt'), upstream: ' https://api.openai.com/v2 ' }, 'own:old': null, 'from:stripe': { ...route('stripe', ['OPENAI_API_KEY'], 'eu.stripe.com') }, 'new:0': route('fresh') },
    added: [{ id: 'new:0', copiedFrom: null }],
    resaved: [],
  };
  const rows = pageState({ page: proxy, place: DEV, parents: [{ path: 'market/prod', page: parentPage }], keys: KEYS, drafts, tried: true }).rows;
  assert.deepEqual(Object.entries(saveOf(rows)).map(([name, definition]) => [name, definition === null ? null : (definition as ProxyRoute).upstream]), [
    ['old', null],
    ['openai', null],
    ['gpt', 'https://api.openai.com/v2'],
    ['stripe', 'https://eu.stripe.com/v1'],
    ['fresh', 'https://api.openai.com/v1'],
  ]);
});

test("a reader's page: every field inert, nothing to delete or add; a key its editor cannot read leaves the row inert, deletable", () => {
  const reader = state(page([route('openai')], { editable: false, readOnly: { reason: 'missing_proxy_edit', message: 'editing proxy definitions takes proxy.edit here: Owners hold it' }, routesSensitive: false, releases: false }));
  // A row's `editable` is its fieldset's: disabled, every control inert (proxy-sheet.tsx); `removable` its Delete.
  assert.deepEqual(reader.rows.map((row) => [row.id, row.editable, row.removable]), [['code:route:maps', false, false], ['own:openai', false, false]]);
  assert.equal(reader.editor.editable, false);
  // A forged object: none of it to edit, and only an Owner of the project, who replaces it whole, saves.
  const forged = state(page([], { state: 'tampered' }));
  assert.deepEqual([forged.replacing, forged.editor.editable], [true, true]);
  assert.equal(state(page([], { state: 'tampered', routesSensitive: false })).editor.editable, false);

  // An Owner who cannot read PARTNER_KEY: the vault would refuse its save, so the row stays as it is, and only goes.
  const owner = state(page([route('partner', ['PARTNER_KEY'], 'api.partner.example'), route('stripe', ['STRIPE_KEY'])]));
  assert.deepEqual(owner.rows.filter((row) => row.item?.source === 'own').map((row) => [row.id, row.editable, row.removable]), [['own:partner', false, true], ['own:stripe', true, true]]);
  assert.deepEqual(owner.rows.find((row) => row.id === 'own:partner')!.keys.blocked, ['PARTNER_KEY']);
  // A sensitive key: an Owner of the project routes it, audited; anyone else may not.
  assert.deepEqual(keyStanding(['STRIPE_KEY', 'NEW_KEY', 'OPENAI_API_KEY'], { keys: KEYS, routesSensitive: true }), { blocked: [], routed: ['STRIPE_KEY'], missing: ['NEW_KEY'] });
  assert.deepEqual(keyStanding(['STRIPE_KEY'], { keys: KEYS, routesSensitive: false }).blocked, ['STRIPE_KEY']);
});

test("an edit's problems, once a save is tried, under the field the vault's own check names", () => {
  const drafts: Drafts = {
    ...NO_DRAFTS,
    edits: {
      'new:0': { ...route('maps'), inject: [{ kind: 'header', name: 'authorization', template: 'Bearer ' }] },
      'new:1': { ...route('Bad Name') },
      'new:2': { ...route('meta'), upstream: 'https://169.254.169.254/latest', allow: [{ methods: [], path: '/a/../b' }] },
      'new:3': route('partner', ['PARTNER_KEY']),
    },
    added: [0, 1, 2, 3].map((n) => ({ id: `new:${n}`, copiedFrom: null })),
    resaved: [],
  };
  const untried = state(page([]), drafts, false);
  assert.deepEqual(untried.rows.map(untried.problems), [{}, {}, {}, {}, {}]);
  const tried = state(page([]), drafts, true);
  const [maps, bad, meta, partner] = tried.rows.slice(1).map(tried.problems);
  assert.match(maps!.name!, /maps is defined in this deployment's code/);
  assert.equal(bad!.name, 'A lowercase letter, then up to 31 lowercase letters, digits or dashes.');
  assert.equal(meta!.upstream, 'Upstream is a private, loopback or link-local address, or localhost, which no UI definition reaches');
  assert.equal(partner!.keys, "You can't read PARTNER_KEY in market/dev, so you can't route it.");
  assert.equal(tried.sound, false);
  assert.deepEqual(fieldOf('openai: inject[1].template names no key: write it as {KEY}', 'openai', 'route'), { field: 'inject.1', words: 'Template names no key: write it as {KEY}' });
  assert.deepEqual(fieldOf('openai: sigv4 sets authorization itself', 'openai', 'route'), { field: 'inject', words: 'Sigv4 sets authorization itself' });
});

test('discarding leaves the page as it was loaded; a save of nothing changed is no change', () => {
  const proxy = page([route('openai')]);
  const edited = state(proxy, { ...NO_DRAFTS, edits: { 'own:openai': route('openai', ['OPENAI_API_KEY'], 'eu.api.openai.com') }, added: [], resaved: [] });
  assert.deepEqual([edited.changed, edited.counts], [1, { added: 0, updated: 1, deleted: 0 }]);
  const discarded = state(proxy, NO_DRAFTS);
  assert.deepEqual([discarded.changed, discarded.rows.map((row) => row.state)], [0, ['same', 'same']]);
  // Typed back to what it was: no change at all.
  assert.equal(state(proxy, { ...NO_DRAFTS, edits: { 'own:openai': route('openai') }, added: [], resaved: [] }).changed, 0);
  // Saved again as it is, under its editor's standing now: a change of its own, which is how an Owner clears a route.
  const resaved = state(proxy, { ...NO_DRAFTS, edits: {}, added: [], resaved: ['own:openai'] });
  assert.deepEqual([resaved.changed, Object.keys(saveOf(resaved.rows))], [1, ['openai']]);
});

test('after a 409, the review says what another save changed since the page loaded', () => {
  const loaded = page([route('openai'), route('stripe', ['STRIPE_KEY'])]);
  const now = page([{ ...route('openai'), upstream: 'https://eu.api.openai.com/v1' }, route('s3')], {
    items: [
      { definition: { ...route('openai'), upstream: 'https://eu.api.openai.com/v1' }, keys: [], savedBy: 'user:lead@acme.example', savedAt: 1_800_000_000_000, routesSensitive: false },
      { definition: route('s3'), keys: [], savedBy: 'user:lead@acme.example', savedAt: 1_800_000_000_000, routesSensitive: false },
    ],
  });
  assert.deepEqual(changedSince(loaded, now), [
    { name: 'openai', what: 'updated', by: 'user:lead@acme.example' },
    { name: 's3', what: 'added', by: 'user:lead@acme.example' },
    { name: 'stripe', what: 'removed', by: null },
  ]);
  assert.deepEqual(changedSince(loaded, loaded), []);
});

test("a copy's review names the keys it sends here and where; a change of destination opens the save's window", () => {
  const sandbox = { ...route('schuman', ['SCHUMAN_API_KEY'], 'sandbox.schuman.example') };
  assert.equal(copiedInWords(sandbox, { project: 'market', environment: 'prod' }, 'market/dev'), "schuman will send market/prod's SCHUMAN_API_KEY to sandbox.schuman.example (copied from market/dev).");
  assert.equal(redirects(route('openai'), { ...route('openai'), limit: { perMinute: 5, perDay: null } }), false);
  assert.equal(redirects(route('openai'), route('openai', ['OPENAI_API_KEY'], 'eu.api.openai.com')), true);
  assert.equal(redirects(route('openai'), null), true);
});

test('the sample call matches as the proxy does: globs by segment, a plain path a prefix', () => {
  const openai: ProxyRoute = { ...route('openai'), allow: [{ methods: ['POST'], path: '/chat/completions' }, { methods: ['GET'], path: '/models/**' }] };
  assert.deepEqual(sampleCall(openai, 'GET', '/models/gpt-4'), { url: 'https://api.openai.com/v1/models/gpt-4', refusal: null });
  assert.equal(sampleCall(openai, 'POST', '/chat/completions/x').refusal, null);
  assert.match(sampleCall(openai, 'DELETE', '/models/gpt-4').refusal!, /^405/);
  assert.match(sampleCall(openai, 'GET', '/files').refusal!, /^403/);
});

test("an item that would not route now says why, and who clears it", () => {
  const item = { definition: route('gemini'), savedBy: 'user:lead@acme.example' };
  assert.equal(notClearedInWords({ ...item, notCleared: { key: 'OPENAI_API_KEY', reason: 'OPENAI_API_KEY: its editor does not read it in dev (no_grant)' } }, DEV),
    'gemini does not route now: lead@acme.example, who saved it, no longer reads OPENAI_API_KEY here. Someone who does saves it again.');
  assert.equal(notClearedInWords({ ...item, notCleared: { key: 'OPENAI_API_KEY', reason: "OPENAI_API_KEY is sensitive, and its editor was no Owner of its project when they saved it" } }, DEV),
    "gemini does not route now: OPENAI_API_KEY is sensitive, and lead@acme.example's save was not an Owner's. An Owner of market saves it again.");
});

test('code may give a route and a signer one name: each its own row', () => {
  const both = page([], {
    code: [
      { definition: route('dfns', ['DFNS_KEY'], 'api.dfns.io'), environments: null, limitPerService: false, bound: false },
      { definition: { kind: 'signer', name: 'dfns', signer: { kind: 'private-key', key: 'DFNS_KEY' }, limit: NONE }, environments: null, limitPerService: false, bound: false },
    ],
  });
  const ids = itemsOf(both, DEV).map((item) => item.id);
  assert.deepEqual(ids, ['code:route:dfns', 'code:signer:dfns']);
  assert.equal(new Set(ids).size, 2);
});

test('a sensitive reference is routed by an Owner of its source\'s project, not of the place\'s', () => {
  const reference = (ownsSource: boolean) =>
    key('BILLING_KEY', { sensitivity: 'sensitive', readable: false, reference: { id: 'r', holder: 'market/dev/BILLING_KEY', source: 'billing/prod/STRIPE_KEY', state: 'live', version: 1, createdBy: 'user:ada@acme.example', createdAt: '', endedBy: null, endedAt: null, canOpenSource: true, ownsSource } });
  // Ada owns market, not billing: the vault would refuse, and the page says so first.
  const market = { keys: [...KEYS, reference(false)], routesSensitive: true };
  assert.deepEqual(keyStanding(['BILLING_KEY'], market), { blocked: ['BILLING_KEY'], routed: [], missing: [] });
  assert.equal(blockedInWords(['BILLING_KEY'], DEV, market.keys), 'BILLING_KEY is sensitive, from billing: only an Owner of billing routes it.');
  // An Owner of billing who is no Owner of market routes it, and is told whose Owner they route it as.
  const billing = { keys: [...KEYS, reference(true)], routesSensitive: false };
  assert.deepEqual(keyStanding(['BILLING_KEY'], billing).routed, ['BILLING_KEY']);
  assert.equal(routedInWords(['BILLING_KEY'], DEV, billing.keys), 'BILLING_KEY is sensitive: as an Owner of billing you may route it, and the save is audited.');
  assert.equal(routedInWords(['STRIPE_KEY'], DEV, KEYS), 'STRIPE_KEY is sensitive: as an Owner of this project you may route it, and the save is audited.');
});

test('an edit outlives another save removing its item: it stays, over the item that now has its name', () => {
  const editor = state(page([])).editor;
  const origin = itemsOf(page([route('openai')]), DEV)[1]!;
  const inherited: ProxyItem = { ...origin, id: 'from:openai', source: 'inherited', from: 'market/base' };
  const renamed = { ...NO_DRAFTS, edits: { 'own:openai': route('gpt') }, origins: { 'own:openai': origin } };
  // Bob deleted openai first: Alice's rename is a row still, saved as the new name alone.
  const alone = rowsOf([], renamed, editor);
  assert.deepEqual(alone.map((row) => [row.id, row.state, row.gone, row.definition.name]), [['own:openai', 'changed', true, 'gpt']]);
  assert.deepEqual(Object.keys(saveOf(alone)), ['gpt']);
  // dev inherits a parent's openai again: Alice's edit is the override, in its place.
  const edited = { ...NO_DRAFTS, edits: { 'own:openai': route('openai', ['OPENAI_API_KEY'], 'eu.api.openai.com') }, origins: { 'own:openai': origin } };
  const over = rowsOf([inherited], edited, editor);
  assert.deepEqual(over.map((row) => [row.id, row.state]), [['own:openai', 'changed']]);
  assert.deepEqual(Object.keys(saveOf(over)), ['openai']);
  // A deletion of what is gone already is nothing to save.
  assert.deepEqual(rowsOf([inherited], { ...NO_DRAFTS, edits: { 'own:openai': null }, origins: { 'own:openai': origin } }, editor).map((row) => [row.id, row.state]), [['from:openai', 'same']]);
});

test("the review shows what a change removes: a last rule, a last allow entry", () => {
  const before: ProxyRoute = { ...route('openai', ['OPENAI_API_KEY', 'ORG_ID']), allow: [{ methods: ['GET'], path: '/models' }, { methods: ['POST'], path: '/chat' }] };
  const after: ProxyRoute = { ...route('openai'), allow: [{ methods: ['GET'], path: '/models' }] };
  assert.deepEqual(diffOf(before, after), [
    { label: 'Sends 2', before: 'Header x-key-1: {ORG_ID}', after: '–' },
    { label: 'Allows 2', before: 'POST /chat', after: '–' },
  ]);
});

test('an inherited item whose save no longer clears is saved again here, as the fork\'s own', () => {
  const parent = page([route('gemini')]);
  const fork = { project: 'market', environment: 'dev-eu' };
  const resaved = pageState({ page: page([]), place: fork, parents: [{ path: 'market/dev', page: parent }], keys: KEYS, drafts: { ...NO_DRAFTS, resaved: ['from:gemini'] }, tried: true });
  const row = resaved.rows.find((one) => one.id === 'from:gemini')!;
  assert.equal(row.state, 'resaved');
  assert.deepEqual(Object.keys(saveOf(resaved.rows)), ['gemini']);
});

test("as code, a UI item serves where it serves now", () => {
  assert.match(codeOf(route('openai'), ['market/dev']), /environments: \['market\/dev'\],/);
  assert.match(codeOf({ kind: 'tunnel', name: 'db', key: 'DATABASE_URL', hosts: ['db.internal'], network: null }, ['market/dev']), /postgres\('DATABASE_URL', \{ hosts: \['db.internal'\], environments: \['market\/dev'\] \}\)/);
  assert.match(codeOf({ kind: 'signer', name: 'sign', signer: { kind: 'private-key', key: 'K' }, limit: NONE }, ['market/dev']), /privateKey\('K', \{ environments: \['market\/dev'\] \}\)/);
  assert.doesNotMatch(codeOf(route('openai')), /environments/);
});

test('inheritance stops at the first parent the page cannot read or trust: past it, what shows may be overridden', () => {
  const fork = { project: 'market', environment: 'dev-eu-x' };
  const base = { path: 'market/dev', page: page([route('openai'), route('stripe', ['STRIPE_KEY'], 'api.stripe.com')]) };
  const names = (parents: Parameters<typeof itemsOf>[2]) => itemsOf(page([]), fork, parents).filter((item) => item.source === 'inherited').map((item) => `${item.from} ${item.definition.name}`);
  assert.deepEqual(names([{ path: 'market/dev-eu', page: page([route('gemini')]) }, base]), ['market/dev-eu gemini', 'market/dev openai', 'market/dev stripe']);
  // dev-eu is closed to this person: its own openai, to another upstream, may override dev's. Neither shows.
  assert.deepEqual(names([{ path: 'market/dev-eu', page: null }, base]), []);
  assert.deepEqual(inheritanceOf([{ path: 'market/dev-eu', page: null }, base]).stop, { path: 'market/dev-eu', why: 'closed' });
  // A forged dev-eu: the vault refuses a use through it, so nothing past it shows either.
  assert.deepEqual(names([{ path: 'market/dev-eu', page: page([], { state: 'tampered' }) }, base]), []);
  assert.deepEqual(inheritanceOf([{ path: 'market/dev-eu', page: page([], { state: 'tampered' }) }, base]).stop, { path: 'market/dev-eu', why: 'tampered' });
  assert.equal(inheritanceOf([base]).stop, null);
});

test('a pending resave outlives another save removing its item: saving makes it again, as it was', () => {
  const editor = state(page([])).editor;
  const origin = itemsOf(page([route('gemini')]), DEV).find((item) => item.id === 'own:gemini')!;
  const drafts = { ...NO_DRAFTS, resaved: ['own:gemini'], origins: { 'own:gemini': origin } };
  const rows = rowsOf([], drafts, editor);
  assert.deepEqual(rows.map((row) => [row.id, row.state, row.gone]), [['own:gemini', 'resaved', true]]);
  assert.deepEqual(saveOf(rows), { gemini: route('gemini') });
});

test("a code route's sample call matches as code does: legacy paths as written, a trailing slash, methods: [] taking none", () => {
  const legacy: ProxyRoute = { ...route('files'), allow: [{ methods: ['GET'], path: '/files/*' }] };
  // Before 0.16, `*` is itself: only `/files/*` and below, never `/files/a`.
  assert.match(sampleCall(legacy, 'GET', '/files/a', { from: 'legacy', methods: ['GET'] }).refusal!, /^403/);
  assert.equal(sampleCall(legacy, 'GET', '/files/*', { from: 'legacy', methods: ['GET'] }).refusal, null);
  assert.equal(sampleCall(legacy, 'GET', '/files/a').refusal, null, "the tab's own reads it as a glob");
  // `allow` in code keeps a trailing slash: what is below it.
  const below: ProxyRoute = { ...route('files'), allow: [{ methods: [], path: '/files/' }] };
  assert.equal(sampleCall(below, 'GET', '/files/a/b', { from: 'code', methods: null }).refusal, null);
  // Legacy `methods: []` took no method: the converted `methods: []` would read as any.
  const none: ProxyRoute = { ...route('files'), allow: [{ methods: [], path: '/' }] };
  assert.match(sampleCall(none, 'GET', '/x', { from: 'legacy', methods: [] }).refusal!, /^405/);
});

test("a queued resave keeps the item as its editor saw it: a parent's change read since shows as one to review, never adopted", () => {
  const fork = { project: 'market', environment: 'dev-eu' };
  const parents = (host: string) => [{ path: 'market/dev', page: page([route('gemini', ['OPENAI_API_KEY'], host)]) }];
  const seen = itemsOf(page([]), fork, parents('api.openai.com')).find((item) => item.id === 'from:gemini')!;
  // "Save again" as the hook queues it: the definition as shown, its item as the origin.
  const drafts = { ...NO_DRAFTS, edits: { 'from:gemini': seen.definition }, resaved: ['from:gemini'], origins: { 'from:gemini': seen } };
  const still = pageState({ page: page([]), place: fork, parents: parents('api.openai.com'), keys: KEYS, drafts, tried: true });
  assert.deepEqual(still.rows.filter((row) => row.id === 'from:gemini').map((row) => [row.state, row.overtaken]), [['resaved', false]]);
  // dev's gemini now goes elsewhere, read in the background: the fork's seal is the same, so no 409 would say so.
  const moved = pageState({ page: page([]), place: fork, parents: parents('other.example'), keys: KEYS, drafts, tried: true });
  const row = moved.rows.find((one) => one.id === 'from:gemini')!;
  assert.deepEqual([row.state, row.overtaken], ['changed', true]);
  assert.deepEqual(diffOf(row.before, row.definition), [{ label: 'Upstream', before: 'https://other.example/v1', after: 'https://api.openai.com/v1' }]);
  assert.equal((saveOf(moved.rows).gemini as ProxyRoute).upstream, 'https://api.openai.com/v1');
});

test('a resave outlives a removal even when its draft is the item as it was (an edit typed back)', () => {
  const editor = state(page([])).editor;
  const origin = itemsOf(page([route('gemini')]), DEV).find((item) => item.id === 'own:gemini')!;
  const drafts = { ...NO_DRAFTS, edits: { 'own:gemini': route('gemini') }, resaved: ['own:gemini'], origins: { 'own:gemini': origin } };
  const rows = rowsOf([], drafts, editor);
  assert.deepEqual(rows.map((row) => [row.id, row.state, row.gone]), [['own:gemini', 'resaved', true]]);
  assert.deepEqual(saveOf(rows), { gemini: route('gemini') });
  // An edit typed back, never resaved, is nothing to save once its item is gone; a deletion neither.
  assert.deepEqual(rowsOf([], { ...drafts, resaved: [] }, editor), []);
  assert.deepEqual(rowsOf([], { ...drafts, edits: { 'own:gemini': null } }, editor), []);
});

test("code's methods beyond the tab's seven show as written, and the sample call offers them", () => {
  const dav: ProxyRoute = { ...route('dav'), allow: [{ methods: ['PROPFIND' as 'GET'], path: '/files/**' }] };
  assert.deepEqual(methodsLabel(['PROPFIND']), { all: 'PROPFIND', shown: 'PROPFIND' });
  assert.deepEqual(methodsLabel([]), { all: '', shown: 'Any' });
  assert.deepEqual(methodsLabel(['POST', 'GET', 'PUT', 'DELETE']).shown, 'GET +3');
  assert.deepEqual(methodChoices(dav).slice(-2), ['OPTIONS', 'PROPFIND']);
  assert.equal(sampleCall(dav, 'PROPFIND', '/files/a', { from: 'code', methods: null }).refusal, null);
  assert.match(sampleCall(dav, 'GET', '/files/a', { from: 'code', methods: null }).refusal!, /^405/);
});

test('an empty allow list takes no request: a 403, whatever the method, as the proxy answers', () => {
  const none: ProxyRoute = { ...route('closed'), allow: [] };
  assert.match(sampleCall(none, 'DELETE', '/x').refusal!, /^403/);
  assert.match(sampleCall(none, 'GET', '/x', { from: 'code', methods: null }).refusal!, /^403/);
});

test("legacy `paths: []` keeps its methods: they answer first, a 405, and the sample call offers them", () => {
  const pathless: ProxyRoute = { ...route('dav'), allow: [] };
  const allowAs = { from: 'legacy' as const, methods: ['POST', 'PROPFIND'] };
  assert.match(sampleCall(pathless, 'GET', '/x', allowAs).refusal!, /^405/);
  assert.match(sampleCall(pathless, 'PROPFIND', '/x', allowAs).refusal!, /^403/);
  assert.deepEqual(methodChoices(pathless, allowAs).slice(-1), ['PROPFIND']);
  // No `methods` at all: any method, and still no path.
  assert.match(sampleCall(pathless, 'GET', '/x', { from: 'legacy', methods: null }).refusal!, /^403/);
});

test('a sample call reads its path as the proxy does: encoded, without its query, and refused when it climbs out', () => {
  const cafe: ProxyRoute = { ...route('menu'), upstream: 'https://api.example.com/v1', allow: [{ methods: [], path: '/caf%C3%A9' }] };
  assert.deepEqual(sampleCall(cafe, 'GET', '/café'), { url: 'https://api.example.com/v1/caf%C3%A9', refusal: null });
  assert.deepEqual(sampleCall(cafe, 'GET', '/caf%C3%A9?limit=1'), { url: 'https://api.example.com/v1/caf%C3%A9?limit=1', refusal: null });
  const open: ProxyRoute = { ...route('open'), allow: null };
  assert.match(sampleCall(open, 'GET', '/%2e%2e/admin').refusal!, /^400/);
  assert.match(sampleCall(open, 'GET', '/a%2fb').refusal!, /^400/);
  assert.equal(sampleCall(open, 'GET', '/a/b').refusal, null);
  // `À` (U+00C0) and `Á` go as their UTF-8 bytes, `%C3%80`: no slash or dot, whatever the code point.
  const about: ProxyRoute = { ...route('site'), allow: [{ methods: [], path: '/%C3%80-propos' }] };
  assert.equal(sampleCall(about, 'GET', '/À-propos').refusal, null);
  assert.equal(sampleCall(open, 'GET', '/Á/b').refusal, null);
});

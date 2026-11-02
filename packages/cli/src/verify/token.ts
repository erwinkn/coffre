// An instance checked with a bearer token that reads one canary and
// audits its project: its value nowhere but its reveal, the reveal audited,
// nothing else in reach. The token is the operator's, from CI, or the one
// `coffre verify instance` issues for the run when an owner is signed in.
import { CoffreError, shownMember, type AuthInfo, type CoffreClient } from '@coffre/client';
import { getCalls, getUrls } from '@coffre/client/routes';

import { CLOSED_PAGES, NOBODY, NOWHERE, OPEN_PAGES } from './anonymous.ts';
import { bearer, expect, refused, Skip, type Checks } from './checks.ts';

/** A secret the operator set up, and its value, for the token to read and to look for. */
export type Canary = { project: string; environment: string; key: string; value: string };

/** Parse `<project>/<environment>/<KEY>=<value>`, or the path alone with the value given apart. */
export function parseCanary(text: string, value?: string): Canary {
  const at = text.indexOf('=');
  const path = at === -1 ? text : text.slice(0, at);
  const given = at === -1 ? value : text.slice(at + 1);
  const parts = path.split('/');
  if (parts.length !== 3 || parts.some((part) => part === '')) {
    throw new Error(`the canary is <project>/<environment>/<KEY>, not "${path}"`);
  }
  if (given === undefined || given === '') throw new Error('the canary has no value: paste it when asked, or pipe it in');
  const [project, environment, key] = parts as [string, string, string];
  return { project, environment, key, value: given };
}

/**
 * The checks with a bearer token that reads the canary, and audits its
 * project. `prefix` names them apart, run twice; `verification` false leaves
 * out the last, which a token can only skip, for a caller that verifies the
 * chain otherwise.
 */
export async function tokenChecks(
  report: Checks,
  origin: string,
  setup: { token?: string; canary?: Canary },
  { prefix = '', verification = true }: { prefix?: string; verification?: boolean } = {},
): Promise<void> {
  const api = setup.token === undefined ? undefined : bearer(origin, setup.token);
  const token = await report.check(`${prefix}token`, { api, canary: setup.canary }, ({ api, canary }) => whoIsToken(origin, api, canary));
  const needs = { api, canary: setup.canary, token, secret: setup.token };
  await report.check(`${prefix}token reveal`, needs, ({ api, canary, token }) => tokenReveal(api, canary, token));
  await report.check(`${prefix}token scan`, needs, ({ canary, secret }) => tokenScan(origin, secret, canary));
  await report.check(`${prefix}token scope`, needs, ({ api, canary }) => tokenScope(api, canary));
  if (verification) await report.check(`${prefix}token verification`, { api }, ({ api }) => tokenVerification(api));
}

// --- with a token ---------------------------------------------------------------

/** The token's service, and its credential, as `GET /me` names it (null from a server before 0.15). */
export type Token = { member: string; credentialId: string | null };

/** The token is a service's, and reads the canary's environment. */
async function whoIsToken(origin: string, api: CoffreClient, canary: Canary): Promise<{ detail: string; value: Token }> {
  const auth = (await (await fetch(`${origin}/api/auth`)).json()) as AuthInfo;
  if (auth.signin === null) throw new Skip("behind Cloudflare Access, coffre issues no bearer tokens: the token's checks need coffre's own sign-in");
  const me = await api.me();
  expect(me.principal.type === 'service', `the token is ${me.principal.type}:${me.principal.id}'s, not a service's`);
  const member = `token:${me.principal.id}`;
  const place = `${canary.project}/${canary.environment}`;
  const reads = me.environments.find((env) => `${env.project}/${env.environment}` === place);
  expect(reads?.permissions.includes('secret.read'), `${shownMember(member)} cannot read ${place}`, me.environments);
  const { keys } = await api.secrets.list(place);
  expect(keys.some((key) => key.key === canary.key), `${place} holds no ${canary.key}`, keys.map((key) => key.key));
  return { detail: `${shownMember(member)}, reading ${place}`, value: { member, credentialId: me.credentialId ?? null } };
}

/**
 * How long before a reveal 0.15's log may have logged the read it rides on:
 * a repeat of a use within a minute rides on the first one's entry (a
 * cover, R53), and the server's clock may stand a little off this one's.
 */
const COVERED_MS = 90_000;

/** How long a read may wait to be listed in 0.15's log: sealed at the checkpointer's tick, then listed by the projector. */
const LISTED_WITHIN_MS = 20_000;

/**
 * Reveal the canary once, and find its `secret.read` in the audit log: by
 * the reveal's operation, in 0.14's log; in 0.15's, where a read is its use
 * and names no operation (T166), the token's own read of the canary, on
 * its own page (0.15.0 lists reads by member, never by place: D160), by its
 * credential, for a reveal, of the version the token lists: the use
 * the reveal made, or the one within the minute before it that it rode on
 * (a cover is of the same credential, purpose and key), once listed, which
 * may take a few seconds (`LISTED_WITHIN_MS`).
 */
export async function tokenReveal(api: CoffreClient, canary: Canary, token: Token): Promise<string> {
  const path = `${canary.project}/${canary.environment}`;
  const asked = Date.now();
  const { operationId, values } = await api.secrets.reveal(`${path}/${canary.key}`);
  expect(values[canary.key] === canary.value, `${path}/${canary.key} is not the value given as the canary`);
  const version = (await api.secrets.list(path)).keys.find((key) => key.key === canary.key)?.version;
  const list = async (query: { path?: string; before?: string }) => {
    try {
      return await api.audit.list({ ...query, actor: token.member, limit: 50, sealed: '1' });
    } catch (error) {
      if (error instanceof CoffreError && error.status === 403) {
        throw new Skip(`the token holds no audit.read on ${canary.project}, so the reveal's entry cannot be looked for`);
      }
      throw error;
    }
  };
  const first = await list({ path });
  let { entries, reads } = first;
  const read = entries.filter((entry) => entry.operationId === operationId);
  // A server that keeps 0.15's log lists its reads on the whole log and by member, and since 0.15.x by place (T175); 0.15.0
  // never by place (D160), and says so: the token's own page lists its own, whatever it audits.
  if (read.length === 0 && (reads !== undefined || first.readsOmitted !== undefined)) {
    expect(token.credentialId !== null, "the server names no credential of the token's, so its read in 0.15's log cannot be told from another's");
    // Of the version revealed: an earlier version's read of the minute before stops no wait for this one (review r11).
    const ownOf = (listed: typeof entries) => listed.filter((entry) => entry.log === '0.15' && entry.action === 'secret.read' && entry.key === canary.key
      && entry.project === canary.project && entry.environment === canary.environment
      && entry.metadata.credentialId === token.credentialId && entry.metadata.purpose === 'reveal' && entry.version === version
      && Date.parse(entry.occurredAt) >= asked - COVERED_MS);
    // Page back as far as the cover's minute: newer entries of the token's may fill the first page (review r6).
    const recent = async () => {
      const all: typeof entries = [];
      for (let before: string | undefined; ;) {
        const page = await list(before === undefined ? {} : { before });
        all.push(...page.entries);
        reads = page.reads;
        const oldest = page.entries.at(-1);
        if (page.next === null || oldest === undefined || Date.parse(oldest.occurredAt) < asked - COVERED_MS) return all;
        before = page.next;
      }
    };
    entries = await recent();
    for (const deadline = Date.now() + LISTED_WITHIN_MS; ownOf(entries).length === 0 && Date.now() < deadline;) {
      await new Promise((resolve) => setTimeout(resolve, 250));
      entries = await recent();
    }
    const own = ownOf(entries);
    const [used] = own;
    expect(used !== undefined, `the reveal is logged 0 times, not once: no read of ${canary.key} by the token's credential since the minute before it, listed within ${LISTED_WITHIN_MS / 1000} s (reads listed through ${reads?.through ?? 'none'})`, entries.slice(0, 3));
    expect(used.decision === 'allow' && used.forged !== true && used.version === version,
      `the reveal's entry is not an allowed read of the canary's version ${String(version)} the vault vouches for`, used);
    return `one secret.read of ${canary.key}, entry ${used.seq} of 0.15's log, by the token's credential`;
  }
  expect(read.length === 1, `the reveal is logged ${read.length} times, not once`, entries.slice(0, 5));
  const [entry] = read as [(typeof read)[number]];
  expect(
    entry.action === 'secret.read' && entry.decision === 'allow' && entry.key === canary.key && entry.requestId !== null,
    "the reveal's entry is not an allowed read of the canary, under a request",
    entry,
  );
  return `one secret.read of ${canary.key}, entry ${entry.seq}, under request ${entry.requestId}`;
}

/**
 * The canary's value, in any answer to a GET route as the token or as no
 * one, or in any page. The reveal is the only answer allowed to carry it.
 */
async function tokenScan(origin: string, token: string, canary: Canary): Promise<string> {
  const api = bearer(origin, token);
  const me = await api.me();
  const member = `token:${me.principal.id}`;
  const listed = me.environments.map(({ project, environment }) => ({ project, environment }));
  const places = [...listed, NOWHERE];
  const calls = getCalls({
    places,
    secrets: [{ project: canary.project, environment: canary.environment, key: canary.key }, { ...NOWHERE, key: 'NONE' }],
    members: [member, NOBODY, 'user:nobody@conformance.example'],
    services: [member, NOBODY],
  });
  const forms = [canary.value, Buffer.from(canary.value).toString('base64'), Buffer.from(canary.value).toString('hex')];
  const leaks: string[] = [];
  const callers: [string, Record<string, string>][] = [
    ['the token', { authorization: `Bearer ${token}` }],
    ['no one', {}],
  ];
  let answers = 0;
  const look = async (what: string, url: string, headers: Record<string, string>) => {
    const text = await (await fetch(url, { headers, redirect: 'manual' })).text();
    answers++;
    if (forms.some((form) => text.includes(form))) leaks.push(what);
  };
  for (const { key, url } of getUrls(origin, calls)) {
    for (const [name, headers] of callers) await look(`${key} as ${name}`, url, headers);
  }
  const pages = [
    ...OPEN_PAGES,
    ...CLOSED_PAGES,
    ...listed.flatMap(({ project, environment }) => [`/projects/${project}`, `/projects/${project}/${environment}`]),
  ];
  for (const path of new Set(pages)) {
    for (const [name, headers] of callers) await look(`the page ${path} as ${name}`, `${origin}${path}`, headers);
  }
  expect(leaks.length === 0, "the canary's value was found outside its reveal", leaks);
  return `${answers} answers from ${Object.keys(calls).length} GET routes and ${new Set(pages).size} pages, as the token and as no one: no value`;
}

/** The token reaches the canary's project and nothing else: not another environment, project or member. */
async function tokenScope(api: CoffreClient, canary: Canary): Promise<string> {
  const { projects } = await api.projects.list();
  const seen = projects.map((project) => project.slug);
  expect(seen.length === 1 && seen[0] === canary.project, `the token sees ${seen.join(', ') || 'no project'}, not only ${canary.project}`);
  const me = await api.me();
  const own = `${canary.project}/${canary.environment}`;
  const reads = me.environments.filter((env) => env.permissions.includes('secret.read')).map((env) => `${env.project}/${env.environment}`);
  expect(reads.length === 1 && reads[0] === own, `the token reads ${reads.join(', ')}, not only ${own}`);
  const more = [...new Set(me.environments.flatMap((env) => env.permissions))].filter(
    // Every role that reads uses too (secret.use): a Viewer's token holds both.
    (permission) => permission !== 'secret.read' && permission !== 'secret.use' && permission !== 'audit.read',
  );
  expect(more.length === 0, `the token holds more than reading: ${more.join(', ')}`);

  const others = projects[0]!.environments.map((env) => `${canary.project}/${env.slug}`).filter((path) => path !== own);
  const nowhere = `${NOWHERE.project}/${NOWHERE.environment}`;
  let refusals = 0;
  for (const path of [...others, nowhere]) {
    await refused(`the token listed ${path}`, api.secrets.list(path));
    await refused(`the token revealed ${path}`, api.secrets.reveal(path));
    refusals += 2;
  }
  // Its project's log is the token's to read, as `audit.read` there; another's is not.
  await refused(`the token read ${nowhere}'s audit`, api.audit.list({ path: nowhere, limit: 1 }));
  await refused('the token listed the members', api.members.list());
  await refused(`the token read ${shownMember(NOBODY)}`, api.members.get(NOBODY));
  refusals += 3;
  try {
    const { entries } = await api.audit.list({ limit: 500 });
    const outside = entries.filter((entry) => entry.project !== null && entry.project !== canary.project);
    expect(outside.length === 0, `the token reads audit entries about ${[...new Set(outside.map((entry) => entry.project))].join(', ')}`);
  } catch (error) {
    if (!(error instanceof CoffreError && error.status === 403)) throw error;
  }
  const elsewhere = others.length === 0 ? 'no other environment' : `${others.length} other environment${others.length === 1 ? '' : 's'}`;
  return `only ${own}; ${refusals} reads elsewhere refused: ${elsewhere} of ${canary.project}, a made-up place, the members`;
}

async function tokenVerification(api: CoffreClient): Promise<string> {
  let verified;
  try {
    verified = await api.audit.verify();
  } catch (error) {
    if (error instanceof CoffreError && error.status === 403) {
      throw new Skip('verification is for auditors, admins and owners of the whole instance, which this token is not: not checked');
    }
    throw error;
  }
  expect(verified.ok, 'the audit log does not verify', verified);
  return `${verified.entries} entries verify, through entry ${verified.through}`;
}

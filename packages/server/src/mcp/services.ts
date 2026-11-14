// The tools that issue and end a service account's ways in (docs/design/mcp.md,
// section 6): its tokens, and the CI workloads it trusts. Each waits for its
// person's approval (changes.ts). Issuing a token or trusting a workload
// binds the approval to what it would reach, weighed by the vault when the
// page opens (`?dryRun=1`): Approve weighs it again and is refused if it
// changed, then makes it with that scope named, so that it reaches what the
// person read or nothing.
import { apiMember, shownMember } from '@coffre/client';
import { credentialScopeInWords, MAX_SCOPE_PLACES } from '@coffre/core/access';
import { BEARER_PROFILES, claimValues, defaultIssuer, EVENT_EXPOSURE, GITHUB_ISSUER, GITLAB_ISSUER, type BindingClaims, type WorkloadProfile } from '@coffre/core/identity';
import { roleId } from '@coffre/core/schemas';
import { z } from 'zod';

import type { ApiContext } from '../api/context.ts';
import { bind, newBinding, type BindingPlan } from '../api/routes/bindings.ts';
import { runRoute } from '../api/router.ts';
import { FetchRefused, type WorkloadTransport } from '../workloads/transport.ts';
import { approved, changeTool, type Detail, type Replaced } from './changes.ts';
import { manages } from './members.ts';
import type { Tool } from './tools.ts';

const service = z.string().min(1).max(200).describe('A service account: service:ci-deploy, or ci-deploy');

/** A service account as the API names it, from `ci-deploy`, `service:ci-deploy` or `token:ci-deploy`. */
const serviceMember = (name: string) => apiMember(name.includes(':') ? name : `service:${name}`);
const shownService = (name: string) => shownMember(serviceMember(name));

/** A token's or a binding's scope, by path and role. */
type Scope = Record<string, string>;
const credentialScope = z
  .record(z.string().max(200), roleId)
  .refine((scope) => Object.keys(scope).length <= MAX_SCOPE_PLACES, `a scope names at most ${MAX_SCOPE_PLACES} places`)
  .optional()
  .describe('What it reaches, each project or environment by path and its role, as {"market/dev": "developer"}; at most what the account holds. Left out: all it holds now. Nothing the account is given later reaches it.');

/**
 * What a token or a binding will reach, as the vault weighs it now, as the
 * page says it, and its basis: Approve weighs it again and is refused if it
 * differs from what the person read, as when the account was given another
 * grant since, and makes the change with it (`pinned`).
 */
function reaching(scope: Scope): Replaced {
  return { state: { scope }, details: [{ label: 'Reaches', value: credentialScopeInWords(scope), note: 'Never more than the account holds, and nothing it is given later.' }] };
}

/**
 * The scope the page showed and Approve found again (`reaching`), which the
 * token or binding is made with, rather than left for the vault to decide
 * a moment after Approve compared it.
 */
function pinned(replaced: Replaced | undefined): Scope {
  const scope = (replaced?.state as { scope?: Scope } | undefined)?.scope;
  if (scope === undefined) throw new Error('approved without what it reaches');
  return scope;
}

type TokenArgs = { service: string; label?: string | undefined; expiresInDays: number; scope?: Scope | undefined };

/** What a token would reach: its dry run, one weigh. */
async function tokenPlan(ctx: ApiContext, { service, label, expiresInDays, scope }: TokenArgs): Promise<Scope> {
  const plan = await runRoute('POST /members/:member/tokens', { member: serviceMember(service) }, { label: label ?? null, expiresInDays, ...(scope === undefined ? {} : { scope }) }, ctx, { dryRun: '1' });
  return plan.scope;
}

type BindingArgs = { service: string; profile: string; issuer?: string | undefined; claims: BindingClaims; scope?: Scope | undefined; label?: string | undefined };
const bindingInput = ({ profile, issuer, claims, label }: BindingArgs, scope: Scope | undefined) => ({ profile, issuer: issuer ?? null, claims, label: label ?? null, ...(scope === undefined ? {} : { scope }) });

/** The bindings a new one ends, each by id and why: named, or one of its issuer's whose keys are elsewhere. */
type Ending = { id: string; why: 'asked' | 'keys_moved' }[];

/**
 * What a binding would reach and end: its dry run (its issuer asked where
 * its keys are, then one weigh), as the page says it. Each binding it ends
 * is listed by its label and claims, read from the service's list only
 * when there is one: a binding is never edited, so its id is its basis.
 */
async function bindingPlan(ctx: ApiContext, args: BindingArgs): Promise<Replaced> {
  const member = serviceMember(args.service);
  const plan = (await runRoute('POST /members/:member/bindings', { member }, bindingInput(args, args.scope), ctx, { dryRun: '1' })) as BindingPlan;
  const { details } = reaching(plan.scope);
  const live = plan.replaces.length === 0 ? [] : (await runRoute('GET /members/:member/bindings', { member }, undefined, ctx)).bindings;
  for (const { id, why } of plan.replaces) {
    const ended = live.find((binding) => binding.id === id);
    const claims = ended === undefined ? id : Object.entries(ended.claims).map(([claim, value]) => `${claim}: ${claimValues(value).join(', ')}`).join('; ');
    details.push({
      label: 'Ends',
      value: `${ended?.label ?? 'unlabelled'} (${claims})`,
      note: why === 'asked' ? 'Asked to replace it: its runs are refused from now on.' : "Its issuer's keys are elsewhere now: trusting a workload there ends it, and its runs are refused from now on.",
      warn: true,
    });
  }
  return { details, state: { scope: plan.scope, replaces: plan.replaces } };
}

/** The bindings the page listed as ended, and Approve found again: the binding ends those, as asked, and refuses `stale` should it end another. */
function ending(replaced: Replaced | undefined): string[] {
  const listed = (replaced?.state as { replaces?: Ending } | undefined)?.replaces;
  if (listed === undefined) throw new Error('approved without what it ends');
  return listed.map(({ id }) => id);
}

/** What the page says of an ID github.com or gitlab.com did not name. */
const UNNAMED = 'private or unknown: check this ID yourself';
/** What the page says of an ID on any other issuer, whose answers coffre has no reason to believe. */
const UNCHECKED = "coffre can't check this host: check this ID yourself";

/** The claims that hold GitHub's or GitLab's numeric IDs. */
const ID_CLAIMS = new Set(['repository_id', 'repository_owner_id', 'project_id', 'namespace_id']);

/**
 * What a binding's numeric IDs name, read back from github.com's or
 * gitlab.com's API through the workloads' transport: a repository, project
 * or owner by its path. Only those two answer: the app chose the issuer,
 * and a host it chose could name its IDs anything. Each ID claim gets a
 * note: what it names, that coffre could not tell, or that it does not ask
 * that host.
 */
async function namesOf(transport: WorkloadTransport, profile: WorkloadProfile, issuer: string | null, claims: BindingClaims): Promise<Record<string, string>> {
  const notes: Record<string, string> = {};
  const own = defaultIssuer(profile);
  if (own === null || (issuer ?? own) !== own) {
    for (const claim of Object.keys(claims)) if (ID_CLAIMS.has(claim)) notes[claim] = UNCHECKED;
    return notes;
  }
  const ask = async (url: string): Promise<Record<string, unknown> | null> => {
    try {
      const answer = await transport.json(new URL(url));
      return typeof answer === 'object' && answer !== null ? (answer as Record<string, unknown>) : null;
    } catch (error) {
      if (error instanceof FetchRefused) return null;
      throw error;
    }
  };
  const text = (value: unknown) => (typeof value === 'string' && value.length > 0 ? value.slice(0, 200) : null);
  const field = (object: Record<string, unknown> | null, key: string) => {
    const value = object?.[key];
    return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : null;
  };
  const id = (claim: string) => {
    const value = claims[claim];
    return typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value) ? value : null;
  };
  const name = (claim: string, what: string, path: string | null) => {
    if (claims[claim] !== undefined) notes[claim] = path === null ? UNNAMED : `the ${what} ${path}`;
  };

  if (profile.startsWith('github')) {
    const [repositoryId, ownerId] = [id('repository_id'), id('repository_owner_id')];
    const repository = repositoryId === null ? null : await ask(`https://api.github.com/repositories/${repositoryId}`);
    const owner = field(repository, 'owner');
    const ownerLogin = owner !== null && String(owner.id) === ownerId ? text(owner.login) : ownerId === null ? null : text((await ask(`https://api.github.com/user/${ownerId}`))?.login);
    name('repository_id', 'GitHub repository', text(repository?.full_name));
    name('repository_owner_id', 'GitHub account', ownerLogin);
  } else {
    const [projectId, namespaceId] = [id('project_id'), id('namespace_id')];
    const project = projectId === null ? null : await ask(`${GITLAB_ISSUER}/api/v4/projects/${projectId}`);
    const namespace = field(project, 'namespace');
    const namespacePath =
      namespace !== null && String(namespace.id) === namespaceId ? text(namespace.full_path) : namespaceId === null ? null : text((await ask(`${GITLAB_ISSUER}/api/v4/namespaces/${namespaceId}`))?.full_path);
    name('project_id', 'GitLab project', text(project?.path_with_namespace));
    name('namespace_id', 'GitLab namespace', namespacePath);
  }
  return notes;
}

/** A binding's claims as the page's lines: each in full, what an ID names where coffre could tell, and what an event that runs unreviewed code exposes. */
function claimLines(claims: BindingClaims, names: Record<string, string>): Detail[] {
  return Object.entries(claims).map(([claim, value]) => {
    const exposed = claim === 'event_name' ? claimValues(value).flatMap((event) => (EVENT_EXPOSURE[event] === undefined ? [] : [EVENT_EXPOSURE[event]])) : [];
    const note = exposed.length > 0 ? exposed.join(' ') : names[claim];
    return { label: claim, value: claimValues(value).join(', '), kind: 'mono' as const, ...(note === undefined ? {} : { note }), ...(exposed.length > 0 ? { warn: true as const } : {}) };
  });
}

const ISSUE_TOKEN = changeTool({
  name: 'issue_service_token',
  needs: 'services',
  title: 'Issue a service token',
  description: `Issue a bearer token for a service account. coffre shows the token to the person on its page, once; it never reaches you. ${approved}`,
  scope: 'manage-access',
  idempotent: false,
  destructive: false,
  input: z.object({ service, label: z.string().trim().min(1).max(120).optional(), expiresInDays: z.number().int().min(1).max(366), scope: credentialScope }).strict(),
  change: {
    summary: ({ service, expiresInDays }) => `issue a token for ${shownService(service)}, good for ${expiresInDays} days`,
    place: () => null,
    done: ({ service, expiresInDays }, at) => {
      const until = new Date(at.getTime() + expiresInDays * 86_400_000).toISOString().replace(/\.\d+Z$/, 'Z');
      return { result: { service: shownService(service), expiresAt: until }, text: `A token for ${shownService(service)} is issued, good until ${until}. coffre showed it to the person, once; it is not here.` };
    },
    // As the connection, before anyone is asked: whoever manages the account. The vault weighs nothing on an MCP
    // token's word, so what the token reaches is weighed on the page, as the person.
    check: (tool, { service }) => manages(tool, serviceMember(service)),
    // What it will reach, as the vault weighs it: what it names, or all the account holds. Approve refuses it changed.
    replaces: async (ctx, args) => reaching(await tokenPlan(ctx, args)),
    preview: async (_ctx, { service, label, expiresInDays }, _viewing, replaced) => [
      { label: 'Service account', value: shownService(service), kind: 'mono' },
      ...(label === undefined ? [] : [{ label: 'The app calls it', value: label }]),
      ...replaced,
      { label: 'Good for', value: `${expiresInDays} days` },
      { label: 'The token', value: 'shown here once, after you approve; never to the app' },
    ],
    apply: async (ctx, { service, label, expiresInDays }, { replaced }) => {
      const issued = await runRoute('POST /members/:member/tokens', { member: serviceMember(service) }, { label: label ?? null, expiresInDays, scope: pinned(replaced) }, ctx);
      if (!('token' in issued)) throw new Error('a token asked for came back a plan');
      return { shown: [{ label: 'Token', value: issued.token, kind: 'mono' }] };
    },
  },
});

const REVOKE_TOKEN = changeTool({
  name: 'revoke_service_token',
  needs: 'services',
  title: 'Revoke a service token',
  description: `Revoke one of a service account's tokens, by the ID describe_member lists. ${approved}`,
  scope: 'manage-access',
  idempotent: true,
  destructive: true,
  input: z.object({ service, id: z.uuid() }).strict(),
  change: {
    summary: ({ service }) => `revoke a token of ${shownService(service)}`,
    place: () => null,
    done: ({ service, id }) => ({ result: { service: shownService(service), id, revoked: true }, text: 'The token is revoked: whatever used it is refused from now on.' }),
    check: (tool, { service }) => manages(tool, serviceMember(service)),
    preview: async (ctx, { service, id }) => {
      const token = (await runRoute('GET /members/:member/tokens', { member: serviceMember(service) }, undefined, ctx)).tokens.find((entry) => entry.id === id);
      return [
        { label: 'Service account', value: shownService(service), kind: 'mono' },
        { label: 'Token', value: token === undefined ? `${id}, which it does not hold` : `${token.label ?? 'unlabelled'} (…${token.hint})` },
        ...(token?.lastUsedAt == null ? [] : [{ label: 'Last used', value: token.lastUsedAt, kind: 'time' as const }]),
      ];
    },
    apply: async (ctx, { service, id }) => {
      await runRoute('DELETE /members/:member/tokens/:id', { member: serviceMember(service), id }, undefined, ctx);
      return {};
    },
  },
});

const TRUST = changeTool({
  name: 'trust_workload',
  needs: 'services',
  title: 'Trust a CI workload',
  description: `Let CI runs whose ID token has these claims sign in as a service account, with no stored token. event_name may list several events; a pull_request run matches by the branch it merges into. A GitHub binding may name environment, a GitHub environment, to take only the jobs that run in it, under its protection rules. ${approved}`,
  scope: 'manage-access',
  idempotent: false,
  destructive: false,
  input: z
    .object({
      service,
      profile: z.enum(BEARER_PROFILES),
      issuer: z.string().max(400).optional().describe("The issuer's URL, for a custom profile"),
      claims: z
        .record(z.string().max(64), z.union([z.string().max(1024), z.array(z.string().max(64)).min(1).max(16)]))
        .describe('The ID token claims a run must carry, such as repository_id and ref; event_name or pipeline_source may be a list, as ["push", "pull_request"]; environment, on GitHub, the GitHub environment the job runs in, as "production", matched whatever its case'),
      scope: credentialScope,
      label: z.string().trim().min(1).max(120).optional(),
    })
    .strict(),
  change: {
    summary: ({ service, profile }) => `let ${profile} CI runs sign in as ${shownService(service)}`,
    place: () => null,
    done: ({ service }) => ({ result: { service: shownService(service), trusted: true }, text: `CI runs that match are trusted as ${shownService(service)}: describe_member lists the binding.` }),
    // As the connection, whoever manages the account; the binding is weighed, and its issuer asked where its keys are,
    // on the page, as the person: the vault weighs nothing on an MCP token's word.
    check: (tool, { service }) => manages(tool, serviceMember(service)),
    // What its runs will reach, and the bindings it ends, as the vault weighs it: Approve refuses either changed.
    replaces: async (ctx, args) => bindingPlan(ctx, args),
    // The model picks the IDs: each is named back from GitHub or GitLab, where it can be, so the person reads what they trust.
    preview: async (_ctx, { service, profile, issuer, claims, label }, { transport }, replaced) => {
      const names = await namesOf(transport, profile, issuer ?? null, claims);
      // An issuer the app named that is not GitHub's or GitLab's own: whoever runs it signs the tokens.
      const unfamiliar = issuer !== undefined && issuer !== GITHUB_ISSUER && issuer !== GITLAB_ISSUER;
      return [
        { label: 'Service account', value: shownService(service), kind: 'mono' },
        unfamiliar
          ? { label: 'Runs from', value: issuer, kind: 'mono', note: "Not GitHub's or GitLab's own: whoever runs this host can sign in as the account. Approve only if it is yours.", warn: true }
          : { label: 'Runs from', value: issuer ?? `${profile}'s own issuer` },
        ...claimLines(claims, names),
        ...replaced,
        ...(label === undefined ? [] : [{ label: 'The app calls it', value: label }]),
      ];
    },
    // With what it reaches and the bindings it ends, as the page listed them, and no other: one more it would end is `stale`.
    apply: async (ctx, args, { replaced }) => {
      await bind(ctx, serviceMember(args.service), newBinding.parse({ ...bindingInput(args, pinned(replaced)), replaces: ending(replaced) }), { dryRun: false, only: true });
      return {};
    },
  },
});

const UNTRUST = changeTool({
  name: 'untrust_workload',
  needs: 'services',
  title: 'Stop trusting a CI workload',
  description: `Remove one of a service account's trust bindings, by the ID describe_member lists. ${approved}`,
  scope: 'manage-access',
  idempotent: true,
  destructive: true,
  input: z.object({ service, id: z.uuid() }).strict(),
  change: {
    summary: ({ service }) => `stop trusting a CI workload as ${shownService(service)}`,
    place: () => null,
    done: ({ service, id }) => ({ result: { service: shownService(service), id, removed: true }, text: 'The binding is removed: those CI runs are refused from now on.' }),
    check: (tool, { service }) => manages(tool, serviceMember(service)),
    preview: async (ctx, { service, id }) => {
      const binding = (await runRoute('GET /members/:member/bindings', { member: serviceMember(service) }, undefined, ctx)).bindings.find((entry) => entry.id === id);
      return [
        { label: 'Service account', value: shownService(service), kind: 'mono' },
        ...(binding === undefined
          ? [{ label: 'Binding', value: `${id}, which it does not hold` }]
          : [{ label: 'Runs from', value: binding.issuer }, ...Object.entries(binding.claims).map(([claim, value]) => ({ label: claim, value: claimValues(value).join(', '), kind: 'mono' as const }))]),
      ];
    },
    apply: async (ctx, { service, id }) => {
      await runRoute('DELETE /members/:member/bindings/:id', { member: serviceMember(service), id }, undefined, ctx);
      return {};
    },
  },
});

/** A service account's ways in: its tokens, then the workloads it trusts. */
export const SERVICE_TOOLS: readonly Tool[] = [ISSUE_TOKEN, REVOKE_TOKEN, TRUST, UNTRUST];

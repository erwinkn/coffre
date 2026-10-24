/**
 * `coffre trust` and `coffre untrust`: which CI runs may sign in as a
 * service account by OIDC, the ID token their platform signs
 * (docs/design/oidc.md).
 *
 *   coffre trust api-deploy --github acme/api --workflow deploy.yml --branch main
 *
 * builds the binding's claims from flags, looks up the IDs it names when
 * not given, and shows what the server would save: the claims in full, the
 * issuer and the keys it names. `--apply` saves it.
 */
import { apiMember, CoffreError, shownMember, type BindingPlan, type BindingView, type KeysPlan, type WorkloadIds } from '@coffre/client';
import { credentialScopeInWords, ROLE_ID, type Role } from '@coffre/core/access';
import {
  claimValues,
  EVENT_EXPOSURE,
  fullRef,
  GITHUB_EVENTS,
  githubEventsAt,
  GITLAB_PIPELINE_SOURCES,
  githubReusable,
  githubWorkflow,
  gitlabProject,
  type BearerProfile,
  type BindingClaims,
  type ClaimValue,
} from '@coffre/core/workloads';

export type TrustFlags = {
  github?: string;
  workflow?: string;
  reusable?: string;
  sha?: string;
  'any-repository'?: boolean;
  'github-environment'?: string;
  gitlab?: string;
  'gitlab-url'?: string;
  /** Repeated, or a comma list. */
  source?: string[];
  issuer?: string;
  claim?: string[];
  branch?: string;
  tag?: string;
  /** Repeated, or a comma list. */
  event?: string[];
  'repository-id'?: string;
  'owner-id'?: string;
  'project-id'?: string;
  'namespace-id'?: string;
};

export type BindingRequest = { profile: BearerProfile; issuer: string | null; claims: BindingClaims };

export type Lookup = (input: { github?: string; gitlab?: string; gitlabUrl?: string }) => Promise<WorkloadIds>;

export const TRUST_USAGE = `usage: coffre trust <service>                       its trust bindings
       coffre trust <service> --github <owner>/<repo> --workflow <file> (--branch <b> | --tag <t>)
                    [--event push,workflow_dispatch,schedule,release,pull_request,workflow_run]
                    [--github-environment <name>]
       coffre trust <service> --github <owner>/<repo> --reusable <owner>/<repo>/.github/workflows/<file>@<ref>
                    --sha <commit> (--branch <b> | --tag <t>) [--event …] [--github-environment <name>]
       coffre trust <service> --github <owner> --reusable … --any-repository
       coffre trust <service> --gitlab <group>/<project> (--branch <b> | --tag <t>)
                    [--source push,web,schedule] [--gitlab-url <url>]
       coffre trust <service> --issuer <url> --claim sub=<subject> [--claim <name>=<value> …]
       coffre trust <service> --issuer <iss> --jwks-file <path> --claim sub=<subject> [--claim …]
       coffre trust <service> --issuer <iss> --replace-keys --jwks-file <path>
         IDs, when the lookup cannot see a private repository, owner or project:
                    [--repository-id <n> --owner-id <n>] [--project-id <n> --namespace-id <n>]
         [--scope <path>=<role>,…] [--label <text>] [--replace <binding-id>] [--apply]
         --scope is what its runs reach, as market/dev=developer: at most what the account holds,
         all of it unless told, and nothing it is given later
         --event and --source take one or more, push alone unless told; a pull request matches
         by the branch it merges into
         --github-environment takes only the jobs that run in that GitHub environment, under its
         protection rules
         --claim names a nested claim by its path: kubernetes.io.serviceaccount.uid=<uid>
         --jwks-file uploads the issuer's public keys, a JWKS, for an issuer coffre cannot fetch them
         from, such as a private Kubernetes cluster's (kubectl get --raw /openid/v1/jwks): then
         --issuer is any string its tokens name, and coffre asks it nothing
         --replace-keys gives every binding of the service on --issuer the keys of --jwks-file, as
         when the issuer rotates its keys: a set that holds the old and the new takes tokens of both
       coffre untrust <service> <binding-id> [--apply]   shows the CI runs it would cut off; --apply removes it
A service account, service:<name>, signs in by OIDC this way, its CI's ID token matched by a trust
binding, with no stored secret; or, for CI without OIDC, with a bearer token: coffre tokens issue <service>.`;

/** A service account as the API names it, `token:api-deploy`, from `api-deploy`, `service:api-deploy` or `token:api-deploy`. */
export function serviceMember(value: string): string {
  const member = apiMember(value);
  return member.startsWith('token:') ? member : `token:${member}`;
}

/**
 * A token's or a binding's scope, from `--scope market/dev=developer,market/prod=viewer`,
 * repeated or a comma list; undefined, all its account holds, when not given.
 * `admit --grant` takes places and roles the same way.
 */
export function scopeFrom(values: string[] | undefined, flag = '--scope'): Record<string, Role> | undefined {
  const pairs = listOf(values);
  if (pairs === undefined) return undefined;
  return Object.fromEntries(pairs.map((pair) => {
    const [path, role, ...rest] = pair.split('=');
    // A role by id: which the instance defines, it says, and `coffre roles` lists.
    if (!path || role === undefined || rest.length > 0 || !ROLE_ID.test(role)) {
      throw new Error(`${flag} takes <project>[/<environment>]=<role>, a role \`coffre roles\` lists, such as viewer or developer; not "${pair}"`);
    }
    return [path, role];
  }));
}

/** A token's or a binding's scope in words; null for one 0.4 made, not sealed yet, which reaches all its account holds. */
export function reaches(scope: Record<string, string> | null): string {
  return scope === null ? 'all its account holds' : credentialScopeInWords(scope);
}

/** `push,workflow_dispatch` and `--event schedule`, as one list, each once. */
function listOf(values: string[] | undefined): string[] | undefined {
  if (values === undefined) return undefined;
  return [...new Set(values.flatMap((value) => value.split(',')).map((value) => value.trim()).filter((value) => value !== ''))];
}

/**
 * What the binding accepts, by the event (GitHub) or the pipeline source
 * (GitLab) that started the run; the flag that adds the others the ref
 * allows (a schedule runs on a branch, a release at a tag), short of those
 * that run unreviewed code; and what each of those chosen exposes.
 */
export function describeEvents(binding: Pick<BindingPlan, 'profile' | 'claims'>): string | null {
  if (binding.profile === 'custom') return null;
  const gitlab = binding.profile === 'gitlab';
  const chosen = claimValues(binding.claims[gitlab ? 'pipeline_source' : 'event_name']);
  const tag = gitlab ? binding.claims.ref_type === 'tag' : String(binding.claims.ref).startsWith('refs/tags/');
  const all: readonly string[] = gitlab
    ? GITLAB_PIPELINE_SOURCES
    : githubEventsAt(tag ? 'tag' : 'branch').filter((event) => EVENT_EXPOSURE[event] === undefined);
  const others = all.filter((value) => !chosen.includes(value));
  const [what, flag] = gitlab ? ['pipelines', '--source'] : ['runs', '--event'];
  const accepts = `Accepts ${what} started by ${listing(chosen)}.`;
  const lines = [others.length === 0 ? accepts : `${accepts} Not by ${listing(others, 'or')}: add them with ${flag}, as ${flag} ${[...chosen, ...others].join(',')}.`];
  for (const event of chosen) if (EVENT_EXPOSURE[event] !== undefined) lines.push(`${event}: ${EVENT_EXPOSURE[event]}`);
  return lines.join('\n');
}

function listing(items: readonly string[], last: 'and' | 'or' = 'and'): string {
  return items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} ${last} ${items.at(-1)}`;
}

/**
 * The binding the flags describe, its IDs looked up where they were not
 * given: one, whatever the events (GitHub) or pipeline sources (GitLab) it
 * names; `push` unless told. Throws a sentence.
 */
export async function bindingFrom(flags: TrustFlags, lookup: Lookup): Promise<BindingRequest> {
  const kinds = [flags.github !== undefined, flags.gitlab !== undefined, flags.issuer !== undefined].filter(Boolean).length;
  if (kinds !== 1) throw new Error('name one of --github, --gitlab or --issuer');
  const [events, sources] = [listOf(flags.event), listOf(flags.source)];
  if (flags.github === undefined && events !== undefined) throw new Error('--event is a GitHub run\'s: --source names a GitLab pipeline\'s');
  if (flags.github === undefined && flags['github-environment'] !== undefined) throw new Error('--github-environment narrows a GitHub binding: name the repository with --github');
  if (flags.gitlab === undefined && sources !== undefined) throw new Error('--source is a GitLab pipeline\'s: --event names a GitHub run\'s');
  for (const event of events ?? []) {
    if (!(GITHUB_EVENTS as readonly string[]).includes(event)) throw new Error(`--event takes ${GITHUB_EVENTS.join(', ')}, not ${event}`);
  }
  for (const source of sources ?? []) {
    if (!(GITLAB_PIPELINE_SOURCES as readonly string[]).includes(source)) throw new Error(`--source takes ${GITLAB_PIPELINE_SOURCES.join(', ')}, not ${source}`);
  }
  if (flags.github !== undefined) return github(flags, events ?? ['push'], lookup);
  if (flags.gitlab !== undefined) return gitlab(flags, sources ?? ['push'], lookup);
  return custom(flags);
}

function refFrom(flags: TrustFlags, form: 'full' | 'name'): { ref: string; type: 'branch' | 'tag' } {
  if ((flags.branch === undefined) === (flags.tag === undefined)) throw new Error('name one of --branch or --tag');
  const type = flags.branch !== undefined ? 'branch' : 'tag';
  const name = (flags.branch ?? flags.tag)!;
  return { ref: form === 'name' ? name : fullRef(type, name), type };
}

async function github(flags: TrustFlags, events: string[], lookup: Lookup): Promise<BindingRequest> {
  const { ref } = refFrom(flags, 'full');
  const environment = flags['github-environment'];
  /** IDs given, or looked up: then the name as GitHub spells it, as its tokens do. */
  const found = async (name: string, ids: string, flagsToAdd: string): Promise<Extract<WorkloadIds, { github: string }>> => {
    try {
      const answer = await lookup({ github: name });
      if (!('github' in answer)) throw new Error('not a GitHub repository or owner');
      return answer;
    } catch (error) {
      if (!(error instanceof CoffreError && error.status === 404)) throw error;
      throw new Error(
        `GitHub shows coffre nothing of ${name}: it is private, or not there. Get its IDs with\n` +
          `  gh api ${name.includes('/') ? 'repos' : 'users'}/${name} --jq '${ids}'\n` +
          `and add ${flagsToAdd}, to this coffre trust.`,
      );
    }
  };
  const repository = async () => {
    if (flags['repository-id'] !== undefined && flags['owner-id'] !== undefined) {
      return { github: flags.github!, repositoryId: flags['repository-id'], ownerId: flags['owner-id'] };
    }
    const answer = await found(flags.github!, '"--repository-id \\(.id) --owner-id \\(.owner.id)"', 'the two flags it prints, --repository-id <n> --owner-id <n>');
    if (!('repositoryId' in answer)) throw new Error(`--github takes <owner>/<repo>, not ${flags.github}`);
    return answer;
  };

  if (flags.reusable !== undefined) {
    if (flags.sha === undefined) throw new Error('a reusable workflow is trusted at one commit: --sha <commit>');
    const called = { ref, events, called: flags.reusable, sha: flags.sha, environment };
    if (flags['any-repository'] === true) {
      // The organization, `acme`, or any of its repositories, `acme/api`: its ID, given or looked up.
      const owner = flags.github!.split('/')[0]!;
      const ownerId = flags['owner-id'] ?? (await found(owner, '"--owner-id \\(.id)"', 'the flag it prints, --owner-id <n>')).ownerId;
      const caller = flags.workflow === undefined ? undefined : { repository: flags.github!, workflow: flags.workflow };
      return { ...githubReusable({ ...called, caller, repositoryId: null, ownerId }), issuer: null };
    }
    const { github: name, repositoryId, ownerId } = await repository();
    const caller = flags.workflow === undefined ? undefined : { repository: name, workflow: flags.workflow };
    return { ...githubReusable({ ...called, caller, repositoryId, ownerId }), issuer: null };
  }
  if (flags.workflow === undefined) throw new Error('name the workflow file: --workflow deploy.yml');
  const { github: name, repositoryId, ownerId } = await repository();
  return { ...githubWorkflow({ repository: name, repositoryId, ownerId, workflow: flags.workflow, ref, events, environment }), issuer: null };
}

async function gitlab(flags: TrustFlags, sources: string[], lookup: Lookup): Promise<BindingRequest> {
  const project = flags.gitlab!;
  const { ref, type } = refFrom(flags, 'name');
  let ids: { projectId: string; namespaceId: string };
  if (flags['project-id'] !== undefined && flags['namespace-id'] !== undefined) {
    ids = { projectId: flags['project-id'], namespaceId: flags['namespace-id'] };
  } else {
    let found: WorkloadIds;
    try {
      found = await lookup({ gitlab: project, gitlabUrl: flags['gitlab-url'] });
    } catch (error) {
      if (!(error instanceof CoffreError && error.status === 404)) throw error;
      const host = flags['gitlab-url'] === undefined ? '' : ` --hostname ${new URL(flags['gitlab-url']).host}`;
      throw new Error(
        `GitLab shows coffre nothing of ${project}: it is private, or not there. Get its IDs with\n` +
          `  glab api${host} projects/${encodeURIComponent(project)} | jq -r '"--project-id \\(.id) --namespace-id \\(.namespace.id)"'\n` +
          'and add the two flags it prints, --project-id <n> --namespace-id <n>, to this coffre trust.',
      );
    }
    if (!('projectId' in found)) throw new Error('not a GitLab project');
    ids = found;
  }
  return {
    ...gitlabProject({ namespaceId: ids.namespaceId, projectId: ids.projectId, refType: type, ref, sources }),
    issuer: flags['gitlab-url'] ?? null,
  };
}

function custom(flags: TrustFlags): BindingRequest {
  const claims: BindingClaims = {};
  for (const pair of flags.claim ?? []) {
    const at = pair.indexOf('=');
    if (at <= 0) throw new Error(`--claim takes <name>=<value>, not "${pair}"`);
    claims[pair.slice(0, at)] = pair.slice(at + 1);
  }
  return { profile: 'custom', issuer: flags.issuer!, claims };
}

/**
 * The JWKS `--jwks-file` holds, as the API takes it; the server checks each
 * key. Throws a sentence.
 */
export function keySetFrom(text: string, path: string): { keys: Record<string, unknown>[] } {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(`${path} is not JSON: --jwks-file takes the issuer's key set, { "keys": [ … ] }`);
  }
  const keys = (value as { keys?: unknown } | null)?.keys;
  if (!Array.isArray(keys)) throw new Error(`${path} is no key set: --jwks-file takes { "keys": [ … ] }, as kubectl get --raw /openid/v1/jwks prints it`);
  return { keys: keys as Record<string, unknown>[] };
}

/** Where a binding's keys come from: the URL coffre fetches them from, or those uploaded with it, by `kid` (or thumbprint) and algorithm. */
export function keysLine(binding: Pick<BindingPlan, 'jwksUri' | 'keys'>): string {
  // A server before 0.7 says nothing of uploaded keys.
  if (binding.keys == null) return binding.jwksUri;
  return `uploaded: ${binding.keys.map((key) => `${key.kid ?? `thumbprint ${key.thumbprint}`} (${key.alg})`).join(', ')}`;
}

/** A binding, or a plan for one, as lines: what it trusts, every claim in full. */
export function describeBinding(binding: Pick<BindingPlan, 'profile' | 'issuer' | 'jwksUri' | 'keys' | 'claims'> & { scope: BindingPlan['scope'] | null }): string[] {
  const width = Math.max(0, ...Object.keys(binding.claims).map((name) => name.length));
  const claims = Object.entries(binding.claims).map(([name, value], i) => `  ${i === 0 ? 'claims ' : '       '}  ${name.padEnd(width)}  ${claimValues(value).join(', ')}`);
  return [`  profile  ${binding.profile}`, `  issuer   ${binding.issuer}`, `  keys     ${keysLine(binding)}`, ...claims, `  reaches  ${reaches(binding.scope)}`];
}

/**
 * What `coffre trust --replace-keys` would do, or did: the keys, and each
 * binding on the issuer a new one replaces, as the server planned it or, once
 * saved, as it answered, whatever changed between the two.
 */
export function describeKeys(member: string, plan: KeysPlan, saved: { bindings: BindingView[]; replaced: string[] } | null): string {
  const replaced = saved?.replaced ?? plan.replaces;
  const count = replaced.length === 1 ? 'binding' : `${replaced.length} bindings`;
  const lines = [
    saved === null
      ? `Would give ${shownMember(member)}'s ${count} on ${plan.issuer} these keys, each replaced by a binding the same but for them:`
      : `Gave ${shownMember(member)}'s ${count} on ${plan.issuer} these keys:`,
    `  keys     ${keysLine(plan)}`,
    ...replaced.map((id, i) => (saved === null ? `  replaces ${id}` : `  ${saved.bindings[i]!.id} replaces ${id}`)),
    ...[withheldLine(plan.withheld)].flatMap((unread) => (unread === null ? [] : [`  ${unread}`])),
    saved === null
      ? 'Credentials those bindings issued, five minutes each at most, would end at once.'
      : 'Credentials the bindings replaced issued have ended.',
  ];
  return `${lines.join('\n')}\n`;
}

export function describePlan(member: string, plan: BindingPlan, applied: BindingView | null): string {
  const lines = [applied === null ? `Would trust CI runs to sign in as ${shownMember(member)}, by OIDC:` : `Trusted CI runs to sign in as ${shownMember(member)}, by OIDC, binding ${applied.id}:`];
  lines.push(...describeBinding(plan));
  for (const replaced of plan.replaces) {
    lines.push(`  replaces ${replaced.id}${replaced.why === 'keys_moved' ? ': the issuer moved its keys' : ''}`);
  }
  const unread = withheldLine(plan.withheld);
  if (unread !== null) lines.push(`  ${unread}`);
  return `${lines.join('\n')}\n`;
}

/**
 * What a service's new token or binding will not read, as the server said
 * (`withheld`): the sensitive values of these places, which only one an
 * Owner of their project issues reads. Null when there are none.
 */
export function withheldLine(withheld: readonly string[] | undefined): string | null {
  if (withheld === undefined || withheld.length === 0) return null;
  return `reads no sensitive value of ${withheld.join(', ')}: only one an Owner of ${withheld.length === 1 ? 'its project' : 'their projects'} issues does`;
}

/** `refs/heads/main` as `branch main`, `refs/tags/v1` as `tag v1`; anything else as it is. */
function refName(ref: string): string {
  const [, kind, name] = /^refs\/(heads|tags)\/(.+)$/.exec(ref) ?? [];
  return kind === undefined ? ref : `${kind === 'heads' ? 'branch' : 'tag'} ${name}`;
}

/**
 * The CI runs a binding lets sign in, in a sentence, from its claims: the
 * platform, the repository or project, the workflow, the ref. Bindings keep
 * IDs where a name could change hands; a name is shown where a claim has one.
 */
export function runsOf(binding: Pick<BindingView, 'profile' | 'issuer' | 'claims'>): string {
  // Every claim is one value, but what started the run, which may be several.
  const claims = binding.claims as Record<string, string | undefined>;
  const on = (ref: string | undefined, how: ClaimValue | undefined) => {
    const into = claimValues(how).includes('pull_request') ? ' or a pull request into it' : '';
    return [
      ref === undefined ? null : `on ${refName(ref)}${into}`,
      how === undefined ? null : `by ${listing(claimValues(how), 'or')}`,
      claims.environment === undefined || binding.profile === 'custom' ? null : `in environment ${claims.environment}`,
    ].filter(Boolean).join(', ');
  };
  /** `acme/api/.github/workflows/deploy.yml@refs/heads/main` as its repository and workflow file. */
  const workflow = (ref: string) => /^([^/]+\/[^/]+)\/(?:\.github\/workflows\/)?(.+)@/.exec(ref);
  switch (binding.profile) {
    case 'github': {
      const [, repository, file] = workflow(claims.workflow_ref ?? '') ?? [];
      return `GitHub Actions runs of ${repository ?? `repository ${claims.repository_id}`}'s workflow ${file ?? '(any)'}, ${on(claims.ref, binding.claims.event_name)}`;
    }
    case 'github-reusable':
    case 'github-reusable-organization': {
      const [, repository, file] = workflow(claims.workflow_ref ?? '') ?? [];
      const callers =
        binding.profile === 'github-reusable-organization'
          ? `any repository of owner ${claims.repository_owner_id}`
          : repository === undefined ? `repository ${claims.repository_id}` : `${repository}'s workflow ${file}`;
      const sha = claims.job_workflow_sha === undefined ? '' : ` at commit ${claims.job_workflow_sha.slice(0, 12)}`;
      return `GitHub Actions runs of ${callers} that call the reusable workflow ${claims.job_workflow_ref}${sha}, ${on(claims.ref, binding.claims.event_name)}`;
    }
    case 'gitlab': {
      const ref = claims.ref === undefined ? undefined : `${claims.ref_type === 'tag' ? 'refs/tags' : 'refs/heads'}/${claims.ref}`;
      const where = binding.issuer === 'https://gitlab.com' ? '' : ` on ${binding.issuer}`;
      return `GitLab pipelines of project ${claims.project_id} (namespace ${claims.namespace_id})${where}, ${on(ref, binding.claims.pipeline_source)}`;
    }
    case 'custom':
      return `runs whose ID token, from ${binding.issuer}, says ${Object.entries(claims).map(([name, value]) => `${name}=${value}`).join(', ')}`;
    default: {
      // A workload's binding (docs/design/workload-access.md), which `coffre trust` makes from PR 2 on, and says better there.
      const says = Object.entries(claims).map(([name, value]) => `${name}=${value}`).join(', ');
      return `${binding.profile} workloads${says === '' ? '' : ` whose proof says ${says}`}`;
    }
  }
}

/** What `coffre untrust` shows: the binding, the runs it would cut off, and, unless done, how to do it. */
export function describeRemoval(service: string, binding: BindingView, removed: boolean): string {
  const member = shownMember(service);
  const used = binding.lastUsedAt === null ? 'never used' : `last used ${binding.lastUsedAt.slice(0, 16).replace('T', ' ')}`;
  const head = `${binding.id}${binding.label === null ? '' : `  ${binding.label}`}  (added by ${binding.createdBy} ${binding.createdAt.slice(0, 10)}, ${used})`;
  const runs = runsOf(binding);
  return [
    removed ? `Removed ${member}'s trust binding ${head}` : `Would remove ${member}'s trust binding ${head}`,
    ...describeBinding(binding),
    removed
      ? `${runs.charAt(0).toUpperCase()}${runs.slice(1)} can no longer sign in as ${member}, and the credentials they hold have ended.`
      : `${runs.charAt(0).toUpperCase()}${runs.slice(1)} would no longer sign in as ${member}, and the credentials they hold would end at once.\nNothing changed. Re-run with --apply to remove it.`,
  ].join('\n') + '\n';
}

export function describeBindings(member: string, bindings: BindingView[]): string {
  if (bindings.length === 0) return `${shownMember(member)} trusts no CI runs: none signs in as it by OIDC\n`;
  const blocks = bindings.map((binding) => {
    const used = binding.lastUsedAt === null ? 'never used' : `last used ${binding.lastUsedAt.slice(0, 16).replace('T', ' ')}`;
    const head = `${binding.id}${binding.label === null ? '' : `  ${binding.label}`}  (added by ${binding.createdBy} ${binding.createdAt.slice(0, 10)}, ${used})`;
    return [head, ...describeBinding(binding)].join('\n');
  });
  return `${blocks.join('\n\n')}\n`;
}

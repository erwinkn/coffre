/**
 * `coffre trust` and `coffre untrust`: which CI runs may sign in as a
 * service, by the ID token their platform signs (docs/design/oidc.md).
 *
 *   coffre trust api-deploy --github acme/api --workflow deploy.yml --branch main
 *
 * builds the binding's claims from flags, looks up the IDs it names when
 * not given, and shows what the server would save: the claims in full, the
 * issuer and the keys it names. `--apply` saves it.
 */
import { CoffreError, type BindingPlan, type BindingView, type WorkloadIds } from '@coffre/client';
import { fullRef, GITHUB_EVENTS, GITLAB_PIPELINE_SOURCES, githubReusable, githubWorkflow, gitlabProject, type BindingClaims } from '@coffre/core/workloads';

export type TrustFlags = {
  github?: string;
  workflow?: string;
  reusable?: string;
  sha?: string;
  'any-repository'?: boolean;
  gitlab?: string;
  'gitlab-url'?: string;
  source?: string;
  issuer?: string;
  claim?: string[];
  branch?: string;
  tag?: string;
  event?: string;
  'repository-id'?: string;
  'owner-id'?: string;
  'project-id'?: string;
  'namespace-id'?: string;
};

export type BindingRequest = { profile: BindingPlan['profile']; issuer: string | null; claims: BindingClaims };

export type Lookup = (input: { github?: string; gitlab?: string; gitlabUrl?: string }) => Promise<WorkloadIds>;

export const TRUST_USAGE = `usage: coffre trust <service>                       its trust bindings
       coffre trust <service> --github <owner>/<repo> --workflow <file> (--branch <b> | --tag <t>)
                    [--event push,workflow_dispatch,schedule,release]
       coffre trust <service> --github <owner>/<repo> --reusable <owner>/<repo>/.github/workflows/<file>@<ref>
                    --sha <commit> (--branch <b> | --tag <t>) [--event …] [--any-repository]
       coffre trust <service> --gitlab <group>/<project> (--branch <b> | --tag <t>)
                    [--source push,web,schedule] [--gitlab-url <url>]
       coffre trust <service> --issuer <url> --claim sub=<subject> [--claim <name>=<value> …]
         IDs, when the lookup cannot see a private repository or project:
                    [--repository-id <n> --owner-id <n>] [--project-id <n> --namespace-id <n>]
         [--label <text>] [--replace <binding-id>] [--apply]
         --event and --source take one or more, each a binding of its own; push alone unless told
       coffre untrust <service> <binding-id> [--apply]   shows the CI runs it would cut off; --apply removes it`;

/** The service as a member: `api-deploy` or `token:api-deploy`. */
export function serviceMember(value: string): string {
  return value.startsWith('token:') ? value : `token:${value}`;
}

/** The binding the flags describe, its IDs looked up where they were not given. Throws a sentence. */
/** The flags as `coffre trust` takes them: --event and --source repeated, or a comma list. */
export type TrustArgs = Omit<TrustFlags, 'event' | 'source'> & { event?: string[]; source?: string[] };

/** `push,workflow_dispatch` and `--event schedule`, as one list, each once. */
function listOf(values: string[] | undefined): string[] | undefined {
  if (values === undefined) return undefined;
  return [...new Set(values.flatMap((value) => value.split(',')).map((value) => value.trim()).filter((value) => value !== ''))];
}

/**
 * The bindings the flags describe: one for each event (GitHub) or pipeline
 * source (GitLab) named, since a binding matches one; `push` unless told.
 * The repository's or project's IDs are looked up once.
 */
export async function bindingsFrom(flags: TrustArgs, lookup: Lookup): Promise<BindingRequest[]> {
  const [events, sources] = [listOf(flags.event), listOf(flags.source)];
  if (flags.github === undefined && events !== undefined) throw new Error('--event is a GitHub run\'s: --source names a GitLab pipeline\'s');
  if (flags.gitlab === undefined && sources !== undefined) throw new Error('--source is a GitLab pipeline\'s: --event names a GitHub run\'s');
  for (const event of events ?? []) {
    if (!(GITHUB_EVENTS as readonly string[]).includes(event)) throw new Error(`--event takes ${GITHUB_EVENTS.join(', ')}, not ${event}`);
  }
  for (const source of sources ?? []) {
    if (!(GITLAB_PIPELINE_SOURCES as readonly string[]).includes(source)) throw new Error(`--source takes ${GITLAB_PIPELINE_SOURCES.join(', ')}, not ${source}`);
  }
  let looked: Promise<WorkloadIds> | undefined;
  const once: Lookup = (input) => (looked ??= lookup(input));
  const each = flags.github !== undefined ? (events ?? ['push']).map((event) => ({ event })) : flags.gitlab !== undefined ? (sources ?? ['push']).map((source) => ({ source })) : [{}];
  const bindings: BindingRequest[] = [];
  // One after another: the first lookup's refusal is said once, not raced.
  const { event: _events, source: _sources, ...rest } = flags;
  for (const one of each) bindings.push(await bindingFrom({ ...rest, ...one }, once));
  return bindings;
}

/**
 * What the bindings accept, by the event (GitHub) or the pipeline source
 * (GitLab) that started the run, and the flag that adds the others, those
 * the ref allows: a schedule runs on a branch, a release at a tag.
 */
export function describeEvents(bindings: readonly Pick<BindingPlan, 'profile' | 'claims'>[]): string | null {
  const [first] = bindings;
  if (first === undefined || first.profile === 'custom') return null;
  const gitlab = first.profile === 'gitlab';
  const claim = gitlab ? 'pipeline_source' : 'event_name';
  const chosen = bindings.map(({ claims }) => claims[claim]!).filter((value) => value !== undefined);
  const tag = gitlab ? first.claims.ref_type === 'tag' : first.claims.ref?.startsWith('refs/tags/') === true;
  const all: readonly string[] = gitlab ? GITLAB_PIPELINE_SOURCES : GITHUB_EVENTS.filter((event) => (tag ? event !== 'schedule' : event !== 'release'));
  const others = all.filter((value) => !chosen.includes(value));
  const [what, flag] = gitlab ? ['pipelines', '--source'] : ['runs', '--event'];
  const accepts = `Accepts ${what} started by ${listing(chosen)}${chosen.length > 1 ? ', a binding each' : ''}.`;
  return others.length === 0 ? accepts : `${accepts} Not by ${listing(others, 'or')}: add them with ${flag}, as ${flag} ${[...chosen, ...others].join(',')}.`;
}

function listing(items: readonly string[], last: 'and' | 'or' = 'and'): string {
  return items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} ${last} ${items.at(-1)}`;
}

export async function bindingFrom(flags: TrustFlags, lookup: Lookup): Promise<BindingRequest> {
  const kinds = [flags.github !== undefined, flags.gitlab !== undefined, flags.issuer !== undefined].filter(Boolean).length;
  if (kinds !== 1) throw new Error('name one of --github, --gitlab or --issuer');
  if (flags.github !== undefined) return github(flags, lookup);
  if (flags.gitlab !== undefined) return gitlab(flags, lookup);
  return custom(flags);
}

function refFrom(flags: TrustFlags, form: 'full' | 'name'): { ref: string; type: 'branch' | 'tag' } {
  if ((flags.branch === undefined) === (flags.tag === undefined)) throw new Error('name one of --branch or --tag');
  const type = flags.branch !== undefined ? 'branch' : 'tag';
  const name = (flags.branch ?? flags.tag)!;
  return { ref: form === 'name' ? name : fullRef(type, name), type };
}

async function github(flags: TrustFlags, lookup: Lookup): Promise<BindingRequest> {
  const repository = flags.github!;
  const { ref } = refFrom(flags, 'full');
  const event = flags.event ?? 'push';
  const ids = async () => {
    if (flags['repository-id'] !== undefined && flags['owner-id'] !== undefined) {
      return { repositoryId: flags['repository-id'], ownerId: flags['owner-id'] };
    }
    let found: WorkloadIds;
    try {
      found = await lookup({ github: repository });
    } catch (error) {
      if (!(error instanceof CoffreError && error.status === 404)) throw error;
      throw new Error(
        `GitHub shows coffre nothing of ${repository}: it is private, or not there. Get its IDs with\n` +
          `  gh api repos/${repository} --jq '"--repository-id \\(.id) --owner-id \\(.owner.id)"'\n` +
          'and add the two flags it prints, --repository-id <n> --owner-id <n>, to this coffre trust.',
      );
    }
    if (!('repositoryId' in found)) throw new Error('not a GitHub repository');
    return found;
  };

  if (flags.reusable !== undefined) {
    if (flags.sha === undefined) throw new Error('a reusable workflow is trusted at one commit: --sha <commit>');
    const caller = flags.workflow === undefined ? undefined : { repository, workflow: flags.workflow };
    const called = { ref, event, called: flags.reusable, sha: flags.sha, caller };
    if (flags['any-repository'] === true) {
      if (flags['owner-id'] === undefined) throw new Error('--any-repository trusts every repository of the organization: name it by --owner-id <n>');
      return { ...githubReusable({ ...called, repositoryId: null, ownerId: flags['owner-id'] }), issuer: null };
    }
    const { repositoryId, ownerId } = await ids();
    return { ...githubReusable({ ...called, repositoryId, ownerId }), issuer: null };
  }
  if (flags.workflow === undefined) throw new Error('name the workflow file: --workflow deploy.yml');
  const { repositoryId, ownerId } = await ids();
  return { ...githubWorkflow({ repository, repositoryId, ownerId, workflow: flags.workflow, ref, event }), issuer: null };
}

async function gitlab(flags: TrustFlags, lookup: Lookup): Promise<BindingRequest> {
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
    ...gitlabProject({ namespaceId: ids.namespaceId, projectId: ids.projectId, refType: type, ref, source: flags.source ?? 'push' }),
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

/** A binding, or a plan for one, as lines: what it trusts, every claim in full. */
export function describeBinding(binding: Pick<BindingPlan, 'profile' | 'issuer' | 'jwksUri' | 'claims'>): string[] {
  const width = Math.max(0, ...Object.keys(binding.claims).map((name) => name.length));
  const claims = Object.entries(binding.claims).map(([name, value], i) => `  ${i === 0 ? 'claims ' : '       '}  ${name.padEnd(width)}  ${value}`);
  return [`  profile  ${binding.profile}`, `  issuer   ${binding.issuer}`, `  keys     ${binding.jwksUri}`, ...claims];
}

export function describePlan(member: string, plan: BindingPlan, applied: BindingView | null): string {
  const lines = [applied === null ? `Would trust CI runs to sign in as ${member}:` : `Trusted CI runs to sign in as ${member}, binding ${applied.id}:`];
  lines.push(...describeBinding(plan));
  for (const replaced of plan.replaces) {
    lines.push(`  replaces ${replaced.id}${replaced.why === 'keys_moved' ? ': the issuer moved its keys' : ''}`);
  }
  return `${lines.join('\n')}\n`;
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
  const claims = binding.claims;
  const on = (ref: string | undefined, how: string | undefined) => [ref === undefined ? null : `on ${refName(ref)}`, how === undefined ? null : `by ${how}`].filter(Boolean).join(', ');
  /** `acme/api/.github/workflows/deploy.yml@refs/heads/main` as its repository and workflow file. */
  const workflow = (ref: string) => /^([^/]+\/[^/]+)\/(?:\.github\/workflows\/)?(.+)@/.exec(ref);
  switch (binding.profile) {
    case 'github': {
      const [, repository, file] = workflow(claims.workflow_ref ?? '') ?? [];
      return `GitHub Actions runs of ${repository ?? `repository ${claims.repository_id}`}'s workflow ${file ?? '(any)'}, ${on(claims.ref, claims.event_name)}`;
    }
    case 'github-reusable':
    case 'github-reusable-organization': {
      const [, repository, file] = workflow(claims.workflow_ref ?? '') ?? [];
      const callers =
        binding.profile === 'github-reusable-organization'
          ? `any repository of owner ${claims.repository_owner_id}`
          : repository === undefined ? `repository ${claims.repository_id}` : `${repository}'s workflow ${file}`;
      const sha = claims.job_workflow_sha === undefined ? '' : ` at commit ${claims.job_workflow_sha.slice(0, 12)}`;
      return `GitHub Actions runs of ${callers} that call the reusable workflow ${claims.job_workflow_ref}${sha}, ${on(claims.ref, claims.event_name)}`;
    }
    case 'gitlab': {
      const ref = claims.ref === undefined ? undefined : `${claims.ref_type === 'tag' ? 'refs/tags' : 'refs/heads'}/${claims.ref}`;
      const where = binding.issuer === 'https://gitlab.com' ? '' : ` on ${binding.issuer}`;
      return `GitLab pipelines of project ${claims.project_id} (namespace ${claims.namespace_id})${where}, ${on(ref, claims.pipeline_source)}`;
    }
    case 'custom':
      return `runs whose ID token, from ${binding.issuer}, says ${Object.entries(claims).map(([name, value]) => `${name}=${value}`).join(', ')}`;
  }
}

/** What `coffre untrust` shows: the binding, the runs it would cut off, and, unless done, how to do it. */
export function describeRemoval(member: string, binding: BindingView, removed: boolean): string {
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
  if (bindings.length === 0) return `${member} trusts no CI runs\n`;
  const blocks = bindings.map((binding) => {
    const used = binding.lastUsedAt === null ? 'never used' : `last used ${binding.lastUsedAt.slice(0, 16).replace('T', ' ')}`;
    const head = `${binding.id}${binding.label === null ? '' : `  ${binding.label}`}  (added by ${binding.createdBy} ${binding.createdAt.slice(0, 10)}, ${used})`;
    return [head, ...describeBinding(binding)].join('\n');
  });
  return `${blocks.join('\n\n')}\n`;
}

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
import type { BindingPlan, BindingView, WorkloadIds } from '@coffre/client';
import { fullRef, githubReusable, githubWorkflow, gitlabProject, type BindingClaims } from '@coffre/core/workloads';

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
                    [--event push|workflow_dispatch|schedule|release]
       coffre trust <service> --github <owner>/<repo> --reusable <owner>/<repo>/.github/workflows/<file>@<ref>
                    --sha <commit> (--branch <b> | --tag <t>) [--event …] [--any-repository]
       coffre trust <service> --gitlab <group>/<project> (--branch <b> | --tag <t>)
                    [--source push|web|schedule] [--gitlab-url <url>]
       coffre trust <service> --issuer <url> --claim sub=<subject> [--claim <name>=<value> …]
         IDs, when the lookup cannot see a private repository or project:
                    [--repository-id <n> --owner-id <n>] [--project-id <n> --namespace-id <n>]
         [--label <text>] [--replace <binding-id>] [--apply]
       coffre untrust <service> <binding-id>`;

/** The service as a member: `api-deploy` or `token:api-deploy`. */
export function serviceMember(value: string): string {
  return value.startsWith('token:') ? value : `token:${value}`;
}

/** The binding the flags describe, its IDs looked up where they were not given. Throws a sentence. */
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
    try {
      const found = await lookup({ github: repository });
      if (!('repositoryId' in found)) throw new Error('not a GitHub repository');
      return found;
    } catch (error) {
      throw new Error(
        `${error instanceof Error ? error.message : String(error)}\n` +
          `  for a private repository, pass its IDs: gh api repos/${repository} --jq '"--repository-id \\(.id) --owner-id \\(.owner.id)"'`,
      );
    }
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
    try {
      const found = await lookup({ gitlab: project, gitlabUrl: flags['gitlab-url'] });
      if (!('projectId' in found)) throw new Error('not a GitLab project');
      ids = found;
    } catch (error) {
      throw new Error(
        `${error instanceof Error ? error.message : String(error)}\n` +
          `  for a private project, pass its IDs, from its page or: glab api projects/${encodeURIComponent(project)}` +
          ` (--project-id is .id, --namespace-id is .namespace.id)`,
      );
    }
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
  if (applied === null) lines.push('Run it again with --apply to save it.');
  return `${lines.join('\n')}\n`;
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

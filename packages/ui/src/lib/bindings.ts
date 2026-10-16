import { CoffreError, type BindingPlan, type BindingView } from '@coffre/client';
import { claimValues, fullRef, githubReusable, githubWorkflow, gitlabProject, type BindingClaims } from '@coffre/core/workloads';

/**
 * Trust bindings as the pages show and make them. A binding is its claims;
 * the presets in core fill them in, and the server holds every one to its
 * profile, whatever built it.
 */

/** A binding in a line: what it trusts, and at which ref. */
export function summary(binding: Pick<BindingView, 'profile' | 'issuer' | 'claims'>): { title: string; detail: string } {
  // Every claim is one value, but what started the run, which may be several.
  const claims = binding.claims as Record<string, string | undefined>;
  const events = claimValues(binding.claims.event_name).join(', ');
  const short = (ref: string | undefined) => ref?.replace(/^refs\/(heads|tags)\//, '') ?? '';
  const [workflow, at] = (claims.workflow_ref ?? '').split('@');
  const environment = claims.environment === undefined ? '' : `, in environment ${claims.environment}`;
  if (binding.profile === 'github') {
    const [owner, repository, , , file] = (workflow ?? '').split('/');
    return { title: `${owner}/${repository} · ${file}`, detail: `${events} at ${short(at)}${environment}` };
  }
  if (binding.profile.startsWith('github-reusable')) {
    const called = (claims.job_workflow_ref ?? '').split('@')[0]!.replace('/.github/workflows/', ' · ');
    const from = binding.profile === 'github-reusable-organization' ? 'any repository of the organization' : `repository ${claims.repository_id}`;
    return { title: `${called} @ ${claims.job_workflow_sha?.slice(0, 7)}`, detail: `${events} at ${short(claims.ref)}, from ${from}${environment}` };
  }
  if (binding.profile === 'gitlab') {
    return { title: `GitLab project ${claims.project_id}`, detail: `${claimValues(binding.claims.pipeline_source).join(', ')} at ${claims.ref_type} ${claims.ref}` };
  }
  return { title: new URL(binding.issuer).host, detail: `sub ${claims.sub}` };
}

/**
 * What a new binding reaches, in the Trust dialog: what the person chose in
 * the picker, or until they do, what the server makes it, which the request
 * leaves out: what the bindings it replaces reached, or all the account
 * holds. Once a plan says it, the picker shows it.
 */
export type ScopeChoice = { scope: BindingPlan['scope']; chosen: boolean };

/** The scope the dialog asks for: the person's, or none, for the server's own. */
export function askedScope(choice: ScopeChoice): { scope?: BindingPlan['scope'] } {
  return choice.chosen ? { scope: choice.scope } : {};
}

/** The picker once a plan came back: what the server would make, unless the person chose. */
export function planned(choice: ScopeChoice, plan: Pick<BindingPlan, 'scope'>): ScopeChoice {
  return choice.chosen ? choice : { scope: plan.scope, chosen: false };
}

export type Platform = 'github' | 'gitlab' | 'other';
export type RefKind = 'branch' | 'tag';

export const EMPTY_FORM = {
  platform: 'github' as Platform,
  label: '',
  // GitHub: the repository, or for a reusable workflow called from any of its repositories, the owner.
  reusable: false,
  repository: '',
  owner: '',
  // IDs typed in, for a repository GitHub does not show: the lookup's otherwise.
  typedIds: false,
  repositoryId: '',
  ownerId: '',
  workflow: '',
  environment: '',
  events: ['push'] as string[],
  refKind: 'branch' as RefKind,
  refName: 'main',
  called: '',
  sha: '',
  anyRepository: false,
  // GitLab
  gitlabUrl: '',
  project: '',
  projectId: '',
  namespaceId: '',
  sources: ['push'] as string[],
  // Any other issuer
  issuer: '',
  sub: '',
  extra: '',
};

export type Form = typeof EMPTY_FORM;

/**
 * A GitHub repository or owner by its IDs, under the name GitHub gives it
 * (`acme/api` for `Acme/API`), as its tokens spell it: what the lookup
 * found, or what a picker knows. An owner has no repository ID.
 */
export type GitHubIds = { github: string; repositoryId?: string; ownerId: string };

/** Who the GitHub form names: a repository, or for a reusable workflow called from any of its repositories, an owner. */
export function githubTarget(form: Form): { kind: 'repository' | 'owner'; name: string } {
  return form.reusable && form.anyRepository ? { kind: 'owner', name: form.owner.trim() } : { kind: 'repository', name: form.repository.trim() };
}

const GITHUB_NAME = { repository: /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/, owner: /^[A-Za-z0-9-]{1,39}$/ };

/** Whether a name is one GitHub could know: `acme/api` for a repository, `acme` for an owner; not `acme/` while it is typed. */
export function lookupable(target: { kind: 'repository' | 'owner'; name: string }): boolean {
  return GITHUB_NAME[target.kind].test(target.name);
}

/** How the dialog remembers a lookup, by name in any case: GitHub's names are case-insensitive. */
export const lookupKey = (name: string) => name.trim().toLowerCase();

/**
 * What GitHub said of a name: still asking; its IDs; nothing public there
 * (private, or not there), which is final; or no answer, such as when the
 * hour's lookups are spent, which asking again may change.
 */
export type GitHubLookup =
  | { state: 'looking' }
  | { state: 'found'; ids: GitHubIds }
  | { state: 'missing' | 'failed'; message: string };

/** The lookups a page made, by `lookupKey`: a Map, since `constructor` is an owner's name, not a lookup made. */
export type GitHubLookups = ReadonlyMap<string, GitHubLookup>;

/** What the page knows of the name the form names: nothing yet, or nothing to ask while it reads as no name. */
export function lookupOf(known: GitHubLookups, target: { kind: 'repository' | 'owner'; name: string }): GitHubLookup | null {
  return lookupable(target) ? (known.get(lookupKey(target.name)) ?? null) : null;
}

/**
 * The lookups with one more answer. IDs found always stand. Anything else
 * replaces only the lookup under way for that name: a failure arriving after
 * the name was found otherwise, as a repository's owner, changes nothing.
 */
export function answered(known: GitHubLookups, name: string, answer: GitHubLookup): GitHubLookups {
  const key = lookupKey(name);
  if (answer.state !== 'found' && answer.state !== 'looking' && known.get(key)?.state !== 'looking') return known;
  return new Map(known).set(key, answer);
}

/** A lookup that failed, as the dialog says it. */
export function lookupFailure(name: string, failure: unknown): GitHubLookup {
  if (failure instanceof CoffreError && failure.status === 404) return { state: 'missing', message: `GitHub shows nothing public at ${name}.` };
  if (failure instanceof CoffreError && failure.status === 429) {
    return { state: 'failed', message: "GitHub's hourly limit on lookups without signing in is spent. Enter the IDs, or try again later." };
  }
  return { state: 'failed', message: failure instanceof Error ? failure.message : 'GitHub could not be asked.' };
}

/**
 * The binding the form describes, or why it does not describe one yet. The
 * server checks the rest. A GitHub binding takes its IDs, and its
 * repository's name as GitHub spells it, from `found`, unless typed in.
 */
export function bindingOf(form: Form, found: GitHubIds | null = null): { profile: BindingPlan['profile']; issuer: string | null; claims: BindingClaims } {
  const needed = (value: string, what: string) => {
    if (value.trim() === '') throw new Error(`${what} is needed`);
    return value.trim();
  };
  const some = (values: string[], what: string) => {
    if (values.length === 0) throw new Error(`Choose at least one ${what}`);
    return values;
  };
  if (form.platform === 'github') {
    const target = githubTarget(form);
    const what = target.kind === 'owner' ? 'The organization' : 'The repository';
    needed(target.name, what);
    // Typed in, or found under the name now in the field: never IDs found for a name since changed.
    const ids: GitHubIds | null = form.typedIds
      ? {
          github: target.name,
          ...(target.kind === 'repository' ? { repositoryId: needed(form.repositoryId, "The repository's ID") } : {}),
          ownerId: needed(form.ownerId, "The owner's ID"),
        }
      : found !== null && lookupKey(found.github) === lookupKey(target.name) ? found : null;
    if (ids === null) throw new Error(`${what}'s IDs are needed: wait for GitHub to find ${target.name}, or enter them`);
    const ref = fullRef(form.refKind, needed(form.refName, form.refKind === 'branch' ? 'The branch' : 'The tag'));
    const environment = form.environment.trim() === '' ? undefined : form.environment.trim();
    const events = some(form.events, 'event');
    if (form.reusable) {
      const called = needed(form.called, 'The called workflow');
      const sha = needed(form.sha, "The called workflow's commit");
      if (form.anyRepository) return { ...githubReusable({ repositoryId: null, ownerId: ids.ownerId, ref, events, called, sha, environment }), issuer: null };
      const caller = form.workflow.trim() === '' ? undefined : { repository: ids.github, workflow: form.workflow.trim() };
      const repositoryId = needed(ids.repositoryId ?? '', "The repository's ID");
      return { ...githubReusable({ repositoryId, ownerId: ids.ownerId, ref, events, called, sha, caller, environment }), issuer: null };
    }
    return {
      ...githubWorkflow({
        repository: ids.github,
        repositoryId: needed(ids.repositoryId ?? '', "The repository's ID"),
        ownerId: ids.ownerId,
        workflow: needed(form.workflow, 'The workflow file'),
        ref,
        events,
        environment,
      }),
      issuer: null,
    };
  }
  if (form.platform === 'gitlab') {
    return {
      ...gitlabProject({
        namespaceId: needed(form.namespaceId, "The namespace's ID"),
        projectId: needed(form.projectId, "The project's ID"),
        refType: form.refKind,
        ref: needed(form.refName, form.refKind === 'branch' ? 'The branch' : 'The tag'),
        sources: some(form.sources, 'pipeline source'),
      }),
      issuer: form.gitlabUrl.trim() === '' ? null : form.gitlabUrl.trim(),
    };
  }
  const claims: BindingClaims = { sub: needed(form.sub, 'The subject') };
  for (const line of form.extra.split('\n').map((each) => each.trim()).filter((each) => each !== '')) {
    const at = line.indexOf('=');
    if (at <= 0) throw new Error(`"${line}" is not <claim>=<value>`);
    claims[line.slice(0, at).trim()] = line.slice(at + 1).trim();
  }
  return { profile: 'custom', issuer: needed(form.issuer, 'The issuer'), claims };
}


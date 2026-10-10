import type { BindingPlan, BindingView } from '@coffre/client';
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
  if (binding.profile === 'github') {
    const [owner, repository, , , file] = (workflow ?? '').split('/');
    return { title: `${owner}/${repository} · ${file}`, detail: `${events} at ${short(at)}` };
  }
  if (binding.profile.startsWith('github-reusable')) {
    const called = (claims.job_workflow_ref ?? '').split('@')[0]!.replace('/.github/workflows/', ' · ');
    const from = binding.profile === 'github-reusable-organization' ? 'any repository of the organization' : `repository ${claims.repository_id}`;
    return { title: `${called} @ ${claims.job_workflow_sha?.slice(0, 7)}`, detail: `${events} at ${short(claims.ref)}, from ${from}` };
  }
  if (binding.profile === 'gitlab') {
    return { title: `GitLab project ${claims.project_id}`, detail: `${claimValues(binding.claims.pipeline_source).join(', ')} at ${claims.ref_type} ${claims.ref}` };
  }
  return { title: new URL(binding.issuer).host, detail: `sub ${claims.sub}` };
}


export type Platform = 'github' | 'gitlab' | 'other';
export type RefKind = 'branch' | 'tag';

export const EMPTY_FORM = {
  platform: 'github' as Platform,
  label: '',
  // GitHub
  reusable: false,
  repository: '',
  repositoryId: '',
  ownerId: '',
  workflow: '',
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

/** The binding the form describes, or why it does not describe one yet. The server checks the rest. */
export function bindingOf(form: Form): { profile: BindingPlan['profile']; issuer: string | null; claims: BindingClaims } {
  const needed = (value: string, what: string) => {
    if (value.trim() === '') throw new Error(`${what} is needed`);
    return value.trim();
  };
  const some = (values: string[], what: string) => {
    if (values.length === 0) throw new Error(`Choose at least one ${what}`);
    return values;
  };
  if (form.platform === 'github') {
    const ref = fullRef(form.refKind, needed(form.refName, form.refKind === 'branch' ? 'The branch' : 'The tag'));
    if (form.reusable) {
      const called = needed(form.called, 'The called workflow');
      const sha = needed(form.sha, "The called workflow's commit");
      const ownerId = needed(form.ownerId, "The owner's ID");
      const caller = form.workflow.trim() === '' ? undefined : { repository: needed(form.repository, 'The repository'), workflow: form.workflow.trim() };
      const repositoryId = form.anyRepository ? null : needed(form.repositoryId, "The repository's ID");
      return { ...githubReusable({ repositoryId, ownerId, ref, events: some(form.events, 'event'), called, sha, caller }), issuer: null };
    }
    return {
      ...githubWorkflow({
        repository: needed(form.repository, 'The repository'),
        repositoryId: needed(form.repositoryId, "The repository's ID"),
        ownerId: needed(form.ownerId, "The owner's ID"),
        workflow: needed(form.workflow, 'The workflow file'),
        ref,
        events: some(form.events, 'event'),
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


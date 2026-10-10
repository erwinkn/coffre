/**
 * Trust bindings: which CI runs may sign in as a service, by the ID token
 * their platform signs for them (docs/design/oidc.md).
 *
 * A binding names a profile, an issuer, and claims a token must carry, each
 * a top-level string matched exactly. The event that started the run may
 * be any of several: a list. The profile sets the minimum: the server
 * refuses a binding that lacks a claim its profile requires, from the UI,
 * the CLI or the API alike. Say a service is bound to `ci.yml` of
 * `acme/api`, pushed or dispatched on `main`, or run for a pull request
 * into `main`:
 *
 *   { profile: 'github', issuer: 'https://token.actions.githubusercontent.com',
 *     claims: { repository_owner_id: '9919', repository_id: '41532',
 *               workflow_ref: 'acme/api/.github/workflows/ci.yml@refs/heads/main',
 *               ref: 'refs/heads/main',
 *               event_name: ['pull_request', 'push', 'workflow_dispatch'] } }
 */

export const GITHUB_ISSUER = 'https://token.actions.githubusercontent.com';
export const GITLAB_ISSUER = 'https://gitlab.com';

/**
 * - `github`: a workflow of the repository.
 * - `github-reusable`: a reusable workflow, pinned to one commit, called from
 *   one repository at one ref.
 * - `github-reusable-organization`: the same, called from any repository of
 *   the organization: an explicit choice, never what a missing claim means.
 * - `gitlab`: a project's pipelines, outside merge requests.
 * - `custom`: any other issuer, by its subject, which the owner vouches for.
 */
export type WorkloadProfile = 'github' | 'github-reusable' | 'github-reusable-organization' | 'gitlab' | 'custom';

export const WORKLOAD_PROFILES: readonly WorkloadProfile[] = [
  'github',
  'github-reusable',
  'github-reusable-organization',
  'gitlab',
  'custom',
];

/** The claims each profile requires; a binding may add more, to narrow it. */
export const REQUIRED_CLAIMS: Record<WorkloadProfile, readonly string[]> = {
  github: ['repository_owner_id', 'repository_id', 'workflow_ref', 'ref', 'event_name'],
  'github-reusable': ['repository_owner_id', 'repository_id', 'ref', 'event_name', 'job_workflow_ref', 'job_workflow_sha'],
  'github-reusable-organization': ['repository_owner_id', 'ref', 'event_name', 'job_workflow_ref', 'job_workflow_sha'],
  gitlab: ['namespace_id', 'project_id', 'ref_type', 'ref', 'pipeline_source'],
  custom: ['sub'],
};

/**
 * The events a GitHub binding may trust. The first four are started by
 * someone with write access, at the ref the binding names. The last two
 * can run code nobody reviewed, so the owner opts in to each:
 *
 * - `pull_request` runs the pull request's own code and workflow file, at
 *   `refs/pull/<n>/merge`; a binding matches it by the branch it merges
 *   into. Forks get no ID token, unless the repository sends write tokens
 *   to their pull requests (a setting of private repositories), so this
 *   trusts whoever can push a branch to the repository.
 * - `workflow_run` runs the default branch's workflow, but a fork's pull
 *   request can start it: the run is as safe as what it does with the
 *   code and artifacts of the run that started it.
 *
 * `pull_request_target` and the rest are refused, even when their ref
 * happens to match: they exist to act on anyone's pull request, with the
 * base repository's tokens.
 */
export const GITHUB_EVENTS = ['push', 'workflow_dispatch', 'schedule', 'release', 'pull_request', 'workflow_run'] as const;

/**
 * What trusting each of the last two events exposes, as the UI, the CLI and
 * the approval page say it when one is chosen.
 */
export const EVENT_EXPOSURE: Readonly<Record<string, string>> = {
  pull_request:
    'Anyone who can push a branch to the repository can open a pull request and run their own code as this service account, unreviewed. ' +
    'Pull requests from forks get no ID token, unless the repository sends them write tokens.',
  workflow_run:
    "A fork's pull request can start workflow_run. The workflow comes from the default branch, so this is safe unless it runs code or artifacts from the run that started it.",
};

/** Pipelines that run the project's own code, at its own ref: never a merge request's. */
export const GITLAB_PIPELINE_SOURCES = ['push', 'web', 'schedule'] as const;

/** The claim that says what started the run, which a binding may name several values of, and why the others are refused. */
const GITHUB_EVENT = { name: 'event_name', values: GITHUB_EVENTS, why: "other events can run a stranger's code" };
const EVENT_CLAIM: Record<WorkloadProfile, { name: string; values: readonly string[]; why: string } | null> = {
  github: GITHUB_EVENT,
  'github-reusable': GITHUB_EVENT,
  'github-reusable-organization': GITHUB_EVENT,
  gitlab: { name: 'pipeline_source', values: GITLAB_PIPELINE_SOURCES, why: 'merge-request pipelines name another project' },
  custom: null,
};

/** At most this many live bindings per service, and claims per binding. */
export const MAX_BINDINGS = 16;
export const MAX_CLAIMS = 16;
/** The longest claim value, in bytes. */
export const MAX_CLAIM_BYTES = 256;

/** Claims a binding never names: the issuer is its own field, and the audience, times and ID are the exchange's. */
const RESERVED = new Set(['iss', 'aud', 'exp', 'iat', 'nbf', 'jti']);
const CLAIM_NAME = /^[A-Za-z0-9_.:/-]{1,64}$/;
const DIGITS = /^[1-9][0-9]{0,19}$/;
const SHA = /^[0-9a-f]{40}$/;
const REF = /^refs\/(heads|tags)\/\S{1,200}$/;
const WORKFLOW = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/\.github\/workflows\/[^@\s]+\.ya?ml@\S+$/;

/** A claim a binding names: one value, or, for what started the run, any of several. */
export type ClaimValue = string | string[];
export type BindingClaims = Record<string, ClaimValue>;

/** What makes a binding, checked: its profile, its issuer as a URL, and its claims, sorted. */
export type BindingPolicy = { profile: WorkloadProfile; issuer: string; claims: BindingClaims };

/** A binding that breaks a rule, said so an owner can fix it. */
export class BindingInvalid extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BindingInvalid';
  }
}

/** The profile an issuer must use, for the issuers coffre knows: github.com's for GitHub, gitlab.com's for GitLab. */
function forcedProfiles(issuer: string): readonly WorkloadProfile[] | null {
  if (issuer === GITHUB_ISSUER) return ['github', 'github-reusable', 'github-reusable-organization'];
  if (issuer === GITLAB_ISSUER) return ['gitlab'];
  return null;
}

/** The issuer a profile means when none is given: github.com's or gitlab.com's. A GitHub Enterprise Server or a self-managed GitLab names its own. */
export function defaultIssuer(profile: WorkloadProfile): string | null {
  if (profile === 'gitlab') return GITLAB_ISSUER;
  return profile === 'custom' ? null : GITHUB_ISSUER;
}

/**
 * Check a binding against its profile, and return it as stored: the
 * issuer as given, the claims sorted by name. Throws `BindingInvalid`.
 */
export function checkBinding(
  input: { profile: string; issuer: string | null; claims: Record<string, unknown> },
  options: { allowLoopback?: boolean } = {},
): BindingPolicy {
  const profile = input.profile as WorkloadProfile;
  if (!WORKLOAD_PROFILES.includes(profile)) {
    throw new BindingInvalid(`unknown profile "${input.profile}": one of ${WORKLOAD_PROFILES.join(', ')}`);
  }
  const issuer = input.issuer ?? defaultIssuer(profile);
  if (issuer === null) throw new BindingInvalid('a custom binding names its issuer');
  checkFetchUrl(issuer, 'the issuer', { allowLoopback: options.allowLoopback, path: true, query: false });
  const forced = forcedProfiles(issuer);
  if (forced !== null && !forced.includes(profile)) {
    throw new BindingInvalid(`${issuer} signs only for the ${forced[0]} profile${forced.length > 1 ? 's' : ''}`);
  }

  const entries = Object.entries(input.claims);
  if (entries.length > MAX_CLAIMS) throw new BindingInvalid(`a binding names at most ${MAX_CLAIMS} claims`);
  const event = EVENT_CLAIM[profile];
  const claims: BindingClaims = {};
  for (const [name, value] of entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    if (!CLAIM_NAME.test(name)) throw new BindingInvalid(`"${name}" is not a claim name a binding can match`);
    if (RESERVED.has(name)) throw new BindingInvalid(`a binding never names "${name}": the exchange checks it`);
    if (name === event?.name) {
      // Stored once each, in the profile's order, and a single one as a plain value.
      const given: unknown[] = Array.isArray(value) ? value : [value];
      if (given.length === 0 || given.some((each) => !event.values.includes(each as string))) {
        throw new BindingInvalid(`${name} must be one or more of ${event.values.join(', ')}: ${event.why}`);
      }
      const values = event.values.filter((each) => given.includes(each));
      claims[name] = values.length === 1 ? values[0]! : values;
      continue;
    }
    if (typeof value !== 'string' || value.length === 0) {
      throw new BindingInvalid(`claim ${name} must be a nonempty string${Array.isArray(value) && event !== null ? `: only ${event.name} lists several` : ''}`);
    }
    if (new TextEncoder().encode(value).length > MAX_CLAIM_BYTES) {
      throw new BindingInvalid(`claim ${name} is longer than ${MAX_CLAIM_BYTES} bytes`);
    }
    claims[name] = value;
  }
  const missing = REQUIRED_CLAIMS[profile].filter((name) => claims[name] === undefined);
  if (missing.length > 0) throw new BindingInvalid(`the ${profile} profile requires ${missing.join(', ')}`);
  if (profile === 'github-reusable-organization' && claims.repository_id !== undefined) {
    throw new BindingInvalid('a binding for any repository of the organization names no repository_id: use github-reusable');
  }

  if (profile.startsWith('github')) checkGitHub(profile, claims);
  if (profile === 'gitlab') checkGitLab(claims);
  return { profile, issuer, claims };
}

/** A claim's values, one or several. */
export function claimValues(value: ClaimValue | undefined): string[] {
  return value === undefined ? [] : typeof value === 'string' ? [value] : value;
}

/** What a ref must be for each event: the branch or tag it runs at, or for a pull request, the branch it merges into. */
const EVENT_REFS: Record<string, { prefix: string; why: string }> = {
  release: { prefix: 'refs/tags/', why: 'a release runs at its tag: refs/tags/<tag>' },
  schedule: { prefix: 'refs/heads/', why: 'a schedule runs on the default branch: refs/heads/<branch>' },
  workflow_run: { prefix: 'refs/heads/', why: 'a workflow_run runs on the default branch: refs/heads/<branch>' },
  pull_request: { prefix: 'refs/heads/', why: 'a pull request matches by the branch it merges into: refs/heads/<branch>' },
};

function checkGitHub(profile: WorkloadProfile, claims: BindingClaims): void {
  for (const id of ['repository_owner_id', 'repository_id']) {
    const value = claims[id];
    if (value !== undefined && !DIGITS.test(value as string)) throw new BindingInvalid(`${id} is GitHub's numeric ID, not a name`);
  }
  const events = claimValues(claims.event_name);
  const ref = claims.ref as string;
  if (!REF.test(ref)) throw new BindingInvalid('ref is a full ref: refs/heads/<branch> or refs/tags/<tag>');
  for (const event of events) {
    const rule = EVENT_REFS[event];
    if (rule !== undefined && !ref.startsWith(rule.prefix)) throw new BindingInvalid(rule.why);
  }
  const workflow = claims.workflow_ref as string | undefined;
  if (profile === 'github') {
    // The workflow file at the binding's ref, which a pull request's run is matched at too.
    if (!WORKFLOW.test(workflow!) || !workflow!.endsWith(`@${ref}`)) {
      throw new BindingInvalid('workflow_ref is <owner>/<repository>/.github/workflows/<file>@<ref>, at the binding\'s ref');
    }
    return;
  }
  // A reusable workflow, pinned to one commit: its path can be reused and its branch changed.
  if (!WORKFLOW.test(claims.job_workflow_ref as string)) {
    throw new BindingInvalid('job_workflow_ref is <owner>/<repository>/.github/workflows/<file>@<ref>');
  }
  if (!SHA.test(claims.job_workflow_sha as string)) throw new BindingInvalid('job_workflow_sha is the called workflow\'s full commit SHA');
  if (workflow !== undefined && !WORKFLOW.test(workflow)) {
    throw new BindingInvalid('workflow_ref, which narrows the binding to one caller, is <owner>/<repository>/.github/workflows/<file>@<ref>');
  }
}

function checkGitLab(claims: BindingClaims): void {
  for (const id of ['namespace_id', 'project_id']) {
    if (!DIGITS.test(claims[id] as string)) throw new BindingInvalid(`${id} is GitLab's numeric ID, not a path`);
  }
  if (claims.ref_type !== 'branch' && claims.ref_type !== 'tag') throw new BindingInvalid('ref_type is branch or tag');
  if ((claims.ref as string).startsWith('refs/')) throw new BindingInvalid('GitLab\'s ref is the branch or tag name, without refs/');
}

/**
 * The claims of a verified token that differ from what a binding expects,
 * by name: none when it matches. A claim matches when the token carries its
 * value, or one of its values. A GitHub `pull_request` run, at
 * `refs/pull/<n>/merge`, counts as a run at the branch it merges into: its
 * `ref`, and the ref its `workflow_ref` ends in, are read as
 * `refs/heads/<base_ref>`.
 */
export function differingClaims(profile: WorkloadProfile, expected: BindingClaims, token: Record<string, unknown>): string[] {
  const claims = profile.startsWith('github') ? atBaseBranch(token) : token;
  return Object.entries(expected)
    .filter(([name, value]) => {
      const actual = claims[name];
      return typeof actual !== 'string' || !claimValues(value).includes(actual);
    })
    .map(([name]) => name);
}

function atBaseBranch(claims: Record<string, unknown>): Record<string, unknown> {
  const { event_name: event, ref, base_ref: base, workflow_ref: workflow } = claims;
  if (event !== 'pull_request' || typeof ref !== 'string' || typeof base !== 'string' || base === '') return claims;
  const at = `refs/heads/${base}`;
  const file = typeof workflow === 'string' && workflow.endsWith(`@${ref}`) ? `${workflow.slice(0, -ref.length)}${at}` : workflow;
  return { ...claims, ref: at, workflow_ref: file };
}

/** The claims as the MAC and the database hold them: JSON, sorted by name. */
export function canonicalClaims(claims: BindingClaims): string {
  return JSON.stringify(Object.fromEntries(Object.entries(claims).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))));
}

/**
 * A URL coffre may fetch for a binding: an issuer, or the keys its
 * discovery names. `https` on port 443, a host name rather than an address,
 * and nothing that names this machine or its network. Loopback over plain
 * HTTP only where the deployment allows it, for the dev IdP. Where the name
 * resolves is checked again when connecting, on Node (`addresses.ts` in the
 * server).
 */
export function checkFetchUrl(
  value: string,
  what: string,
  options: { allowLoopback?: boolean; path: boolean; query: boolean },
): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new BindingInvalid(`${what} is not a URL`);
  }
  if (url.username !== '' || url.password !== '') throw new BindingInvalid(`${what} carries no user or password`);
  if (url.hash !== '' || (!options.query && url.search !== '')) throw new BindingInvalid(`${what} has no ${options.query ? 'fragment' : 'query or fragment'}`);
  if (!options.path && url.pathname !== '/') throw new BindingInvalid(`${what} has no path`);
  // Tokens name their issuer exactly, so it is stored as written, written as a URL is.
  if (url.href !== value && url.href !== `${value}/`) throw new BindingInvalid(`${what} must be written as a plain URL: ${url.href}`);
  const host = url.hostname;
  const loopback = host === '127.0.0.1' || host === 'localhost' || host === '[::1]';
  if (options.allowLoopback === true && loopback) return url;
  if (url.protocol !== 'https:') throw new BindingInvalid(`${what} must use https`);
  if (url.port !== '' && url.port !== '443') throw new BindingInvalid(`${what} must use port 443`);
  if (/^[0-9.]+$/.test(host) || host.startsWith('[')) throw new BindingInvalid(`${what} names a host, not an IP address`);
  if (!host.includes('.') || /(^|\.)(localhost|local|internal|localdomain|home\.arpa)$/.test(host)) {
    throw new BindingInvalid(`${what} must be a public host name`);
  }
  return url;
}

// --- presets -----------------------------------------------------------------
//
// What the UI's forms and the CLI's flags ask for, and the claims they fill
// in. They decide nothing: `checkBinding`, on the server, holds the result
// to its profile, whoever built it.

/** `refs/heads/main`, or `refs/tags/v1`, as GitHub names a ref. */
export function fullRef(kind: 'branch' | 'tag', name: string): string {
  return `refs/${kind === 'branch' ? 'heads' : 'tags'}/${name}`;
}

/** The GitHub events a binding at a branch, or at a tag, may name. */
export function githubEventsAt(kind: 'branch' | 'tag'): string[] {
  return GITHUB_EVENTS.filter((event) => EVENT_REFS[event] === undefined || EVENT_REFS[event].prefix === fullRef(kind, ''));
}

/** A workflow file at a ref, as GitHub's tokens name it: `acme/api/.github/workflows/deploy.yml@refs/heads/main`. */
export function workflowRef(repository: string, file: string, ref: string): string {
  return `${repository}/.github/workflows/${file.replace(/^\.github\/workflows\//, '')}@${ref}`;
}

/**
 * What started the run, as the presets take it: `event` (`source`, for
 * GitLab), the one value 0.4.6's presets took, or `events` (`sources`), any
 * of several. Naming both, or neither, is a type error and, for a caller the
 * types do not reach, a `BindingInvalid` at run time: a preset never guesses
 * which one was meant.
 */
export type Starts<One extends string, Many extends string> =
  | ({ [K in One]: string } & { [K in Many]?: never })
  | ({ [K in Many]: string[] } & { [K in One]?: never });

function started(input: Record<string, unknown>, one: string, many: string): ClaimValue {
  const single = input[one];
  const list = input[many];
  if (single !== undefined && list !== undefined) throw new BindingInvalid(`name ${one} or ${many}, not both`);
  // As 0.4.6 made it: the plain value, so a one-event binding is the same claim either way.
  if (single !== undefined) return single as string;
  if (list === undefined) throw new BindingInvalid(`name ${one} or ${many}`);
  return list as string[];
}

/** A workflow of the repository, run at `ref` by any of `events`; a pull request, by the branch it merges into. */
export function githubWorkflow(input: {
  repository: string;
  repositoryId: string;
  ownerId: string;
  workflow: string;
  ref: string;
} & Starts<'event', 'events'>): Omit<BindingPolicy, 'issuer'> {
  return {
    profile: 'github',
    claims: {
      repository_owner_id: input.ownerId,
      repository_id: input.repositoryId,
      workflow_ref: workflowRef(input.repository, input.workflow, input.ref),
      ref: input.ref,
      event_name: started(input, 'event', 'events'),
    },
  };
}

/**
 * A reusable workflow at one commit, called at `ref`: from one repository,
 * or, with `repositoryId` null, from any repository of the organization. A
 * `caller` workflow narrows it to one calling workflow.
 */
export function githubReusable(input: {
  repositoryId: string | null;
  ownerId: string;
  ref: string;
  called: string;
  sha: string;
  caller?: { repository: string; workflow: string };
} & Starts<'event', 'events'>): Omit<BindingPolicy, 'issuer'> {
  const claims: BindingClaims = {
    repository_owner_id: input.ownerId,
    ...(input.repositoryId === null ? {} : { repository_id: input.repositoryId }),
    ref: input.ref,
    event_name: started(input, 'event', 'events'),
    job_workflow_ref: input.called,
    job_workflow_sha: input.sha,
  };
  if (input.caller !== undefined) claims.workflow_ref = workflowRef(input.caller.repository, input.caller.workflow, input.ref);
  return { profile: input.repositoryId === null ? 'github-reusable-organization' : 'github-reusable', claims };
}

/** A GitLab project's pipelines from any of `sources`, at a branch or tag. */
export function gitlabProject(input: {
  namespaceId: string;
  projectId: string;
  refType: 'branch' | 'tag';
  ref: string;
} & Starts<'source', 'sources'>): Omit<BindingPolicy, 'issuer'> {
  return {
    profile: 'gitlab',
    claims: {
      namespace_id: input.namespaceId,
      project_id: input.projectId,
      ref_type: input.refType,
      ref: input.ref,
      pipeline_source: started(input, 'source', 'sources'),
    },
  };
}

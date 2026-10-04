/**
 * Trust bindings: which CI runs may sign in as a service, by the ID token
 * their platform signs for them (docs/design/oidc.md).
 *
 * A binding names a profile, an issuer, and claims a token must carry, each
 * a top-level string matched exactly. The profile sets the minimum: the
 * server refuses a binding that lacks a claim its profile requires, from the
 * UI, the CLI or the API alike. Say a service is bound to `deploy.yml`,
 * pushed to `main` of `acme/api`:
 *
 *   { profile: 'github', issuer: 'https://token.actions.githubusercontent.com',
 *     claims: { repository_owner_id: '9919', repository_id: '41532',
 *               workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main',
 *               ref: 'refs/heads/main', event_name: 'push' } }
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
 * Events triggered by someone with write access, at a ref the binding names
 * exactly. `pull_request`, `pull_request_target`, `workflow_run` and the
 * rest are refused, even when their ref happens to match: their runs can
 * carry a stranger's code.
 */
export const GITHUB_EVENTS = ['push', 'workflow_dispatch', 'schedule', 'release'] as const;

/** Pipelines that run the project's own code, at its own ref: never a merge request's. */
export const GITLAB_PIPELINE_SOURCES = ['push', 'web', 'schedule'] as const;

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

export type BindingClaims = Record<string, string>;

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
  const claims: BindingClaims = {};
  for (const [name, value] of entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    if (!CLAIM_NAME.test(name)) throw new BindingInvalid(`"${name}" is not a claim name a binding can match`);
    if (RESERVED.has(name)) throw new BindingInvalid(`a binding never names "${name}": the exchange checks it`);
    if (typeof value !== 'string' || value.length === 0) throw new BindingInvalid(`claim ${name} must be a nonempty string`);
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

function checkGitHub(profile: WorkloadProfile, claims: BindingClaims): void {
  for (const id of ['repository_owner_id', 'repository_id']) {
    if (claims[id] !== undefined && !DIGITS.test(claims[id])) throw new BindingInvalid(`${id} is GitHub's numeric ID, not a name`);
  }
  const event = claims.event_name;
  if (!(GITHUB_EVENTS as readonly string[]).includes(event)) {
    throw new BindingInvalid(`event_name must be one of ${GITHUB_EVENTS.join(', ')}: other events can run a stranger's code`);
  }
  const ref = claims.ref;
  if (!REF.test(ref)) throw new BindingInvalid('ref is a full ref: refs/heads/<branch> or refs/tags/<tag>');
  if (event === 'release' && !ref.startsWith('refs/tags/')) throw new BindingInvalid('a release runs at its tag: refs/tags/<tag>');
  if (event === 'schedule' && !ref.startsWith('refs/heads/')) throw new BindingInvalid('a schedule runs on the default branch: refs/heads/<branch>');
  if (profile === 'github') {
    // The workflow file at the ref it ran from, which for these events is the run's ref.
    if (!WORKFLOW.test(claims.workflow_ref) || !claims.workflow_ref.endsWith(`@${ref}`)) {
      throw new BindingInvalid('workflow_ref is <owner>/<repository>/.github/workflows/<file>@<ref>, at the binding\'s ref');
    }
    return;
  }
  // A reusable workflow, pinned to one commit: its path can be reused and its branch changed.
  if (!WORKFLOW.test(claims.job_workflow_ref)) {
    throw new BindingInvalid('job_workflow_ref is <owner>/<repository>/.github/workflows/<file>@<ref>');
  }
  if (!SHA.test(claims.job_workflow_sha)) throw new BindingInvalid('job_workflow_sha is the called workflow\'s full commit SHA');
  if (claims.workflow_ref !== undefined && !WORKFLOW.test(claims.workflow_ref)) {
    throw new BindingInvalid('workflow_ref, which narrows the binding to one caller, is <owner>/<repository>/.github/workflows/<file>@<ref>');
  }
}

function checkGitLab(claims: BindingClaims): void {
  for (const id of ['namespace_id', 'project_id']) {
    if (!DIGITS.test(claims[id])) throw new BindingInvalid(`${id} is GitLab's numeric ID, not a path`);
  }
  if (claims.ref_type !== 'branch' && claims.ref_type !== 'tag') throw new BindingInvalid('ref_type is branch or tag');
  if (claims.ref.startsWith('refs/')) throw new BindingInvalid('GitLab\'s ref is the branch or tag name, without refs/');
  if (!(GITLAB_PIPELINE_SOURCES as readonly string[]).includes(claims.pipeline_source)) {
    throw new BindingInvalid(`pipeline_source must be one of ${GITLAB_PIPELINE_SOURCES.join(', ')}: merge-request pipelines name another project`);
  }
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

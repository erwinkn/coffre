/**
 * Trust bindings: which CI runs may sign in as a service, by the ID token
 * their platform signs for them (docs/design/oidc.md).
 *
 * A binding names a profile, an issuer, and claims a token must carry, each
 * a string matched exactly, at the top of the token or nested in it
 * (`claimAt`). The event that started the run may be any of several: a
 * list. The profile sets the minimum: the server refuses a binding that
 * lacks a claim its profile requires, from the UI, the CLI or the API
 * alike. Say a service is bound to `ci.yml` of
 * `acme/api`, pushed or dispatched on `main`, or run for a pull request
 * into `main`:
 *
 *   { profile: 'github', issuer: 'https://token.actions.githubusercontent.com',
 *     claims: { repository_owner_id: '9919', repository_id: '41532',
 *               workflow_ref: 'acme/api/.github/workflows/ci.yml@refs/heads/main',
 *               ref: 'refs/heads/main',
 *               event_name: ['pull_request', 'push', 'workflow_dispatch'] } }
 *
 * A GitHub binding may also name `environment`, the GitHub environment its
 * job runs in, so that the environment's protection rules (its required
 * reviewers, the branches it deploys) gate every run that signs in. GitHub
 * changes `sub` for such a job, `repo:acme/api:environment:production`, but
 * no GitHub binding matches `sub`: `ref` and `workflow_ref` stay as they were.
 */

import { shownMember } from '../schemas.ts';
import type { Constraints } from './constraints.ts';

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
 *
 * Then the platforms of docs/design/workload-access.md, section 4, which
 * sign in at `/api/auth/workload` alone, for a key-bound session:
 *
 * - `kubernetes`, `gcp`, `azure`, `fly`, `vercel`: the platform's ID token.
 * - `aws`: a signed `GetCallerIdentity`, bound to the session's key.
 * - `enrollment`: a code CI mints, for platforms that sign nothing.
 * - `cloudflare`: a service binding's `props`, which no request carries.
 */
export type WorkloadProfile =
  | 'github'
  | 'github-reusable'
  | 'github-reusable-organization'
  | 'gitlab'
  | 'custom'
  | 'kubernetes'
  | 'gcp'
  | 'azure'
  | 'fly'
  | 'vercel'
  | 'aws'
  | 'enrollment'
  | 'cloudflare';

export const WORKLOAD_PROFILES: readonly WorkloadProfile[] = [
  'github',
  'github-reusable',
  'github-reusable-organization',
  'gitlab',
  'custom',
  'kubernetes',
  'gcp',
  'azure',
  'fly',
  'vercel',
  'aws',
  'enrollment',
  'cloudflare',
];

/**
 * The profiles `/api/auth/oidc` exchanges for a bearer credential, and only
 * on a binding with no policy: a platform's token bought at that route reads
 * values, so a binding made for a key-bound session, policy and all, is never
 * one it matches. Every binding of another profile carries a policy.
 */
export const BEARER_PROFILES = ['github', 'github-reusable', 'github-reusable-organization', 'gitlab', 'custom'] as const satisfies readonly WorkloadProfile[];
export type BearerProfile = (typeof BEARER_PROFILES)[number];

/** Whether a binding's profile is one `/api/auth/oidc` takes; it takes the binding only if it has no policy, too. */
export function isBearerProfile(profile: string): profile is BearerProfile {
  return (BEARER_PROFILES as readonly string[]).includes(profile);
}

/** The profiles whose proof is no ID token: their binding's issuer is this URN, which no token names, and its keys none. */
export const PROFILE_URNS = {
  aws: 'urn:coffre:aws',
  enrollment: 'urn:coffre:enrollment',
  cloudflare: 'urn:coffre:cloudflare',
} as const satisfies Partial<Record<WorkloadProfile, string>>;

/** The profiles whose proof is a platform's ID token. */
export const OIDC_PROFILES: readonly WorkloadProfile[] = WORKLOAD_PROFILES.filter((profile) => !Object.hasOwn(PROFILE_URNS, profile));

/**
 * Tokens a platform hands out again, the same one to every replica and
 * restart for its lifetime: a managed identity's. Spending one would
 * refuse them, so none is spent: it is a bearer until its own `exp`, which
 * ends the session it makes (section 4.2).
 */
export const REPEATING_PROFILES: readonly WorkloadProfile[] = ['azure'];

/** The claims each profile requires; a binding may add more, to narrow it. An `aws` binding's are the role's account and unique ID. */
export const REQUIRED_CLAIMS: Record<WorkloadProfile, readonly string[]> = {
  github: ['repository_owner_id', 'repository_id', 'workflow_ref', 'ref', 'event_name'],
  'github-reusable': ['repository_owner_id', 'repository_id', 'ref', 'event_name', 'job_workflow_ref', 'job_workflow_sha'],
  'github-reusable-organization': ['repository_owner_id', 'ref', 'event_name', 'job_workflow_ref', 'job_workflow_sha'],
  gitlab: ['namespace_id', 'project_id', 'ref_type', 'ref', 'pipeline_source'],
  custom: ['sub'],
  kubernetes: ['sub', 'kubernetes.io.serviceaccount.uid'],
  gcp: ['sub'],
  azure: ['tid', 'oid'],
  fly: ['org_id', 'app_id'],
  vercel: ['owner_id', 'project_id', 'environment'],
  aws: ['account', 'role_id'],
  enrollment: [],
  cloudflare: [],
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
  kubernetes: null,
  gcp: null,
  azure: null,
  fly: null,
  vercel: null,
  aws: null,
  enrollment: null,
  cloudflare: null,
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
/**
 * A GitHub environment's name, as GitHub takes one: at most 255 characters,
 * none a control character, and no space at either end, which GitHub would
 * not keep. GitHub documents no narrower set: `production`, `Staging EU`
 * and `prod/eu:1` are all names.
 */
const ENVIRONMENT = /^(?! )[^\p{Cc}]{1,255}(?<! )$/u;

/** A claim a binding names: one value, or, for what started the run, any of several. */
export type ClaimValue = string | string[];
export type BindingClaims = Record<string, ClaimValue>;

/**
 * What makes a binding, checked: its profile, its issuer, and its claims,
 * sorted. The issuer is a URL coffre may fetch, unless the binding carries
 * its keys (`uploaded`): then coffre fetches nothing, and it is any string,
 * matched exactly, such as a private Kubernetes cluster's.
 */
export type CheckedBinding = { profile: WorkloadProfile; issuer: string; claims: BindingClaims };

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
  // The platforms of workload access (section 4.2): a custom binding of theirs would drop the key-naming audience, or spend a token they repeat.
  if (issuer === GOOGLE_ISSUER) return ['gcp'];
  if (issuer.startsWith('https://oidc.fly.io/')) return ['fly'];
  if (issuer === 'https://oidc.vercel.com' || issuer.startsWith('https://oidc.vercel.com/')) return ['vercel'];
  if (issuer.startsWith('https://sts.windows.net/') || issuer.startsWith('https://login.microsoftonline.com/')) return ['azure'];
  return null;
}

/** Google's, for every `gcp` binding. */
export const GOOGLE_ISSUER = 'https://accounts.google.com';

/**
 * The issuer a profile means when none is given: github.com's, gitlab.com's
 * or Google's, or the URN of a profile that is no ID token. A GitHub
 * Enterprise Server, a self-managed GitLab, a cluster, a tenant or a team
 * names its own.
 */
export function defaultIssuer(profile: WorkloadProfile): string | null {
  if (Object.hasOwn(PROFILE_URNS, profile)) return PROFILE_URNS[profile as keyof typeof PROFILE_URNS];
  if (profile.startsWith('github')) return GITHUB_ISSUER;
  if (profile === 'gitlab') return GITLAB_ISSUER;
  return profile === 'gcp' ? GOOGLE_ISSUER : null;
}

/** The longest issuer a binding with uploaded keys names, in bytes. */
export const MAX_ISSUER_BYTES = 400;

/**
 * Check a binding against its profile, and return it as stored: the
 * issuer as given, the claims sorted by name. With `uploaded`, the binding
 * carries its issuer's keys, and its issuer need not be a URL coffre can
 * fetch. Throws `BindingInvalid`.
 */
export function checkBinding(
  input: { profile: string; issuer: string | null; claims: Record<string, unknown> },
  options: { allowLoopback?: boolean; uploaded?: boolean } = {},
): CheckedBinding {
  const profile = input.profile as WorkloadProfile;
  if (!WORKLOAD_PROFILES.includes(profile)) {
    throw new BindingInvalid(`unknown profile "${input.profile}": one of ${WORKLOAD_PROFILES.join(', ')}`);
  }
  const issuer = input.issuer ?? defaultIssuer(profile);
  if (issuer === null) throw new BindingInvalid(`a ${profile} binding names its issuer`);
  const urn = defaultIssuer(profile);
  if (Object.hasOwn(PROFILE_URNS, profile)) {
    // No token names it, and coffre fetches nothing for it: the URN alone keeps one key source per issuer.
    if (issuer !== urn) throw new BindingInvalid(`a ${profile} binding's issuer is ${urn}`);
    if (options.uploaded === true) throw new BindingInvalid(`a ${profile} binding carries no keys: its proof is no ID token`);
  } else if (options.uploaded === true) checkIssuerName(issuer);
  else checkFetchUrl(issuer, 'the issuer', { allowLoopback: options.allowLoopback, path: true, query: false });
  // Google signs every service account's tokens, as one issuer.
  if (profile === 'gcp' && issuer !== GOOGLE_ISSUER) throw new BindingInvalid(`a gcp binding's issuer is ${GOOGLE_ISSUER}`);
  const forced = forcedProfiles(issuer);
  if (forced !== null && !forced.includes(profile)) {
    throw new BindingInvalid(`${issuer} signs only for the ${forced[0]} profile${forced.length > 1 ? 's' : ''}`);
  }

  const entries = Object.entries(input.claims);
  if (entries.length > MAX_CLAIMS) throw new BindingInvalid(`a binding names at most ${MAX_CLAIMS} claims`);
  const event = EVENT_CLAIM[profile];
  const claims: BindingClaims = {};
  for (const [name, value] of entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    // `__proto__` too: assigned below, it would set the object's prototype, and the binding would silently lose the claim.
    if (!CLAIM_NAME.test(name) || name === '__proto__') throw new BindingInvalid(`"${name}" is not a claim name a binding can match`);
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
  if (REQUIRED_CLAIMS[profile].length === 0 && entries.length > 0) throw new BindingInvalid(`a ${profile} binding names no claims: its proof carries none`);
  const missing = REQUIRED_CLAIMS[profile].filter((name) => claims[name] === undefined);
  if (missing.length > 0) throw new BindingInvalid(`the ${profile} profile requires ${missing.join(', ')}`);
  if (profile === 'github-reusable-organization' && claims.repository_id !== undefined) {
    throw new BindingInvalid('a binding for any repository of the organization names no repository_id: use github-reusable');
  }

  if (profile.startsWith('github')) checkGitHub(profile, claims);
  if (profile === 'gitlab') checkGitLab(claims);
  return { profile, issuer, claims };
}

/**
 * An issuer whose keys a binding carries: any string a token's `iss` can
 * be, matched exactly, so none with a control character or a space at
 * either end. Never github.com's or gitlab.com's, whose keys change when
 * they rotate them: coffre fetches those.
 */
function checkIssuerName(issuer: string): void {
  if (issuer === '' || /^\s|\s$/.test(issuer) || /\p{Cc}/u.test(issuer)) {
    throw new BindingInvalid('the issuer is its tokens\' iss, exactly: no control character, no space at either end');
  }
  if (new TextEncoder().encode(issuer).length > MAX_ISSUER_BYTES) throw new BindingInvalid(`the issuer is longer than ${MAX_ISSUER_BYTES} bytes`);
  if (issuer === GITHUB_ISSUER || issuer === GITLAB_ISSUER) {
    throw new BindingInvalid(`${issuer} publishes its keys and rotates them: coffre fetches them, so upload none`);
  }
  if (issuer.startsWith('urn:coffre:')) throw new BindingInvalid(`${issuer} is coffre's own, for a binding that is no ID token's`);
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
  if (claims.environment !== undefined && !ENVIRONMENT.test(claims.environment as string)) {
    throw new BindingInvalid('environment is a GitHub environment\'s name: at most 255 characters, no control character, no space at either end');
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
 * A claim of a token, by the name a binding gives it: a top-level claim, or
 * one nested in objects, its path joined by dots. A key may hold dots of
 * its own, as Kubernetes' `kubernetes.io` does, so a name is read every way
 * its dots can split it, and names a claim only when exactly one of those
 * readings reaches a value; none, or several, and it names nothing. In
 *
 *   { "sub": "system:serviceaccount:ci:deploy",
 *     "kubernetes.io": { "namespace": "ci", "serviceaccount": { "name": "deploy", "uid": "4f1c…" } } }
 *
 * `kubernetes.io.serviceaccount.uid` is `4f1c…`, `kubernetes.io` an object,
 * and `kubernetes.io.pod` nothing.
 */
export function claimAt(claims: Record<string, unknown>, name: string): unknown {
  const parts = name.split('.');
  let found: unknown;
  let readings = 0;
  // Each step takes one key, of one or more parts, from the object it is in; stops once a second reading shows.
  const walk = (at: unknown, from: number): void => {
    if (readings > 1) return;
    if (from === parts.length) {
      found = at;
      readings++;
      return;
    }
    if (typeof at !== 'object' || at === null || Array.isArray(at)) return;
    for (let to = from + 1; to <= parts.length; to++) {
      const key = parts.slice(from, to).join('.');
      if (Object.hasOwn(at, key)) walk((at as Record<string, unknown>)[key], to);
    }
  };
  walk(claims, 0);
  return readings === 1 ? found : undefined;
}

/**
 * The claims of a verified token that differ from what a binding expects,
 * by name: none when it matches. A claim matches when the token carries its
 * value, or one of its values, where `claimAt` reads it. On GitHub's
 * profiles, two readings:
 *
 * - A `pull_request` run, at `refs/pull/<n>/merge`, counts as a run at the
 *   branch it merges into: its `ref`, and the ref its `workflow_ref` ends
 *   in, are read as `refs/heads/<base_ref>`.
 * - `environment` matches whatever its case: GitHub's environment names are
 *   case-insensitive, so `Production` and `production` are one environment,
 *   under the same protection rules.
 */
export function differingClaims(profile: WorkloadProfile, expected: BindingClaims, token: Record<string, unknown>): string[] {
  const github = profile.startsWith('github');
  const claims = github ? atBaseBranch(token) : token;
  return Object.entries(expected)
    .filter(([name, value]) => {
      const actual = claimAt(claims, name);
      if (typeof actual !== 'string') return true;
      if (github && name === 'environment') return actual.toLowerCase() !== (value as string).toLowerCase();
      return !claimValues(value).includes(actual);
    })
    .map(([name]) => name);
}

function atBaseBranch(claims: Record<string, unknown>): Record<string, unknown> {
  const { event_name: event, ref, base_ref: base, workflow_ref: workflow } = claims;
  if (event !== 'pull_request' || typeof ref !== 'string' || typeof base !== 'string' || base === '') return claims;
  const at = `refs/heads/${base}`;
  const file = typeof workflow === 'string' && workflow.endsWith(`@${ref}`) ? `${workflow.slice(0, workflow.length - ref.length)}${at}` : workflow;
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

/** What a preset fills in: a profile `/api/auth/oidc` takes, and its claims. */
export type Preset = { profile: BearerProfile; claims: BindingClaims };

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

/**
 * A workflow of the repository, run at `ref` by any of `events`; a pull
 * request, by the branch it merges into. An `environment` narrows it to the
 * jobs that run in that GitHub environment.
 */
export function githubWorkflow(input: {
  repository: string;
  repositoryId: string;
  ownerId: string;
  workflow: string;
  ref: string;
  environment?: string;
} & Starts<'event', 'events'>): Preset {
  return {
    profile: 'github',
    claims: {
      repository_owner_id: input.ownerId,
      repository_id: input.repositoryId,
      workflow_ref: workflowRef(input.repository, input.workflow, input.ref),
      ref: input.ref,
      event_name: started(input, 'event', 'events'),
      ...inEnvironment(input.environment),
    },
  };
}

/** The `environment` claim, when one is named. */
function inEnvironment(environment: string | undefined): BindingClaims {
  return environment === undefined ? {} : { environment };
}

/**
 * A reusable workflow at one commit, called at `ref`: from one repository,
 * or, with `repositoryId` null, from any repository of the organization. A
 * `caller` workflow narrows it to one calling workflow, and an
 * `environment` to the jobs that run in that GitHub environment.
 */
export function githubReusable(input: {
  repositoryId: string | null;
  ownerId: string;
  ref: string;
  called: string;
  sha: string;
  caller?: { repository: string; workflow: string };
  environment?: string;
} & Starts<'event', 'events'>): Preset {
  const claims: BindingClaims = {
    repository_owner_id: input.ownerId,
    ...(input.repositoryId === null ? {} : { repository_id: input.repositoryId }),
    ref: input.ref,
    event_name: started(input, 'event', 'events'),
    job_workflow_ref: input.called,
    job_workflow_sha: input.sha,
    ...inEnvironment(input.environment),
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
} & Starts<'source', 'sources'>): Preset {
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

// --- policy --------------------------------------------------------------------
//
// What a binding says beyond its claims (docs/design/workload-access.md,
// section 11): stored beside them, under the binding's MAC, as canonical
// JSON, and as immutable as the rest of it. Each profile takes a fixed
// subset of the fields.

/**
 * What a binding's sessions may read, by environment ID and key ID, so a
 * rename moves nothing: `keys` lists keys, or `'*'` every key of the
 * environment; `mints`, the minters whose children it is handed.
 */
export type BindingReads = Readonly<Record<string, { readonly keys?: readonly string[] | '*'; readonly mints?: readonly string[] }>>;

/**
 * A binding's policy, as `checkPolicy` returns it: a field left out holds
 * its default (`POLICY_DEFAULTS`), so one policy has one spelling.
 *
 * - `audience`: the exact audience of an `azure` token, an Entra
 *   application ID URI, which Entra fixes; required for it, refused for
 *   every other profile.
 * - `keyAudience`: the token's audience must name the session's key,
 *   `<publicUrl>#jkt=<thumbprint>`: always for the platforms whose caller
 *   picks the audience (`KEY_NAMING_PROFILES`), and where a `custom`
 *   binding says so.
 * - `reads`: the escape hatch, by ID (section 6.1).
 * - `sources`: CIDRs a session's client address must be within.
 * - `sessionHours`: a session's hard end after its proof, at most 168.
 * - An `enrollment` binding's codes: `replicas` (required), `sessionDays`,
 *   `overlapMinutes`, `mintedBy` (the service, never the binding's own,
 *   that may mint them), `approve` and `onContention` (section 4.4).
 * - `unsignedUploads`: a streamed upload no digest binds may go through a
 *   credential that takes one (section 5.1), which leaves column B at use.
 */
export type BindingPolicy = {
  readonly audience?: string;
  readonly keyAudience?: true;
  readonly reads?: BindingReads;
  readonly sources?: readonly string[];
  readonly sessionHours?: number;
  readonly replicas?: number;
  readonly sessionDays?: number;
  readonly overlapMinutes?: number;
  readonly mintedBy?: string;
  readonly approve?: true;
  readonly onContention?: 'alert';
  readonly unsignedUploads?: true;
};

/** What a field left out of a policy means. */
export const POLICY_DEFAULTS = {
  keyAudience: false,
  sessionHours: 24,
  sessionDays: 30,
  overlapMinutes: 15,
  approve: false,
  onContention: 'freeze',
  unsignedUploads: false,
} as const;

/** The most environments, and keys in each, a binding's `reads` lists; the most `sources`. */
export const MAX_READ_PLACES = 64;
export const MAX_READ_KEYS = 256;
export const MAX_SOURCES = 16;

type PolicyField = keyof BindingPolicy;

const SESSION_FIELDS: readonly PolicyField[] = ['reads', 'sources', 'sessionHours', 'unsignedUploads'];
const KEY_AUDIENCE: readonly PolicyField[] = [...SESSION_FIELDS, 'keyAudience'];

/**
 * The profiles whose caller picks the token's audience, so their binding's
 * policy always says `keyAudience`: `checkPolicy` sets it, and refuses it off.
 * A Vercel function picks one by exchanging its own token at
 * `https://oidc.vercel.com/~token`, as `@vercel/oidc`'s
 * `getVercelOidcToken({ audience })` does.
 */
export const KEY_NAMING_PROFILES: readonly WorkloadProfile[] = ['github', 'github-reusable', 'github-reusable-organization', 'gcp', 'fly', 'vercel'];

/** The fields each profile's policy may hold. */
export const POLICY_FIELDS: Record<WorkloadProfile, readonly PolicyField[]> = {
  github: KEY_AUDIENCE,
  'github-reusable': KEY_AUDIENCE,
  'github-reusable-organization': KEY_AUDIENCE,
  gitlab: SESSION_FIELDS,
  custom: KEY_AUDIENCE,
  kubernetes: SESSION_FIELDS,
  gcp: KEY_AUDIENCE,
  azure: [...SESSION_FIELDS, 'audience'],
  fly: KEY_AUDIENCE,
  vercel: KEY_AUDIENCE,
  aws: SESSION_FIELDS,
  enrollment: ['reads', 'sources', 'replicas', 'sessionDays', 'overlapMinutes', 'mintedBy', 'approve', 'onContention', 'unsignedUploads'],
  // A call from another Worker has no address of its own and no session to end.
  cloudflare: ['reads'],
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** A credential's name in the proxy's config: a minter's, a signer's, an upstream's. */
export const CREDENTIAL_NAME = /^[a-z][a-z0-9-]{0,31}$/;
/** A service's name after `token:`, as a member names it. */
const SERVICE_NAME = /^[^\s\p{Cc}]{1,320}$/u;

function integer(value: unknown, name: string, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) {
    throw new BindingInvalid(`${name} is a whole number from ${min} to ${max}`);
  }
  return value as number;
}

function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

function uuidList(value: unknown, what: string, max: number): string[] {
  if (!Array.isArray(value) || value.length > max || value.some((id) => typeof id !== 'string' || !UUID.test(id.toLowerCase()))) {
    throw new BindingInvalid(`${what} lists at most ${max} IDs`);
  }
  return sortedUnique(value.map((id: string) => id.toLowerCase()));
}

function checkReads(value: unknown): BindingReads | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new BindingInvalid('reads maps environment IDs to { keys, mints }');
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > MAX_READ_PLACES) throw new BindingInvalid(`reads names at most ${MAX_READ_PLACES} environments`);
  const reads: Record<string, { keys?: readonly string[] | '*'; mints?: readonly string[] }> = {};
  const seen = new Set<string>();
  for (const [environment, entry] of entries) {
    const id = environment.toLowerCase();
    if (!UUID.test(id)) throw new BindingInvalid(`reads names environments by ID: ${environment} is none`);
    if (seen.has(id)) throw new BindingInvalid(`reads names ${id} twice`);
    seen.add(id);
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) throw new BindingInvalid('each environment of reads is { keys, mints }');
    const { keys, mints, ...rest } = entry as Record<string, unknown>;
    if (Object.keys(rest).length > 0) throw new BindingInvalid(`each environment of reads holds keys and mints, not ${Object.keys(rest).join(', ')}`);
    const read: { keys?: readonly string[] | '*'; mints?: readonly string[] } = {};
    if (keys !== undefined) {
      const listed = keys === '*' ? '*' : uuidList(keys, 'reads.keys', MAX_READ_KEYS);
      if (listed === '*' || listed.length > 0) read.keys = listed;
    }
    if (mints !== undefined) {
      if (!Array.isArray(mints) || mints.length > MAX_READ_KEYS || mints.some((name) => typeof name !== 'string' || !CREDENTIAL_NAME.test(name))) {
        throw new BindingInvalid('reads.mints lists minters by name');
      }
      if (mints.length > 0) read.mints = sortedUnique(mints as string[]);
    }
    // A place that lists nothing reads nothing: one spelling, left out.
    if (read.keys !== undefined || read.mints !== undefined) reads[id] = read;
  }
  return Object.keys(reads).length === 0 ? undefined : reads;
}

/**
 * Check a binding's policy against its profile and return it canonical:
 * every field its profile allows, valid, those at their default left out,
 * lists sorted and IDs in lower case, so that one policy has one spelling
 * (`policyText`). `service` is the binding's own, `token:<name>`, which its
 * `mintedBy` may not name: a session of the service would then mint codes
 * for itself, and outlive every deploy. Throws `BindingInvalid`.
 */
export function checkPolicy(profile: WorkloadProfile, input: unknown, options: { service: string }): BindingPolicy {
  if (input === undefined || input === null) input = {};
  if (typeof input !== 'object' || Array.isArray(input)) throw new BindingInvalid('a policy is an object');
  const given = input as Record<string, unknown>;
  const allowed = POLICY_FIELDS[profile];
  const extra = Object.keys(given).filter((name) => given[name] !== undefined && !allowed.includes(name as PolicyField));
  if (extra.length > 0) throw new BindingInvalid(`a ${profile} binding's policy holds ${allowed.join(', ') || 'nothing'}, not ${extra.join(', ')}`);
  const policy: { -readonly [K in PolicyField]?: BindingPolicy[K] } = {};

  if (given.audience !== undefined) {
    if (typeof given.audience !== 'string' || given.audience === '' || given.audience.length > 400 || /\p{Cc}|^\s|\s$/u.test(given.audience)) {
      throw new BindingInvalid('audience is the exact audience the platform puts in its tokens');
    }
    policy.audience = given.audience;
  } else if (allowed.includes('audience')) {
    throw new BindingInvalid(`a ${profile} binding names the audience its platform puts in its tokens: ${profile} lets no caller choose one`);
  }
  if (given.keyAudience !== undefined && typeof given.keyAudience !== 'boolean') throw new BindingInvalid('keyAudience is true or false');
  if (KEY_NAMING_PROFILES.includes(profile)) {
    // Its caller picks the audience, so the token names the key, or a copy of it would buy a session for any key.
    if (given.keyAudience === false) {
      throw new BindingInvalid(`a ${profile} binding's tokens name the session's key in their audience: ${profile} lets its caller choose one, so a copied token works for no other key`);
    }
    policy.keyAudience = true;
  } else if (given.keyAudience === true) policy.keyAudience = true;
  if (given.reads !== undefined) {
    const reads = checkReads(given.reads);
    if (reads !== undefined) policy.reads = reads;
  }
  if (given.sources !== undefined) {
    if (!Array.isArray(given.sources) || given.sources.length > MAX_SOURCES) throw new BindingInvalid(`sources lists at most ${MAX_SOURCES} CIDRs`);
    const sources = sortedUnique(given.sources.map((source: unknown) => {
      const block = typeof source === 'string' ? parseCidr(source) : null;
      if (block === null) throw new BindingInvalid(`sources lists CIDRs, such as 162.220.232.0/24 or 2001:db8::/32: ${String(source)} is none`);
      return block.text;
    }));
    if (sources.length > 0) policy.sources = sources;
  }
  const number = (name: 'sessionHours' | 'sessionDays' | 'overlapMinutes' | 'replicas', min: number, max: number) => {
    if (given[name] === undefined) return;
    const value = integer(given[name], name, min, max);
    if (name === 'replicas' || value !== POLICY_DEFAULTS[name]) policy[name] = value;
  };
  number('sessionHours', 1, 168);
  number('sessionDays', 1, 90);
  number('overlapMinutes', 1, 60);
  number('replicas', 1, 64);
  if (profile === 'enrollment' && policy.replicas === undefined) {
    throw new BindingInvalid('an enrollment binding says how many replicas run, its replicas: a code admits twice that many sessions');
  }
  if (given.mintedBy !== undefined) {
    const named = typeof given.mintedBy === 'string' ? (given.mintedBy.startsWith('token:') ? given.mintedBy : `token:${given.mintedBy}`) : '';
    if (!SERVICE_NAME.test(named.slice('token:'.length))) throw new BindingInvalid('mintedBy names a service account');
    if (named === options.service) throw new BindingInvalid(`mintedBy names another service than ${shownMember(options.service)}: a session of its own would mint codes for itself`);
    policy.mintedBy = named;
  }
  for (const flag of ['approve', 'unsignedUploads'] as const) {
    if (given[flag] === undefined) continue;
    if (typeof given[flag] !== 'boolean') throw new BindingInvalid(`${flag} is true or false`);
    if (given[flag]) policy[flag] = true;
  }
  if (given.onContention !== undefined) {
    if (given.onContention !== 'freeze' && given.onContention !== 'alert') throw new BindingInvalid('onContention is freeze or alert');
    if (given.onContention === 'alert') policy.onContention = 'alert';
  }
  return policy;
}

/** A value as canonical JSON: every object's keys sorted, at every depth. */
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object' && value !== null) {
    const entries = Object.entries(value).filter(([, item]) => item !== undefined).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/** A policy as the binding's `policy` column and its MAC hold it: `checkPolicy`'s result, as canonical JSON. */
export function policyText(policy: BindingPolicy): string {
  return canonicalJson(policy);
}

// --- sources -------------------------------------------------------------------

/** An address block: its version, its network's bytes, its prefix length, and its one spelling. */
export type Cidr = { version: 4 | 6; bytes: Uint8Array; bits: number; text: string };

function ipv4(text: string): Uint8Array | null {
  const parts = text.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255)) return null;
  return Uint8Array.from(parts.map(Number));
}

function ipv6(text: string): Uint8Array | null {
  const halves = text.toLowerCase().split('::');
  if (halves.length > 2) return null;
  const groups = halves.map((half) => (half === '' ? [] : half.split(':')));
  if (groups.flat().some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;
  const count = groups.flat().length;
  if (halves.length === 1 ? count !== 8 : count > 7) return null;
  const words = halves.length === 1 ? groups[0]! : [...groups[0]!, ...Array<string>(8 - count).fill('0'), ...groups[1]!];
  const bytes = new Uint8Array(16);
  words.forEach((word, i) => {
    const value = parseInt(word, 16);
    bytes[2 * i] = value >> 8;
    bytes[2 * i + 1] = value & 0xff;
  });
  return bytes;
}

/** An address, IPv4 dotted or IPv6 in hex groups; null for anything else. */
export function parseAddress(text: string): { version: 4 | 6; bytes: Uint8Array } | null {
  // An IPv4 client of a server listening on `::`, as Node reports it: the IPv4 address it is.
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(text);
  if (mapped !== null) return parseAddress(mapped[1]!);
  const v4 = ipv4(text);
  if (v4 !== null) return { version: 4, bytes: v4 };
  const v6 = text.includes(':') ? ipv6(text) : null;
  return v6 === null ? null : { version: 6, bytes: v6 };
}

/** IPv6 as RFC 5952 writes it: lower case, no leading zeros, the longest run of two or more zero groups as `::`, the first of equals. */
function ipv6Text(bytes: Uint8Array): string {
  const words = Array.from({ length: 8 }, (_, i) => (bytes[2 * i]! << 8) | bytes[2 * i + 1]!);
  let best = { at: -1, length: 0 };
  for (let i = 0; i < 8;) {
    if (words[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && words[j] === 0) j++;
    if (j - i > best.length) best = { at: i, length: j - i };
    i = j;
  }
  const hexes = words.map((word) => word.toString(16));
  if (best.length < 2) return hexes.join(':');
  return `${hexes.slice(0, best.at).join(':')}::${hexes.slice(best.at + best.length).join(':')}`;
}

/**
 * A CIDR, `162.220.232.0/24` or `2001:db8::/32`, as its one spelling; null
 * for anything else, a block with host bits set included, since
 * `162.220.232.5/24` most likely means another block than it says.
 */
export function parseCidr(text: string): Cidr | null {
  const slash = text.indexOf('/');
  if (slash < 0 || !/^(0|[1-9][0-9]{0,2})$/.test(text.slice(slash + 1))) return null;
  const address = parseAddress(text.slice(0, slash));
  const bits = Number(text.slice(slash + 1));
  if (address === null || bits > address.bytes.length * 8) return null;
  for (let bit = bits; bit < address.bytes.length * 8; bit++) {
    if ((address.bytes[bit >> 3]! >> (7 - (bit & 7))) & 1) return null;
  }
  const shown = address.version === 4 ? Array.from(address.bytes).join('.') : ipv6Text(address.bytes);
  return { ...address, bits, text: `${shown}/${bits}` };
}

/** Whether an address is within any of these blocks, each `parseCidr`'s: never for an address that does not parse, or of the other version. */
export function addressWithin(address: string, sources: readonly string[]): boolean {
  const parsed = parseAddress(address);
  if (parsed === null) return false;
  return sources.some((source) => {
    const block = parseCidr(source);
    if (block === null || block.version !== parsed.version) return false;
    for (let bit = 0; bit < block.bits; bit++) {
      const mask = 1 << (7 - (bit & 7));
      if ((block.bytes[bit >> 3]! & mask) !== (parsed.bytes[bit >> 3]! & mask)) return false;
    }
    return true;
  });
}

// --- freezes -------------------------------------------------------------------

/**
 * What a freeze names, in its one spelling (section 8.2): every workload's
 * use, one service, one binding, one session, or one upstream credential of
 * an environment, by the environment's ID so a rename moves nothing.
 *
 *   freezeTarget('Binding:0F0E…') → null      freezeTarget('binding:0f0e…') → 'binding:0f0e…'
 *   freezeTarget('credential:6B1C…-…/stripe') → 'credential:6b1c…-…/stripe'
 */
export function freezeTarget(text: string): string | null {
  if (text === 'instance') return text;
  const colon = text.indexOf(':');
  if (colon < 0) return null;
  const kind = text.slice(0, colon);
  const rest = text.slice(colon + 1);
  switch (kind) {
    // `service:<name>` is how the CLI and the pages name one: `token:<name>` is its one spelling.
    case 'token':
    case 'service':
      return SERVICE_NAME.test(rest) ? `token:${rest}` : null;
    case 'binding':
    case 'session':
      return UUID.test(rest.toLowerCase()) ? `${kind}:${rest.toLowerCase()}` : null;
    case 'credential': {
      const [environment, name, ...more] = rest.split('/');
      if (more.length > 0 || environment === undefined || name === undefined) return null;
      return UUID.test(environment.toLowerCase()) && CREDENTIAL_NAME.test(name) ? `credential:${environment.toLowerCase()}/${name}` : null;
    }
    default:
      return null;
  }
}

// --- callers -------------------------------------------------------------------

/**
 * A workload, authenticated for one request (section 5.3): a key-bound
 * session's, or a Cloudflare service binding's, which has no session row.
 * `PluginContext.workload(request, …)` returns it, so the proxy sees one
 * kind of caller whichever way it signed in, and never parses a proof.
 */
export type WorkloadCaller = {
  readonly kind: 'workload';
  /** The service, `token:<name>`. */
  readonly principal: string;
  /** The session's credential ID, or `binding:<id>` for a Cloudflare call: what the log names. */
  readonly credentialId: string;
  readonly bindingId: string;
  readonly profile: WorkloadProfile;
  /** A `narrow` child's limits; null for a root, which only its scope bounds. */
  readonly constraints: Constraints | null;
  /** The headers the proof signs, which alone are forwarded; null for a Cloudflare call, whose request nobody in between could change. */
  readonly hdr: readonly string[] | null;
  readonly sourceIp: string | null;
};

/** What a workload's alert says (section 8.3), to the log and to the deployment's `alert`. */
export type WorkloadAlert = {
  readonly kind: 'enrolled' | 'contention' | 'limit' | 'expiring' | 'frozen';
  readonly service: string;
  readonly binding: string | null;
  readonly session: string | null;
  readonly ip: string | null;
  /** One line for a person: `api-prod enrolled from 203.0.113.9 (railway, code minted by deploy run 7001)`. */
  readonly text: string;
};

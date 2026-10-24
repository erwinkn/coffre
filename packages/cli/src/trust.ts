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
 *
 * A workload's binding (docs/design/workload-access.md, section 4) is made
 * the same way, by its platform's flag, and carries a policy: what its
 * key-bound sessions may read, where from, and for how long.
 *
 *   coffre trust ingest --aws arn:aws:iam::671742253563:role/ingest-task
 *   coffre trust api-prod --enrollment --replicas 2 --source 162.220.232.0/24 --minted-by deploy
 */
import { execFile } from 'node:child_process';

import { apiMember, CoffreError, shownMember, type BindingPlan, type BindingView, type KeysPlan, type WorkloadIds } from '@coffre/client';
import { credentialScopeInWords, ROLE_ID, type Role } from '@coffre/core/access';
import {
  BindingInvalid,
  checkPolicy,
  claimValues,
  EVENT_EXPOSURE,
  fullRef,
  GITHUB_EVENTS,
  githubEventsAt,
  GITLAB_PIPELINE_SOURCES,
  githubReusable,
  githubWorkflow,
  gitlabProject,
  GOOGLE_ISSUER,
  KEY_NAMING_PROFILES,
  parseCidr,
  POLICY_FIELDS,
  PROFILE_URNS,
  type BindingClaims,
  type ClaimValue,
  type WorkloadProfile,
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
  // A workload's platform, one of these (docs/design/workload-access.md, section 4.2).
  aws?: string;
  'role-id'?: string;
  kubernetes?: string;
  uid?: string;
  gcp?: string;
  azure?: boolean;
  tenant?: string;
  object?: string;
  audience?: string;
  fly?: string;
  'org-id'?: string;
  'app-id'?: string;
  vercel?: string;
  'vercel-environment'?: string;
  enrollment?: boolean;
  cloudflare?: boolean;
  /** A key-bound session's binding for --github, --gitlab or --issuer, which make a bearer one without it. */
  workload?: boolean;
  // Its policy.
  /** Repeated: `<project>/<environment>=<KEY>,<KEY>`, or `=*`. */
  reads?: string[];
  'session-hours'?: string;
  'unsigned-uploads'?: boolean;
  replicas?: string;
  'minted-by'?: string;
  approve?: boolean;
  'session-days'?: string;
  'overlap-minutes'?: string;
  'on-contention'?: string;
};

/** `coffre trust`'s flags, as `parseArgs` reads them. */
export const TRUST_OPTIONS = {
  github: { type: 'string' },
  workflow: { type: 'string' },
  reusable: { type: 'string' },
  sha: { type: 'string' },
  'any-repository': { type: 'boolean' },
  'github-environment': { type: 'string' },
  gitlab: { type: 'string' },
  'gitlab-url': { type: 'string' },
  source: { type: 'string', multiple: true },
  issuer: { type: 'string' },
  claim: { type: 'string', multiple: true },
  branch: { type: 'string' },
  tag: { type: 'string' },
  event: { type: 'string', multiple: true },
  'repository-id': { type: 'string' },
  'owner-id': { type: 'string' },
  'project-id': { type: 'string' },
  'namespace-id': { type: 'string' },
  aws: { type: 'string' },
  'role-id': { type: 'string' },
  kubernetes: { type: 'string' },
  uid: { type: 'string' },
  gcp: { type: 'string' },
  azure: { type: 'boolean' },
  tenant: { type: 'string' },
  object: { type: 'string' },
  audience: { type: 'string' },
  fly: { type: 'string' },
  'org-id': { type: 'string' },
  'app-id': { type: 'string' },
  vercel: { type: 'string' },
  'vercel-environment': { type: 'string' },
  enrollment: { type: 'boolean' },
  cloudflare: { type: 'boolean' },
  workload: { type: 'boolean' },
  reads: { type: 'string', multiple: true },
  'session-hours': { type: 'string' },
  'unsigned-uploads': { type: 'boolean' },
  replicas: { type: 'string' },
  'minted-by': { type: 'string' },
  approve: { type: 'boolean' },
  'session-days': { type: 'string' },
  'overlap-minutes': { type: 'string' },
  'on-contention': { type: 'string' },
  scope: { type: 'string', multiple: true },
  label: { type: 'string' },
  replace: { type: 'string', multiple: true },
  'jwks-file': { type: 'string' },
  'replace-keys': { type: 'boolean' },
  apply: { type: 'boolean', default: false },
} as const;

/**
 * A binding's policy as the CLI sends it: `checkPolicy`'s fields, but
 * `reads` by path and key name, which the server resolves to IDs.
 */
export type PolicyRequest = {
  audience?: string;
  reads?: Record<string, string[] | '*'>;
  sources?: string[];
  sessionHours?: number;
  replicas?: number;
  sessionDays?: number;
  overlapMinutes?: number;
  mintedBy?: string;
  approve?: true;
  onContention?: 'freeze' | 'alert';
  unsignedUploads?: true;
};

/** A binding as the CLI asks for it: a bearer one, with no policy; a workload's, with one. */
export type BindingRequest = { profile: WorkloadProfile; issuer: string | null; claims: BindingClaims; policy?: PolicyRequest };

/**
 * The platform's own CLI, where one turns a name into the ID a binding
 * names: `aws`, `kubectl` and `gcloud`, as the person running `coffre
 * trust` is signed in to them. Each throws a sentence.
 */
export type PlatformLookup = {
  /** An IAM role's unique ID, `AROA…`, and its ARN, by its name. */
  awsRole(name: string): Promise<{ roleId: string; arn: string }>;
  /** The current cluster's issuer, as its discovery says it. */
  kubernetesIssuer(): Promise<string>;
  /** A service account's UID. */
  kubernetesUid(namespace: string, name: string): Promise<string>;
  /** A Google service account's unique ID, by its email. */
  gcpUniqueId(email: string): Promise<string>;
};

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
binding, with no stored secret; or, for CI without OIDC, with a bearer token: coffre tokens issue <service>.

A workload signs in for a key-bound session, by its platform's proof:
       coffre trust <service> --aws arn:aws:iam::<account>:role/<name> [--role-id AROA…]
       coffre trust <service> --kubernetes <namespace>/<service-account> [--issuer <url>] [--uid <uid>]
                    [--jwks-file <path>] [--claim <name>=<value> …]
       coffre trust <service> --gcp <service-account-email | unique-id> [--claim …]
       coffre trust <service> --azure --tenant <tenant-id> --object <object-id> --audience <app-id-uri>
       coffre trust <service> --azure --tenant <tenant-id> --object <object-id> --audience <the API's client ID>
                    --issuer https://login.microsoftonline.com/<tenant-id>/v2.0   for an API that takes v2 tokens
                    [--claim …]
       coffre trust <service> --fly <organization> --org-id <id> --app-id <id> [--claim …]
       coffre trust <service> --vercel <team> --owner-id team_… --project-id prj_…
                    [--vercel-environment production] [--issuer https://oidc.vercel.com] [--claim …]
       coffre trust <service> --enrollment --replicas <n> [--minted-by <service>] [--approve]
                    [--session-days 30] [--overlap-minutes 15] [--on-contention freeze|alert]
       coffre trust <service> --cloudflare
       coffre trust <service> (--github … | --gitlab … | --issuer …) --workload
         and, for any of them:
                    [--reads <project>/<env>=<KEY>,… | <project>/<env>=*] [--source <cidr> …]
                    [--session-hours 24] [--unsigned-uploads]
         --aws, --kubernetes and --gcp look up the IDs they bind with the aws, kubectl and gcloud you
         are signed in to; --role-id, --uid and a unique ID skip the lookup
         --reads lists the values its sessions may read, which its platform then holds: every other
         key they use through coffre, never read
         --source takes CIDRs its sessions must come from; with --gitlab, push, web and schedule
         remain pipeline sources
         --workload makes a CI run's binding one for a key-bound session; without it, --github,
         --gitlab and --issuer make one for /api/auth/oidc's five-minute bearer credential`;

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
  if (!binding.profile.startsWith('github') && binding.profile !== 'gitlab') return null;
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

/** The flags that name a workload's platform, each its profile. */
const PLATFORMS = ['aws', 'kubernetes', 'gcp', 'azure', 'fly', 'vercel', 'enrollment', 'cloudflare'] as const satisfies readonly WorkloadProfile[];
type Platform = (typeof PLATFORMS)[number];

/** The flags only some platforms take, and which. */
const PLATFORM_ONLY: Partial<Record<keyof TrustFlags, readonly string[]>> = {
  'role-id': ['aws'],
  uid: ['kubernetes'],
  tenant: ['azure'],
  object: ['azure'],
  audience: ['azure'],
  'org-id': ['fly'],
  'app-id': ['fly'],
  'vercel-environment': ['vercel'],
  'owner-id': ['github', 'vercel'],
  'project-id': ['gitlab', 'vercel'],
};

/** The flags that say which CI runs a binding takes, which no workload's platform has. */
const CI_ONLY = ['workflow', 'reusable', 'sha', 'any-repository', 'github-environment', 'gitlab-url', 'branch', 'tag', 'event', 'repository-id', 'namespace-id'] as const satisfies readonly (keyof TrustFlags)[];

/** Each policy flag, by the field it sets. */
const POLICY_FLAGS = {
  reads: 'reads',
  source: 'sources',
  'session-hours': 'sessionHours',
  'unsigned-uploads': 'unsignedUploads',
  replicas: 'replicas',
  'minted-by': 'mintedBy',
  approve: 'approve',
  'session-days': 'sessionDays',
  'overlap-minutes': 'overlapMinutes',
  'on-contention': 'onContention',
} as const satisfies Partial<Record<keyof TrustFlags, keyof PolicyRequest>>;

/**
 * The binding the flags describe, its IDs looked up where they were not
 * given: one, whatever the events (GitHub) or pipeline sources (GitLab) it
 * names; `push` unless told. A workload's platform, or `--workload`, makes
 * one with a policy, for a key-bound session. Throws a sentence.
 */
export async function bindingFrom(
  flags: TrustFlags,
  lookup: Lookup,
  options: { service?: string; platforms?: PlatformLookup } = {},
): Promise<BindingRequest> {
  const platforms = PLATFORMS.filter((name) => flags[name] !== undefined && flags[name] !== false);
  const named = [...platforms, ...(['github', 'gitlab'] as const).filter((name) => flags[name] !== undefined)];
  if (named.length === 0 && flags.issuer === undefined) {
    throw new Error(`name one of --github, --gitlab or --issuer, or a workload's platform: ${PLATFORMS.map((name) => `--${name}`).join(', ')}`);
  }
  if (named.length > 1) throw new Error(`name one platform, not ${named.map((name) => `--${name}`).join(' and ')}`);
  const kind = named[0] ?? 'issuer';
  for (const [flag, kinds] of Object.entries(PLATFORM_ONLY)) {
    if (flags[flag as keyof TrustFlags] !== undefined && !kinds.includes(kind)) throw new Error(`--${flag} is ${kinds.map((name) => `--${name}`).join(' or ')}'s`);
  }
  if (flags.issuer !== undefined && named.length > 0 && !['kubernetes', 'azure', 'vercel'].includes(kind)) {
    throw new Error(`--issuer names a custom binding's issuer, or a cluster's, a tenant's or a team's: --${kind} names its own`);
  }
  // A GitLab pipeline's source is a word, a session's a CIDR.
  const given = listOf(flags.source);
  const cidrs = given?.filter((value) => /[./:]/.test(value));
  const pipelines = given?.filter((value) => !/[./:]/.test(value));
  for (const cidr of cidrs ?? []) {
    if (parseCidr(cidr) === null) throw new Error(`--source takes CIDRs, such as 162.220.232.0/24 or 2001:db8::/32: ${cidr} is none`);
  }
  const policy = policyFrom(flags, cidrs);

  if (platforms.length === 1) {
    if (flags.workload === true) throw new Error(`--${kind} makes a workload's binding: --workload is for --github, --gitlab and --issuer`);
    const ci = CI_ONLY.find((flag) => flags[flag] !== undefined);
    if (ci !== undefined) throw new Error(`--${ci} says which CI runs a --github or --gitlab binding takes: --${kind} has none`);
    if (pipelines !== undefined && pipelines.length > 0) throw new Error(`--source takes CIDRs, such as 162.220.232.0/24: ${pipelines.join(', ')} is none`);
    const binding = await platformBinding(kind as Platform, flags, options.platforms ?? platformLookup());
    return checked(binding, { ...binding.policy, ...policy }, options.service);
  }

  const events = listOf(flags.event);
  if (flags.github === undefined && events !== undefined) throw new Error('--event is a GitHub run\'s: --source names a GitLab pipeline\'s');
  if (flags.github === undefined && flags['github-environment'] !== undefined) throw new Error('--github-environment narrows a GitHub binding: name the repository with --github');
  if (flags.gitlab === undefined && pipelines !== undefined && pipelines.length > 0) throw new Error(`--source is a GitLab pipeline's, or a CIDR: ${pipelines.join(', ')} is neither`);
  for (const event of events ?? []) {
    if (!(GITHUB_EVENTS as readonly string[]).includes(event)) throw new Error(`--event takes ${GITHUB_EVENTS.join(', ')}, not ${event}`);
  }
  for (const source of pipelines ?? []) {
    if (!(GITLAB_PIPELINE_SOURCES as readonly string[]).includes(source)) throw new Error(`--source takes ${GITLAB_PIPELINE_SOURCES.join(', ')}, or CIDRs, not ${source}`);
  }
  const binding = flags.github !== undefined
    ? await github(flags, events ?? ['push'], lookup)
    : flags.gitlab !== undefined
      ? await gitlab(flags, pipelines !== undefined && pipelines.length > 0 ? pipelines : ['push'], lookup)
      : custom(flags);
  if (flags.workload === true) return checked(binding, policy ?? {}, options.service);
  if (policy !== undefined) {
    const flag = Object.entries(POLICY_FLAGS).find(([, field]) => policy[field] !== undefined)![0];
    throw new Error(`--${flag} is a key-bound session's: add --workload, for a binding that signs in at /api/auth/workload`);
  }
  return binding;
}

/** The policy the flags give, `reads` by path and key name; undefined when they give none. */
function policyFrom(flags: TrustFlags, sources: string[] | undefined): PolicyRequest | undefined {
  const policy: PolicyRequest = {};
  const whole = (flag: keyof TrustFlags): number | undefined => {
    const value = flags[flag] as string | undefined;
    if (value === undefined) return undefined;
    if (!/^\d{1,6}$/.test(value)) throw new Error(`--${flag} takes a whole number, not ${value}`);
    return Number(value);
  };
  if (flags.reads !== undefined) policy.reads = readsFrom(flags.reads);
  if (sources !== undefined && sources.length > 0) policy.sources = sources;
  for (const flag of ['session-hours', 'replicas', 'session-days', 'overlap-minutes'] as const) {
    const value = whole(flag);
    if (value !== undefined) policy[POLICY_FLAGS[flag]] = value;
  }
  if (flags['minted-by'] !== undefined) policy.mintedBy = serviceMember(flags['minted-by']);
  if (flags.approve === true) policy.approve = true;
  if (flags['unsigned-uploads'] === true) policy.unsignedUploads = true;
  const contention = flags['on-contention'];
  if (contention !== undefined) {
    if (contention !== 'freeze' && contention !== 'alert') throw new Error(`--on-contention takes freeze or alert, not ${contention}`);
    policy.onContention = contention;
  }
  return Object.keys(policy).length === 0 ? undefined : policy;
}

/**
 * `--reads market/prod=STRIPE_WEBHOOK_SECRET,DATABASE_URL`, repeated, or
 * `market/prod=*` for every key of it, by path and name: the server finds
 * their IDs, which the binding keeps, so that a rename moves nothing.
 */
export function readsFrom(values: string[]): Record<string, string[] | '*'> {
  const reads: Record<string, string[] | '*'> = {};
  for (const value of values) {
    const at = value.indexOf('=');
    const [path, list] = at < 0 ? [value, ''] : [value.slice(0, at), value.slice(at + 1)];
    const keys = list.split(',').map((key) => key.trim()).filter((key) => key !== '');
    if (!/^[^/=\s]+\/[^/=\s]+$/.test(path) || keys.length === 0) {
      throw new Error(`--reads takes <project>/<environment>=<KEY>,<KEY>, or <project>/<environment>=* for every key of it; not "${value}"`);
    }
    if (Object.hasOwn(reads, path)) throw new Error(`--reads names ${path} twice: list its keys once, comma-separated`);
    if (keys.includes('*') && keys.length > 1) throw new Error(`--reads ${path}=* reads every key of it: name keys, or *, not both`);
    reads[path] = keys.includes('*') ? '*' : [...new Set(keys)].sort();
  }
  return reads;
}

/**
 * A workload's binding with its policy, checked here as far as the CLI
 * can: each flag is one the profile's policy takes, and every field but
 * `reads`, which names keys only the server can find, as `checkPolicy`
 * checks it.
 */
function checked(binding: BindingRequest, policy: PolicyRequest, service: string | undefined): BindingRequest {
  const allowed = POLICY_FIELDS[binding.profile] as readonly string[];
  for (const [flag, field] of Object.entries(POLICY_FLAGS)) {
    if (policy[field] !== undefined && !allowed.includes(field)) {
      const takes = Object.entries(POLICY_FLAGS).filter(([, each]) => allowed.includes(each)).map(([name]) => `--${name}`);
      throw new Error(`${/^[aeiou]/.test(binding.profile) ? 'an' : 'a'} ${binding.profile} binding takes ${takes.join(', ') || 'no policy flag'}, not --${flag}`);
    }
  }
  try {
    checkPolicy(binding.profile, { ...policy, reads: undefined }, { service: service ?? '' });
  } catch (error) {
    if (error instanceof BindingInvalid) throw new Error(error.message);
    throw error;
  }
  return { ...binding, policy };
}

/** The claims `--claim` adds, to narrow a binding. */
function claimsFrom(flags: TrustFlags): BindingClaims {
  const claims: BindingClaims = {};
  for (const pair of flags.claim ?? []) {
    const at = pair.indexOf('=');
    if (at <= 0) throw new Error(`--claim takes <name>=<value>, not "${pair}"`);
    claims[pair.slice(0, at)] = pair.slice(at + 1);
  }
  return claims;
}

const ROLE_ARN = /^arn:aws:iam::(\d{12}):role\/(?:[\w+=,.@-]+\/)*([\w+=,.@-]{1,64})$/;
const DNS_LABEL = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;
/** A Kubernetes service account's name, a DNS subdomain, as its tokens' `sub` names it. */
const DNS_SUBDOMAIN = /^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$/;
/** A Google service account's email: none begins with `-`, which gcloud would read as a flag. */
const GOOGLE_ACCOUNT = /^[a-z0-9][a-z0-9-]*@[a-z0-9][a-z0-9.-]*\.gserviceaccount\.com$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A workload's binding, by its platform's flags: IDs given, or looked up with its CLI. */
async function platformBinding(platform: Platform, flags: TrustFlags, lookup: PlatformLookup): Promise<BindingRequest> {
  const extra = claimsFrom(flags);
  /** The platform's claims, and those `--claim` adds: never one the platform's flags set, which would be dropped. */
  const claimed = (own: BindingClaims): BindingClaims => {
    const taken = Object.keys(extra).find((name) => Object.hasOwn(own, name));
    if (taken !== undefined) throw new Error(`--${platform} sets ${taken} from its own flags: --claim adds other claims`);
    return { ...extra, ...own };
  };
  const required = (flag: keyof TrustFlags, what: string): string => {
    const value = flags[flag];
    if (typeof value !== 'string' || value === '') throw new Error(`--${platform} names ${what}: --${flag} <${what.split(' ').at(-1)}>`);
    return value;
  };
  switch (platform) {
    case 'aws': {
      if (Object.keys(extra).length > 0) throw new Error('an aws binding names the role alone: its proof carries no other claim');
      const arn = ROLE_ARN.exec(flags.aws!);
      if (arn === null) throw new Error(`--aws takes a role's ARN, arn:aws:iam::<account>:role/<name>, not ${flags.aws}`);
      const [, account, name] = arn as unknown as [string, string, string];
      let roleId = flags['role-id'];
      if (roleId === undefined) {
        const found = await lookup.awsRole(name);
        if (found.arn !== flags.aws) {
          throw new Error(`aws iam get-role finds ${found.arn}, not ${flags.aws}: sign in to the role's account, or add --role-id <AROA…>`);
        }
        roleId = found.roleId;
      }
      return { profile: 'aws', issuer: null, claims: { account, role_id: roleId } };
    }
    case 'kubernetes': {
      const [namespace, name, ...rest] = flags.kubernetes!.split('/');
      if (!namespace || !name || rest.length > 0 || !DNS_LABEL.test(namespace) || !DNS_SUBDOMAIN.test(name)) {
        throw new Error(`--kubernetes takes <namespace>/<service-account>, not ${flags.kubernetes}`);
      }
      const issuer = flags.issuer ?? (await lookup.kubernetesIssuer());
      const uid = flags.uid ?? (await lookup.kubernetesUid(namespace, name));
      return { profile: 'kubernetes', issuer, claims: claimed({ sub: `system:serviceaccount:${namespace}:${name}`, 'kubernetes.io.serviceaccount.uid': uid }) };
    }
    case 'gcp': {
      const account = flags.gcp!;
      const sub = /^\d+$/.test(account) ? account : GOOGLE_ACCOUNT.test(account) ? await lookup.gcpUniqueId(account) : null;
      if (sub === null) throw new Error(`--gcp takes a service account's email or unique ID, not ${account}`);
      return { profile: 'gcp', issuer: GOOGLE_ISSUER, claims: claimed({ sub }) };
    }
    case 'azure': {
      const tenant = required('tenant', "the managed identity's tenant ID");
      const object = required('object', "the managed identity's object ID");
      const audience = required('audience', "the application ID URI Entra mints its tokens for, the resource's audience");
      return { profile: 'azure', issuer: flags.issuer ?? `https://sts.windows.net/${tenant}/`, claims: claimed({ tid: tenant, oid: object }), policy: { audience } };
    }
    case 'fly': {
      if (!DNS_LABEL.test(flags.fly!)) throw new Error(`--fly takes the organization's slug, as its tokens' issuer names it, not ${flags.fly}`);
      const orgId = required('org-id', "the organization's ID");
      const appId = required('app-id', "the app's ID");
      return { profile: 'fly', issuer: `https://oidc.fly.io/${flags.fly}`, claims: claimed({ org_id: orgId, app_id: appId }) };
    }
    case 'vercel': {
      if (!DNS_LABEL.test(flags.vercel!)) throw new Error(`--vercel takes the team's slug, as its tokens' issuer names it, not ${flags.vercel}`);
      const ownerId = required('owner-id', "the team's ID, from .vercel/project.json's orgId");
      const projectId = required('project-id', "the project's ID, from .vercel/project.json's projectId");
      const claims = claimed({ owner_id: ownerId, project_id: projectId, environment: flags['vercel-environment'] ?? 'production' });
      return { profile: 'vercel', issuer: flags.issuer ?? `https://oidc.vercel.com/${flags.vercel}`, claims };
    }
    case 'enrollment':
    case 'cloudflare':
      if (Object.keys(extra).length > 0) throw new Error(`a ${platform} binding names no claims: its proof carries none`);
      return { profile: platform, issuer: null, claims: {} };
  }
}

/** The platforms' CLIs, as the person running `coffre trust` is signed in to them. */
export function platformLookup(): PlatformLookup {
  return {
    async awsRole(name) {
      const instead = 'add --role-id <AROA…>';
      const [roleId, arn] = parsed(await run('aws', ['iam', 'get-role', `--role-name=${name}`, '--query', 'Role.[RoleId,Arn]', '--output', 'json'], instead), 'aws iam get-role', instead) as unknown[];
      if (typeof roleId !== 'string' || !/^AROA[A-Z0-9]+$/.test(roleId) || typeof arn !== 'string') throw new Error(`aws iam get-role answered no role ID and ARN; ${instead}`);
      return { roleId, arn };
    },
    async kubernetesIssuer() {
      const instead = "add --issuer, the cluster's service account issuer";
      const { issuer } = (parsed(await run('kubectl', ['get', '--raw', '/.well-known/openid-configuration'], instead), 'kubectl get --raw', instead) ?? {}) as { issuer?: unknown };
      if (typeof issuer !== 'string' || issuer === '') throw new Error(`the cluster's discovery names no issuer; ${instead}`);
      return issuer;
    },
    async kubernetesUid(namespace, name) {
      const instead = 'add --uid <uid>';
      const uid = (await run('kubectl', ['get', 'serviceaccount', name, '--namespace', namespace, '--output', 'jsonpath={.metadata.uid}'], instead)).trim();
      if (!UUID.test(uid)) throw new Error(`kubectl answered no service account UID; ${instead}`);
      return uid;
    },
    async gcpUniqueId(email) {
      const instead = 'name it by its unique ID: --gcp <digits>';
      const id = (await run('gcloud', ['iam', 'service-accounts', 'describe', email, '--format=value(uniqueId)'], instead)).trim();
      if (!/^\d+$/.test(id)) throw new Error(`gcloud answered no unique ID; ${instead}`);
      return id;
    },
  };
}

/** A platform CLI's JSON, or a sentence saying what to add instead. */
function parsed(out: string, what: string, instead: string): unknown {
  try {
    return JSON.parse(out);
  } catch {
    throw new Error(`${what} answered what is not JSON; ${instead}`);
  }
}

/** A platform CLI's output, or a sentence saying what to add instead. */
function run(command: string, args: string[], instead: string): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
      if (error === null) {
        resolve(stdout);
        return;
      }
      const what = `${command} ${args.slice(0, 2).join(' ')}`;
      const why = (error as NodeJS.ErrnoException).code === 'ENOENT'
        ? `${command} is not installed here`
        : error.killed ? `${what} did not answer within 30 s`
        : `${what} failed${stderr.trim() === '' ? '' : `: ${stderr.trim().split('\n')[0]!.slice(0, 200)}`}`;
      reject(new Error(`${why}; ${instead}`));
    });
  });
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
  return { profile: 'custom', issuer: flags.issuer!, claims: claimsFrom(flags) };
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

/** A binding's policy as the server shows it: `checkPolicy`'s, with `reads` by path and key name. */
export type PolicyView = PolicyRequest & { keyAudience?: true };

/** A binding, as the lines describing it take it: a plan, a saved one, and a workload's with its policy. */
type Described = Pick<BindingPlan, 'profile' | 'issuer' | 'jwksUri' | 'keys' | 'claims'> & { scope: BindingPlan['scope'] | null; policy?: PolicyView | null };

/** A binding, or a plan for one, as lines: what it trusts, every claim in full, and a workload's policy. */
export function describeBinding(binding: Described): string[] {
  const width = Math.max(0, ...Object.keys(binding.claims).map((name) => name.length));
  const claims = Object.entries(binding.claims).map(([name, value], i) => `  ${i === 0 ? 'claims ' : '       '}  ${name.padEnd(width)}  ${claimValues(value).join(', ')}`);
  // A proof that is no ID token has no issuer to ask, and no keys.
  const urn = (Object.values(PROFILE_URNS) as string[]).includes(binding.issuer);
  const signer = urn ? [] : [`  issuer   ${binding.issuer}`, `  keys     ${keysLine(binding)}`];
  return [`  profile  ${binding.profile}`, ...signer, ...claims, `  reaches  ${reaches(binding.scope)}`, ...policyLines(binding.profile, binding.policy ?? null)];
}

/**
 * A workload binding's policy, a line for each thing it says, and what
 * each costs: a key listed in `reads` is a value its platform then holds.
 */
export function policyLines(profile: string, policy: PolicyView | null): string[] {
  if (policy === null) return [];
  const uploads = policy.unsignedUploads === true ? '; streamed uploads no digest binds go through' : '';
  // An enrollment's session lives as long as its code, renewed or dead within 90 s; a Worker's call is no session.
  const sessions = profile === 'enrollment'
    ? `  sessions key-bound, each renewed every 30 s and ended at its code's expiry, ${policy.sessionDays ?? 30} days after minting${uploads}`
    : profile === 'cloudflare' ? null : `  sessions key-bound, at most ${policy.sessionHours ?? 24} h from each proof${uploads}`;
  const lines = sessions === null ? [] : [sessions];
  if (policy.audience !== undefined) lines.push(`  audience ${policy.audience}`);
  else if (policy.keyAudience === true || (KEY_NAMING_PROFILES as readonly string[]).includes(profile)) lines.push("  audience names the session's key: <publicUrl>#jkt=<thumbprint>");
  const reads = Object.entries(policy.reads ?? {});
  if (reads.length === 0) lines.push('  reads    nothing: every secret value is used through coffre, never read');
  for (const [i, [place, keys]] of reads.entries()) {
    lines.push(`  ${i === 0 ? 'reads   ' : '        '} ${place}: ${keys === '*' ? 'every key, those made later included' : keys.join(', ')}, exposed if ${profile} is breached`);
  }
  if (policy.sources !== undefined) lines.push(`  from     ${policy.sources.join(', ')}`);
  if (profile === 'enrollment') {
    const minted = policy.mintedBy === undefined ? 'its managers' : `its managers and ${shownMember(policy.mintedBy)}`;
    lines.push(`  codes    minted by ${minted}, ${policy.sessionDays ?? 30} days each; up to ${2 * (policy.replicas ?? 1)} sessions of ${policy.replicas} replica${policy.replicas === 1 ? '' : 's'}`);
    lines.push(`           ${policy.onContention === 'alert' ? 'alerts' : 'freezes'} when a copy contends past ${policy.overlapMinutes ?? 15} minutes of overlap${policy.approve === true ? '; each session waits for approval' : ''}`);
  }
  return lines;
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

export function describePlan(member: string, plan: BindingPlan & { policy?: PolicyView | null }, applied: BindingView | null): string {
  const [who, how] = plan.policy == null ? ['CI runs', 'by OIDC'] : [runsOf(plan), 'for key-bound sessions'];
  const lines = [applied === null ? `Would trust ${who} to sign in as ${shownMember(member)}, ${how}:` : `Trusted ${who} to sign in as ${shownMember(member)}, ${how}, binding ${applied.id}:`];
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
    // A workload's (docs/design/workload-access.md, section 4), by what its proof names.
    case 'aws':
      return `AWS workloads running as role ${claims.role_id} of account ${claims.account}`;
    case 'kubernetes': {
      const [, namespace, name] = /^system:serviceaccount:([^:]+):(.+)$/.exec(claims.sub ?? '') ?? [];
      return `pods of service account ${namespace}/${name} (UID ${claims['kubernetes.io.serviceaccount.uid']}) of the cluster ${binding.issuer}`;
    }
    case 'gcp':
      return `Google Cloud workloads running as service account ${claims.sub}`;
    case 'azure':
      return `Azure workloads of managed identity ${claims.oid} in tenant ${claims.tid}`;
    case 'fly':
      return `Fly Machines of app ${claims.app_id} in organization ${claims.org_id}`;
    case 'vercel':
      return `Vercel functions of project ${claims.project_id} of team ${claims.owner_id}, in ${claims.environment}`;
    case 'enrollment':
      return 'workloads enrolled with a code minted for this binding';
    case 'cloudflare':
      return "Workers that call it through a service binding's props";
    default: {
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
  if (bindings.length === 0) return `${shownMember(member)} trusts no CI runs or workloads: none signs in as it by OIDC or a platform's proof\n`;
  const blocks = bindings.map((binding) => {
    const used = binding.lastUsedAt === null ? 'never used' : `last used ${binding.lastUsedAt.slice(0, 16).replace('T', ' ')}`;
    const head = `${binding.id}${binding.label === null ? '' : `  ${binding.label}`}  (added by ${binding.createdBy} ${binding.createdAt.slice(0, 10)}, ${used})`;
    return [head, ...describeBinding(binding)].join('\n');
  });
  return `${blocks.join('\n\n')}\n`;
}

/**
 * The audit log in sentences: who did what, to what. One entry is one
 * human action, named for it (`secret.read`, `access.grant`, …); a batch of
 * them, one reveal of twelve secrets, shares an operation and reads as one
 * line, "ran market/prod: 12 secrets".
 *
 * A sentence is parts rather than a string, so the page can make the people
 * and places in it links. `plain` flattens it, for tests and titles.
 */
import { shownMember, type AuditEntryView } from '@coffre/client';
import { INSTANCE_ROLES, isBuiltinRole, isInstanceRole, isScope, ROLES, scopeInWords, type Scope } from '@coffre/core/access';

/** What a sentence is made from: an entry of the log, as `GET /api/audit` gives it. */
export type AuditEntry = Pick<
  AuditEntryView,
  | 'seq'
  | 'author'
  | 'actorType'
  | 'actorId'
  | 'action'
  | 'decision'
  | 'reason'
  | 'detail'
  | 'subject'
  | 'project'
  | 'environment'
  | 'key'
  | 'version'
  | 'secrets'
  | 'operationId'
  | 'metadata'
>;

/**
 * Text, a place (`market`, `market/prod`, `market/prod/KEY`), or a member,
 * as the log stores it (`user:…`, `token:…`): `shownMember` says it as people
 * read it, `service:…`, where it is shown.
 */
export type Part = string | { place: string } | { member: string };

export type Sentence = { parts: Part[]; refused: boolean };

/** What one template needs: the line's leading entry, its batch, and how it was decided. */
type Facts = {
  entry: AuditEntry;
  /** Every entry of the batch, the lead included, a read of several once per secret (`perSecret`). */
  batch: AuditEntry[];
  /** Secrets the batch was about. */
  count: number;
  refused: boolean;
};

type Template = {
  /** What they did: "revealed". */
  did: string | ((facts: Facts) => string);
  /** What they tried, after "tried to": "reveal". */
  tried: string | ((facts: Facts) => string);
  /** To what: "market/prod/API_KEY". */
  what: (facts: Facts) => Part[];
  /** Said only of what happened: ", now version 5". */
  then?: (facts: Facts) => Part[];
};

// --- the pieces of a sentence ---------------------------------------------------

const text = (value: unknown): string | null => (typeof value === 'string' && value !== '' ? value : null);
const number = (value: unknown): number | null => (typeof value === 'number' ? value : null);

/** The entry's place, as deep as it goes. */
function place({ project, environment, key }: AuditEntry): Part[] {
  const path = [project, environment, key].filter((part): part is string => part !== null);
  return path.length === 0 ? ['coffre'] : [{ place: path.join('/') }];
}

function environmentOf({ project, environment }: AuditEntry): Part[] {
  return place({ project, environment, key: null } as AuditEntry);
}

/** The member an entry is about: its subject, or the principal a token entry names. */
function subject(entry: AuditEntry): Part[] {
  if (entry.subject !== null) return [{ member: entry.subject }];
  const id = text(entry.metadata.principalId);
  if (id === null) return ['someone'];
  return [{ member: `${entry.metadata.principalType === 'service' ? 'token' : 'user'}:${id}` }];
}

/** Whether a token entry is about a personal token, which acts as its person, rather than a service account's. */
function personal(entry: AuditEntry): boolean {
  return entry.metadata.kind === 'personal';
}

/** A personal token's label, as it was made: ` "cursor-agent"`. */
function labelled(entry: AuditEntry): Part[] {
  const label = text(entry.metadata.label);
  return label === null ? [] : [` “${label}”`];
}

/** Why the vault made someone an Owner itself, said after it. */
function owned(entry: AuditEntry): Part[] {
  return entry.metadata.reason === 'owners' ? [': the deployment names them one'] : [];
}

/** An MCP client, by the name it connected under. */
function app(entry: AuditEntry): Part[] {
  return [text(entry.metadata.clientName) ?? 'an app'];
}

/** A tool's call: its name, and what it named. */
function tool(entry: AuditEntry): Part[] {
  const names = Array.isArray(entry.metadata.names) ? entry.metadata.names.filter((name): name is string => typeof name === 'string') : [];
  return [text(entry.metadata.tool) ?? 'a tool', ...(names.length === 0 ? [] : [` on ${names.join(', ')}`])];
}

/** The client a request came through, said after what it did: "via Claude". */
function via(entry: AuditEntry): Part[] {
  const client = (entry.metadata.via as { clientName?: unknown } | undefined)?.clientName;
  return typeof client === 'string' ? [` via ${client}`] : [];
}

/** Why coffre itself ended a connection, said after it. */
const DISCONNECTED: Record<string, string> = {
  code_reused: ': its sign-in code was used twice',
  refresh_reused: ': a refresh token it had replaced was used again',
  revocation_endpoint: ', at its own request',
  superseded: ': a connection with more scopes replaced it',
};

function plural(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}

/** A batch reads as its environment and a count; one entry as its secret. */
/**
 * The secrets a read or write was about. A read through a reference is a
 * read of its source, "market/prod/DATABASE_URL through
 * billing/prod/DATABASE_URL"; a run that read some that way is a run of
 * the environment that holds them. A value a fork inherits is its parent's,
 * read in the fork: "market/prod/STRIPE_KEY in market/prod-eu".
 */
function secrets(facts: Facts): Part[] {
  const through = (entry: AuditEntry) => text((entry.metadata.via as { path?: unknown } | undefined)?.path);
  // The fork a value was inherited in, by path: in its parent's project, which holds the reference a read went through.
  const forkOf = (entry: AuditEntry) => {
    const slug = text((entry.metadata.through as { slug?: unknown } | undefined)?.slug);
    const project = through(entry)?.split('/')[0] ?? entry.project;
    return slug === null || project === null ? null : `${project}/${slug}`;
  };
  if (facts.batch.length === 1) {
    const [held, fork] = [through(facts.entry), forkOf(facts.entry)];
    return [...place(facts.entry), ...(held === null ? [] : [' through ', { place: held }]), ...(fork === null ? [] : [' in ', { place: fork }])];
  }
  const fork = facts.batch.map(forkOf).find((path) => path !== null);
  const own = facts.batch.find((entry) => through(entry) === null && forkOf(entry) === null);
  const held = facts.batch.map(through).filter((path): path is string => path !== null);
  const inherited = facts.batch.filter((entry) => forkOf(entry) !== null).length;
  const where = fork !== undefined && fork !== null
    ? [{ place: fork }]
    : own !== undefined ? environmentOf(own) : [{ place: held[0]!.split('/').slice(0, 2).join('/') }];
  return [
    ...where,
    facts.refused ? ', ' : ': ',
    plural(facts.count, 'secret'),
    ...(held.length === 0 ? [] : [`, ${held.length} through ${held.length === 1 ? 'a reference' : 'references'}`]),
    ...(inherited === 0 ? [] : [`, ${inherited} inherited`]),
  ];
}

/** "market/prod/OLD", or "OLD and STALE in market/prod" for an archive of several keys refused. */
function archivedKeys(entry: AuditEntry): Part[] {
  const keys = Array.isArray(entry.metadata.keys) ? entry.metadata.keys.filter((key): key is string => text(key) !== null) : [];
  if (entry.key !== null || keys.length === 0) return place(entry);
  return [keys.length === 1 ? keys[0]! : `${keys.slice(0, -1).join(', ')} and ${keys.at(-1)!}`, ' in ', ...environmentOf(entry)];
}

/** "SENTRY_DSN in market/dev", or "3 keys in market/dev" for a Dismiss all. */
function missingKeys(facts: Facts): Part[] {
  const key = text(facts.entry.metadata.key);
  return [facts.batch.length === 1 && key !== null ? key : plural(facts.count, 'key'), ' in ', ...environmentOf(facts.entry)];
}

/** "billing/prod/DATABASE_URL a reference to market/prod/DATABASE_URL", from either author's entry. */
function referenceTo(entry: AuditEntry): Part[] {
  const holder = text(entry.metadata.subject);
  const key = text(entry.metadata.key);
  const source = text(entry.metadata.source) ?? text((entry.metadata.source as { path?: unknown } | undefined)?.path);
  return [
    ...(holder !== null ? [{ place: holder }] : key !== null ? place(entry) : environmentOf(entry)),
    ...(source === null ? [] : [' a reference to ', { place: source }]),
  ];
}

const READ_VERBS: Record<string, [did: string, tried: string]> = {
  reveal: ['revealed', 'reveal'],
  run: ['ran', 'run'],
  compare: ['compared', 'compare'],
  copy: ['copied', 'copy'],
  // The credential proxy's: a value injected into a request for its person, or one handed to their app.
  use: ['used', 'use'],
  expose: ['was given', 'be given'],
};

function readVerb({ entry }: Facts): [string, string] {
  return READ_VERBS[text(entry.metadata.purpose) ?? 'reveal'] ?? READ_VERBS.reveal!;
}

const placeTemplates = (kind: 'project' | 'environment'): Record<string, Template> => {
  // A personal config by what it is a config of, `market/dev`: its own slug is generated, and shown nowhere else.
  const of = (entry: AuditEntry): string | null => {
    const parent = text(entry.metadata.personal) ?? text(entry.metadata.with);
    return parent === null || entry.project === null ? null : `${entry.project}/${parent}`;
  };
  const what = (facts: Facts): Part[] => {
    const personal = kind === 'environment' ? of(facts.entry) : null;
    if (personal !== null) return ['a personal config of ', { place: personal }];
    if (kind === 'environment' && facts.entry.metadata.personal === true) return [`a personal config, ${text(facts.entry.metadata.path) ?? ''}`];
    return [`${kind} `, ...(kind === 'project' ? place({ ...facts.entry, environment: null, key: null }) : environmentOf(facts.entry))];
  };
  return {
    [`${kind}.create`]: {
      did: 'created',
      tried: 'create',
      what,
      // A fork names the environment it copied.
      then: ({ entry }) =>
        text(entry.metadata.inherits) !== null
          ? [`, inheriting from ${text(entry.metadata.inherits)}`]
          : text(entry.metadata.from) === null
            ? []
            : [`, a fork of ${text(entry.metadata.from)}`],
    },
    [`${kind}.update`]: { did: 'changed', tried: 'change', what },
    [`${kind}.archive`]: { did: 'archived', tried: 'archive', what },
    [`${kind}.restore`]: { did: 'restored', tried: 'restore', what },
    // Named by its tombstone from then on, `market~deleted-2026-10-05`, as every entry about it is.
    [`${kind}.delete`]: { did: 'deleted', tried: 'delete', what },
  };
};

// --- one template per action ----------------------------------------------------

const TEMPLATES: Record<string, Template> = {
  'secret.read': {
    did: (facts) => readVerb(facts)[0],
    tried: (facts) => readVerb(facts)[1],
    what: secrets,
  },
  'secret.write': {
    // New secrets are added, others changed; a batch of both is written. One whose level changed is made that.
    did: ({ entry, batch }) => {
      if (batch.length === 1 && text(entry.metadata.was) !== null) return 'made';
      const firsts = batch.filter((entry) => entry.version === 1).length;
      return firsts === batch.length ? 'added' : firsts === 0 ? 'changed' : 'wrote';
    },
    tried: 'change',
    what: secrets,
    // Who sees the value, where it is not a secret's or it changed: a mark keeps the value, a write gives a new one.
    then: ({ entry, batch }) => {
      const version = batch.length > 1 || entry.version === null || entry.version === 1 ? [] : [`, now version ${entry.version}`];
      if (batch.length > 1) return version;
      const level = entry.metadata.sensitive === true ? 'sensitive' : entry.metadata.plain === true ? 'plain' : 'secret';
      if (text(entry.metadata.was) !== null) return [` ${level}`, ...(number(entry.metadata.kept) === null ? [' with a new value'] : []), ...version];
      return [...version, ...(level === 'plain' ? [', as a plain value, no secret'] : level === 'sensitive' ? [', as a sensitive value, shown to nobody'] : [])];
    },
  },
  // The credential proxy's own entry beside the vault's read: which credential the keys went into, where, and by which road.
  'credential.use': {
    did: ({ entry }) => (entry.metadata.purpose === 'expose' ? 'was given the values of' : 'used the credential'),
    tried: ({ entry }) => (entry.metadata.purpose === 'expose' ? 'be given the values of' : 'use the credential'),
    what: ({ entry }) => [
      text(entry.metadata.credential) ?? '',
      ...(text(entry.metadata.host) === null ? [] : [` on ${text(entry.metadata.host)}`]),
      ...(entry.metadata.egress === true ? [", through the deployment's egress"] : []),
    ],
  },
  'secret.restore': {
    did: 'restored',
    tried: 'restore',
    what: ({ entry }) => [...place(entry), ...(number(entry.metadata.from) === null ? [] : [` to version ${number(entry.metadata.from)}`])],
    then: ({ entry }) => (entry.version === null ? [] : [`, now ${entry.version}`]),
  },
  // A sensitive value made a secret in place, by an Owner of its project: its value kept, shown to its readers from then on.
  'secret.loosen': {
    did: 'made',
    tried: 'make',
    what: ({ entry }) => place(entry),
    then: ({ entry }) => [
      ` ${text(entry.metadata.to) ?? 'secret'}, from ${text(entry.metadata.from) ?? 'sensitive'}, its value kept`,
      ...(entry.version === null ? [] : [`, now version ${entry.version}`]),
    ],
  },
  'secret.rename': {
    did: 'renamed',
    tried: 'rename',
    what: ({ entry }) => [...place(entry), ...(text(entry.metadata.nextKey) === null ? [] : [` to ${text(entry.metadata.nextKey)}`])],
    // In a fork, carried down from a rename in its parent.
    then: ({ entry }) => (text(entry.metadata.parent) === null ? [] : [`, as ${text(entry.metadata.parent)} did`]),
  },
  'secret.archive': { did: 'archived', tried: 'archive', what: ({ entry }) => archivedKeys(entry) },
  // In a fork: its own value set aside, kept, for its parent's.
  'secret.reset': {
    did: 'reset',
    tried: 'reset',
    what: ({ entry }) => place(entry),
    then: ({ entry }) => (text(entry.metadata.from) === null ? [] : [` to ${text(entry.metadata.from)}'s value`]),
  },
  'missing.dismiss': {
    did: 'dismissed',
    tried: 'dismiss',
    what: (facts) => missingKeys(facts),
    then: () => [' as not needed'],
  },
  'missing.restore': { did: 'restored', tried: 'restore', what: (facts) => missingKeys(facts), then: () => [' to the missing keys'] },
  'secret.reference': { did: 'made', tried: 'make', what: ({ entry }) => referenceTo(entry) },
  'reference.create': { did: 'made', tried: 'make', what: ({ entry }) => referenceTo(entry) },
  'reference.end': {
    did: ({ entry }) => (entry.metadata.reason === 'replaced' ? 'gave a value of its own to' : entry.metadata.reason === 'abandoned' ? 'abandoned' : 'broke'),
    tried: ({ entry }) => (entry.metadata.reason === 'replaced' ? 'replace' : entry.metadata.reason === 'abandoned' ? 'abandon' : 'break'),
    what: ({ entry }) => {
      const source = text((entry.metadata.source as { path?: unknown } | undefined)?.path);
      const holder = text(entry.metadata.subject);
      if (entry.metadata.reason === 'replaced') return [...(holder === null ? ['a reference'] : [{ place: holder }]), ...(source === null ? [] : [', no longer a reference to ', { place: source }])];
      return ['the reference ', ...(holder === null ? [] : [{ place: holder }]), ...(source === null ? [] : [' to ', { place: source }])];
    },
    then: ({ entry }) => (entry.metadata.reason === 'abandoned' ? [', which its write never stored'] : []),
  },
  'secret.unarchive': { did: 'brought back', tried: 'bring back', what: (facts) => place(facts.entry) },
  'secret.move': { did: 'moved', tried: 'move', what: (facts) => place(facts.entry), then: ({ entry }) => intoFolder(entry) },
  ...placeTemplates('project'),
  'project.move': {
    did: 'moved',
    tried: 'move',
    what: ({ entry }) => ['project ', ...place({ ...entry, environment: null, key: null })],
    then: ({ entry }) => intoFolder(entry),
  },
  ...placeTemplates('environment'),
  'environment.fork': {
    did: 'forked',
    tried: 'fork',
    what: ({ entry }) => [...environmentOf(entry), ...(text(entry.metadata.slug) === null ? [] : [` into ${text(entry.metadata.slug)}`])],
  },
  'access.grant': {
    did: 'gave',
    tried: 'give',
    what: ({ entry }) => [...subject(entry), ` ${text(entry.metadata.role) ?? 'a role'} on `, ...placeOnly(entry)],
    then: ({ entry }) => [
      ...(text(entry.metadata.previousRole) === null ? [] : [`, was ${text(entry.metadata.previousRole)}`]),
      ...(text(entry.metadata.expiresAt) === null ? [] : [`, until ${text(entry.metadata.expiresAt)!.slice(0, 10)}`]),
      ...(entry.metadata.reason === 'every-project' ? [', for a grant on every project'] : []),
    ],
  },
  'access.revoke': {
    did: 'took',
    tried: 'take',
    what: ({ entry }) => [
      ...(text(entry.metadata.previousRole ?? entry.metadata.role) === null ? ['access to '] : [`${text(entry.metadata.previousRole ?? entry.metadata.role)} on `]),
      ...placeOnly(entry),
      ' from ',
      ...subject(entry),
    ],
    // The vault replacing a grant on every project of 0.4: by what, an instance role or project grants.
    then: ({ entry }) => {
      const by = entry.metadata.replacedBy as { role?: unknown } | undefined;
      if (by === undefined) return [];
      const role = typeof by.role === 'string' ? roleName(by.role) : null;
      return [role === null || role === 'Member' ? ', replaced by project grants' : `, replaced by the instance role ${role}`];
    },
  },
  'member.add': {
    did: 'added',
    tried: 'add',
    what: ({ entry }) => [
      ...subject(entry),
      ...(entry.metadata.rootAdmin === true ? [' as a root admin'] : entry.metadata.owner === true ? [' as an owner'] : asRole(entry)),
    ],
    then: ({ entry }) => owned(entry),
  },
  'member.remove': {
    did: 'removed',
    tried: 'remove',
    what: (facts) => subject(facts.entry),
    then: ({ entry }) => (number(entry.metadata.revoked) === null ? [] : [`, who held ${plural(number(entry.metadata.revoked)!, 'grant')}`]),
  },
  'member.restore': {
    did: 'brought back',
    tried: 'bring back',
    what: ({ entry }) => [...subject(entry), ...asRole(entry)],
    then: ({ entry }) => owned(entry),
  },
  'member.role': {
    did: 'made',
    tried: 'make',
    what: ({ entry }) => [...subject(entry), ` ${article(roleName(text(entry.metadata.role) ?? 'member') ?? 'Member')}`, ...scoped(entry)],
    then: ({ entry }) => {
      const before = roleName(text(entry.metadata.previousRole) ?? '');
      return [
        ...(before === null ? [] : [`, was ${before}`]),
        ...(entry.metadata.reason === 'every-project' ? [', for their grants on every project'] : []),
        ...owned(entry),
      ];
    },
  },
  'member.owner': {
    did: ({ entry }) => (entry.metadata.owner === false ? 'took owner from' : 'made'),
    tried: ({ entry }) => (entry.metadata.owner === false ? 'take owner from' : 'make'),
    what: ({ entry }) => [...subject(entry), ...(entry.metadata.owner === false ? [] : [' an owner'])],
  },
  // Where people set up service accounts themselves, which those who run the instance set.
  'settings.change': {
    did: 'set',
    tried: 'set',
    what: ({ entry }) => ['where people set up service accounts', ...setting(entry.metadata.serviceAccounts).map((words) => `: ${words}`)],
    then: ({ entry }) => {
      const previous = (entry.metadata.previous as { serviceAccounts?: unknown } | undefined)?.serviceAccounts;
      return setting(previous).map((words) => `, was ${words}`);
    },
  },
  // The roles an Owner edits and which environments are protected (docs/design/roles.md), the vault's to change.
  'policy.change': {
    did: ({ entry }) => POLICY_VERBS[policyOf(entry).verb][0],
    tried: ({ entry }) => POLICY_VERBS[policyOf(entry).verb][1],
    what: ({ entry }) => policyOf(entry).what,
  },
  // A binding trusts CI runs to sign in as a service; removing one is its tombstone.
  'token.bind': {
    did: 'trusted CI runs to sign in as',
    tried: 'trust CI runs to sign in as',
    what: (facts) => subject(facts.entry),
    then: ({ entry }) => [...inGitHubEnvironment(entry), ...reaching(entry)],
  },
  // The tokens and bindings 0.4 made, given their own scope when 0.5 first checked a credential: what their account held then.
  'token.seal': {
    did: 'sealed',
    tried: 'seal',
    what: ({ entry }) => [`${sealedOf(entry)} of `, ...subject(entry)],
    then: ({ entry }) => reaching(entry, ', reaching nothing'),
  },
  'token.unbind': {
    did: 'stopped trusting CI runs to sign in as',
    tried: 'stop trusting CI runs to sign in as',
    what: (facts) => subject(facts.entry),
  },
  'vault.tampered': {
    did: 'found',
    tried: 'check',
    what: ({ entry }) => [
      ...(entry.subject === null ? ['an entry'] : [...subject(entry), "'s record"]),
      ` tampered with: ${TAMPERING[entry.reason ?? ''] ?? 'it fails its seal'}`,
    ],
  },
  'key.rotate': { did: 'rotated its key', tried: 'rotate its key', what: () => [] },
  // An MCP client a person connected, such as Claude: named as the consent page showed it.
  'mcp.connect': { did: 'connected', tried: 'connect', what: ({ entry }) => app(entry) },
  // A tool an MCP client called, by its name, and the places it named.
  'mcp.call': { did: 'used', tried: 'use', what: ({ entry }) => tool(entry), then: ({ entry }) => via(entry) },
  // A person's decision, on coffre's page, on a change an MCP client asked for; the change's own entries follow, via the client.
  'mcp.approve': { did: 'approved', tried: 'approve', what: ({ entry }) => tool(entry), then: ({ entry }) => [` for ${text(entry.metadata.clientName) ?? 'an app'}`] },
  'mcp.deny': { did: 'turned down', tried: 'turn down', what: ({ entry }) => tool(entry), then: ({ entry }) => [` for ${text(entry.metadata.clientName) ?? 'an app'}`] },
  'mcp.view': { did: 'opened an approval', tried: 'open an approval', what: () => [] },
  // The app's prompt declined, which cancels the approval it would have opened.
  'mcp.cancel': { did: 'cancelled', tried: 'cancel', what: ({ entry }) => tool(entry), then: ({ entry }) => via(entry) },
  'mcp.disconnect': {
    did: 'disconnected',
    tried: 'disconnect',
    what: ({ entry }) => [...app(entry), ...(entry.metadata.principalId === undefined ? [] : [' of ', ...subject(entry)])],
    then: ({ entry }) => [DISCONNECTED[text(entry.metadata.reason) ?? ''] ?? ''],
  },

  // Detail, hidden unless asked for.
  sign_in: {
    did: ({ entry }) => (entry.metadata.kind === 'cli' ? 'signed in to the CLI' : 'signed in'),
    tried: 'sign in',
    what: ({ entry }) => (text(entry.metadata.provider) === null ? [] : [`with ${text(entry.metadata.provider)}`]),
  },
  sign_out: { did: 'signed out', tried: 'sign out', what: () => [] },
  // A personal token is its person's own, and named by its label; a bearer token is a service account's.
  'token.create': {
    did: ({ entry }) => (entry.metadata.kind === 'handle' ? 'made a handle' : personal(entry) ? 'made a personal token' : 'issued a bearer token to'),
    tried: ({ entry }) => (entry.metadata.kind === 'handle' ? 'make a handle' : personal(entry) ? 'make a personal token' : 'issue a bearer token to'),
    what: ({ entry }) => (personal(entry) ? labelled(entry) : subject(entry)),
    then: ({ entry }) => reaching(entry),
  },
  'token.revoke': {
    did: ({ entry }) => (personal(entry) ? 'revoked a personal token of' : 'revoked a bearer token of'),
    tried: ({ entry }) => (personal(entry) ? 'revoke a personal token of' : 'revoke a bearer token of'),
    what: (facts) => subject(facts.entry),
  },
  // A personal token refused a route only its person reaches: the route, as the API names it.
  'token.use': {
    did: 'used a personal token for',
    tried: 'use a personal token for',
    what: ({ entry }) => [text(entry.metadata.route) ?? 'something'],
  },
  'device.approve': { did: 'approved a CLI sign-in', tried: 'approve a CLI sign-in', what: () => [] },
  'device.deny': { did: 'turned down a CLI sign-in', tried: 'turn down a CLI sign-in', what: () => [] },
  'mcp.read': { did: 'used', tried: 'use', what: ({ entry }) => tool(entry), then: ({ entry }) => via(entry) },
  'mcp.token': {
    did: ({ entry }) => (entry.metadata.grant === 'refresh_token' ? 'refreshed the tokens of' : 'gave its first tokens to'),
    tried: 'give tokens to',
    what: ({ entry }) => app(entry),
  },
  'account.link': {
    did: 'linked',
    tried: 'link',
    what: ({ entry }) => [`a ${text(entry.metadata.provider) ?? 'sign-in'} account`],
  },
  'account.unlink': {
    did: 'unlinked',
    tried: 'unlink',
    what: ({ entry }) => [`a ${text(entry.metadata.provider) ?? 'sign-in'} account`],
  },
  'key.wrap': { did: 'sealed the key of', tried: 'seal the key of', what: (facts) => versioned(facts.entry) },
  'key.rewrap': { did: 'resealed the key of', tried: 'reseal the key of', what: (facts) => versioned(facts.entry) },
  'key.intent': { did: 'asked KMS about', tried: 'ask KMS about', what: (facts) => secrets(facts) },
  'key.check': {
    did: 'recorded the check value of',
    tried: 'check',
    what: ({ entry }) => [['the', text(entry.metadata.kekProvider) === 'local' ? null : text(entry.metadata.kekProvider), 'vault key', text(entry.metadata.kekId)].filter((word) => word !== null).join(' ')],
  },
  'audit.heartbeat': { did: 'checked in', tried: 'check in', what: () => [] },
  'audit.checkpoint': {
    did: 'signed the log',
    tried: 'sign the log',
    what: ({ entry }) => (number(entry.metadata.seq) === null ? [] : [`through entry ${number(entry.metadata.seq)}`]),
  },

  // Only ever refused: a read of a list, which is not logged when allowed.
  'secret.list': { did: 'listed', tried: 'list', what: ({ entry }) => environmentOf(entry) },
  'secret.history': { did: 'read the history of', tried: 'read the history of', what: (facts) => place(facts.entry) },
  'secret.update': { did: 'changed', tried: 'change', what: (facts) => place(facts.entry) },
};

/** " to the folder stripe", or " out of its folder". */
function intoFolder(entry: AuditEntry): Part[] {
  const folder = text(entry.metadata.to);
  return [folder === null ? ' out of its folder' : ` to the folder ${folder}`];
}

/** An instance role's name, from its slug; null for none it knows. */
function roleName(role: string): string | null {
  return isInstanceRole(role) ? INSTANCE_ROLES[role].name : null;
}

/** What a policy change did, and what it did it to, as `did` and `tried` say it. */
const POLICY_VERBS = {
  protect: ['protected', 'protect'],
  unprotect: ['unprotected', 'unprotect'],
  edit: ['edited', 'edit'],
  reset: ['reset', 'reset'],
  make: ['made', 'make'],
  delete: ['deleted', 'delete'],
} as const;

/**
 * A `policy.change` entry, from what it names: its `change`, an
 * environment's protection or a role's definition, and the role `before`
 * it. A built-in role's definition dropped is a reset; one an Owner made, a
 * deletion; one that was not there, made. A refusal the app wrote names the
 * role alone.
 *
 *   protected market/prod             edited the Developer role
 *   made the Release manager role     reset the Auditor instance role
 */
function policyOf(entry: AuditEntry): { verb: keyof typeof POLICY_VERBS; what: Part[] } {
  const change = record(entry.metadata.change);
  if (change.kind === 'protect') {
    const count = Array.isArray(change.environmentIds) ? change.environmentIds.length : 1;
    // A fork's, protected before its row is written, names its project alone.
    const what: Part[] = entry.environment !== null
      ? place({ ...entry, key: null })
      : entry.project === null
        ? [count === 1 ? 'an environment' : plural(count, 'environment')]
        : [count === 1 ? 'a new environment of ' : `${plural(count, 'environment')} of `, { place: entry.project }];
    return { verb: change.protected === false ? 'unprotect' : 'protect', what };
  }
  const instance = (change.kind ?? entry.metadata.kind) === 'instance-role';
  const id = text(change.role) ?? text(entry.metadata.role);
  const shipped = id !== null && (instance ? isInstanceRole(id) : isBuiltinRole(id));
  const definition = change.definition === null ? null : record(change.definition);
  const before = record(entry.metadata.before);
  const name = text(definition?.name) ?? text(record(before.definition).name)
    ?? (id === null ? null : shipped ? (instance ? INSTANCE_ROLES[id as keyof typeof INSTANCE_ROLES] : ROLES[id as keyof typeof ROLES]).name : id);
  // A reset or deletion: the vault's entry says so in its change, a refusal of the app's in its own metadata.
  const verb = change.definition === null || entry.metadata.definition === null || entry.reason === 'role_granted'
    ? (shipped ? 'reset' : 'delete')
    : before.definition === null ? 'make' : 'edit';
  return { verb, what: [name === null ? 'a role' : `the ${name} ${instance ? 'instance role' : 'role'}`] };
}

/** An object of the metadata's, or an empty one for anything else. */
function record(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function article(name: string): string {
  return `${/^[AEIOU]/.test(name) ? 'an' : 'a'} ${name}`;
}

/** Whether an entry's scope narrows the role; its projects are ids, which a sentence cannot name. */
function scoped(entry: AuditEntry): Part[] {
  const scope = entry.metadata.scope as { projects?: unknown; environments?: unknown } | undefined;
  return scope === undefined || (scope.projects === 'all' && scope.environments === 'all') ? [] : [', with a scope'];
}

/**
 * What a token or binding reaches, its scope, each role with the places it
 * holds, counted, as the log names them by id: `, reaching developer on 2 places`.
 */
function reaching(entry: AuditEntry, none = ''): Part[] {
  const scope = entry.metadata.scope;
  if (!Array.isArray(scope)) return [];
  if (scope.length === 0) return none === '' ? [] : [none];
  const byRole = new Map<string, number>();
  for (const grant of scope as { role?: unknown }[]) {
    const role = text(grant.role);
    if (role !== null) byRole.set(role, (byRole.get(role) ?? 0) + 1);
  }
  return [`, reaching ${[...byRole].map(([role, count]) => `${role} on ${plural(count, 'place')}`).join(', ')}`];
}

/** The GitHub environment a binding takes its runs from, when it names one. */
function inGitHubEnvironment(entry: AuditEntry): Part[] {
  const environment = text((entry.metadata.claims as Record<string, unknown> | undefined)?.environment);
  return environment === null || !String(entry.metadata.profile).startsWith('github') ? [] : [`, in GitHub environment ${environment}`];
}

/** The tokens and trust bindings a `token.seal` names, counted: `2 tokens and a trust binding`. */
function sealedOf(entry: AuditEntry): string {
  const count = (key: string) => (Array.isArray(entry.metadata[key]) ? (entry.metadata[key] as unknown[]).length : 0);
  const parts = [[count('tokens'), 'token'], [count('bindings'), 'trust binding']] as const;
  return parts.filter(([n]) => n > 0).map(([n, one]) => plural(n, one)).join(' and ') || 'nothing';
}

/**
 * The setting of where people set up service accounts, in words: its
 * projects counted, as the log names them by id, its environments by name.
 *
 *   All projects · all but prod      2 projects · dev only
 */
function setting(scope: unknown): string[] {
  if (!isScope(scope)) return [];
  const { projects } = scope;
  const counted: Scope = projects === 'all'
    ? scope
    : { ...scope, projects: 'only' in projects ? { only: [plural(projects.only.length, 'project')] } : { except: [plural(projects.except.length, 'project')] } };
  return [scopeInWords(counted)];
}

/** The role a member is added or brought back with, said when it is more than Member. */
function asRole(entry: AuditEntry): Part[] {
  const role = roleName(text(entry.metadata.role) ?? '');
  return role === null || role === 'Member' ? [] : [` as ${article(role)}`, ...scoped(entry)];
}

function placeOnly(entry: AuditEntry): Part[] {
  // A grant on every project names no project: its place is a path in its payload, `*` or `*/dev`.
  const everywhere = entry.project === null ? text(entry.metadata.place) : null;
  if (everywhere !== null) return [everywhere === '*' ? 'every project' : `${everywhere.slice('*/'.length)} in every project`];
  return place({ ...entry, key: null });
}

function versioned(entry: AuditEntry): Part[] {
  return [...place(entry), ...(entry.version === null ? [] : [`, version ${entry.version}`])];
}

const TAMPERING: Record<string, string> = {
  mac: "it does not carry the vault's seal",
  stale: 'an older copy was put back',
  forged_entry: 'the vault did not write it',
};

/** Why something was refused, in words. Codes from the vault and the app. */
const REASONS: Record<string, string> = {
  no_grant: 'no grant',
  bulk_limit: 'bulk limit',
  // 0.9's `people: 'stand-ins'`, in entries written before 0.10.
  stand_ins: 'people get placeholders',
  sensitive: 'the value is sensitive',
  looser: 'making it visible takes a new value',
  inherited: 'it is inherited',
  expired: 'grant expired',
  removed: 'removed from coffre',
  not_a_member: 'not a member',
  not_registered: 'not invited',
  tampered: 'their record was tampered with',
  bad_claim: 'the key did not match the secret',
  deleted: 'the place was deleted',
  not_allowed: 'not allowed',
  root_admin: 'root admins are set by the deployment',
  last_owner: 'they are the last Owner of the whole instance',
  requires_instance_admin: 'requires an admin or owner of the whole instance',
  requires_instance_owner: 'requires an instance owner',
  own_role: 'nobody changes their own role',
  own_grant: 'nobody grants themselves a role',
  service_cannot_hold_role: 'service accounts hold project grants only',
  not_service_manager: 'they hold less than the service account, or than they gave it',
  unknown_environment: 'no such environment',
  unknown_secret: 'no such secret',
  no_value: 'it holds no value',
  unknown_project: 'no such project',
  not_archived: 'it was not archived',
  referenced: 'references read it',
  kms_unavailable: 'KMS did not answer',
  wrong_kek: "the vault's key is not the one that wrapped the data",
  person_denied: 'they said no',
  too_many_connections: 'too many connected apps',
  unknown_connection: 'no such connected app',
  not_yours: "it was someone else's",
  too_many_approvals: 'too many changes waiting for approval',
  request_state: 'its retry did not match its call',
  changed: 'the change was not the one shown',
  replaced: 'what it replaces changed since it was shown',
  unconfirmed: 'what it replaces could not be read',
  disconnected: 'the app was disconnected',
  personal_token: 'only its person can, signed in as themselves',
  beyond_holder: 'more than they hold',
  role_granted: 'grants still name it',
};

/** What a missing permission meant, from the app's `missing_<permission>`. */
const MISSING: Record<string, string> = {
  secret_read: 'no grant to read it',
  secret_write: 'no grant to write',
  secret_archive: 'no grant to archive',
  audit_read: 'no grant to read the audit log',
  environment_manage: 'no grant to manage environments',
  grant_manage: 'no grant to manage access',
  project_manage: 'no grant to manage the project',
};

export function reasonInWords(reason: string | null): string {
  if (reason === null) return 'refused';
  if (reason.startsWith('missing_')) return MISSING[reason.slice('missing_'.length)] ?? 'no grant';
  return REASONS[reason] ?? reason.replace(/_/g, ' ');
}

// --- lines ----------------------------------------------------------------------

/** In a batch of mixed actions, the one the line is named for: a write, not its reads. */
const LEAD = ['secret.write', 'secret.read'];

export function leadOf(batch: AuditEntry[]): AuditEntry {
  for (const action of LEAD) {
    const found = batch.find((entry) => entry.action === action);
    if (found !== undefined) return found;
  }
  return batch[0]!;
}

/**
 * A read of several secrets, logged once for its place, as the entries it
 * would be about one secret each: its key and version, and what its own
 * part of the metadata says, such as the reference it went through. Any
 * other entry as it is.
 */
export function perSecret<T extends AuditEntry>(entry: T): T[] {
  const listed = entry.metadata.secrets;
  // One whose list was emptied or mangled, which verification would flag, still reads as itself.
  if (entry.secrets === null || entry.secrets.length === 0 || !Array.isArray(listed)) return [entry];
  return entry.secrets.map(({ key, version }, i) => {
    const own = listed[i];
    return {
      ...entry,
      key,
      version,
      secrets: null,
      metadata: { ...entry.metadata, secrets: undefined, ...(typeof own === 'object' && own !== null && !Array.isArray(own) ? own : {}) },
    };
  });
}

/** What a line says: one entry, or a batch that shares an operation. */
export function describe(batch: AuditEntry[]): Sentence {
  const entry = perSecret(leadOf(batch))[0]!;
  const same = batch.filter((other) => other.action === entry.action).flatMap(perSecret);
  const denied = same.filter((other) => other.decision === 'deny');
  const refused = denied.length === same.length;
  const facts: Facts = {
    entry,
    batch: same,
    count: new Set(same.map((other) => `${other.project}/${other.environment}/${other.key}`)).size,
    refused,
  };
  const template = TEMPLATES[entry.action];
  if (template === undefined) return { parts: [entry.action, ' ', ...place(entry)], refused };
  const say = (verb: Template['did']) => (typeof verb === 'string' ? verb : verb(facts));
  const what = template.what(facts);
  const gap = what.length === 0 ? [] : [' '];
  if (refused) {
    const reason = reasonInWords((denied[0] ?? entry).reason);
    return { parts: ['tried to ', say(template.tried), ...gap, ...what, `: ${reason}`], refused };
  }
  const partly = denied.length === 0 ? [] : [`, ${denied.length} refused: ${reasonInWords(denied[0]!.reason)}`];
  return { parts: [say(template.did), ...gap, ...what, ...(template.then?.(facts) ?? []), ...partly], refused };
}

/** Who acted, as a part: a member links to their page; coffre itself is text. */
export function who(entry: Pick<AuditEntry, 'actorType' | 'actorId'>): string | { member: string } {
  if (entry.actorType === 'user') return { member: `user:${entry.actorId}` };
  if (entry.actorType === 'service') return { member: `token:${entry.actorId}` };
  return SYSTEM[entry.actorId] ?? entry.actorId;
}

const SYSTEM: Record<string, string> = {
  scheduler: 'the scheduler',
  cron: 'the scheduler',
  vault: 'the vault',
  app: 'coffre',
};

/** Which components wrote the line, the vault first: "vault", "app", "vault, app". */
export function decidedBy(batch: Pick<AuditEntry, 'author'>[]): string {
  return (['vault', 'app'] as const).filter((author) => batch.some((entry) => entry.author === author)).join(', ');
}

/**
 * Entries in the order the page shows them, newest first, each batch as one
 * line at its newest entry. The server leaves detail out unless asked.
 */
export function lines<T extends AuditEntry>(entries: T[]): T[][] {
  const shown: T[][] = [];
  const batches = new Map<string, T[]>();
  for (const entry of entries) {
    const batch = entry.operationId === null ? undefined : batches.get(entry.operationId);
    if (batch !== undefined) {
      batch.push(entry);
      continue;
    }
    const fresh = [entry];
    if (entry.operationId !== null) batches.set(entry.operationId, fresh);
    shown.push(fresh);
  }
  return shown;
}

/** A sentence as text. */
export function plain(parts: Part[]): string {
  return parts
    .map((part) =>
      typeof part === 'string' ? part : 'place' in part ? part.place : part.member.startsWith('user:') ? part.member.slice(5) : shownMember(part.member),
    )
    .join('');
}

/**
 * The CI run an entry was written for, as its issuer stated it at the
 * exchange: `acme/api run 7001 at 3f2a9c1`, a GitLab pipeline, or the
 * token's subject. Null for an entry no trust binding's credential wrote.
 */
export function runLabel(run: { claims: Record<string, string | number> } | null): string | null {
  if (run === null) return null;
  const { claims } = run;
  const text = (name: string) => (typeof claims[name] === 'string' || typeof claims[name] === 'number' ? String(claims[name]) : null);
  const at = text('sha') === null ? '' : ` at ${text('sha')!.slice(0, 7)}`;
  if (text('repository') !== null && text('run_id') !== null) return `${text('repository')} run ${text('run_id')}${at}`;
  if (text('project_path') !== null && text('pipeline_id') !== null) return `${text('project_path')} pipeline ${text('pipeline_id')}${at}`;
  return text('sub') === null ? 'a CI run' : `CI run ${text('sub')}`;
}

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
  /** Every entry of the batch, the lead included. */
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

function plural(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}

/** A batch reads as its environment and a count; one entry as its secret. */
function secrets(facts: Facts): Part[] {
  if (facts.batch.length === 1) return place(facts.entry);
  return [...environmentOf(facts.entry), facts.refused ? ', ' : ': ', plural(facts.count, 'secret')];
}

/** " to acme/market", when the entry names where a sync pushes. */
function toDestination(entry: AuditEntry): string {
  const where = text(entry.metadata.destination);
  return where === null ? '' : ` to ${where}`;
}

function destination(entry: AuditEntry): string {
  return text(entry.metadata.destination) ?? 'its destination';
}

const READ_VERBS: Record<string, [did: string, tried: string]> = {
  reveal: ['revealed', 'reveal'],
  run: ['ran', 'run'],
  compare: ['compared', 'compare'],
  sync: ['read', 'read'],
};

function readVerb({ entry }: Facts): [string, string] {
  return READ_VERBS[text(entry.metadata.purpose) ?? 'reveal'] ?? READ_VERBS.reveal!;
}

const placeTemplates = (kind: 'project' | 'environment'): Record<string, Template> => {
  const what = (facts: Facts): Part[] => [`${kind} `, ...(kind === 'project' ? place({ ...facts.entry, environment: null, key: null }) : environmentOf(facts.entry))];
  return {
    [`${kind}.create`]: { did: 'created', tried: 'create', what },
    [`${kind}.update`]: { did: 'changed', tried: 'change', what },
    [`${kind}.archive`]: { did: 'archived', tried: 'archive', what },
    [`${kind}.restore`]: { did: 'restored', tried: 'restore', what },
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
    // New secrets are added, others changed; a batch of both is written.
    did: ({ batch }) => {
      const firsts = batch.filter((entry) => entry.version === 1).length;
      return firsts === batch.length ? 'added' : firsts === 0 ? 'changed' : 'wrote';
    },
    tried: 'change',
    what: secrets,
    then: ({ entry, batch }) =>
      batch.length > 1 || entry.version === null || entry.version === 1 ? [] : [`, now version ${entry.version}`],
  },
  'secret.restore': {
    did: 'restored',
    tried: 'restore',
    what: ({ entry }) => [...place(entry), ...(number(entry.metadata.from) === null ? [] : [` to version ${number(entry.metadata.from)}`])],
    then: ({ entry }) => (entry.version === null ? [] : [`, now ${entry.version}`]),
  },
  'secret.rename': {
    did: 'renamed',
    tried: 'rename',
    what: ({ entry }) => [...place(entry), ...(text(entry.metadata.nextKey) === null ? [] : [` to ${text(entry.metadata.nextKey)}`])],
  },
  'secret.archive': { did: 'archived', tried: 'archive', what: (facts) => place(facts.entry) },
  'secret.unarchive': { did: 'brought back', tried: 'bring back', what: (facts) => place(facts.entry) },
  ...placeTemplates('project'),
  ...placeTemplates('environment'),
  'access.grant': {
    did: 'gave',
    tried: 'give',
    what: ({ entry }) => [...subject(entry), ` ${text(entry.metadata.role) ?? 'a role'} on `, ...placeOnly(entry)],
    then: ({ entry }) => [
      ...(text(entry.metadata.previousRole) === null ? [] : [`, was ${text(entry.metadata.previousRole)}`]),
      ...(text(entry.metadata.expiresAt) === null ? [] : [`, until ${text(entry.metadata.expiresAt)!.slice(0, 10)}`]),
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
  },
  'member.add': {
    did: 'added',
    tried: 'add',
    what: ({ entry }) => [
      ...subject(entry),
      ...(entry.metadata.rootAdmin === true ? [' as a root admin'] : entry.metadata.owner === true ? [' as an owner'] : []),
    ],
  },
  'member.remove': {
    did: 'removed',
    tried: 'remove',
    what: (facts) => subject(facts.entry),
    then: ({ entry }) => (number(entry.metadata.revoked) === null ? [] : [`, who held ${plural(number(entry.metadata.revoked)!, 'grant')}`]),
  },
  'member.restore': { did: 'brought back', tried: 'bring back', what: (facts) => subject(facts.entry) },
  'member.owner': {
    did: ({ entry }) => (entry.metadata.owner === false ? 'took owner from' : 'made'),
    tried: ({ entry }) => (entry.metadata.owner === false ? 'take owner from' : 'make'),
    what: ({ entry }) => [...subject(entry), ...(entry.metadata.owner === false ? [] : [' an owner'])],
  },
  'sync.create': {
    did: 'set up a sync of',
    tried: 'set up a sync of',
    what: ({ entry }) => [...environmentOf(entry), toDestination(entry)],
  },
  'sync.update': {
    did: ({ entry }) => (entry.metadata.paused === true ? 'paused the sync of' : entry.metadata.paused === false ? 'resumed the sync of' : 'changed the sync of'),
    tried: 'change the sync of',
    what: ({ entry }) => [...environmentOf(entry), toDestination(entry)],
  },
  'sync.delete': {
    did: 'removed the sync of',
    tried: 'remove the sync of',
    what: ({ entry }) => [...environmentOf(entry), toDestination(entry)],
  },
  'sync.push': {
    did: 'pushed',
    tried: 'push',
    what: (facts) =>
      facts.batch.length === 1
        ? [...place(facts.entry), ` to ${destination(facts.entry)}`]
        : [...environmentOf(facts.entry), ` to ${destination(facts.entry)}: ${plural(facts.count, 'secret')}`],
  },
  'sync.remove': {
    did: 'removed',
    tried: 'remove',
    what: (facts) =>
      facts.batch.length === 1
        ? [...place(facts.entry), ` from ${destination(facts.entry)}`]
        : [plural(facts.count, 'secret'), ' of ', ...environmentOf(facts.entry), ` from ${destination(facts.entry)}`],
  },
  // A binding trusts CI runs to sign in as a service; removing one is its tombstone.
  'token.bind': {
    did: 'trusted CI runs to sign in as',
    tried: 'trust CI runs to sign in as',
    what: (facts) => subject(facts.entry),
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

  // Detail, hidden unless asked for.
  sign_in: {
    did: ({ entry }) => (entry.metadata.kind === 'cli' ? 'signed in to the CLI' : 'signed in'),
    tried: 'sign in',
    what: ({ entry }) => (text(entry.metadata.provider) === null ? [] : [`with ${text(entry.metadata.provider)}`]),
  },
  sign_out: { did: 'signed out', tried: 'sign out', what: () => [] },
  'token.create': { did: 'issued a bearer token to', tried: 'issue a bearer token to', what: (facts) => subject(facts.entry) },
  'token.revoke': { did: 'revoked a bearer token of', tried: 'revoke a bearer token of', what: (facts) => subject(facts.entry) },
  'device.approve': { did: 'approved a CLI sign-in', tried: 'approve a CLI sign-in', what: () => [] },
  'device.deny': { did: 'turned down a CLI sign-in', tried: 'turn down a CLI sign-in', what: () => [] },
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
  'sync.run': {
    did: 'ran the sync of',
    tried: 'run the sync of',
    what: ({ entry }) => [...environmentOf(entry), toDestination(entry)],
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
  'sync.list': { did: 'listed the syncs of', tried: 'list the syncs of', what: ({ entry }) => environmentOf(entry) },
};

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
  expired: 'grant expired',
  removed: 'removed from coffre',
  not_a_member: 'not a member',
  not_registered: 'not invited',
  tampered: 'their record was tampered with',
  bad_claim: 'the key did not match the secret',
  not_allowed: 'not allowed',
  root_admin: 'root admins are set by the deployment',
  unknown_environment: 'no such environment',
  unknown_secret: 'no such secret',
  unknown_project: 'no such project',
  unusable_credential: 'its token is not a secret they can read',
  duplicate_destination: 'already synced from elsewhere',
  cannot_grant_sync: 'cannot grant the sync its reads',
  kms_unavailable: 'KMS did not answer',
  wrong_kek: "the vault's key is not the one that wrapped the data",
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

/** In a batch of mixed actions, the one the line is named for: a sync's push, not its reads. */
const LEAD = ['sync.push', 'sync.remove', 'secret.write', 'secret.read'];

export function leadOf(batch: AuditEntry[]): AuditEntry {
  for (const action of LEAD) {
    const found = batch.find((entry) => entry.action === action);
    if (found !== undefined) return found;
  }
  return batch[0]!;
}

/** What a line says: one entry, or a batch that shares an operation. */
export function describe(batch: AuditEntry[]): Sentence {
  const entry = leadOf(batch);
  const same = batch.filter((other) => other.action === entry.action);
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

/**
 * Who acted, as a part: a member links to their page; a sync or coffre
 * itself is text. A sync is named for where it pushes, which any entry of
 * its batch may say.
 */
export function who(batch: Pick<AuditEntry, 'actorType' | 'actorId' | 'metadata'>[]): string | { member: string } {
  const entry = batch[0]!;
  if (entry.actorType === 'user') return { member: `user:${entry.actorId}` };
  if (entry.actorType === 'service') return { member: `token:${entry.actorId}` };
  if (entry.actorId.startsWith('sync:')) {
    const id = batch.map((other) => text(other.metadata.provider)).find((provider) => provider !== null);
    const provider = id === undefined ? undefined : (PROVIDERS[id!] ?? id!);
    return provider === undefined ? 'a sync' : `sync to ${provider}`;
  }
  return SYSTEM[entry.actorId] ?? entry.actorId;
}

const PROVIDERS: Record<string, string> = {
  'github-actions': 'GitHub',
  vercel: 'Vercel',
  railway: 'Railway',
  'cloudflare-workers': 'Cloudflare',
};

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

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
import { INSTANCE_ROLES, isBuiltinRole, isInstanceRole, isScope, normalDefinition, ROLES, scopeInWords, type Scope } from '@coffre/core/access';
import type { LogAction } from '@coffre/core/vault';

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

/** What one template needs: the line's leading entry, and its batch. */
type Facts = {
  entry: AuditEntry;
  /** Every entry of the batch, the lead included, a read of several once per secret (`perSecret`). */
  batch: AuditEntry[];
  /** Secrets the batch was about. */
  count: number;
};

/** An allowed entry's sentence; a refused one has none (`refusal`). */
type Template = {
  /** What they did: "revealed". */
  did: string | ((facts: Facts) => string);
  /** To what: "market/prod/API_KEY". */
  what: (facts: Facts) => Part[];
  /** Said only of what happened: ", now version 5". */
  then?: (facts: Facts) => Part[];
  /** Asked, and nothing changed: said after it, ", unchanged", as `unchanged: true` in its detail is. */
  unchanged?: (facts: Facts) => boolean;
};

// --- the pieces of a sentence ---------------------------------------------------

const text = (value: unknown): string | null => (typeof value === 'string' && value !== '' ? value : null);
const number = (value: unknown): number | null => (typeof value === 'number' ? value : null);
const list = (value: unknown): string[] => (Array.isArray(value) ? value.filter((item): item is string => text(item) !== null) : []);

/** An object of the detail's, or an empty one for anything else. */
function record(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

/** The entry's place, as deep as it goes. */
function place(entry: Pick<AuditEntry, 'project' | 'environment' | 'key'>): Part[] {
  const path = [entry.project, entry.environment, entry.key].filter((part): part is string => part !== null);
  return path.length === 0 ? ['coffre'] : [{ place: path.join('/') }];
}

function environmentOf(entry: AuditEntry): Part[] {
  return place({ ...entry, key: null });
}

/** A personal config's entry by the environment it is a config of, `market/dev`: its own slug is generated, and shown nowhere else. */
function asPersonal(entry: AuditEntry): [AuditEntry, Part[]] {
  const of = text(entry.metadata.personal);
  return of === null || entry.project === null ? [entry, []] : [{ ...entry, environment: of }, [', in their personal config']];
}

/** The member an entry is about: its subject, or the member or principal its detail names. */
function subject(entry: AuditEntry): Part[] {
  const member = entry.subject ?? text(entry.metadata.member) ?? text(entry.metadata.principal);
  return member === null ? ['someone'] : [{ member }];
}

/** An MCP client, by the host its metadata document is at; one registered by its own request names none in the entry. */
function app(entry: AuditEntry): Part[] {
  return [text(entry.metadata.host) ?? 'an MCP client'];
}

/** A tool's call: its name, and what it named. */
function tool(entry: AuditEntry): Part[] {
  const names = list(entry.metadata.names);
  return [text(entry.metadata.tool) ?? 'a tool', ...(names.length === 0 ? [] : [` on ${names.join(', ')}`])];
}

/** Why the vault itself ended a connection, said after it. */
const DISCONNECTED: Record<string, string> = {
  code_reused: ': its sign-in code was used twice',
  refresh_reused: ': a refresh token it had replaced was used again',
};

function plural(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}

/**
 * The secrets a read or write was about: one entry as its secret, a batch as
 * its environment and a count. The vault logs a read where it was asked, so
 * a read through a reference is the reference's, "billing/prod/DATABASE_URL
 * through a reference"; its own part of the entry names the source by id
 * alone (`through`), which the page cannot say as a path.
 */
function secrets(facts: Facts): Part[] {
  const [entry, mine] = asPersonal(facts.entry);
  const referred = (entry: AuditEntry) => text(entry.metadata.through) !== null;
  if (facts.batch.length === 1) return [...place(entry), ...(referred(entry) ? [' through a reference'] : []), ...mine];
  const held = facts.batch.filter(referred).length;
  return [
    ...environmentOf(entry),
    ': ',
    plural(facts.count, 'secret'),
    ...(held === 0 ? [] : [`, ${held} through ${held === 1 ? 'a reference' : 'references'}`]),
    ...mine,
  ];
}

/** "OLD in market/prod", "OLD and STALE in market/prod", or "5 keys in market/prod". */
function keysIn(entry: AuditEntry, keys: string[]): Part[] {
  const [here, mine] = asPersonal(entry);
  if (keys.length === 0) return [...environmentOf(here), ...mine];
  const named = keys.length > 3 ? plural(keys.length, 'key') : keys.length === 1 ? keys[0]! : `${keys.slice(0, -1).join(', ')} and ${keys.at(-1)!}`;
  return [named, ' in ', ...environmentOf(here), ...mine];
}

/** A folder renamed onto its own name: nothing moved. */
const sameFolder = ({ entry }: Facts) => entry.metadata.folder === entry.metadata.to;

/** " to the folder stripe", or " out of its folder". */
function intoFolder(folder: unknown): Part[] {
  return [text(folder) === null ? ' out of its folder' : ` to the folder ${text(folder)}`];
}

const READ_VERBS: Record<string, string> = {
  reveal: 'revealed',
  run: 'ran',
  compare: 'compared',
  copy: 'copied',
  // The credential proxy's: a value injected into a request for its person, or one handed to their app.
  use: 'used',
  expose: 'was given',
};

/**
 * What a write did to one key, from its line of the entry (`keys`): made it
 * a reference, restored a version, wrote a value (a new key's, or one over
 * a reference's), set it aside for what a parent passes down or took it
 * back, archived it or brought it back, or filed it in a folder.
 */
type Written = 'reference' | 'restore' | 'add' | 'own' | 'mark' | 'change' | 'reset' | 'archive' | 'unarchive' | 'move';

function written({ metadata: line }: AuditEntry): Written {
  if (text(line.refers) !== null) return 'reference';
  if (number(line.restored) !== null) return 'restore';
  // A nature marked in place: `was` the nature it had, `kept` the version whose value it is.
  if (text(line.was) !== null && number(line.kept) !== null) return 'mark';
  if (number(line.version) !== null) return line.made === true ? 'add' : text(line.source) !== null ? 'own' : 'change';
  if (line.reset === true) return 'reset';
  if (typeof line.archived === 'boolean') return line.archived ? 'archive' : 'unarchive';
  return 'folder' in line ? 'move' : 'change';
}

const WRITTEN: Record<Written, string> = {
  reference: 'made',
  restore: 'restored',
  add: 'added',
  own: 'gave a value of its own to',
  mark: 'marked',
  change: 'changed',
  reset: 'reset',
  archive: 'archived',
  unarchive: 'brought back',
  move: 'moved',
};

/** Who sees a value written: said where it is not a secret's. */
function nature(entry: AuditEntry): Part[] {
  return entry.metadata.nature === 'plain' ? [', as a plain value, no secret'] : entry.metadata.nature === 'sensitive' ? [', as a sensitive value, shown to nobody'] : [];
}

/** A project's or an environment's, as `place` names it: a personal config by what it is a config of. */
function placeWhat(kind: 'project' | 'environment') {
  return ({ entry }: Facts): Part[] => {
    if (kind === 'project') return ['project ', ...place({ ...entry, environment: null, key: null })];
    const of = text(entry.metadata.personal);
    if (of !== null && entry.project !== null) return ['a personal config of ', { place: `${entry.project}/${of}` }];
    if (entry.metadata.personal === true) return [`a personal config, ${text(entry.metadata.path) ?? ''}`];
    return ['environment ', ...environmentOf(entry)];
  };
}

/** A re-slugging, said as one where the slug changed. */
function updated(kind: 'project' | 'environment'): Template {
  const renamed = ({ metadata }: AuditEntry) => text(metadata.from) !== null && metadata.from !== metadata.slug;
  return {
    did: ({ entry }) => (renamed(entry) ? 'renamed' : 'changed'),
    what: placeWhat(kind),
    then: ({ entry }) => (renamed(entry) ? [`, was ${text(entry.metadata.from)}`] : []),
  };
}

/** Archived, restored or deleted: a deleted one is named by its tombstone from then on, `market~deleted-2026-10-05`, as every entry about it is. */
const plainly = (kind: 'project' | 'environment', did: string): Template => ({ did, what: placeWhat(kind) });

/** An environment made: a fork names the one it inherits from, a copy the one it copied. */
function created(kind: 'project' | 'environment'): Template {
  return {
    ...plainly(kind, 'created'),
    then: ({ entry }) =>
      text(entry.metadata.inherits) !== null
        ? [`, inheriting from ${text(entry.metadata.inherits)}`]
        : text(entry.metadata.from) === null ? [] : [`, a copy of ${text(entry.metadata.from)}`],
  };
}

/** A grant's lines (`changes`), the first said, the others counted. */
const changesOf = ({ metadata }: AuditEntry) => (Array.isArray(metadata.changes) ? metadata.changes.map(record) : []);

/**
 * A grant's sentence, and a revocation's, from what changed: the action is the
 * request's (a grant if it gives any role), and its lines only what changed, a
 * role given (`role`) or taken (`role: null`), each at its own place, which the
 * server names the entry for (`viewOf`).
 */
const accessSentence: Template = {
  did: ({ entry }) => {
    const [first] = changesOf(entry);
    return first === undefined ? 'set' : first.role === null ? 'took' : 'gave';
  },
  what: ({ entry }) => {
    const [first] = changesOf(entry);
    if (first === undefined) return ['the access of ', ...subject(entry), ' on ', ...environmentOf(entry)];
    if (first.role !== null) return [...subject(entry), ` ${text(first.role) ?? 'a role'} on `, ...environmentOf(entry)];
    const role = text(first.was);
    return [...(role === null ? ['access to '] : [`${role} on `]), ...environmentOf(entry), ' from ', ...subject(entry)];
  },
  then: ({ entry }) => {
    const [first] = changesOf(entry);
    if (first === undefined) return [];
    return [
      ...(first.role === null ? [] : [
        ...(text(first.was) === null ? [] : [`, was ${text(first.was)}`]),
        ...(text(first.expiresAt) === null ? [] : [`, until ${text(first.expiresAt)!.slice(0, 10)}`]),
      ]),
      ...others(entry),
      // Admitted with it, which 0.14.7 logged apart.
      ...(entry.metadata.admitted === 'member.add' ? [', added to coffre with it'] : entry.metadata.admitted === 'member.restore' ? [', brought back with it'] : []),
    ];
  },
  unchanged: ({ entry }) => changesOf(entry).length === 0,
};

/** The changes after a grant's first: "on 2 other places" where each gave or took what the first did; else "2 other changes". */
function others(entry: AuditEntry): Part[] {
  const [first, ...rest] = changesOf(entry);
  if (first === undefined || rest.length === 0) return [];
  const same = rest.every((line) => (['role', 'was', 'expiresAt'] as const).every((field) => text(line[field]) === text(first[field])));
  return [same ? `, and on ${plural(rest.length, 'other place')}` : `, and ${plural(rest.length, 'other change')}`];
}

/** Who a revoked credential was: a token, or a session or handle ended. */
const REVOKED: Record<string, string> = {
  personal: 'revoked a personal token of',
  service: 'revoked a bearer token of',
  handle: 'ended a handle of',
  cli: 'ended a CLI session of',
  browser: 'ended a browser session of',
};

/** A CLI sign-in's label, as its CLI named it: `, “laptop”`. */
const labelled = ({ entry }: Facts): Part[] => (text(entry.metadata.label) === null ? [] : [`, “${text(entry.metadata.label)}”`]);

/** A trust binding's keys replaced, rather than a binding made. */
const rekeyed = ({ entry }: Facts) => entry.metadata.reason === 'keys_replaced';

/** The profiles whose tokens are CI runs'; every other binding trusts a workload. */
const CI_PROFILES = ['github', 'github-reusable', 'github-reusable-organization', 'gitlab'];

/** Whom a binding trusts, by its profile: CI runs, a platform's workloads, or a custom issuer's tokens. */
function trusted({ metadata }: AuditEntry): string {
  const profile = text(metadata.profile) ?? 'custom';
  if (CI_PROFILES.includes(profile)) return 'CI runs';
  return profile === 'custom' ? `tokens from ${text(metadata.issuer) ?? 'an issuer'}` : `${profile} workloads`;
}

/** What a freeze is on: the whole instance, a service account's workloads, a binding's or a session. */
function frozen({ entry }: Facts): Part[] {
  const target = text(entry.metadata.target);
  if (target === null) return ['workloads'];
  if (target === 'instance') return ['every workload'];
  if (target.startsWith('token:')) return ['the workloads of ', { member: target }];
  return [target.startsWith('binding:') ? 'the workloads of a trust binding of ' : 'a workload session of ', ...subject(entry)];
}

/** A write that wrote no key: a nature asked of keys that had it already. The entry does not say why. */
const empty = ({ metadata }: AuditEntry) => Array.isArray(metadata.keys) && metadata.keys.length === 0;

/** A write's sentence, and a loosening's: one key as what was done to it; a batch as what was done to every key, or as written. */
const writeSentence: Template = {
  did: ({ entry, batch }) => {
    if (empty(entry)) return 'marked keys in';
    const kinds = new Set(batch.map(written));
    if (batch.length === 1 || (kinds.size === 1 && !kinds.has('reference') && !kinds.has('own'))) return WRITTEN[written(entry)];
    return [...kinds].every((kind) => kind === 'add' || kind === 'change') ? 'wrote' : 'changed';
  },
  what: (facts) => (empty(facts.entry) ? keysIn(facts.entry, []) : [...secrets(facts), ...(facts.batch.length === 1 && written(facts.entry) === 'reference' ? [' a reference'] : [])]),
  then: ({ entry, batch }) => {
    if (empty(entry)) return [];
    const kind = written(entry);
    const folder = entry.metadata.folder;
    // A folder said of the batch only where every key moved to it.
    if (kind === 'move' && batch.every((other) => written(other) === 'move' && other.metadata.folder === folder)) return intoFolder(folder);
    if (batch.length > 1) return [];
    if (kind === 'restore') return [` to version ${number(entry.metadata.restored)}`, ...(entry.version === null ? [] : [`, now ${entry.version}`])];
    if (kind === 'mark') return [` ${text(entry.metadata.nature) ?? ''}, from ${text(entry.metadata.was) ?? ''}, its value kept`];
    return kind === 'add' || kind === 'change' || kind === 'own' ? [...((entry.version ?? 1) === 1 ? [] : [`, now version ${entry.version}`]), ...nature(entry)] : [];
  },
  unchanged: ({ entry }) => empty(entry),
};

// --- one template per action ----------------------------------------------------

const TEMPLATES: Record<LogAction, Template> = {
  'secret.read': { did: ({ entry }) => READ_VERBS[text(entry.metadata.purpose) ?? 'reveal'] ?? READ_VERBS.reveal!, what: secrets },
  // One key as what was done to it; a batch as what was done to every key, or as written.
  'secret.write': writeSentence,
  // A nature marked looser in place, by an Owner of the project: its own action, as 0.14.7 logged it.
  'secret.loosen': writeSentence,
  'secret.rename': {
    did: 'renamed',
    what: ({ entry }) => {
      const [here, mine] = asPersonal(entry);
      return [...place({ ...here, key: text(entry.metadata.key) ?? entry.key }), ...(text(entry.metadata.to) === null ? [] : [` to ${text(entry.metadata.to)}`]), ...mine];
    },
    // Carried down to the forks that inherit it.
    then: ({ entry }) => {
      // Each line is a row renamed, moved aside or a dismissal moved or ended, by its environment's id: the first, the key's own.
      const [own, ...rest] = changesOf(entry).map((line) => text(line.environment));
      const forks = new Set(rest.filter((environment) => environment !== null && environment !== own)).size;
      return forks === 0 ? [] : [`, and in ${plural(forks, 'fork')}`];
    },
    unchanged: ({ entry }) => text(entry.metadata.to) === text(entry.metadata.key),
  },
  'secret.refile': { did: 'moved', what: ({ entry }) => keysIn(entry, list(entry.metadata.keys)), then: ({ entry }) => intoFolder(entry.metadata.to), unchanged: sameFolder },
  // The source, by id alone in the entry, is no path the page can say.
  'reference.break': { did: 'broke', what: ({ entry }) => ['the reference ', ...place(entry)] },
  // What changed, by key: dismissed, brought back, both, or neither (asked as it was).
  'missing.dismiss': {
    did: ({ entry }) => (list(entry.metadata.dismissed).length > 0 ? 'dismissed' : list(entry.metadata.restored).length > 0 ? 'restored' : 'set which missing keys are dismissed in'),
    what: ({ entry }) => {
      const dismissed = list(entry.metadata.dismissed);
      const restored = list(entry.metadata.restored);
      if (dismissed.length === 0 && restored.length === 0) return keysIn(entry, []);
      return keysIn(entry, dismissed.length > 0 ? dismissed : restored);
    },
    then: ({ entry }) => {
      const dismissed = list(entry.metadata.dismissed);
      const restored = list(entry.metadata.restored);
      if (dismissed.length === 0) return restored.length === 0 ? [] : [' to the missing keys'];
      return [' as not needed', ...(restored.length === 0 ? [] : [`, and restored ${restored.length > 3 ? plural(restored.length, 'key') : restored.join(', ')} to the missing keys`])];
    },
    unchanged: ({ entry }) => list(entry.metadata.dismissed).length === 0 && list(entry.metadata.restored).length === 0,
  },
  'project.create': created('project'),
  'project.update': updated('project'),
  'project.archive': plainly('project', 'archived'),
  'project.restore': plainly('project', 'restored'),
  'project.delete': plainly('project', 'deleted'),
  'project.move': { ...plainly('project', 'moved'), then: ({ entry }) => intoFolder(entry.metadata.to), unchanged: ({ entry }) => entry.metadata.from === entry.metadata.to },
  // A folder renamed, or emptied: every project filed there.
  'folder.refile': {
    did: ({ entry }) => (text(entry.metadata.to) === null ? 'emptied' : 'renamed'),
    what: ({ entry }) => [text(entry.metadata.folder) === null ? 'a folder' : `the folder ${text(entry.metadata.folder)}`],
    then: ({ entry }) => [...(text(entry.metadata.to) === null ? [] : [` to ${text(entry.metadata.to)}`]), `, ${plural(list(entry.metadata.projects).length, 'project')}`],
    unchanged: sameFolder,
  },
  'environment.create': created('environment'),
  'environment.update': updated('environment'),
  'environment.archive': plainly('environment', 'archived'),
  'environment.restore': plainly('environment', 'restored'),
  'environment.delete': plainly('environment', 'deleted'),
  'environment.protect': { did: 'protected', what: ({ entry }) => environmentOf(entry) },
  'environment.unprotect': { did: 'unprotected', what: ({ entry }) => environmentOf(entry) },
  // An upstream credential a deployment names, frozen in one environment.
  'upstream.freeze': { did: 'froze the upstream credential', what: ({ entry }) => [`${text(entry.metadata.upstream) ?? ''} in `, ...environmentOf(entry)] },
  'upstream.thaw': { did: 'unfroze the upstream credential', what: ({ entry }) => [`${text(entry.metadata.upstream) ?? ''} in `, ...environmentOf(entry)] },
  'access.grant': accessSentence,
  'access.revoke': accessSentence,
  'member.add': { did: 'added', what: ({ entry }) => [...subject(entry), ...asRole(entry)] },
  'member.restore': { did: 'brought back', what: ({ entry }) => [...subject(entry), ...asRole(entry)] },
  'member.remove': {
    did: 'removed',
    what: (facts) => subject(facts.entry),
    then: ({ entry }) => (Array.isArray(entry.metadata.revoked) && entry.metadata.revoked.length > 0 ? [`, who held ${plural(entry.metadata.revoked.length, 'grant')}`] : []),
  },
  'member.role': {
    did: 'made',
    what: ({ entry }) => [...subject(entry), ` ${article(roleName(text(entry.metadata.role) ?? 'member') ?? 'Member')}`, ...scoped(entry)],
  },
  // Where people set up service accounts themselves, which those who run the instance set.
  'settings.change': {
    did: 'set',
    what: ({ entry }) => ['where people set up service accounts', ...setting(entry.metadata.serviceAccounts).map((words) => `: ${words}`)],
    then: ({ entry }) => setting(entry.metadata.was).map((words) => `, was ${words}`),
  },
  // The roles an Owner edits (docs/design/roles.md), the vault's to change.
  'policy.change': {
    did: ({ entry }) => policyOf(entry).verb,
    what: ({ entry }) => policyOf(entry).what,
  },
  // A binding trusts CI runs or a workload to sign in as a service; removing one is its tombstone. New keys uploaded replace the bindings that named the old.
  'token.bind': {
    did: (facts) => (rekeyed(facts) ? 'replaced the keys of' : `trusted ${trusted(facts.entry)} to sign in as`),
    what: (facts) => [...(rekeyed(facts) ? [`${plural(Array.isArray(facts.entry.metadata.bindings) ? facts.entry.metadata.bindings.length : 0, 'trust binding')} of `] : []), ...subject(facts.entry)],
    then: (facts) => (rekeyed(facts) ? [] : [...inGitHubEnvironment(facts.entry), ...reaching(facts.entry)]),
  },
  // Its entry names the binding by id alone, not whom it trusted.
  'token.unbind': { did: 'removed a trust binding of', what: (facts) => subject(facts.entry) },
  'workload.freeze': { did: 'froze', what: frozen, then: ({ entry }) => (text(entry.metadata.reason) === null ? [] : [`: ${text(entry.metadata.reason)}`]) },
  'workload.unfreeze': { did: 'unfroze', what: frozen },
  // An MCP client a person connected, such as Claude.
  'mcp.connect': { did: 'connected', what: ({ entry }) => app(entry) },
  // A change an MCP client asked for, on its access token: it waits for the person's approval.
  'mcp.ask': { did: 'was asked by an MCP client for', what: ({ entry }) => tool(entry) },
  // A person's decision, on coffre's page, on a change an MCP client asked for; the change's own entry follows, through the approval.
  'mcp.approve': { did: 'approved', what: ({ entry }) => tool(entry) },
  'mcp.deny': { did: 'turned down', what: ({ entry }) => tool(entry) },
  'mcp.disconnect': {
    did: 'disconnected',
    // The vault's own, on a code or a token used twice, names whose it was.
    what: ({ entry }) => [...app(entry), ...(entry.actorType === 'system' && text(entry.metadata.principal) !== null ? [' of ', ...subject(entry)] : [])],
    then: ({ entry }) => [DISCONNECTED[text(entry.metadata.reason) ?? ''] ?? ''],
  },
  // What lapsed, removed by the vault itself: sessions, sign-in codes, apps never connected.
  'upkeep.expire': { did: 'removed what had lapsed', what: () => [] },
  // The log's first entry: an instance upgraded from 0.14 names where 0.14's log, archived, ends.
  'vault.adopt': {
    did: ({ entry }) => (entry.metadata.archive == null ? 'started the log' : 'took over the 0.14 database'),
    what: () => [],
    then: ({ entry }) => (number(record(entry.metadata.archive).seq) === null ? [] : [`, its log archived through entry ${number(record(entry.metadata.archive).seq)}`]),
  },

  // Detail, hidden unless asked for.
  sign_in: {
    did: ({ entry }) => (entry.metadata.kind === 'cli' ? 'signed in to the CLI' : 'signed in'),
    what: ({ entry }) => (text(entry.metadata.provider) === null ? [] : [`with ${text(entry.metadata.provider)}`]),
    // Made an Owner by the vault, as the deployment names them one.
    then: ({ entry }) => (entry.metadata.owner === 'made' ? [', made an Owner: the deployment names them one'] : entry.metadata.owner === 'restored' ? [', brought back as an Owner: the deployment names them one'] : []),
  },
  sign_out: { did: 'signed out', what: () => [] },
  // A personal token is its person's own, a handle a run's; a bearer token is a service account's.
  'token.create': {
    did: ({ entry }) => (entry.metadata.kind === 'handle' ? 'made a handle' : entry.metadata.kind === 'personal' ? 'made a personal token' : 'issued a bearer token to'),
    what: ({ entry }) => (entry.metadata.kind === 'handle' || entry.metadata.kind === 'personal' ? [] : subject(entry)),
    then: ({ entry }) => reaching(entry),
  },
  'token.revoke': { did: ({ entry }) => REVOKED[text(entry.metadata.kind) ?? ''] ?? 'revoked a token of', what: (facts) => subject(facts.entry) },
  'device.start': { did: 'was asked for a CLI sign-in', what: () => [], then: labelled },
  'device.approve': { did: 'approved a CLI sign-in', what: () => [], then: labelled },
  'device.deny': { did: 'turned down a CLI sign-in', what: () => [], then: labelled },
  // A CI run's ID token, or a workload's proof, exchanged for a session.
  'token.exchange': {
    did: ({ entry }) => (entry.metadata.kind === 'workload' ? 'started a workload session' : 'signed in for a CI run'),
    what: () => [],
  },
  'workload.renew': { did: 'renewed its workload session', what: () => [] },
  // Anyone may register an MCP client: what it reaches is the person's to connect.
  'oauth.register': { did: 'registered an MCP client', what: () => [] },
  'mcp.token': {
    did: ({ entry }) => (entry.metadata.grant === 'refresh_token' ? 'refreshed the tokens of' : 'gave its first tokens to'),
    what: ({ entry }) => app(entry),
  },
  'account.link': { did: 'linked', what: ({ entry }) => [`a ${text(entry.metadata.provider) ?? 'sign-in'} account`] },
  'account.unlink': { did: 'unlinked', what: ({ entry }) => [`a ${text(entry.metadata.provider) ?? 'sign-in'} account`] },
};

/** An instance role's name, from its slug; null for none it knows. */
function roleName(role: string): string | null {
  return isInstanceRole(role) ? INSTANCE_ROLES[role].name : null;
}

/**
 * A `policy.change` entry, from its role, its `definition` and the one it
 * replaced (`was`): a built-in role put back as it ships is a reset; one
 * an Owner made, gone, a deletion; one that was not there, made.
 *
 *   edited the Developer role         made the Release manager role
 *   reset the Auditor instance role   deleted the Release manager role
 */
function policyOf(entry: AuditEntry): { verb: 'edited' | 'reset' | 'made' | 'deleted'; what: Part[] } {
  const instance = entry.metadata.instance === true;
  const id = text(entry.metadata.role);
  const shipped = id === null ? null : instance ? (isInstanceRole(id) ? INSTANCE_ROLES[id] : null) : isBuiltinRole(id) ? ROLES[id] : null;
  const definition = entry.metadata.definition === null ? null : record(entry.metadata.definition);
  const name = text(definition?.name) ?? text(record(entry.metadata.was).name) ?? shipped?.name ?? id;
  const verb = definition === null
    ? 'deleted'
    : shipped !== null && JSON.stringify(definition) === JSON.stringify(normalDefinition(shipped))
      ? 'reset'
      : entry.metadata.was === null ? 'made' : 'edited';
  return { verb, what: [name === null ? 'a role' : `the ${name} ${instance ? 'instance role' : 'role'}`] };
}

function article(name: string): string {
  return `${/^[AEIOU]/.test(name) ? 'an' : 'a'} ${name}`;
}

/** Whether an entry's scope narrows the role; its projects are ids, which a sentence cannot name. */
function scoped(entry: AuditEntry): Part[] {
  // An unscoped member's is null, the vault's `standing`.
  const scope = entry.metadata.scope as { projects?: unknown; environments?: unknown } | null | undefined;
  return scope == null || (scope.projects === 'all' && scope.environments === 'all') ? [] : [', with a scope'];
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

/**
 * A refused change in words, after "tried to": its kind alone. The vault
 * logs a refusal once a minute per caller and action (D236), so one entry
 * stands for every one refused them that minute, each asking its own key,
 * kind or direction: none of those is the entry's to say.
 */
const TRIED: Record<LogAction, string> = {
  'secret.read': 'read secrets',
  'secret.write': 'write secrets',
  'secret.loosen': 'make a sensitive value secret in place',
  'secret.rename': 'rename a key',
  'secret.refile': 'move keys between folders',
  'reference.break': 'break a reference',
  'missing.dismiss': 'change which missing keys are dismissed',
  'project.create': 'create a project',
  'project.update': 'change a project',
  'project.archive': 'archive a project',
  'project.restore': 'restore a project',
  'project.move': 'move a project between folders',
  'project.delete': 'delete a project',
  'folder.refile': 'change a folder',
  'environment.create': 'create an environment',
  'environment.update': 'change an environment',
  'environment.archive': 'archive an environment',
  'environment.restore': 'restore an environment',
  'environment.delete': 'delete an environment',
  'environment.protect': 'protect an environment',
  'environment.unprotect': 'unprotect an environment',
  'upstream.freeze': 'freeze an upstream credential',
  'upstream.thaw': 'unfreeze an upstream credential',
  // Every membership asked is logged as an addition, a role change and a return too.
  'member.add': 'change a membership',
  'member.restore': 'change a membership',
  'member.role': "change a member's instance role",
  'member.remove': 'remove a member',
  'access.grant': 'change access',
  'access.revoke': 'take away access',
  'policy.change': 'change a role',
  'settings.change': 'change where people set up service accounts',
  sign_in: 'sign in',
  sign_out: 'sign out',
  'token.create': 'issue a credential',
  'token.revoke': 'end a credential',
  'account.link': 'link a sign-in account',
  'account.unlink': 'unlink a sign-in account',
  'device.start': 'start a CLI sign-in',
  'device.approve': 'approve a CLI sign-in',
  'device.deny': 'turn down a CLI sign-in',
  'token.exchange': 'start a session from a CI run or a workload',
  'workload.renew': 'renew a workload session',
  'token.bind': 'change a trust binding',
  'token.unbind': 'remove a trust binding',
  'workload.freeze': 'freeze workloads',
  'workload.unfreeze': 'unfreeze workloads',
  'mcp.connect': 'connect an MCP client',
  'mcp.token': 'get tokens for an MCP client',
  'mcp.disconnect': 'disconnect an MCP client',
  'oauth.register': 'register an MCP client',
  'mcp.ask': 'ask for a change through MCP',
  'mcp.approve': 'approve a change asked through MCP',
  'mcp.deny': 'turn down a change asked through MCP',
  'upkeep.expire': 'remove what had lapsed',
  'vault.adopt': 'take over the database',
};

/**
 * A refused entry's sentence: what kind of change, where the entry's own
 * rows put it (its project and environment, never a name the caller asked
 * for), and why. "tried to rename a key at market/dev: no access".
 */
function refusal(entry: AuditEntry): Part[] {
  const kind = Object.hasOwn(TRIED, entry.action) ? TRIED[entry.action as LogAction] : entry.action;
  const at = entry.project === null ? [] : [' at ', { place: [entry.project, entry.environment].filter((part) => part !== null).join('/') }];
  return ['tried to ', kind, ...at, `: ${reasonInWords(entry.reason)}`];
}

/** Why something was refused, in words. Codes from the vault and the app. */
const REASONS: Record<string, string> = {
  no_grant: 'no grant',
  bulk_limit: 'bulk limit',
  // 0.9's `people: 'stand-ins'`, in entries written before 0.10.
  stand_ins: 'people get placeholders',
  sensitive: 'the value is sensitive',
  looser: 'making it visible takes a new value',
  // A sensitive value made a secret in place by anyone but an Owner of its project.
  not_owner: 'only an Owner of the project does it in place',
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
const LEAD = ['secret.write', 'secret.loosen', 'secret.read'];

export function leadOf(batch: AuditEntry[]): AuditEntry {
  for (const action of LEAD) {
    const found = batch.find((entry) => entry.action === action);
    if (found !== undefined) return found;
  }
  return batch[0]!;
}

/**
 * A read, logged once for every key it released, or a write, once for
 * every key it wrote, as the entries it would be about one key each: its
 * key and version, and its own part of the detail (`keys`: a read's
 * `{ key, secret, version, through? }`, a write's line), such as the
 * reference it went through. Any other entry as it is.
 */
export function perSecret<T extends AuditEntry>(entry: T): T[] {
  const listed = entry.metadata.keys;
  const released = entry.secrets ?? [{ key: entry.key, version: entry.version }];
  // One whose list was emptied or mangled, which its proof would flag, still reads as itself.
  if (!['secret.read', 'secret.write', 'secret.loosen'].includes(entry.action) || !Array.isArray(listed) || released.length === 0 || listed.length !== released.length) return [entry];
  return released.map(({ key, version }, i) => {
    const own = listed[i];
    return {
      ...entry,
      key,
      version,
      secrets: null,
      metadata: { ...entry.metadata, keys: undefined, ...(typeof own === 'object' && own !== null && !Array.isArray(own) ? own : {}) },
    };
  });
}

/** What a line says: one entry, or a batch that shares an operation. */
export function describe(batch: AuditEntry[]): Sentence {
  const lead = perSecret(leadOf(batch))[0]!;
  const same = batch.filter((other) => other.action === lead.action).flatMap(perSecret);
  // A batch is what was done: its refusals are counted after it, never said or counted as done.
  const allowed = same.filter((other) => other.decision !== 'deny');
  const denied = same.filter((other) => other.decision === 'deny');
  const refused = allowed.length === 0;
  if (refused) return { parts: refusal(lead), refused };
  const entry = allowed[0]!;
  const facts: Facts = { entry, batch: allowed, count: new Set(allowed.map((other) => `${other.project}/${other.environment}/${other.key}`)).size };
  const template = Object.hasOwn(TEMPLATES, entry.action) ? TEMPLATES[entry.action as LogAction] : undefined;
  if (template === undefined) return { parts: [entry.action, ' ', ...place(entry)], refused };
  const what = template.what(facts);
  const gap = what.length === 0 ? [] : [' '];
  const partly = denied.length === 0 ? [] : [`, ${denied.length} refused: ${reasonInWords(denied[0]!.reason)}`];
  // A change that changed nothing, and one made through an MCP client's approval, say so.
  const unchanged = entry.metadata.unchanged === true || template.unchanged?.(facts) === true ? [', unchanged'] : [];
  const approved = text(entry.metadata.via) === null ? [] : [', approved through MCP'];
  return { parts: [typeof template.did === 'string' ? template.did : template.did(facts), ...gap, ...what, ...(template.then?.(facts) ?? []), ...unchanged, ...approved, ...partly], refused };
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
  'coffre-key-rotation': 'coffre',
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

// The Proxy tab's rules, without React (0.16, T186; docs/design/proxy-ui.md):
// what an environment's credential proxy holds, the deployment's code's items
// and the environment's own, inherited through its fork's parents; the page's
// pending edits, one Save for all of them; and the words the page shows.
//
// The vault decides every save (`PUT …/proxy`): who may edit, which keys an
// editor may route, the definition's shape. What the page checks before it
// asks is a courtesy, and checks with the vault's own rules where it can
// (`proxyDefinitionProblem`, `@coffre/core/proxy`), so that a field's note
// and the vault's refusal say the same.
import type { ProxyPage, SecretKey } from '@coffre/client';
import {
  definitionKeys,
  PROXY_METHODS,
  proxyDefinitionProblem,
  TEMPLATE_KEY,
  type ProxyAllow,
  type ProxyDefinition,
  type ProxyHmac,
  type ProxyInject,
  type ProxyKind,
  type ProxyLimit,
  type ProxyMethod,
  type ProxyRoute,
  type ProxySigner,
  type ProxyTunnel,
  type ProxyVerifier,
} from '@coffre/core/proxy';
import { allows, climbs, NOTHING, readPattern, requestSegments, type AllowEntry } from '@coffre/core/proxy-match';
import { CREDENTIAL_NAME } from '@coffre/core/workloads';

export type { ProxyAllow, ProxyDefinition, ProxyHmac, ProxyInject, ProxyKind, ProxyLimit, ProxyMethod, ProxyRoute, ProxySigner, ProxyTunnel, ProxyVerifier };
export { PROXY_METHODS };

export type Place = { project: string; environment: string };

export const KIND_LABELS: Record<ProxyKind, string> = { route: 'Route', signer: 'Signer', verifier: 'Verifier', tunnel: 'Database' };

/** The list's order: routes, then databases, signers and verifiers, each by name. */
const KIND_ORDER: readonly ProxyKind[] = ['route', 'tunnel', 'signer', 'verifier'];

export type InjectKind = ProxyInject['kind'];
export const INJECT_KINDS: readonly InjectKind[] = ['header', 'query', 'form', 'json', 'basic', 'sigv4'];
export const INJECT_LABELS: Record<InjectKind, string> = { header: 'Header', query: 'Query', form: 'Form', json: 'JSON', basic: 'Basic', sigv4: 'SigV4' };
export const ENCODINGS: readonly ProxyHmac['encoding'][] = ['hex', 'base64', 'base64url'];

// --- what the page shows ---------------------------------------------------------------------

/**
 * One item of the environment's proxy, wherever it is defined: in the
 * deployment's code (shown locked, R66), in this environment, or in a parent
 * of its fork, which it inherits by name (decision 6).
 */
export type ProxyItem = {
  /** `code:route:maps`, `own:openai`, `from:openai`: one row's, through every edit; code may give a route and a signer one name. */
  id: string;
  source: 'code' | 'own' | 'inherited';
  definition: ProxyDefinition;
  /** A code item's environments, by path; null: every one. */
  environments: string[] | null;
  /** Whether it serves this environment: a code item scoped elsewhere only takes its name here. */
  serves: boolean;
  limitPerService: boolean;
  /** A code item whose requests leave through a binding, an egress or a network, which has no name to show. */
  bound: boolean;
  /** A code route's allow list, matched as code matches it (`ProxyPage.code`'s `allowAs`); null: as the tab's. */
  allowAs: AllowAs | null;
  savedBy: string | null;
  savedAt: number | null;
  routesSensitive: boolean;
  /** Why it would not route now (`route_not_cleared`, decision 5), or null: someone who reads its keys saves it again. */
  notCleared: { key: string; reason: string } | null;
  /** An inherited item's place, `market/dev`; an own item's that it overrides; null otherwise. */
  from: string | null;
};

export type AllowAs = { from: 'code' | 'legacy'; methods: readonly string[] | null };

/** A parent of the fork, nearest first, and its page; null where the page could not be read. */
export type ParentPage = { path: string; page: ProxyPage | null };

/**
 * What the page can show of its inheritance: the parents it resolves, nearest
 * first, up to the first it cannot, and that one, closed to this person or
 * failing the vault's check. Past it nothing is shown, since it may override
 * what its own parents hold: with dev-eu-x from dev-eu from dev and dev-eu
 * closed, dev's openai may be dev-eu's own openai, to another upstream; and
 * the vault refuses a use whose chain holds a forged object.
 *
 *   dev-eu-x: dev-eu closed, dev  ->  resolved [], stop dev-eu (closed)
 */
export function inheritanceOf(parents: readonly ParentPage[]): { resolved: (ParentPage & { page: ProxyPage })[]; stop: { path: string; why: 'closed' | 'tampered' | 'stale' } | null } {
  const resolved: (ParentPage & { page: ProxyPage })[] = [];
  for (const parent of parents) {
    if (parent.page === null) return { resolved, stop: { path: parent.path, why: 'closed' } };
    if (parent.page.state !== 'ok') return { resolved, stop: { path: parent.path, why: parent.page.state } };
    resolved.push({ ...parent, page: parent.page });
  }
  return { resolved, stop: null };
}

/**
 * The items the page lists: code's, then the environment's own, then those
 * it inherits and does not override, none whose name code takes (code wins
 * a name in every environment), in the list's order.
 *
 *   code maps; own openai; dev's openai and stripe  ->  maps (code), openai (own, over dev's), stripe (from dev)
 */
export function itemsOf(page: ProxyPage, place: Place, parents: readonly ParentPage[] = []): ProxyItem[] {
  const path = `${place.project}/${place.environment}`;
  const code = new Set(page.code.map((item) => item.definition.name));
  const blank = { environments: null, serves: true, limitPerService: false, bound: false, allowAs: null };
  const items: ProxyItem[] = page.code.map((item) => ({
    id: `code:${item.definition.kind}:${item.definition.name}`,
    source: 'code',
    definition: item.definition,
    environments: item.environments,
    serves: item.environments === null || item.environments.includes(path),
    limitPerService: item.limitPerService,
    bound: item.bound,
    allowAs: item.allowAs ?? null,
    savedBy: null,
    savedAt: null,
    routesSensitive: false,
    notCleared: null,
    from: null,
  }));
  const held = new Set(code);
  const { resolved } = inheritanceOf(parents);
  const parentOf = (name: string) => resolved.find((parent) => parent.page.items.some((item) => item.definition.name === name))?.path ?? null;
  for (const item of page.items) {
    const name = item.definition.name;
    if (held.has(name)) continue;
    held.add(name);
    items.push({ ...blank, id: `own:${name}`, source: 'own', definition: item.definition, savedBy: item.savedBy, savedAt: item.savedAt, routesSensitive: item.routesSensitive, notCleared: item.notCleared ?? null, from: parentOf(name) });
  }
  for (const parent of resolved) {
    for (const item of parent.page.items) {
      const name = item.definition.name;
      if (held.has(name)) continue;
      held.add(name);
      // Its mark is this environment's, where its keys resolve here, never the parent's page's.
      items.push({ ...blank, id: `from:${name}`, source: 'inherited', definition: item.definition, savedBy: item.savedBy, savedAt: item.savedAt, routesSensitive: item.routesSensitive, notCleared: page.inheritedNotCleared?.[name] ?? null, from: parent.path });
    }
  }
  return sortedItems(items);
}

function sortedItems<T extends { definition: ProxyDefinition }>(items: T[]): T[] {
  return items.sort((a, b) => KIND_ORDER.indexOf(a.definition.kind) - KIND_ORDER.indexOf(b.definition.kind) || a.definition.name.localeCompare(b.definition.name));
}

/**
 * The fork's parents of an environment, nearest first, by path, as the
 * project's environments list them: what its items inherit from.
 *
 *   market: dev, dev-eu (from dev), dev-eu-x (from dev-eu)  ->  dev-eu-x: market/dev-eu, market/dev
 */
export function parentsOf(environments: readonly { slug: string; parent: string | null }[], place: Place): string[] {
  const chain: string[] = [];
  let at = environments.find((one) => one.slug === place.environment)?.parent ?? null;
  // The vault follows three parents at most; the list is a project's, so a loop is a bug, and stops.
  while (at !== null && chain.length < 8 && !chain.includes(`${place.project}/${at}`)) {
    chain.push(`${place.project}/${at}`);
    at = environments.find((one) => one.slug === at)?.parent ?? null;
  }
  return chain;
}

// --- the pending edits ----------------------------------------------------------------------

export type RowState = 'same' | 'changed' | 'added' | 'deleted' | 'resaved';

/**
 * The page's edits, none saved yet: each row's definition as edited (null
 * deletes it), the rows added, and those saved again as they are; each
 * edited row's item as it was when its edit began, which keeps the edit
 * when another person's save removes the item; and the page as the first
 * edit found it, whose seal the save names, so that a save since, read in
 * the background, is still a 409 the review shows.
 */
export type Drafts = {
  edits: Readonly<Record<string, ProxyDefinition | null>>;
  added: readonly { id: string; copiedFrom: string | null }[];
  resaved: readonly string[];
  origins: Readonly<Record<string, ProxyItem>>;
  loaded: ProxyPage | null;
};

export const NO_DRAFTS: Drafts = { edits: {}, added: [], resaved: [], origins: {}, loaded: null };

/** Who is editing, and where: what the page knows of them, and of the environment's keys. */
export type Editor = {
  place: Place;
  /** The environment's keys, as its Secrets tab lists them for this person. */
  keys: readonly SecretKey[];
  /** Whether they may save here now (`ProxyPage.editable`). */
  editable: boolean;
  /** An Owner of the project, whose save routes its sensitive keys, audited (R66). */
  routesSensitive: boolean;
  /** The names code defines, and those code reserved before (`ProxyPage.reserved`). */
  code: readonly ProxyItem[];
  reserved: readonly string[];
  insecureUpstreams: boolean;
};

/** One row as the page shows it: an item as stored, or as edited and not yet saved. */
export type Row = {
  id: string;
  /** As stored; null for one added here. */
  item: ProxyItem | null;
  before: ProxyDefinition | null;
  definition: ProxyDefinition;
  state: RowState;
  /** Whether its fields take edits. */
  editable: boolean;
  /** Whether it may be deleted: the environment's own, for whoever may save. */
  removable: boolean;
  /** For a copied row, the environment it came from. */
  copiedFrom: string | null;
  /** An edited item another person's save removed since: saving makes it again. */
  gone: boolean;
  /**
   * An edited or resaved item another save changed since its edit began (a
   * parent's, read in the background, which no 409 catches): the row keeps
   * the definition as its editor saw it, so the review shows each field
   * saving it would set back.
   */
  overtaken: boolean;
  /** How its keys stand for this editor: those they may not route, those an Owner routes (sensitive), and those the place lacks. */
  keys: KeyStanding;
};

export type KeyStanding = { blocked: string[]; routed: string[]; missing: string[] };

/**
 * The rows: the items with their edits, then those added. A row the editor
 * may not route every key of stays as it is: the vault would refuse its
 * save (it clears each key for its editor), so its fields are inert, and
 * only deleting it is offered.
 */
export function rowsOf(items: readonly ProxyItem[], drafts: Drafts, editor: Editor): Row[] {
  // An edit whose item another save removed stays, over the item that now has its name, if any: Bob deleted
  // dev-eu's own openai while Alice edited it, and dev-eu inherits dev's again; Alice's edit is the override.
  const present = new Set(items.map((item) => item.id));
  // A resave whose item went is kept too, even when its draft is the item as it was: saving it again makes it again.
  const orphans = Object.entries(drafts.origins).flatMap(([id, origin]) => {
    if (present.has(id)) return [];
    const draft = drafts.edits[id];
    if (draft === null) return [];
    const definition = draft ?? origin.definition;
    const same = sameDefinition(definition, origin.definition);
    const resaved = drafts.resaved.includes(id);
    return same && !resaved ? [] : [{ id, origin, draft: definition, resaved: same }];
  });
  const twin = (id: string) => (id.startsWith('own:') ? `from:${id.slice(4)}` : id.startsWith('from:') ? `own:${id.slice(5)}` : null);
  const hidden = new Set(orphans.map(({ id }) => twin(id)));
  const rows: Row[] = items.filter((item) => !hidden.has(item.id)).map((item) => {
    const draft = drafts.edits[item.id];
    const definition = draft ?? item.definition;
    const state: RowState =
      draft === null ? 'deleted' : draft !== undefined && !sameDefinition(draft, item.definition) ? 'changed' : drafts.resaved.includes(item.id) ? 'resaved' : 'same';
    const keys = keyStanding(definitionKeys(definition), editor);
    const before = keyStanding(definitionKeys(item.definition), editor);
    const mine = editor.editable && item.source !== 'code';
    const origin = drafts.origins[item.id];
    return {
      id: item.id,
      item,
      before: item.definition,
      definition,
      state,
      editable: mine && state !== 'deleted' && before.blocked.length === 0,
      removable: mine && item.source === 'own',
      copiedFrom: null,
      gone: false,
      overtaken: state !== 'same' && state !== 'deleted' && origin !== undefined && !sameDefinition(origin.definition, item.definition),
      keys,
    };
  });
  for (const { id, origin, draft, resaved } of orphans) {
    const before = keyStanding(definitionKeys(origin.definition), editor);
    rows.push({ id, item: origin, before: origin.definition, definition: draft, state: resaved ? 'resaved' : 'changed', editable: editor.editable && before.blocked.length === 0, removable: editor.editable, copiedFrom: null, gone: true, overtaken: false, keys: keyStanding(definitionKeys(draft), editor) });
  }
  for (const { id, copiedFrom } of drafts.added) {
    const definition = drafts.edits[id];
    if (definition == null) continue;
    rows.push({ id, item: null, before: null, definition, state: 'added', editable: editor.editable, removable: editor.editable, copiedFrom, gone: false, overtaken: false, keys: keyStanding(definitionKeys(definition), editor) });
  }
  return rows;
}

/**
 * How the keys an item sends stand for its editor, as the vault clears them
 * at save (section 8): a key they read is theirs to route; a sensitive one,
 * which no person reads, only an Owner of the project routes, audited (R66);
 * any other they cannot read, they may not. A key the place lacks yet is
 * accepted: the route serves once it is set.
 */
export function keyStanding(names: readonly string[], editor: Pick<Editor, 'keys' | 'routesSensitive'>): KeyStanding {
  const standing: KeyStanding = { blocked: [], routed: [], missing: [] };
  for (const name of names) {
    const entry = editor.keys.find((one) => one.key === name && !one.archived);
    if (entry === undefined) standing.missing.push(name);
    else if (entry.readable) continue;
    else if (entry.sensitivity === 'sensitive' && (entry.reference === null ? editor.routesSensitive : entry.reference.ownsSource)) standing.routed.push(name);
    else standing.blocked.push(name);
  }
  return standing;
}

/**
 * The project a sensitive key's value is from, whose Owners alone route it:
 * a reference's source's, `billing` for `billing/prod/STRIPE_KEY`; null for
 * a value of the place's own project.
 */
export function sourceProjectOf(name: string, keys: readonly SecretKey[], place: Place): string | null {
  const source = keys.find((one) => one.key === name && !one.archived)?.reference?.source.split('/')[0];
  return source === undefined || source === place.project ? null : source;
}

/** The pending changes, counted. */
export function countsOf(rows: readonly Row[]): { added: number; updated: number; deleted: number } {
  return {
    added: rows.filter((row) => row.state === 'added').length,
    updated: rows.filter((row) => row.state === 'changed' || row.state === 'resaved').length,
    deleted: rows.filter((row) => row.state === 'deleted').length,
  };
}

/** "2 added, 1 updated": the pending changes, in words. */
export function countsInWords(counts: { added: number; updated: number; deleted: number }): string {
  const parts = [counts.added > 0 && `${counts.added} added`, counts.updated > 0 && `${counts.updated} updated`, counts.deleted > 0 && `${counts.deleted} deleted`].filter((part) => part !== false);
  return parts.length === 0 ? 'No changes' : parts.join(', ');
}

/**
 * What a save sends: each item it changes by name, its definition or null.
 * A renamed item is its old name removed and its new one added; an edited
 * inherited item is the environment's own, over its parent's; deleting an
 * own item that overrides a parent's reverts to the parent's.
 *
 *   openai renamed to gpt, maps deleted  ->  { openai: null, maps: null, gpt: { … } }
 */
export function saveOf(rows: readonly Row[]): Record<string, ProxyDefinition | null> {
  const items: Record<string, ProxyDefinition | null> = {};
  for (const row of rows) {
    // An item removed since its edit began has no old name left to remove.
    const was = row.item?.source === 'own' && !row.gone ? row.item.definition.name : null;
    if (row.state === 'deleted' && was !== null) items[was] = null;
    if ((row.state === 'changed' || row.state === 'resaved') && was !== null && was !== row.definition.name.trim()) items[was] = null;
  }
  for (const row of rows) {
    if (row.state === 'changed' || row.state === 'added' || row.state === 'resaved') {
      const definition = normalized(row.definition);
      items[definition.name] = definition;
    }
  }
  return items;
}

/**
 * Everything the page shows of its edits, from what it read and what was
 * edited: the rows, what is wrong with each once a save was tried, and the
 * changes counted. A forged or stale object holds nothing to edit: only an
 * Owner of the project replaces it whole, or nobody saves.
 */
export function pageState({ page, place, parents, keys, drafts, tried }: { page: ProxyPage; place: Place; parents: readonly ParentPage[]; keys: readonly SecretKey[]; drafts: Drafts; tried: boolean }) {
  const items = itemsOf(page, place, parents);
  const replacing = page.state !== 'ok';
  const editor: Editor = {
    place,
    keys,
    editable: page.editable && (!replacing || page.routesSensitive),
    routesSensitive: page.routesSensitive,
    code: items.filter((item) => item.source === 'code'),
    reserved: page.reserved,
    insecureUpstreams: page.insecureUpstreams,
  };
  const rows = rowsOf(items, drafts, editor);
  const found = problemsOf(rows, editor);
  const counts = countsOf(rows);
  return {
    place,
    page,
    editor,
    rows,
    counts,
    changed: counts.added + counts.updated + counts.deleted,
    replacing,
    /** Whether nothing stands in the way of the review: no row has a problem. */
    sound: Object.keys(found).length === 0,
    /** A row's problems, by field, once a save was tried. */
    problems: (row: Row): Problems => (tried ? (found[row.id] ?? {}) : {}),
    faulty: tried ? rows.filter((row) => found[row.id] !== undefined) : [],
  };
}

// --- what is wrong with an edit --------------------------------------------------------------

/** What is wrong with a row, by field: `name`, `upstream`, `inject.0`, `allow.1`, `placeholder`, `limit`, `key`, `signature`, `hosts`, `keys`, and `item` for the rest. */
export type Problems = Record<string, string>;

/** What is wrong with each changed or added row, by row id: what the vault would refuse, said under its field. */
export function problemsOf(rows: readonly Row[], editor: Editor): Record<string, Problems> {
  const found: Record<string, Problems> = {};
  for (const row of rows) {
    if (row.state !== 'changed' && row.state !== 'added' && row.state !== 'resaved') continue;
    const problems = rowProblems(row, rows, editor);
    if (Object.keys(problems).length > 0) found[row.id] = problems;
  }
  return found;
}

function rowProblems(row: Row, rows: readonly Row[], editor: Editor): Problems {
  const problems: Problems = {};
  const item = normalized(row.definition);
  const name = item.name;
  const where = `${editor.place.project}/${editor.place.environment}`;
  const code = editor.code.find((one) => one.definition.name === name);
  const taken = rows.find((other) => other.id !== row.id && other.state !== 'deleted' && other.item?.source !== 'code' && other.definition.name.trim() === name);
  if (!CREDENTIAL_NAME.test(name)) problems.name = 'A lowercase letter, then up to 31 lowercase letters, digits or dashes.';
  else if (code !== undefined) problems.name = `${name} is defined in this deployment's code${code.environments === null ? '' : ` (${code.environments.join(', ')} only)`}: pick another name.`;
  else if (editor.reserved.includes(name)) problems.name = `${name} was defined by an earlier deployment's code: an instance Owner may release it.`;
  else if (taken?.item?.source === 'inherited') problems.name = `${where} inherits ${name} from ${taken.item.from}: open it to change it here.`;
  else if (taken !== undefined) problems.name = `${where} has ${name} already.`;

  // The vault's own check, its words under the field they are about.
  const refused = proxyDefinitionProblem(item, { insecureUpstreams: editor.insecureUpstreams });
  if (refused !== null && problems.name === undefined) {
    const { field, words } = fieldOf(refused, name, item.kind);
    if (field !== 'name' || CREDENTIAL_NAME.test(name)) problems[field] ??= words;
  }
  if (row.keys.blocked.length > 0) problems.keys = blockedInWords(row.keys.blocked, editor.place, editor.keys);
  return problems;
}

/**
 * The field a vault refusal is about, and its words without the item's
 * name: `openai: inject[1].template names no key: write it as {KEY}` is
 * `inject.1`'s "Template names no key: write it as {KEY}".
 */
export function fieldOf(problem: string, name: string, kind: ProxyKind): { field: string; words: string } {
  const prefix = `${name}: `;
  const said = problem.startsWith(prefix) ? problem.slice(prefix.length) : problem;
  const capital = (text: string) => text.charAt(0).toUpperCase() + text.slice(1);
  const at = /^(upstream|egress|network|placeholder|limit|inject|allow|hosts|key|signer|hmac)(?:\[(\d+)\])?(?:\.([A-Za-z]+))?[ :]\s*/.exec(said);
  if (at === null) {
    if (!problem.startsWith(prefix)) return { field: 'name', words: capital(said) };
    return { field: kind === 'route' ? 'inject' : 'item', words: capital(said) };
  }
  const [whole, head, index, sub] = at;
  const rest = said.slice(whole.length);
  const words = capital(sub !== undefined && ['template', 'user', 'password', 'name', 'region', 'service', 'accessKeyId', 'secretAccessKey', 'sessionToken', 'path', 'methods'].includes(sub) ? `${sub} ${rest}` : rest || said);
  switch (head) {
    case 'inject':
    case 'allow':
      return { field: index === undefined ? head : `${head}.${index}`, words };
    case 'signer':
    case 'hmac':
      return { field: sub === 'key' || sub === undefined ? 'key' : 'signature', words };
    case 'egress':
      return { field: 'upstream', words: capital(said) };
    default:
      return { field: head!, words: capital(said) };
  }
}

/**
 * The refusal, in words, of keys the editor may not route: those they cannot
 * read, and sensitive ones from another project, which only its Owners route.
 *
 *   "STRIPE_KEY is sensitive, from billing: only an Owner of billing routes it."
 */
export function blockedInWords(keys: readonly string[], place: Place, all: readonly SecretKey[] = []): string {
  const sentences: string[] = [];
  const unread = keys.filter((key) => !foreignSensitive(key, all, place));
  if (unread.length > 0) sentences.push(`You can't read ${unread.join(', ')} in ${place.project}/${place.environment}, so you can't route ${unread.length === 1 ? 'it' : 'them'}.`);
  for (const key of keys.filter((one) => foreignSensitive(one, all, place))) {
    const project = sourceProjectOf(key, all, place)!;
    sentences.push(`${key} is sensitive, from ${project}: only an Owner of ${project} routes it.`);
  }
  return sentences.join(' ');
}

const foreignSensitive = (name: string, keys: readonly SecretKey[], place: Place) =>
  keys.some((one) => one.key === name && !one.archived && one.sensitivity === 'sensitive') && sourceProjectOf(name, keys, place) !== null;

/**
 * What routing sensitive keys means for an Owner, said where it happens:
 * an Owner of the project each value is from, the place's or a
 * reference's source's.
 */
export function routedInWords(keys: readonly string[], place: Place, all: readonly SecretKey[] = []): string {
  const projects = [...new Set(keys.map((key) => sourceProjectOf(key, all, place) ?? place.project))];
  const owner = projects.length === 1 && projects[0] === place.project ? 'this project' : projects.join(' and ');
  return `${keys.join(', ')} ${keys.length === 1 ? 'is' : 'are'} sensitive: as an Owner of ${owner} you may route ${keys.length === 1 ? 'it' : 'them'}, and the save is audited.`;
}

/**
 * An item that would not route now, in words: which key its save no longer
 * clears, and who clears it again.
 *
 *   "gemini does not route now: lead@acme.example, who saved it, no longer reads OPENAI_API_KEY here. Someone who does saves it again."
 */
export function notClearedInWords(item: Pick<ProxyItem, 'definition' | 'savedBy' | 'notCleared'>, place: Place): string {
  const { key, reason } = item.notCleared!;
  const who = savedByInWords(item.savedBy);
  return / is sensitive/.test(reason)
    ? `${item.definition.name} does not route now: ${key} is sensitive, and ${who}'s save was not an Owner's. An Owner of ${place.project} saves it again.`
    : `${item.definition.name} does not route now: ${who}, who saved it, no longer reads ${key} here. Someone who does saves it again.`;
}

/** Keys the place lacks: the route is saved, and serves once they are set. */
export function missingInWords(keys: readonly string[], place: Place): string {
  return `No ${keys.join(', ')} in ${place.project}/${place.environment} yet: it serves once ${keys.length === 1 ? 'it is' : 'they are'} set.`;
}

// --- making them -----------------------------------------------------------------------------

const NO_LIMIT: ProxyLimit = { perMinute: null, perDay: null };

export function blankInject(kind: InjectKind): ProxyInject {
  switch (kind) {
    case 'basic':
      return { kind, user: '', password: '' };
    case 'sigv4':
      return { kind, accessKeyId: '', secretAccessKey: '', sessionToken: null, region: '', service: 's3' };
    case 'header':
      return { kind, name: 'authorization', template: 'Bearer ' };
    default:
      return { kind, name: '', template: '' };
  }
}

export function blankDefinition(kind: ProxyKind): ProxyDefinition {
  switch (kind) {
    case 'route':
      return { kind, name: '', upstream: 'https://', inject: [blankInject('header')], allow: null, limit: NO_LIMIT, placeholder: null, egress: null };
    case 'signer':
      return { kind, name: '', signer: { kind: 'private-key', key: '' }, limit: NO_LIMIT };
    case 'verifier':
      return { kind, name: '', hmac: { key: '', encoding: 'hex', prefix: '', maxBytes: null }, limit: NO_LIMIT };
    case 'tunnel':
      return { kind, name: '', key: '', hosts: [''], network: null };
  }
}

/** An item as it is saved: its name, upstream and hosts trimmed, methods in their order, empty claims and hosts dropped. */
export function normalized(definition: ProxyDefinition): ProxyDefinition {
  const name = definition.name.trim();
  switch (definition.kind) {
    case 'route':
      return {
        ...definition,
        name,
        upstream: definition.upstream.trim(),
        inject: definition.inject.map((rule) => (rule.kind === 'sigv4' ? { ...rule, sessionToken: rule.sessionToken === '' ? null : rule.sessionToken } : rule)),
        allow: definition.allow === null ? null : definition.allow.map((entry) => ({ methods: PROXY_METHODS.filter((method) => entry.methods.includes(method)), path: entry.path.trim() })),
        placeholder: definition.placeholder?.kind === 'jwt' ? { kind: 'jwt', claims: definition.placeholder.claims.map((claim) => claim.trim()).filter((claim) => claim !== '') } : definition.placeholder,
      };
    case 'tunnel':
      return { ...definition, name, hosts: definition.hosts.map((host) => host.trim()).filter((host) => host !== '') };
    default:
      return { ...definition, name };
  }
}

export const sameDefinition = (a: ProxyDefinition, b: ProxyDefinition) => JSON.stringify(normalized(a)) === JSON.stringify(normalized(b));

// --- templates -------------------------------------------------------------------------------

/** A template in pieces: its text, and each `{KEY}` it names, as the proxy reads them. */
export function templateParts(template: string): ({ text: string } | { key: string })[] {
  const parts: ({ text: string } | { key: string })[] = [];
  let at = 0;
  for (const match of template.matchAll(TEMPLATE_KEY)) {
    if (match.index > at) parts.push({ text: template.slice(at, match.index) });
    parts.push({ key: match[1]! });
    at = match.index + match[0].length;
  }
  if (at < template.length) parts.push({ text: template.slice(at) });
  return parts;
}

/** A key as a SigV4 field names it alone, `{AWS_ACCESS_KEY_ID}`, or ''. */
export const soleKey = (template: string | null) => /^\{([A-Za-z_][A-Za-z0-9_]*)\}$/.exec(template ?? '')?.[1] ?? '';

// --- a sample call ---------------------------------------------------------------------------

/**
 * Where a sample call through a route goes, or why the proxy refuses it,
 * by the proxy's own matcher, as it reads the route's allow list (a code
 * route's as code: `allowAs`): `GET /models/gpt-4` under `GET /models/**`
 * goes to `<upstream>/models/gpt-4`; under legacy `paths: ['/models/*']`,
 * only `/models/*` itself does.
 */
export function sampleCall(route: ProxyRoute, method: string, path: string, allowAs: AllowAs | null = null): { url: string; refusal: string | null } {
  const asked = path.startsWith('/') ? path : `/${path}`;
  // The path as the proxy reads it (`aim`): what is past `?` or `#` is no path, a segment that climbs out (`/%2e%2e/admin`)
  // is refused before any matching, and the rest is matched as the URL holds it, encoded (`/café` is `/caf%C3%A9`).
  const cut = asked.search(/[?#]/);
  const [written, search] = cut === -1 ? [asked, ''] : [asked.slice(0, cut), asked.slice(cut)];
  const rest = written.slice(1).split('/');
  const base = route.upstream.replace(/\/+$/, '');
  let target: URL | null = null;
  try {
    target = new URL(`${base}/${rest.join('/')}${search}`);
  } catch {
    // An upstream still being typed: the call as written, matched as given.
  }
  const url = target?.href ?? `${base}${asked}`;
  // A character beyond ASCII goes as its UTF-8 bytes, encoded (`À` is `%C3%80`), never as the byte its code point names.
  if (rest.map(asSent).some(climbs)) return { url, refusal: '400: the path may not climb out of the upstream' };
  const under = target === null ? '' : new URL(base).pathname.replace(/\/$/, '');
  const tail = target === null ? written : target.pathname.slice(under.length) || '/';
  if (route.allow === null) return { url, refusal: null };
  const from = allowAs?.from ?? 'ui';
  // `allow: []` takes no request: a 403 whatever the method, as the proxy answers it.
  if (from !== 'legacy' && route.allow.length === 0) return { url, refusal: '403: this route takes no request' };
  // Legacy entries take `methods` as code wrote them: `[]` took none, where the tab's `[]` is any.
  const legacy = from === 'legacy' && allowAs?.methods != null ? new Set(allowAs.methods) : null;
  const methods = (given: readonly string[]) => legacy ?? (given.length === 0 ? null : new Set(given));
  const entries: AllowEntry[] = [];
  for (const entry of route.allow) {
    const read = readPattern(entry.path, from);
    if ('problem' in read) continue;
    entries.push({ methods: methods(entry.methods), path: read.pattern });
  }
  // Legacy `paths: []` takes no path, but its `methods` answer first, as code's: `methods: ['POST'], paths: []` is a 405 to a GET, a 403 to a POST.
  if (from === 'legacy' && route.allow.length === 0) entries.push({ methods: legacy, path: NOTHING });
  const answer = allows(entries, method, requestSegments(tail, from === 'legacy'));
  return { url, refusal: answer === 'allowed' ? null : answer === 'method' ? `405: no allow entry takes ${method} there` : `403: no allow entry takes ${method} ${tail}` };
}

/** A segment as a URL sends it: `/À-propos` goes as `/%C3%80-propos`, what is ASCII as written. */
function asSent(segment: string): string {
  try {
    return segment.replace(/[^\x00-\x7f]+/gu, encodeURIComponent);
  } catch {
    return segment; // a lone surrogate: the URL refuses it anyway
  }
}

/**
 * The sample call's methods: the tab's seven, then any other a code item's
 * allow list names, as code takes any HTTP method (`PROPFIND`).
 */
export function methodChoices(route: ProxyRoute, allowAs: AllowAs | null = null): string[] {
  const named: readonly string[] = [...(route.allow ?? []).flatMap((entry) => entry.methods), ...(allowAs?.methods ?? [])];
  return [...PROXY_METHODS, ...new Set(named.filter((method) => !(PROXY_METHODS as readonly string[]).includes(method)))];
}

/**
 * An allow entry's methods on its menu's trigger, one width: none is any,
 * and what does not fit is the first and a count. Code's beyond the seven
 * show as written.
 *
 *   []  ->  Any      ['GET', 'POST']  ->  GET POST      ['PROPFIND']  ->  PROPFIND      four  ->  GET +3
 */
export function methodsLabel(methods: readonly string[]): { all: string; shown: string } {
  const picked = [...PROXY_METHODS.filter((method) => methods.includes(method)), ...methods.filter((method) => !(PROXY_METHODS as readonly string[]).includes(method))];
  const all = picked.join(' ');
  return { all, shown: picked.length === 0 ? 'Any' : all.length <= 9 ? all : `${picked[0]} +${picked.length - 1}` };
}

// --- words, and code -------------------------------------------------------------------------

export function injectInWords(inject: ProxyInject): string {
  switch (inject.kind) {
    case 'header':
      return `${inject.name}: ${inject.template}`;
    case 'query':
      return `?${inject.name}=${inject.template}`;
    case 'form':
      return `${inject.name}=${inject.template}`;
    case 'json':
      return `"${inject.name}": "${inject.template}"`;
    case 'basic':
      return `${inject.user}:${inject.password}`;
    case 'sigv4':
      return `${inject.service} in ${inject.region}, ${[inject.accessKeyId, inject.secretAccessKey, inject.sessionToken ?? ''].filter((one) => one !== '').join(', ')}`;
  }
}

const format = new Intl.NumberFormat('en');

export function limitInWords(limit: ProxyLimit, perService = false): string {
  if (perService) return 'Per service, in code';
  const parts = [limit.perMinute !== null && `${format.format(limit.perMinute)} a minute`, limit.perDay !== null && `${format.format(limit.perDay)} a day`].filter((part) => part !== false);
  return parts.length === 0 ? 'None' : parts.join(', ');
}

/** The host a definition sends its keys to, for the list and the review: a route's upstream's, a database's hosts; a signer's or verifier's key, which stays here. */
export function targetOf(definition: ProxyDefinition): string {
  switch (definition.kind) {
    case 'route':
      try {
        return new URL(definition.upstream).host;
      } catch {
        return definition.upstream;
      }
    case 'signer':
      return definition.signer.key;
    case 'verifier':
      return definition.hmac.key;
    case 'tunnel':
      return definition.hosts.filter((host) => host.trim() !== '').length > 0 ? `${definition.key} @ ${definition.hosts.filter((host) => host.trim() !== '').join(', ')}` : definition.key;
  }
}

/** Where a definition sends its keys, for a copy's review: a route's upstream host, a database's hosts; null for a signer or verifier, which send nothing. */
export function destinationOf(definition: ProxyDefinition): string | null {
  switch (definition.kind) {
    case 'route': {
      const host = targetOf(definition);
      return definition.egress === null ? host : `${host} through ${definition.egress}`;
    }
    case 'tunnel':
      return definition.hosts.join(', ');
    default:
      return null;
  }
}

/**
 * What a copied item will do in its new place, in words (decision 2): which
 * of the target's keys it sends, and where.
 *
 *   "schuman will send market/prod's SCHUMAN_API_KEY to sandbox.schuman.example (copied from market/dev)."
 */
export function copiedInWords(definition: ProxyDefinition, place: Place, from: string): string {
  const keys = definitionKeys(definition);
  const target = `${place.project}/${place.environment}`;
  const destination = destinationOf(definition);
  const what = destination === null ? `will sign with ${target}'s ${keys.join(', ')}` : `will send ${target}'s ${keys.join(', ')} to ${destination}`;
  return `${definition.name} ${what} (copied from ${from}).`;
}

/**
 * Whether a change sends keys somewhere they did not go before: a new item,
 * one deleted, or an upstream, rule, egress, database or key changed. After
 * such a save, values decided before it may still reach the old place for
 * the save's window (decision 4).
 */
export function redirects(before: ProxyDefinition | null, after: ProxyDefinition | null): boolean {
  if (before === null || after === null) return before !== after;
  if (before.kind !== after.kind) return true;
  const a = normalized(before);
  const b = normalized(after);
  const same = (x: unknown, y: unknown) => JSON.stringify(x) === JSON.stringify(y);
  switch (b.kind) {
    case 'route': {
      const was = a as ProxyRoute;
      return was.upstream !== b.upstream || was.egress !== b.egress || !same(was.inject, b.inject);
    }
    case 'tunnel': {
      const was = a as ProxyTunnel;
      return was.key !== b.key || was.network !== b.network || !same(was.hosts, b.hosts);
    }
    default:
      return !same(definitionKeys(a), definitionKeys(b));
  }
}

/**
 * A change, field by field, in words: what the review shows. A field the
 * change leaves is left out; one it removes, a last rule or allow entry,
 * shows as removed ('–').
 *
 *   Sends 1 header, Sends 2 query  ->  Sends 1 header   =>  [{ label: 'Sends 2', before: 'Query …', after: '–' }]
 */
export function diffOf(before: ProxyDefinition | null, after: ProxyDefinition): { label: string; before: string | null; after: string }[] {
  const now = new Map(fieldsOf(normalized(after)));
  const was = before === null ? null : new Map(fieldsOf(normalized(before)));
  const labels = [...now.keys(), ...[...(was?.keys() ?? [])].filter((label) => !now.has(label))];
  return labels.flatMap((label) => {
    const old = was?.get(label) ?? null;
    const value = now.get(label) ?? '–';
    return old === value ? [] : [{ label, before: was === null ? null : (old ?? '–'), after: value }];
  });
}

function fieldsOf(item: ProxyDefinition): [string, string][] {
  const limit = (value: ProxyLimit): [string, string] => ['Limit', limitInWords(value)];
  switch (item.kind) {
    case 'route':
      return [
        ['Name', item.name],
        ['Upstream', item.upstream],
        ['Egress', item.egress ?? 'Direct'],
        ...item.inject.map((rule, index): [string, string] => [`Sends ${index + 1}`, `${INJECT_LABELS[rule.kind]} ${injectInWords(rule)}`]),
        ['Placeholder', item.placeholder === null ? 'The handle' : item.placeholder.kind === 'prefix' ? `Prefix ${item.placeholder.prefix}` : `JWT ${item.placeholder.claims.join(', ')}`],
        ...(item.allow === null
          ? [['Allows', 'Any method, any path'] as [string, string]]
          : item.allow.length === 0
            ? [['Allows', 'No request'] as [string, string]]
            : item.allow.map((entry, index): [string, string] => [`Allows ${index + 1}`, `${entry.methods.length === 0 ? 'Any' : entry.methods.join(' ')} ${entry.path}`])),
        limit(item.limit),
      ];
    case 'signer':
      return [
        ['Name', item.name],
        ['Signs with', item.signer.kind === 'hmac' ? 'HMAC-SHA256' : 'Private key'],
        ['Key', item.signer.key],
        ...(item.signer.kind === 'hmac' ? hmacFields(item.signer) : []),
        limit(item.limit),
      ];
    case 'verifier':
      return [['Name', item.name], ['Key', item.hmac.key], ...hmacFields(item.hmac), limit(item.limit)];
    case 'tunnel':
      return [
        ['Name', item.name],
        ['Key', item.key],
        ['Hosts', item.hosts.join(', ')],
        ['Network', item.network ?? 'Direct'],
      ];
  }
}

const hmacFields = (value: ProxyHmac): [string, string][] => [
  ['Encoding', value.encoding],
  ['Prefix', value.prefix === '' ? 'None' : value.prefix],
  ['Max bytes', value.maxBytes === null ? '64 KiB' : format.format(value.maxBytes)],
];

const q = (text: string) => `'${text.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
const prop = (name: string) => (/^[a-z][a-z0-9]*$/i.test(name) ? name : q(name));
const limitCode = (limit: ProxyLimit) => {
  const parts = [limit.perMinute !== null && `perMinute: ${limit.perMinute}`, limit.perDay !== null && `perDay: ${limit.perDay}`].filter((part) => part !== false);
  return parts.length === 0 ? null : `{ ${parts.join(', ')} }`;
};
const injectCode = (inject: ProxyInject) => {
  switch (inject.kind) {
    case 'basic':
      return `basic(${q(inject.user)}, ${q(inject.password)})`;
    case 'sigv4':
      return `sigv4({ accessKeyId: ${q(inject.accessKeyId)}, secretAccessKey: ${q(inject.secretAccessKey)}${inject.sessionToken === null ? '' : `, sessionToken: ${q(inject.sessionToken)}`}, region: ${q(inject.region)}, service: ${q(inject.service)} })`;
    default:
      return `${inject.kind}(${q(inject.name)}, ${q(inject.template)})`;
  }
};
const hmacCode = (value: ProxyHmac, limit: ProxyLimit, scope: string | null) => {
  const options = [
    `encoding: ${q(value.encoding)}`,
    value.prefix !== '' && `prefix: ${q(value.prefix)}`,
    value.maxBytes !== null && `maxBytes: ${value.maxBytes}`,
    limitCode(limit) !== null && `limit: ${limitCode(limit)}`,
    scope !== null && `environments: ${scope}`,
  ].filter((part) => part !== false);
  return `hmac(${q(value.key)}, { ${options.join(', ')} })`;
};

/**
 * An item as `credentialProxy({ … })` holds it, to move into code, serving
 * the environments named (null: every one), as it serves here: code wins a
 * name both take, in every environment. Only a UI item has one: code's own
 * may leave through a binding, or limit each service, which has no words here.
 *
 *   openai in market/dev  ->  credentials: { openai: { upstream: …, inject: header('authorization', 'Bearer {OPENAI_API_KEY}'), environments: ['market/dev'] } },
 */
export function codeOf(definition: ProxyDefinition, environments: readonly string[] | null = null): string {
  const item = normalized(definition);
  const name = prop(item.name || 'name');
  const scope = environments === null ? null : `[${environments.map(q).join(', ')}]`;
  switch (item.kind) {
    case 'route': {
      const lines = [`upstream: ${q(item.upstream)},`];
      if (item.egress !== null) lines.push(`egress: egresses[${q(item.egress)}],`);
      lines.push(item.inject.length === 1 ? `inject: ${injectCode(item.inject[0]!)},` : `inject: [${item.inject.map(injectCode).join(', ')}],`);
      if (item.placeholder !== null) lines.push(`placeholder: ${item.placeholder.kind === 'prefix' ? `prefix(${q(item.placeholder.prefix)})` : `jwt({ claims: [${item.placeholder.claims.map(q).join(', ')}] })`},`);
      if (item.allow !== null) lines.push(`allow: [`, ...item.allow.map((entry) => `  { ${entry.methods.length === 0 ? '' : `methods: [${entry.methods.map(q).join(', ')}], `}path: ${q(entry.path)} },`), `],`);
      if (limitCode(item.limit) !== null) lines.push(`limit: ${limitCode(item.limit)},`);
      if (scope !== null) lines.push(`environments: ${scope},`);
      return `credentials: {\n  ${name}: {\n${lines.map((line) => `    ${line}`).join('\n')}\n  },\n},`;
    }
    case 'signer': {
      const options = [limitCode(item.limit) !== null && `limit: ${limitCode(item.limit)}`, scope !== null && `environments: ${scope}`].filter((part) => part !== false);
      const body = item.signer.kind === 'hmac' ? hmacCode(item.signer, item.limit, scope) : `privateKey(${q(item.signer.key)}${options.length === 0 ? '' : `, { ${options.join(', ')} }`})`;
      return `signers: {\n  ${name}: ${body},\n},`;
    }
    case 'verifier':
      return `verifiers: {\n  ${name}: ${hmacCode(item.hmac, item.limit, scope)},\n},`;
    case 'tunnel': {
      const options = [item.hosts.length > 0 && `hosts: [${item.hosts.map(q).join(', ')}]`, item.network !== null && `connect: networks[${q(item.network)}]`, scope !== null && `environments: ${scope}`].filter((part) => part !== false);
      return `tunnels: {\n  ${name}: postgres(${q(item.key)}${options.length === 0 ? '' : `, { ${options.join(', ')} }`}),\n},`;
    }
  }
}

// --- since the page loaded -------------------------------------------------------------------

/**
 * What changed in the environment's own items between two reads of its
 * page: what the review shows after another person's save came first (a
 * 409, `proxy_changed`), so that saving again is a decision.
 *
 *   loaded: openai, stripe; now: openai (saved again by lead), maps  ->  openai updated, stripe removed, maps added
 */
export function changedSince(loaded: ProxyPage, now: ProxyPage): { name: string; what: 'added' | 'updated' | 'removed'; by: string | null }[] {
  const before = new Map(loaded.items.map((item) => [item.definition.name, item]));
  const after = new Map(now.items.map((item) => [item.definition.name, item]));
  const changes: { name: string; what: 'added' | 'updated' | 'removed'; by: string | null }[] = [];
  for (const [name, item] of after) {
    const was = before.get(name);
    if (was === undefined) changes.push({ name, what: 'added', by: item.savedBy });
    else if (was.savedAt !== item.savedAt || !sameDefinition(was.definition, item.definition)) changes.push({ name, what: 'updated', by: item.savedBy });
  }
  for (const name of before.keys()) if (!after.has(name)) changes.push({ name, what: 'removed', by: null });
  return changes.sort((a, b) => a.name.localeCompare(b.name));
}

/** A member as the vault names them, `user:ada@acme.example`, as a person reads it. */
export const savedByInWords = (member: string | null) => (member === null ? 'someone' : member.replace(/^user:/, ''));

// The commands that manage an instance, beside its secrets: projects and
// environments, members, bearer tokens, a secret's key, and your own
// sessions and accounts. Each takes the API and where to write, so a test
// drives it with a client of its own; each reads its arguments before it
// asks for one, so a mistyped command needs no session to be told so. A refusal says what to type instead;
// what would end something for good is shown first, and done with --apply.
import { openSync, closeSync, writeSync, rmSync } from 'node:fs';
import { parseArgs } from 'node:util';

import { INSTANCE_ROLES, isInstanceRole, scopeInWords, unscoped, type Filter, type InstanceRole, type Scope } from '@coffre/core/access';
import { apiMember, byFolder, serviceName, shownMember, type CoffreClient, type Deletion } from '@coffre/client';

import { describeRemoval, serviceMember } from './trust.ts';

/** Where a command writes: what it answers on `out`, what it tells a person on `err`. */
export type Io = {
  out: { write(text: string): unknown };
  err: { write(text: string): unknown; isTTY?: boolean };
};

const STDIO: Io = { out: process.stdout, err: process.stderr };

/** A command used wrongly: the CLI says why, then the command's usage, and exits 2. */
export class UsageError extends Error {}

type Options = NonNullable<Parameters<typeof parseArgs>[0]>['options'];

/** Strict options and positionals, each positional named: too few or too many is a usage error. */
export function parse<O extends Options>(args: string[], options: O, names: readonly string[], optional = 0) {
  const { values, positionals } = parseArgs({ args, options, allowPositionals: true, strict: true });
  if (positionals.length > names.length) throw new UsageError(`too many arguments: ${positionals.slice(names.length).join(' ')}`);
  if (positionals.length < names.length - optional) throw new UsageError(`name ${listOf(names.slice(positionals.length))}`);
  return { values, positionals };
}

function listOf(names: readonly string[]): string {
  return names.length < 2 ? names.join('') : `${names.slice(0, -1).join(', ')} and ${names.at(-1)}`;
}

const json = { json: { type: 'boolean', default: false } } as const;

function asJson(io: Io, value: unknown): void {
  io.out.write(`${JSON.stringify(value, null, 2)}\n`);
}

/** `market` and `market/prod`, checked: a project, or a place with its environment. */
function place(text: string, environment: boolean): { project: string; environment?: string } {
  const parts = text.split('/');
  if (parts.length !== (environment ? 2 : 1) || parts.some((part) => part === '')) {
    throw new UsageError(environment ? `expected <project>/<environment>, not "${text}"` : `expected a project, not "${text}"`);
  }
  return { project: parts[0]!, environment: parts[1] };
}

/** `market/prod/KEY`, checked. */
function secret(text: string): string {
  const parts = text.split('/');
  if (parts.length !== 3 || parts.some((part) => part === '')) throw new UsageError(`expected <project>/<environment>/<KEY>, not "${text}"`);
  return text;
}

const day = (iso: string | null) => (iso === null ? 'never' : iso.slice(0, 10));

/**
 * A grant is on a project or an environment: what reaches every project is
 * a person's instance role, and `*` no project.
 */
export function onAProject(project: string): void {
  if (project === '*') {
    throw new UsageError("grants are on a project or an environment: a person reaches every project by their instance role, `coffre admit <email> --role <role>`");
  }
}

/**
 * Someone's instance role in words: `Developer`, or `Developer, All projects · dev only`
 * when a scope narrows it. Only those who run the instance are told the scope (null otherwise).
 */
export function roleInWords(member: { instanceRole: InstanceRole | 'root-admin'; scope: Scope | null }): string {
  if (member.instanceRole === 'root-admin') return 'Root admin';
  const { name } = INSTANCE_ROLES[member.instanceRole];
  return member.scope === null || unscoped(member.scope) ? name : `${name}, ${scopeInWords(member.scope)}`;
}

// --- projects and environments ------------------------------------------------

export async function projects(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values } = parse(args, json, []);
  const api = connect();
  const { projects: list } = await api.projects.list();
  if (values.json) return asJson(io, list);
  for (const [folder, inFolder] of byFolder(list)) {
    const indent = folder === null ? '' : '  ';
    if (folder !== null) io.out.write(`${folder}/\n`);
    for (const project of inFolder) {
      const archived = project.archivedAt === null ? '' : ' (archived)';
      io.out.write(`${indent}${project.slug}${archived}  ${project.name}\n`);
      for (const environment of project.environments) {
        // Environments the caller may only know by name come without details.
        if (environment.details?.archivedAt) continue;
        const count = environment.details?.secretCount;
        io.out.write(`${indent}  ${environment.slug.padEnd(16)} ${count === null || count === undefined ? '' : `${count} secrets`}\n`);
      }
    }
  }
}

const naming = { name: { type: 'string' } } as const;
const renaming = { name: { type: 'string' }, slug: { type: 'string' } } as const;

export async function projectsCreate(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, naming, ['<project>']);
  const { project } = place(positionals[0]!, false);
  const api = connect();
  const made = await api.projects.create(project, { name: values.name ?? project });
  io.out.write(made.created ? `created ${made.project.slug}, "${made.project.name}"\n` : `${made.project.slug} exists already, "${made.project.name}": nothing changed\n`);
}

export async function environmentsCreate(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, naming, [`<project>/<environment>`]);
  const { project, environment } = place(positionals[0]!, true);
  const api = connect();
  const made = await api.environments.create(`${project}/${environment}`, { name: values.name ?? environment! });
  const path = `${project}/${made.environment.slug}`;
  io.out.write(made.created ? `created ${path}, "${made.environment.name}"\n` : `${path} exists already, "${made.environment.name}": nothing changed\n`);
}

/**
 * `coffre fork market/prod staging`: a new environment beside it, with each
 * live key's value and folder, and none of its history. Copying is a read,
 * logged as one; running it again fills the environment if it stopped
 * half way.
 */
export async function fork(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, { ...naming, reference: { type: 'boolean', default: false } }, ['<project>/<environment>', '<new-environment>']);
  const { project, environment: from } = place(positionals[0]!, true);
  const slug = positionals[1]!;
  if (slug.includes('/')) throw new UsageError(`name the new environment alone, as in staging, not "${slug}": it goes in ${project}`);
  const api = connect();
  const made = await api.environments.create(`${project}/${slug}`, { name: values.name ?? slug, from: from!, ...(values.reference ? { references: true } : {}) });
  const { keys = 0, references = 0, copied = [] } = made.forked ?? {};
  const what = values.reference
    ? `${references} reference${references === 1 ? '' : 's'}${copied.length === 0 ? '' : `, and ${copied.length} copied: ${copied.join(', ')}, whose source you read only through ${from}`}`
    : 'values copied, no history';
  io.out.write(`${made.created ? 'created' : 'filled'} ${project}/${made.environment.slug} from ${project}/${from}: ${keys} key${keys === 1 ? '' : 's'}, ${what}\n`);
  if (values.reference && references > 0) io.out.write(`  whoever reads ${project}/${made.environment.slug} reads those values through them, as they change\n`);
}

/** The patch `--name` and `--slug` make: one of them at least. */
function renamed(values: { name?: string; slug?: string }): { name?: string; slug?: string } {
  if (values.name === undefined && values.slug === undefined) throw new UsageError('give it a new --name, a new --slug, or both');
  return { ...(values.name === undefined ? {} : { name: values.name }), ...(values.slug === undefined ? {} : { slug: values.slug }) };
}

export async function projectsRename(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, renaming, ['<project>']);
  const { project } = place(positionals[0]!, false);
  const patch = renamed(values);
  const api = connect();
  const { project: now } = await api.projects.update(project, patch);
  io.out.write(`${project} is now ${now.slug}, "${now.name}"\n`);
}

export async function environmentsRename(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, renaming, ['<project>/<environment>']);
  const { project, environment } = place(positionals[0]!, true);
  const patch = renamed(values);
  const api = connect();
  const { environment: now } = await api.environments.update(`${project}/${environment}`, patch);
  io.out.write(`${project}/${environment} is now ${project}/${now.slug}, "${now.name}"\n`);
  // Scopes name environments by slug: a new one can bring in, or leave out, those scoped to it.
  if (now.slug !== environment) io.out.write(`  instance roles scoped to ${environment} no longer reach it; those scoped to ${now.slug} do\n`);
}

export async function projectsArchive(connect: () => CoffreClient, args: string[], archived: boolean, io: Io = STDIO): Promise<void> {
  const { positionals } = parse(args, {}, ['<project>']);
  const { project } = place(positionals[0]!, false);
  const api = connect();
  await api.projects.update(project, { archived });
  io.out.write(archived ? `archived ${project}: \`coffre projects unarchive ${project}\` brings it back\n` : `unarchived ${project}\n`);
}

export async function environmentsArchive(connect: () => CoffreClient, args: string[], archived: boolean, io: Io = STDIO): Promise<void> {
  const { positionals } = parse(args, {}, ['<project>/<environment>']);
  const { project, environment } = place(positionals[0]!, true);
  const path = `${project}/${environment}`;
  const api = connect();
  await api.environments.update(path, { archived });
  io.out.write(archived ? `archived ${path}: \`coffre environments unarchive ${path}\` brings it back\n` : `unarchived ${path}\n`);
}

/**
 * An archived project or environment deleted for good: first shown, what it
 * would erase and revoke, then, with --apply, deleted. Asked again after a
 * deletion cut off partway, it finishes it.
 */
export async function placeDelete(connect: () => CoffreClient, args: string[], environment: boolean, io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, { apply: { type: 'boolean', default: false } }, [environment ? '<project>/<environment>' : '<project>']);
  const where = place(positionals[0]!, environment);
  const path = environment ? `${where.project}/${where.environment}` : where.project;
  const api = connect();
  const places = environment ? api.environments : api.projects;
  if (!values.apply) {
    io.out.write(describeDeletion((await places.previewDelete(path)).deletion, false));
    return;
  }
  io.out.write(describeDeletion((await places.delete(path)).deletion, true));
}

/** What a deletion takes, before or after: what it erases, revokes and keeps. */
export function describeDeletion(deletion: Deletion, done: boolean): string {
  const { path, tombstone, environments, keys, versions, grants, stranded } = deletion;
  const count = (n: number, one: string) => `${n} ${one}${n === 1 ? '' : 's'}`;
  const where = environments.length === 0 ? '' : `, in ${environments.join(', ')}`;
  const revoked = grants.map((grant) => `${shownMember(grant.member)} (${grant.role} on ${grant.place})`);
  const lines = [
    done ? `deleted ${path}, for good:` : `would delete ${path}, for good:`,
    `  erased: ${count(versions, 'version')}${where}`,
    `  revoked: ${count(grants.length, 'grant')}${revoked.length === 0 ? '' : `, ${revoked.join(', ')}`}`,
    ...(deletion.references.length === 0
      ? []
      : [`  ended: ${count(deletion.references.length, 'reference')}, ${deletion.references.map((reference) => `${reference.holder} → ${reference.source}`).join(', ')}`]),
    `  kept, names only: ${tombstone} and its ${count(keys, 'key')}, for the audit log`,
    `  ${path.split('/').at(-1)} ${done ? 'is' : 'would be'} free to use again`,
  ];
  for (const member of stranded) {
    const offboard = member.startsWith('token:') ? `coffre offboard ${serviceName(member)} --service` : `coffre offboard ${member.slice('user:'.length)}`;
    lines.push(`  ${shownMember(member)} ${done ? 'holds' : 'would hold'} nothing anywhere: \`${offboard}\` removes them`);
  }
  if (!done) lines.push('Backups taken before the deletion still hold the encrypted values.', 'Nothing changed. Re-run with --apply to delete it.');
  return `${lines.join('\n')}\n`;
}

// --- a secret's key -----------------------------------------------------------

export async function renameSecret(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { positionals } = parse(args, {}, ['<project>/<environment>/<KEY>', '<NEW_KEY>']);
  const path = secret(positionals[0]!);
  const api = connect();
  const { key } = await api.secrets.rename(path, positionals[1]!);
  io.out.write(`${path} is now ${path.slice(0, path.lastIndexOf('/'))}/${key}, its versions with it\n`);
}

export async function archiveSecret(connect: () => CoffreClient, args: string[], archived: boolean, io: Io = STDIO): Promise<void> {
  const { positionals } = parse(args, {}, ['<project>/<environment>/<KEY>']);
  const path = secret(positionals[0]!);
  const api = connect();
  await api.secrets.update(path, { archived });
  io.out.write(archived ? `archived ${path}: \`coffre unarchive ${path}\` brings it back\n` : `unarchived ${path}\n`);
}

// --- references --------------------------------------------------------------

/** `coffre references market/prod`: what it lends and what it holds, and who reads through each. */
export async function references(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, json, ['<project>[/<environment>[/<KEY>]]']);
  const api = connect();
  const { references: list } = await api.references.list(positionals[0]!);
  if (values.json) return asJson(io, list);
  if (list.length === 0) return void io.out.write(`no reference into or out of ${positionals[0]}\n`);
  for (const reference of list) {
    const state = reference.state === 'live' ? '' : `  (${reference.state.replace('_', ' ')})`;
    io.out.write(`${reference.holder} → ${reference.source}${state}\n`);
    io.out.write(`  made by ${shownMember(reference.createdBy).replace(/^user:/, '')} on ${reference.createdAt.slice(0, 10)}\n`);
    if (reference.readers !== null) {
      io.out.write(`  read through by ${reference.readers.length === 0 ? 'no one by a grant' : reference.readers.map((reader) => shownMember(reader).replace(/^user:/, '')).join(', ')}\n`);
    }
  }
}

/**
 * `coffre references break billing/prod/DATABASE_URL`: who would stop
 * reading the source through it, and with --apply, the break. Whoever writes
 * the holder may, and whoever manages the source's project's access.
 */
export async function referencesBreak(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, { apply: { type: 'boolean', default: false } }, ['<project>/<environment>/<KEY>']);
  const path = secret(positionals[0]!);
  const api = connect();
  if (!values.apply) {
    const [reference] = (await api.references.list(path)).references.filter((each) => each.holder === path);
    if (reference === undefined) return void io.out.write(`${path} is no reference you can see\n`);
    const readers = reference.readers === null ? 'whoever reads its environment' : reference.readers.map((reader) => shownMember(reader).replace(/^user:/, '')).join(', ') || 'no one by a grant';
    io.out.write(`${path} reads ${reference.source}, made by ${shownMember(reference.createdBy).replace(/^user:/, '')} on ${reference.createdAt.slice(0, 10)}\n`);
    io.out.write(`breaking it stops ${readers} reading it there, and a run of its environment refuses until ${path.split('/')[2]} gets a value\n`);
    io.out.write('Nothing changed. Re-run with --apply to break it.\n');
    return;
  }
  const { reference } = await api.references.break(path);
  io.out.write(`broke ${reference.holder}: it no longer reads ${reference.source}\n`);
}

// --- missing keys ------------------------------------------------------------

/** `coffre missing market/dev`: the keys its siblings have and it lacks, of those you read. */
export async function missing(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, { ...json, dismissed: { type: 'boolean', default: false } }, ['<project>/<environment>']);
  const { project, environment } = place(positionals[0]!, true);
  const path = `${project}/${environment}`;
  const api = connect();
  const result = await api.environments.missing(path);
  if (values.json) return asJson(io, values.dismissed ? result.dismissed : result.missing);
  if (values.dismissed) {
    if (result.dismissed.length === 0) return void io.out.write(`nothing dismissed in ${path}\n`);
    for (const key of result.dismissed) {
      io.out.write(`${key.key.padEnd(28)} in ${key.in.join(', ')}; dismissed by ${key.dismissedBy} on ${key.dismissedAt.slice(0, 10)}\n`);
    }
    return;
  }
  if (result.missing.length === 0) {
    io.out.write(`${path} has every key of the sibling environments you read${result.dismissed.length === 0 ? '' : `, but ${result.dismissed.length} dismissed: --dismissed lists them`}\n`);
    return;
  }
  for (const key of result.missing) io.out.write(`${key.key.padEnd(28)} in ${key.in.join(', ')}\n`);
  io.out.write(`\n\`coffre set ${path}/<KEY>\` adds one; \`coffre missing dismiss ${path}/<KEY>\`, or --all, says it is not needed\n`);
}

/** `coffre missing dismiss market/dev/KEY` (or `market/dev --all`), and `restore`: for the whole team, logged. */
export async function missingDismiss(connect: () => CoffreClient, args: string[], dismiss: boolean, io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, dismiss ? { all: { type: 'boolean', default: false } } : {}, ['<project>/<environment>[/<KEY>]']);
  const parts = positionals[0]!.split('/');
  const all = (values as { all?: boolean }).all === true;
  if (parts.length !== (all ? 2 : 3) || parts.some((part) => part === '')) {
    throw new UsageError(all ? `--all takes <project>/<environment>, not "${positionals[0]}"` : `expected <project>/<environment>/<KEY>, not "${positionals[0]}"`);
  }
  const path = parts.slice(0, 2).join('/');
  const api = connect();
  const keys = all ? (await api.environments.missing(path)).missing.map((key) => key.key) : [parts[2]!];
  if (keys.length === 0) return void io.out.write(`nothing missing from ${path} to dismiss\n`);
  const { keys: outcomes } = await api.environments.dismiss(path, Object.fromEntries(keys.map((key) => [key, dismiss ? true : null])));
  for (const key of keys) {
    const outcome = outcomes[key];
    io.out.write(outcome === 'unchanged' ? `${key} was ${dismiss ? 'dismissed' : 'not dismissed'} already\n` : `${outcome} ${key} in ${path}\n`);
  }
}

// --- folders -----------------------------------------------------------------

/** `coffre move acme Clients`, `coffre move market/prod/STRIPE_KEY stripe`, or `--none` for out of its folder. */
export async function move(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, { none: { type: 'boolean', default: false } }, ['<project> | <project>/<environment>/<KEY>', '<folder>'], 1);
  const [target, given] = positionals as [string, string | undefined];
  if (values.none === (given !== undefined)) throw new UsageError(values.none ? 'a folder, or --none, not both' : 'name a folder, or --none for out of its folder');
  const folder = given ?? null;
  const api = connect();
  if (target.includes('/')) {
    const path = secret(target);
    await api.secrets.update(path, { folder });
    io.out.write(folder === null ? `${path} is in no folder now\n` : `${path} is in ${folder}/ now\n`);
    return;
  }
  const { project } = place(target, false);
  await api.projects.update(project, { folder });
  io.out.write(folder === null ? `${project} is in no folder now\n` : `${project} is in ${folder}/ now\n`);
}

// --- folders -----------------------------------------------------------------

/**
 * What a folder command is about: the projects' folders, or, when its first
 * argument is a `<project>/<environment>`, that environment's key folders.
 * A folder's name has no `/`, so the two cannot be mistaken.
 */
function folderScope(positionals: string[], folders: number): { environment: string | null; names: string[] } {
  const environment = positionals.length > folders ? positionals[0]! : null;
  if (environment !== null) place(environment, true);
  const names = positionals.slice(environment === null ? 0 : 1);
  for (const name of names) {
    if (name.includes('/')) {
      throw new UsageError(`a folder's name has no /, so "${name}" is none: an environment's key folders are \`coffre folders <project>/<environment> …\``);
    }
  }
  return { environment, names };
}

/** Each folder and what is filed in it, by name: the projects', or an environment's keys. */
async function foldersIn(api: CoffreClient, environment: string | null): Promise<{ folder: string; items: string[] }[]> {
  const filed = environment === null
    ? (await api.projects.list()).projects.map((project) => ({ name: project.slug, folder: project.folder }))
    : (await api.secrets.list(environment)).keys.map((key) => ({ name: key.key, folder: key.folder }));
  const folders = new Map<string, string[]>();
  for (const { name, folder } of filed) if (folder !== null) folders.set(folder, [...(folders.get(folder) ?? []), name]);
  return [...folders].sort(([a], [b]) => a.localeCompare(b)).map(([folder, items]) => ({ folder, items }));
}

/** `coffre folders [<project>/<environment>]`: each folder, and what is in it. */
export async function folders(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, json, ['<project>/<environment>'], 1);
  const { environment } = folderScope(positionals, 0);
  const listed = await foldersIn(connect(), environment);
  if (values.json) return asJson(io, listed.map(({ folder, items }) => (environment === null ? { folder, projects: items } : { folder, keys: items })));
  if (listed.length === 0) {
    io.out.write(environment === null
      ? 'No project is in a folder. `coffre move <project> <folder>` files one, and makes the folder.\n'
      : `No key of ${environment} is in a folder. \`coffre move ${environment}/<KEY> <folder>\` files one, and makes the folder.\n`);
    return;
  }
  const width = Math.max(...listed.map(({ folder }) => folder.length)) + 1;
  for (const { folder, items } of listed) io.out.write(`${`${folder}/`.padEnd(width)}  ${items.join(', ')}\n`);
}

/** `coffre folders rename [<project>/<environment>] <folder> <new-folder>`: everything in it, re-filed. */
export async function foldersRename(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { positionals } = parse(args, {}, ['<project>/<environment>', '<folder>', '<new-folder>'], 1);
  const { environment, names } = folderScope(positionals, 2);
  const [folder, name] = names as [string, string];
  const api = connect();
  const { moved } = environment === null ? await api.folders.rename(folder, name) : await api.folders.renameKeys(environment, folder, name);
  io.out.write(`${folder}/ is ${name}/ now${environment === null ? '' : ` in ${environment}`}: ${moved.join(', ')}\n`);
}

/**
 * `coffre folders remove [<project>/<environment>] <folder> [--apply]`:
 * everything out of it, each staying where it is, in no folder. More than
 * one item is shown first; --apply does it.
 */
export async function foldersRemove(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, { apply: { type: 'boolean', default: false } }, ['<project>/<environment>', '<folder>'], 1);
  const { environment, names } = folderScope(positionals, 1);
  const folder = names[0]!;
  const api = connect();
  const items = (await foldersIn(api, environment)).find((each) => each.folder === folder)?.items ?? [];
  const what = environment === null ? 'project' : 'key';
  if (items.length > 1 && !values.apply) {
    io.out.write(`would take ${items.length} ${what}s out of ${folder}/${environment === null ? '' : ` in ${environment}`}: ${items.join(', ')}. Each stays where it is, in no folder.\nNothing changed. Re-run with --apply to remove it.\n`);
    return;
  }
  const { moved } = environment === null ? await api.folders.remove(folder) : await api.folders.removeKeys(environment, folder);
  io.out.write(`${moved.join(', ')} ${moved.length === 1 ? 'is' : 'are'} in no folder now; ${folder}/ is gone\n`);
}

// --- members -----------------------------------------------------------------

/** A name that says it is a service account's: `service:deploy`, or `token:deploy` as before. */
const SERVICE = /^(?:service|token):/;

/**
 * A member as the API names it, `user:ada@acme.example` or `token:deploy`,
 * from what was typed: a `service:` name, or --service, is a service account.
 */
export function memberOf(name: string, service: boolean): string {
  if (SERVICE.test(name)) return apiMember(name);
  return service ? serviceMember(name) : name.startsWith('user:') ? name : `user:${name}`;
}

/** A filter from its two flags, `--projects a,b` or `--except-projects a,b`; neither leaves it out. */
function filterOf(values: Record<string, unknown>, what: 'projects' | 'environments'): Filter | undefined {
  const [only, except] = [values[what], values[`except-${what}`]] as (string | undefined)[];
  if (only !== undefined && except !== undefined) throw new UsageError(`--${what} or --except-${what}, not both`);
  const list = (text: string) => text.split(',').map((name) => name.trim()).filter((name) => name !== '');
  if (only !== undefined) return { only: list(only) };
  if (except !== undefined) return { except: list(except) };
  return undefined;
}

const SCOPE_FLAGS = {
  projects: { type: 'string' },
  'except-projects': { type: 'string' },
  environments: { type: 'string' },
  'except-environments': { type: 'string' },
} as const;

/**
 * `coffre admit ada@acme.example --role developer --environments dev`: a
 * member, and for a person, their instance role and where it applies,
 * every project and environment unless the scope flags narrow it.
 */
export async function admit(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, { service: { type: 'boolean', default: false }, role: { type: 'string' }, ...SCOPE_FLAGS }, ['<principal>']);
  const name = positionals[0]!;
  const service = values.service || SERVICE.test(name);
  const role = values.role;
  if (role !== undefined && !isInstanceRole(role)) throw new UsageError(`no instance role "${role}": member, auditor, developer, admin or owner`);
  const [projects, environments] = [filterOf(values, 'projects'), filterOf(values, 'environments')];
  const scoped = projects !== undefined || environments !== undefined;
  if (scoped && role === undefined) throw new UsageError('a scope goes with a role: add --role');
  if (service && role !== undefined && role !== 'member') throw new UsageError('a service account holds project grants only: drop --role, then coffre grant');
  const who = memberOf(name, service);
  const api = connect();
  const result = await api.members.add(who, role === undefined ? {} : { role, ...(scoped ? { scope: { ...(projects && { projects }), ...(environments && { environments }) } } : {}) });
  const as = result.instanceRole === 'member' ? '' : ` as ${roleInWords(result)}`;
  const shown = shownMember(result.member);
  io.out.write(result.created ? `admitted ${shown}${as}\n` : `${shown} is a member${as}${role === undefined ? ' already' : ' now'}\n`);
  if (service && result.created) {
    const bare = serviceName(who);
    io.out.write(
      `  next: coffre grant <project> ${bare} --role viewer [--env <env>] --service,\n` +
        `        then let its CI sign in by OIDC, coffre trust ${bare} --github … --apply,\n` +
        `        or, for CI without OIDC, give it a bearer token, coffre tokens issue ${bare}\n`,
    );
  }
}

export async function revoke(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, { env: { type: 'string' }, service: { type: 'boolean', default: false } }, ['<project>', '<principal>']);
  const [project, name] = positionals as [string, string];
  onAProject(project);
  const scope = values.env === undefined ? project : `${project}/${values.env}`;
  const who = memberOf(name, values.service);
  const api = connect();
  const { changes } = await api.access.set(who, { [scope]: null });
  io.out.write(changes[scope] === 'revoked' ? `revoked ${shownMember(who)}'s grant on ${scope}\n` : `${shownMember(who)} held no grant on ${scope}: nothing changed\n`);
}

// --- bearer tokens ----------------------------------------------------------

export async function tokens(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, json, ['<service>']);
  const service = serviceMember(positionals[0]!);
  const api = connect();
  const { tokens: list } = await api.tokens.list(service);
  if (values.json) return asJson(io, list);
  if (list.length === 0) io.out.write(`${shownMember(service)} holds no bearer token: coffre tokens issue ${serviceName(service)}\n`);
  for (const token of list) {
    io.out.write(
      `${token.id}  …${token.hint}  ${(token.label ?? '-').padEnd(16)}  expires ${day(token.expiresAt)}  last used ${day(token.lastUsedAt)}\n`,
    );
  }
}

/** A day count `--expires-in` takes: what the API takes, 1 to 366. */
function days(text: string | undefined): number {
  if (text === undefined) return 90;
  const count = Number(text);
  if (!Number.isInteger(count) || count < 1 || count > 366) throw new UsageError(`--expires-in takes a number of days, 1 to 366, not "${text}"`);
  return count;
}

/**
 * A new token, once: on stdout, or written to a file made for it, 0600, and
 * never one already there. The file is made before the token is, so a path
 * that cannot be written costs no token.
 */
export async function tokensIssue(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(
    args,
    { 'expires-in': { type: 'string' }, label: { type: 'string' }, 'output-file': { type: 'string' } },
    ['<service>'],
  );
  const service = serviceMember(positionals[0]!);
  const expiresInDays = days(values['expires-in']);
  const path = values['output-file'];
  const api = connect();
  let fd: number | null = null;
  if (path !== undefined) {
    try {
      fd = openSync(path, 'wx', 0o600);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      throw new Error(code === 'EEXIST' ? `${path} exists already: the token goes only into a new file` : `cannot make ${path}: ${code ?? String(error)}`);
    }
  }
  // A file made for a token that never came goes: whether the request throws, or the CLI exits on its refusal.
  const unmake = () => {
    if (fd === null) return;
    closeSync(fd);
    rmSync(path!, { force: true });
    fd = null;
  };
  process.once('exit', unmake);
  let issued: Awaited<ReturnType<CoffreClient['tokens']['issue']>>;
  try {
    issued = await api.tokens.issue(service, { expiresInDays, label: values.label ?? null });
  } catch (error) {
    unmake();
    throw error;
  } finally {
    process.off('exit', unmake);
  }
  const about = `${shownMember(service)}'s bearer token ${issued.id}, until ${day(issued.expiresAt)}`;
  if (fd !== null) {
    writeSync(fd, `${issued.token}\n`);
    closeSync(fd);
    io.out.write(`wrote ${about}, to ${path}, readable by you alone\n`);
    return;
  }
  io.out.write(`${issued.token}\n`);
  if (io.err.isTTY) io.err.write(`coffre: ${about}. It is shown this once\n`);
}

export async function tokensRevoke(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, { apply: { type: 'boolean', default: false } }, ['<service>', '<id>']);
  const service = serviceMember(positionals[0]!);
  const id = positionals[1]!;
  const api = connect();
  const token = (await api.tokens.list(service)).tokens.find((entry) => entry.id === id);
  if (token === undefined) throw new Error(`${shownMember(service)} holds no bearer token ${id}: \`coffre tokens ${serviceName(service)}\` lists them`);
  const what = `${shownMember(service)}'s bearer token ${id}, …${token.hint}${token.label === null ? '' : ` "${token.label}"`}, last used ${day(token.lastUsedAt)}`;
  if (!values.apply) {
    io.out.write(`would revoke ${what}: whatever uses it stops at once.\nNothing changed. Re-run with --apply to revoke it.\n`);
    return;
  }
  await api.tokens.revoke(service, id);
  io.out.write(`revoked ${what}\n`);
}

/**
 * A trust binding removed: first shown, with the CI runs it would cut off,
 * then, with --apply, removed. The credentials it issued end with it.
 */
export async function untrust(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, { apply: { type: 'boolean', default: false } }, ['<service>', '<binding-id>']);
  const service = serviceMember(positionals[0]!);
  const id = positionals[1]!;
  const api = connect();
  const binding = (await api.bindings.list(service)).bindings.find((entry) => entry.id === id);
  if (binding === undefined) throw new Error(`${shownMember(service)} has no trust binding ${id}: \`coffre trust ${serviceName(service)}\` lists them`);
  if (!values.apply) {
    io.out.write(describeRemoval(service, binding, false));
    return;
  }
  await api.bindings.remove(service, id);
  io.out.write(describeRemoval(service, binding, true));
}

// --- your own sessions and accounts -------------------------------------------

export async function sessions(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values } = parse(args, json, []);
  const api = connect();
  const { sessions: list } = await api.sessions.list();
  if (values.json) return asJson(io, list);
  for (const session of list) {
    const label = session.label ?? session.provider ?? '';
    io.out.write(
      `${session.current ? '*' : ' '} ${session.id}  ${session.kind.padEnd(7)}  …${session.hint}  ${label.padEnd(24)}  last used ${day(session.lastUsedAt)}  ends ${day(session.expiresAt)}\n`,
    );
  }
}

export async function sessionsRevoke(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, { apply: { type: 'boolean', default: false } }, ['<id>']);
  const id = positionals[0]!;
  const api = connect();
  const session = (await api.sessions.list()).sessions.find((entry) => entry.id === id);
  if (session === undefined) throw new Error(`you have no session ${id}: \`coffre sessions\` lists them`);
  const what = `your ${session.kind} session ${id}${session.label === null ? '' : `, "${session.label}"`}, last used ${day(session.lastUsedAt)}`;
  const current = session.current ? ': the one this command runs with, so this CLI signs out too' : '';
  if (!values.apply) {
    io.out.write(`would sign out ${what}${current}.\nNothing changed. Re-run with --apply to sign it out.\n`);
    return;
  }
  await api.sessions.revoke(id);
  io.out.write(`signed out ${what}${current}\n`);
}

/** What `apps` says where the deployment serves no MCP, as `GET /me` reports its configuration. */
const MCP_OFF = "MCP is off on this instance: no app connects here. Its deployment's signin({ mcp }) turns it on (docs/mcp.md)";

/** The MCP clients you connected: Account › Connected apps. */
export async function apps(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values } = parse(args, json, []);
  const api = connect();
  if (!(await api.me()).features.mcp) {
    if (values.json) return asJson(io, []);
    io.out.write(`${MCP_OFF}\n`);
    return;
  }
  const { apps: list } = await api.apps.list();
  if (values.json) return asJson(io, list);
  for (const app of list) {
    const name = `${app.name}${app.registration === 'dcr' ? ' (unverified)' : ''}`;
    io.out.write(
      `${app.id}  ${name.padEnd(28)}  ${(app.host ?? '-').padEnd(24)}  ${app.scopes.join(' ').padEnd(16)}  last used ${day(app.lastUsedAt)}  ends ${day(app.expiresAt)}\n`,
    );
  }
}

export async function appsRevoke(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, { apply: { type: 'boolean', default: false } }, ['<id>']);
  const id = positionals[0]!;
  const api = connect();
  if (!(await api.me()).features.mcp) throw new Error(MCP_OFF);
  const app = (await api.apps.list()).apps.find((entry) => entry.id === id);
  if (app === undefined) throw new Error(`you have no connected app ${id}: \`coffre apps\` lists them`);
  const what = `${app.name}${app.host === null ? '' : ` (${app.host})`}, connected ${day(app.createdAt)}, last used ${day(app.lastUsedAt)}`;
  if (!values.apply) {
    io.out.write(`would disconnect ${what}: it would stop working at once.\nNothing changed. Re-run with --apply to disconnect it.\n`);
    return;
  }
  await api.apps.disconnect(id);
  io.out.write(`disconnected ${what}\n`);
}

export async function identities(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values } = parse(args, json, []);
  const api = connect();
  const { identities: list } = await api.identities.list();
  if (values.json) return asJson(io, list);
  for (const identity of list) {
    io.out.write(`${identity.id}  ${identity.provider.padEnd(10)}  ${(identity.email ?? '-').padEnd(32)}  last sign-in ${day(identity.lastSignInAt)}\n`);
  }
}

export async function identitiesUnlink(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, { apply: { type: 'boolean', default: false } }, ['<id>']);
  const id = positionals[0]!;
  const api = connect();
  const identity = (await api.identities.list()).identities.find((entry) => entry.id === id);
  if (identity === undefined) throw new Error(`you have no linked account ${id}: \`coffre identities\` lists them`);
  const what = `your ${identity.provider} account${identity.email === null ? '' : ` ${identity.email}`} (${id})`;
  if (!values.apply) {
    io.out.write(`would unlink ${what}: it would no longer sign you in, and its sessions would end.\nNothing changed. Re-run with --apply to unlink it.\n`);
    return;
  }
  await api.identities.unlink(id);
  io.out.write(`unlinked ${what}, and ended its sessions\n`);
}

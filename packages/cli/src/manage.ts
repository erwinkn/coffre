// The commands that manage an instance, beside its secrets: projects and
// environments, members, service tokens, a secret's key, and your own
// sessions and accounts. Each takes the API and where to write, so a test
// drives it with a client of its own; each reads its arguments before it
// asks for one, so a mistyped command needs no session to be told so. A refusal says what to type instead;
// what would end something for good is shown first, and done with --apply.
import { openSync, closeSync, writeSync, rmSync } from 'node:fs';
import { parseArgs } from 'node:util';

import type { CoffreClient } from '@coffre/client';

import { serviceMember } from './trust.ts';

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
  if (positionals.length < names.length - optional || positionals.length > names.length) {
    throw new UsageError(positionals.length > names.length ? `too many arguments: ${positionals.slice(names.length).join(' ')}` : `name ${listOf(names.slice(positionals.length))}`);
  }
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

// --- projects and environments ------------------------------------------------

export async function projects(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values } = parse(args, json, []);
  const api = connect();
  const { projects: list } = await api.projects.list();
  if (values.json) return asJson(io, list);
  for (const project of list) {
    const archived = project.archivedAt === null ? '' : ' (archived)';
    io.out.write(`${project.slug}${archived}  ${project.name}\n`);
    for (const environment of project.environments) {
      // Environments the caller may only know by name come without details.
      if (environment.details?.archivedAt) continue;
      const count = environment.details?.secretCount;
      io.out.write(`  ${environment.slug.padEnd(16)} ${count === null || count === undefined ? '' : `${count} secrets`}\n`);
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

// --- members -----------------------------------------------------------------

/** `user:ada@acme.example` or `token:deploy`, from a name and --service. */
function member(name: string, service: boolean): string {
  return service ? serviceMember(name) : name.startsWith('user:') ? name : `user:${name}`;
}

export async function admit(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(
    args,
    { service: { type: 'boolean', default: false }, owner: { type: 'boolean', default: false }, 'no-owner': { type: 'boolean', default: false } },
    ['<principal>'],
  );
  if (values.owner && values['no-owner']) throw new UsageError('--owner or --no-owner, not both');
  if (values.service && values.owner) throw new UsageError('a service cannot own the instance: drop --owner');
  const name = positionals[0]!;
  if (name.startsWith('token:') && !values.service) throw new UsageError(`${name} names a service: coffre admit ${name.slice('token:'.length)} --service`);
  const who = member(name, values.service);
  const owner = values.owner ? true : values['no-owner'] ? false : undefined;
  const api = connect();
  const result = await api.members.add(who, owner === undefined ? {} : { owner });
  const role = result.instanceRole === 'owner' ? ', an owner of the instance' : '';
  io.out.write(result.created ? `admitted ${result.member}${role}\n` : `${result.member} is a member${role}${owner === undefined ? ' already' : ' now'}\n`);
  if (values.service && result.created) {
    const bare = who.slice('token:'.length);
    io.out.write(
      `  next: coffre grant <project> ${bare} --role viewer [--env <env>] --service,\n` +
        `        then coffre trust ${bare} --github … --apply, or coffre tokens issue ${bare}\n`,
    );
  }
}

export async function revoke(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, { env: { type: 'string' }, service: { type: 'boolean', default: false } }, ['<project>', '<principal>']);
  const [project, name] = positionals as [string, string];
  const scope = values.env === undefined ? project : `${project}/${values.env}`;
  const who = member(name, values.service);
  const api = connect();
  const { changes } = await api.access.set(who, { [scope]: null });
  io.out.write(changes[scope] === 'revoked' ? `revoked ${who}'s grant on ${scope}\n` : `${who} held no grant on ${scope}: nothing changed\n`);
}

// --- service tokens ----------------------------------------------------------

export async function tokens(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, json, ['<service>']);
  const service = serviceMember(positionals[0]!);
  const api = connect();
  const { tokens: list } = await api.tokens.list(service);
  if (values.json) return asJson(io, list);
  if (list.length === 0) io.out.write(`${service} holds no token: coffre tokens issue ${service.slice('token:'.length)}\n`);
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
  const about = `${service}'s token ${issued.id}, until ${day(issued.expiresAt)}`;
  if (fd !== null) {
    writeSync(fd, `${issued.token}\n`);
    closeSync(fd);
    io.out.write(`wrote ${about}, to ${path}, readable by you alone; coffre keeps only its hash\n`);
    return;
  }
  io.out.write(`${issued.token}\n`);
  if (io.err.isTTY) io.err.write(`coffre: ${about}. It is shown this once: coffre keeps only its hash\n`);
}

export async function tokensRevoke(connect: () => CoffreClient, args: string[], io: Io = STDIO): Promise<void> {
  const { values, positionals } = parse(args, { apply: { type: 'boolean', default: false } }, ['<service>', '<id>']);
  const service = serviceMember(positionals[0]!);
  const id = positionals[1]!;
  const api = connect();
  const token = (await api.tokens.list(service)).tokens.find((entry) => entry.id === id);
  if (token === undefined) throw new Error(`${service} holds no token ${id}: \`coffre tokens ${service.slice('token:'.length)}\` lists them`);
  const what = `${service}'s token ${id}, …${token.hint}${token.label === null ? '' : ` "${token.label}"`}, last used ${day(token.lastUsedAt)}`;
  if (!values.apply) {
    io.out.write(`would revoke ${what}: whatever uses it stops at once.\nNothing changed. Re-run with --apply to revoke it.\n`);
    return;
  }
  await api.tokens.revoke(service, id);
  io.out.write(`revoked ${what}\n`);
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
    io.out.write(`would unlink ${what}: it would sign you in no more, and the sessions it signed in would end.\nNothing changed. Re-run with --apply to unlink it.\n`);
    return;
  }
  await api.identities.unlink(id);
  io.out.write(`unlinked ${what}, and ended the sessions it signed in\n`);
}

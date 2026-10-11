// `coffre migrate`: bring a deployment's database up to the schema of the
// version it pins, with the migrations this CLI carries, which must be that
// version's. Its pipeline runs it in the deployment's folder before every
// deploy: the app it deploys serves nothing until its migrations have run
// (503 `migrating`), and the app before it keeps serving on the new schema
// until then, as every migration lets it.
//
// It asks for the database owner's direct URL, at a hidden prompt or on
// stdin, never the command line; shows what it will apply; and applies it
// under the migration lock, with the privileges reasserted. Without a
// terminal, only with --yes.
import { parseArgs } from 'node:util';

import { INSTANCE_ROLES, roleGrants, scopeInWords, unscoped } from '@coffre/core/access';
import { shownMember } from '@coffre/core/schemas';
import { openDatabase } from '@coffre/db/connect';
import { everyProjectPreview, readGrants, unsealedCredentials, type EveryProjectPreview, type Unsealed } from '@coffre/db/grants';
import { DatabaseAhead, migrateDatabase, migrationStatus } from '@coffre/db/migrate';

import { readDatabaseUrl } from './database-url.ts';
import { coffrePins, deploymentKind } from './deployment.ts';
import { type Step, StepFailed, Steps } from './steps.ts';
import { Cancelled, type Keyboard, listed, openTerminal, type Output, release, style } from './tty.ts';
import { cliVersion } from './version.ts';

class MigrateError extends Error {}

/** A deployment's folder: where it is, and the one version its `@coffre/*` packages are pinned at. */
export type Deployment = { dir: string; version: string };

/** The deployment `dir` holds, as `coffre init` writes one; null for a folder that holds none. */
export function deploymentAt(dir: string): Deployment | null {
  const kind = deploymentKind(dir);
  if (kind !== 'workers' && kind !== 'node') return null;
  const versions = [...new Set(Object.values(coffrePins(dir)))];
  if (versions.length !== 1) {
    throw new MigrateError(
      `this deployment's @coffre/* packages are pinned at ${versions.length === 0 ? 'no version' : listed(versions, 'and')}, not one: ` +
        '`coffre update` moves them together',
    );
  }
  return { dir, version: versions[0]! };
}

/**
 * Why this CLI may not migrate a deployment that pins `pinned`: the
 * migrations it carries are its own version's. Null when they agree.
 */
export function pinProblem(cli: string, pinned: string): string | null {
  if (cli === pinned) return null;
  return `this deployment pins coffre ${pinned}, and this CLI is ${cli}, whose migrations are another version's: ` +
    "migrate with the deployment's own, `pnpm exec coffre migrate`, after `pnpm install`";
}

/**
 * A migration's refusal, as Postgres raised it: the migration's own sentence,
 * not the SQL around it.
 */
export function migrationFailure(error: unknown): string {
  for (let cause: unknown = error; cause instanceof Error; cause = cause.cause) {
    const code = (cause as { code?: unknown }).code;
    if (typeof code === 'string' && /^[0-9A-Z]{5}$/.test(code)) {
      return `${cause.message}. Nothing was changed: the migrations run in one transaction.`;
    }
  }
  return error instanceof Error ? error.message : String(error);
}

type Options = { yes: boolean };

export async function migrate(args: string[]): Promise<void> {
  const secrets: string[] = [];
  const clean = (error: unknown) => redact(error instanceof Error ? error.message : String(error), secrets);
  let options: Options;
  try {
    options = parseOptions(args);
  } catch (error) {
    return fail(process.stderr, clean(error));
  }
  const terminal = openTerminal();
  const out = terminal?.out ?? process.stderr;
  try {
    const deployment = deploymentAt(process.cwd());
    if (deployment === null) {
      throw new MigrateError(
        "coffre migrate runs in a deployment's folder, as its pipeline does before each deploy, with the migrations of the version it pins: " +
          'there, `pnpm exec coffre migrate`',
      );
    }
    await migrateDeployment(deployment, options, out, terminal, secrets, clean);
  } catch (error) {
    if (error instanceof Cancelled) return fail(out, 'cancelled; nothing was changed', 130);
    if (!(error instanceof StepFailed)) return fail(out, clean(error));
    process.exit(1);
  } finally {
    if (terminal !== null) release(terminal.keys);
  }
}

/**
 * In a deployment's folder: its database to the schema of the version it
 * pins, which this CLI must be. What its pipeline runs before the deploy.
 */
async function migrateDeployment(
  deployment: Deployment,
  options: Options,
  out: Output,
  terminal: { keys: Keyboard } | null,
  secrets: string[],
  clean: (error: unknown) => string,
): Promise<void> {
  const s = style(out);
  const problem = pinProblem(cliVersion(), deployment.version);
  if (problem !== null) throw new MigrateError(problem);

  if (s.ansi) out.write(`\n  ${s.bold('coffre migrate')}  ${s.dim(`this deployment, coffre ${deployment.version}`)}\n\n`);
  const { url, secrets: typed } = await readDatabaseUrl(out, s, {
    question: "The database owner's connection string",
    hint: "Hidden as you type. The login that owns coffre's tables, direct: not a runtime login, not Hyperdrive.",
    command: 'coffre migrate',
  });
  secrets.push(...typed);
  const where = `${url.hostname}${decodeURIComponent(url.pathname)}`;
  let status: { applied: string[]; pending: string[] };
  try {
    status = await migrationStatus(url.href);
  } catch (error) {
    if (!(error instanceof DatabaseAhead)) throw error;
    throw new MigrateError(
      `${where} is ahead of coffre ${deployment.version}: ${error.message.replace(/^the database /, '')}. ` +
        'Deploy that version, or, to go back, restore the database from before it (docs/restore.md). Nothing was changed',
    );
  }
  const { applied, pending } = status;
  if (pending.length === 0) {
    out.write(`${s.green('✓')} ${where} is up to date, at coffre ${deployment.version}'s schema: ${count(applied.length, 'migration')}, the last ${applied.at(-1)}\n`);
    out.write(describeFirstRun(await previewFirstRun(url)));
    return;
  }
  if (!options.yes && terminal === null) {
    throw new MigrateError('Not a terminal, so nothing to confirm on: pass --yes to migrate without asking.');
  }
  out.write(`  ${count(pending.length, 'migration')} to apply to ${where}, for coffre ${deployment.version}: ${listed(pending, 'and')}\n\n`);
  const steps = new Steps(out, [`Apply ${listed(pending, 'and')}`], () => terminal?.keys ?? null, clean);
  try {
    await steps.run(0, (step) => apply(url, where, pending, step, options.yes));
  } finally {
    steps.end();
  }
  out.write(describeFirstRun(await previewFirstRun(url)));
}

/** What this version does to 0.4's rows when it first runs, which the database says: what `coffre migrate` shows. */
export type FirstRun = {
  everyProject: EveryProjectPreview[];
  unsealed: Unsealed[];
  /** The members who hold a live grant on a project or an environment now. */
  holding: ReadonlySet<string>;
};

/**
 * What the vault will make of the grants on every project of 0.4 still
 * there, and the tokens and bindings the app will seal, read with the
 * owner's login.
 */
async function previewFirstRun(url: URL): Promise<FirstRun> {
  const { db, close } = await openDatabase(url.href);
  try {
    const at = new Date();
    const [everyProject, unsealed, grants] = await Promise.all([everyProjectPreview(db, at.getTime()), unsealedCredentials(db, at), readGrants(db, { liveAt: at.getTime() })]);
    return { everyProject, unsealed, holding: new Set(grants.filter((grant) => grant.projectId !== null).map((grant) => grant.principal)) };
  } finally {
    await close();
  }
}

export function describeFirstRun({ everyProject, unsealed, holding }: FirstRun): string {
  // What a member holds once the vault has converted: their grants on a place, and what it makes of those on every project, unless it leaves them.
  const converted = everyProject.filter((preview) => !preview.reported && preview.conversion.grants.length > 0).map((preview) => preview.principal);
  const holds = new Set([...holding, ...converted]);
  return describeEveryProject(everyProject) + describeUnsealed(unsealed, new Set(unsealed.map((row) => row.principal).filter((principal) => !holds.has(principal))));
}

/**
 * The tokens and trust bindings of 0.4, which carry no scope of their own,
 * by account: when this version first checks a credential, each keeps what
 * its account holds then (`sealScopes` in @coffre/server), and nothing the
 * account is given after reaches it. An account that holds nothing then
 * (`empty`) seals them reaching nothing, for good. Nothing when there are none.
 *
 *   service:ci-web   2 tokens and 1 trust binding
 *   service:idle     1 token, which will reach nothing: grant the account before you deploy, or reissue it after
 */
export function describeUnsealed(unsealed: readonly Unsealed[], empty: ReadonlySet<string> = new Set()): string {
  if (unsealed.length === 0) return '';
  const lines = [
    '',
    'Service tokens and trust bindings now carry their own scope, and what an account is given later reaches none made before.',
    "When this version first checks a credential, each of these keeps what its account holds then, after any conversion above:",
  ];
  for (const principal of [...new Set(unsealed.map((row) => row.principal))]) {
    const theirs = unsealed.filter((row) => row.principal === principal);
    const tokens = theirs.filter((row) => row.kind === 'token').length;
    const bindings = theirs.length - tokens;
    const what = [tokens === 0 ? null : count(tokens, 'token'), bindings === 0 ? null : count(bindings, 'trust binding')].filter((part) => part !== null);
    const nothing = empty.has(principal)
      ? `, which will reach nothing: grant the account before you deploy, or reissue ${theirs.length === 1 ? 'it' : 'them'} after`
      : '';
    lines.push(`  ${shownMember(principal)}: ${what.join(' and ')}${nothing}`);
  }
  lines.push('Grant or revoke before you deploy to choose what they keep; to change one after, issue another and revoke it.', '');
  return lines.join('\n');
}

/**
 * The grants on every project of 0.4, each with what the vault replaces it
 * by when this version first runs, and what that reaches less: nothing when
 * there are none.
 *
 *   user:ada@acme.example   developer on dev in every project → Developer, All projects · dev only
 *   service:ci              viewer on every project → viewer on market, billing; not projects made later
 *   user:bo@acme.example    viewer on every project → viewer on market, billing/dev; not projects made later;
 *                           viewer on billing only through its environments, not those made later
 *   service:deploy          maintainer on every project → maintainer on market, billing; not projects made later;
 *                           loses access-manager on billing (keeps maintainer)
 *   service:old             viewer on every project → left as it is: the vault reported their row tampered with
 *                           (if the vault finds that report forged, it makes: viewer on market, billing; not projects made later)
 */
export function describeEveryProject(previews: readonly EveryProjectPreview[]): string {
  if (previews.length === 0) return '';
  const lines = ['', 'Grants on every project are gone in this version. When it first runs, the vault replaces them:'];
  for (const { principal, before, conversion, paths, reported } of previews) {
    const was = before.map((grant) => `${grant.role} on ${grant.place === '*' ? 'every project' : `${grant.place.slice(2)} in every project`}`).join(', ');
    const role = conversion.role === 'member' ? [] : [unscoped(conversion.scope) ? INSTANCE_ROLES[conversion.role].name : `${INSTANCE_ROLES[conversion.role].name}, ${scopeInWords(conversion.scope)}`];
    const byRole = new Map<string, string[]>();
    for (const grant of conversion.grants) byRole.set(grant.role, [...(byRole.get(grant.role) ?? []), paths[grant.environmentId ?? grant.projectId] ?? grant.projectId]);
    const grants = [...byRole].map(([held, places]) => `${held} on ${places.join(', ')}`);
    const narrower = conversion.narrowed.flatMap((loss) => {
      switch (loss.kind) {
        case 'later-projects':
          return [];
        case 'environments': {
          const project = paths[loss.projectId] ?? loss.projectId;
          const log = roleGrants(loss.role, 'audit.read') ? `, nor ${project}'s own log entries` : '';
          return [`${loss.role} on ${project} only through its environments, not those made later${log}`];
        }
        case 'lost': {
          const until = loss.keptUntil === null ? '' : ` until ${new Date(loss.keptUntil).toISOString().slice(0, 10)}`;
          return [`loses ${loss.lost} on ${paths[loss.environmentId ?? loss.projectId] ?? loss.projectId} (keeps ${loss.kept}${until})`];
        }
      }
    });
    const later = conversion.narrowed.some((loss) => loss.kind === 'later-projects') ? ['not projects made later'] : [];
    const after = [[...role, ...grants].join(', and ') || 'nothing', ...later, ...narrower].join('; ');
    // Whether the vault's report is its own, only the vault can tell: either way, what it does is said.
    const then = reported ? `left as it is: the vault reported their row tampered with (if the vault finds that report forged, it makes: ${after})` : after;
    lines.push(`  ${shownMember(principal)}: ${was} → ${then}`);
  }
  lines.push(
    "A root admin's stay as they are while they are one, and so do those of a member whose row the vault finds tampered with: migrate holds no key to check a row, nor whether a report is the vault's own.",
    'Revoke or regrant any of them before you deploy to choose otherwise (docs/design/instance-roles.md).',
    '',
  );
  return lines.join('\n');
}

/** Apply `pending` to the database, asking first unless told yes. */
async function apply(url: URL, where: string, pending: string[], step: Step, yes: boolean): Promise<string> {
  if (!yes && !(await step.ask(`Apply ${count(pending.length, 'migration')} to ${where}?`))) throw new Cancelled();
  step.note(`Applying ${listed(pending, 'and')}`);
  try {
    await migrateDatabase(url.href, (plan) => {
      // Under the lock now: what was read before, or another run got there first.
      if (plan.pending.join() !== pending.join()) {
        throw new MigrateError(`another migration ran meanwhile: ${where} now lacks ${listed(plan.pending, 'and') || 'nothing'}`);
      }
    });
  } catch (error) {
    if (error instanceof MigrateError) throw error;
    throw new MigrateError(migrationFailure(error));
  }
  return `Applied ${listed(pending, 'and')}, and reasserted the database's privileges`;
}

function parseOptions(args: string[]): Options {
  try {
    const { values } = parseArgs({
      args,
      options: { yes: { type: 'boolean', default: false } },
      strict: true,
    });
    return { yes: values.yes };
  } catch {
    // The error would quote the argument, which may be the connection string itself.
    const leaked = args.some((arg) => /postgres(ql)?:|@/i.test(arg));
    throw new MigrateError(
      'coffre migrate takes only --yes. ' +
        `It asks for the database owner's connection string, at a hidden prompt or on stdin, ` +
        `never from the command line, where the shell's history and other users can read it.` +
        (leaked ? ' One of the arguments looks like one: change that password, which is in your shell history now.' : ''),
    );
  }
}

function count(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

function redact(text: string, secrets: string[]): string {
  return secrets.filter((secret) => secret.length > 0).reduce((shown, secret) => shown.split(secret).join('…'), text);
}

function fail(out: Output, message: string, code = 1): never {
  const s = style(out);
  out.write(`${s.red('✗')} ${message}\n`);
  process.exit(code);
}


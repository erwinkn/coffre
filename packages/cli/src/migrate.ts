// `coffre migrate`: bring an instance's database up to the schema the code
// it runs ships. The instance says which version it runs and how far its
// database is (`/me`, to owners and root admins); this CLI applies its own
// migrations, so it goes ahead only when it is that same version. Then it
// asks for the database owner's direct URL, never on the command line,
// shows what it will apply, applies it as `coffre-server migrate` does,
// under the migration lock and with the privileges reasserted, and asks the
// instance whether it sees the new schema and is ready.
import { parseArgs } from 'node:util';

import type { InstanceState } from '@coffre/client';
import { migrateDatabase, migrationStatus } from '@coffre/db/migrate';

import { readDatabaseUrl } from './database-url.ts';
import { StepFailed, Steps } from './steps.ts';
import { Cancelled, type Keyboard, listed, openTerminal, type Output, release, style } from './tty.ts';
import { cliVersion } from './version.ts';

/** Where the owner's connection string comes from, when not from a hidden prompt. */
export const URL_VARIABLE = 'COFFRE_MIGRATE_DATABASE_URL';

/** What `coffre migrate` asks of the instance. */
export type Instance = {
  origin: string;
  /** Who is asking, and what the instance tells them of itself: nothing unless they are an owner. */
  me(): Promise<{ principal: { id: string }; instance: InstanceState | null }>;
  /** Its `/readyz`, as a monitor reads it. */
  ready(): Promise<{ ok: boolean; heartbeatAgeSeconds: number | null; checkpointed: boolean }>;
};

class MigrateError extends Error {}

/** The migrations a database that has applied `applied` of `known` still lacks. */
export function pendingOf(state: InstanceState): string[] {
  return state.migrations.known.slice(state.migrations.applied);
}

/**
 * Why this CLI may not migrate an instance that runs `deployed`: it would
 * apply its own migrations, not the instance's. Null when they agree.
 */
export function versionProblem(cli: string, deployed: string, origin: string): string | null {
  if (cli === deployed) return null;
  return newer(deployed, cli)
    ? `${origin} runs coffre ${deployed}, and this CLI is ${cli}: run \`coffre update\` (to ${deployed}), then \`coffre migrate\` again`
    : `${origin} runs coffre ${deployed}, and this CLI is ${cli}, whose migrations it does not know yet: deploy ${cli} first, ` +
        `or migrate with the CLI it runs, \`npx @coffre/cli@${deployed} migrate\``;
}

/** Whether version `a` comes after `b`, by their numbers. */
function newer(a: string, b: string): boolean {
  const parts = (version: string) => version.split(/[.-]/).map((part) => Number.parseInt(part, 10) || 0);
  const [x, y] = [parts(a), parts(b)];
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) > (y[i] ?? 0);
  }
  return false;
}

/**
 * A migration's refusal, as Postgres raised it: the migration's own sentence,
 * not the SQL around it. `0001_remove_syncs` refuses while syncs remain.
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

/** `connect` reaches the instance: the current one, or the one `--url` names, with your session there. */
export async function migrate(args: string[], connect: (url: string | undefined) => Instance): Promise<void> {
  const secrets: string[] = [];
  const clean = (error: unknown) => redact(error instanceof Error ? error.message : String(error), secrets);
  let options: { yes: boolean; url: string | undefined };
  try {
    options = parseOptions(args);
  } catch (error) {
    return fail(process.stderr, clean(error));
  }
  const { yes } = options;
  const instance = connect(options.url);
  const terminal = openTerminal();
  const out = terminal?.out ?? process.stderr;
  const s = style(out);
  try {
    // Before anything is asked: whether there is anything to do, and whether this CLI may do it.
    const me = await instance.me();
    if (me.instance === null) {
      throw new MigrateError(
        `${instance.origin} tells only its owners and root admins its version, and you are signed in as ${me.principal.id}: ask one of them to run coffre migrate`,
      );
    }
    const problem = versionProblem(cliVersion(), me.instance.version, instance.origin);
    if (problem !== null) throw new MigrateError(problem);
    const pending = pendingOf(me.instance);
    if (pending.length === 0) {
      out.write(`${s.green('✓')} ${instance.origin}'s database is up to date, at coffre ${me.instance.version}'s schema\n`);
      return;
    }
    if (!yes && terminal === null) {
      throw new MigrateError('nothing here to confirm on: run coffre migrate on a terminal, or pass --yes to apply without asking');
    }

    if (s.ansi) out.write(`\n  ${s.bold('coffre migrate')}  ${s.dim(`${instance.origin}, coffre ${me.instance.version}`)}\n\n`);
    out.write(`  ${count(pending.length, 'migration')} to apply: ${listed(pending, 'and')}\n\n`);
    const { url, secrets: typed } = await readDatabaseUrl(out, s, {
      variable: URL_VARIABLE,
      question: "The database owner's connection string",
      hint: "Hidden as you type. The direct Postgres URL of the login that owns coffre's tables, not a runtime login's or Hyperdrive's.",
      command: 'coffre migrate',
    });
    secrets.push(...typed);
    await run(url, instance, pending, out, () => terminal?.keys ?? null, yes, clean);
  } catch (error) {
    if (error instanceof Cancelled) return fail(out, 'cancelled; nothing was changed', 130);
    if (!(error instanceof StepFailed)) return fail(out, clean(error));
    process.exit(1);
  } finally {
    if (terminal !== null) release(terminal.keys);
  }
}

/**
 * The steps: read the database's history and hold it to what the instance
 * reported, so that a URL to another database stops here; show what will be
 * applied and ask; apply it; then ask the instance what it now sees.
 */
async function run(
  url: URL,
  instance: Instance,
  pending: string[],
  out: Output,
  keys: () => Keyboard | null,
  yes: boolean,
  clean: (error: unknown) => string,
): Promise<void> {
  const where = `${url.hostname}${decodeURIComponent(url.pathname)}`;
  const steps = new Steps(
    out,
    [`Read ${where}'s migrations`, `Apply ${listed(pending, 'and')}`, `Check ${instance.origin} sees them`],
    keys,
    clean,
  );
  try {
    await steps.run(0, async () => {
      const status = await migrationStatus(url.href);
      if (status.pending.join() !== pending.join()) {
        throw new MigrateError(
          `${where} lacks ${status.pending.length === 0 ? 'no migration' : listed(status.pending, 'and')}, ` +
            `but ${instance.origin} reports ${listed(pending, 'and')} pending: is this its database? Nothing was changed`,
        );
      }
      return {
        text: `${where} has ${count(status.applied.length, 'migration')} applied, the last ${status.applied.at(-1) ?? 'none'}`,
        details: [],
      };
    });
    await steps.run(1, async (step) => {
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
        throw new MigrateError(migrationFailure(error));
      }
      return `Applied ${listed(pending, 'and')}, and reasserted the database's privileges`;
    });
    await steps.run(2, async () => {
      const after = (await instance.me()).instance;
      const left = after === null ? pending : pendingOf(after);
      if (left.length > 0) {
        throw new MigrateError(`${instance.origin} still reports ${listed(left, 'and')} pending: is the URL its database's?`);
      }
      const ready = await instance.ready();
      if (!ready.ok) {
        throw new MigrateError(
          `${instance.origin} sees the new schema, but is not ready: ` +
            (ready.heartbeatAgeSeconds === null
              ? 'it has no audit heartbeat yet'
              : !ready.checkpointed
                ? 'no checkpoint signed by the vault covers its last heartbeat'
                : `its last heartbeat is ${Math.round(ready.heartbeatAgeSeconds)}s old`) +
            '. The migration is applied; see /readyz',
        );
      }
      return `${instance.origin} sees the new schema, and is ready`;
    });
  } finally {
    steps.end();
  }
}

function parseOptions(args: string[]): { yes: boolean; url: string | undefined } {
  try {
    const { values } = parseArgs({
      args,
      options: { yes: { type: 'boolean', default: false }, url: { type: 'string' } },
      strict: true,
    });
    if (values.url !== undefined && /^postgres(ql)?:/i.test(values.url)) throw new Error('a database URL');
    return { yes: values.yes, url: values.url };
  } catch {
    // The error would quote the argument, which may be the connection string itself.
    const leaked = args.some((arg) => /postgres(ql)?:|@/i.test(arg));
    throw new MigrateError(
      `coffre migrate takes only --yes and --url. It reads the database owner's connection string from a hidden prompt, ` +
        `${URL_VARIABLE} or stdin, never from the command line, where the shell's history and other users can read it.` +
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


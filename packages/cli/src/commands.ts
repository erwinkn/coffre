/**
 * Every command the CLI has, once: `coffre help` is made from this list,
 * `coffre <command> --help` prints its entry, and PARITY holds the API to
 * it. Every route of the API is a command here, or is listed as the
 * browser's, with why: a route added to the server fails the typecheck
 * until it is one or the other, and test/parity.test.ts runs each command
 * named.
 */
import type { RouteKey } from '@coffre/client';

/** A command: how it is written, and what it does, a line or more beside it. */
export type Entry = {
  /** The words that name it, as typed: `projects create`. */
  readonly command: string;
  /** Its synopsis, without `coffre`: a line, or more for a long one. */
  readonly usage: readonly string[];
  readonly about?: readonly string[];
};

export type Section = { readonly title: string; readonly entries: readonly Entry[] };

const P = '<project>/<environment>';

export const SECTIONS = [
  {
    title: 'New deployment',
    entries: [
      { command: 'init', usage: ['init --workers [<dir>]'], about: ['two Cloudflare Workers: the app and its vault'] },
      { command: 'init', usage: ['init --node [<dir>]'], about: ['a Node server, and its vault beside it'] },
      {
        command: 'setup',
        usage: ['setup [--reset-passwords] [--json]'],
        about: [
          'its database logins, migrations and keys in one go,',
          'shown once on a screen of their own; on Workers,',
          'Cloudflare too, and in an empty directory, the deployment',
        ],
      },
      { command: 'keys', usage: ['keys [--json]'], about: ['the app key, vault key and vault ID alone, shown the same way'] },
    ],
  },
  {
    title: 'Upgrade',
    entries: [
      { command: 'update', usage: ['update [--yes]'], about: ['this CLI, and in a deployment, its coffre packages'] },
      {
        command: 'migrate',
        usage: ['migrate [--yes]'],
        about: [
          "the instance's database, to the schema its version ships,",
          "with the owner's connection string, asked for hidden;",
          "in a deployment's folder, as its pipeline runs it before",
          "the deploy: to its pinned version's, with no instance",
          '(piped in, and --yes, without a terminal)',
        ],
      },
    ],
  },
  {
    title: 'Session',
    entries: [
      { command: 'login', usage: ['login [<url>] [--no-browser]'], about: ['sign in, and make <url> the current instance'] },
      { command: 'login', usage: ['login <url> --token'], about: ["a CI run's sign-in: a bearer token, asked for or piped in"] },
      { command: 'login', usage: ['login <url> --access-client-id <id>'], about: ['the same, behind Cloudflare Access: its secret asked for'] },
      {
        command: 'login',
        usage: ['login <url> --service <name> [--id-token]'],
        about: ["the same, as a service account, by OIDC, the run's ID token:", "GitHub's runner gives it; elsewhere, --id-token asks for it"],
      },
      { command: 'logout', usage: ['logout [<url>]'] },
      { command: 'whoami', usage: ['whoami [--json]'] },
      { command: 'use', usage: ['use [<url>]'], about: ['list instances, or switch the current one'] },
      { command: 'sessions', usage: ['sessions [--json]'], about: ["where you are signed in, this CLI's session among them"] },
      { command: 'sessions revoke', usage: ['sessions revoke <id> [--apply]'], about: ['signs that session out'] },
      { command: 'identities', usage: ['identities [--json]'], about: ['the accounts you sign in with'] },
      { command: 'identities unlink', usage: ['identities unlink <id> [--apply]'], about: ['stops that account signing you in'] },
    ],
  },
  {
    title: 'Secrets',
    entries: [
      { command: 'list', usage: [`list      ${P} [--json]`], about: ['keys, versions and who changed them; no value'] },
      { command: 'get', usage: [`get       ${P}/<KEY>`] },
      { command: 'set', usage: [`set       ${P}/<KEY>`], about: ['the value asked for, or piped in'] },
      { command: 'run', usage: [`run       ${P} -- <command>`] },
      { command: 'export', usage: [`export    ${P} [--format dotenv|json|shell|github]`] },
      { command: 'history', usage: [`history   ${P}/<KEY> [--json]`] },
      { command: 'rollback', usage: [`rollback  ${P}/<KEY> <version>`] },
      { command: 'import', usage: [`import    ${P} [--file .env] [--apply]`] },
      { command: 'rename', usage: [`rename    ${P}/<KEY> <NEW_KEY>`], about: ['the key, with its versions'] },
      { command: 'archive', usage: [`archive   ${P}/<KEY>`], about: ['out of reads, runs and exports; its versions kept'] },
      { command: 'unarchive', usage: [`unarchive ${P}/<KEY>`] },
      { command: 'move', usage: [`move      ${P}/<KEY> (<folder> | --none)`], about: ['into a folder, to arrange the list; nothing else changes'] },
    ],
  },
  {
    title: 'Projects',
    entries: [
      { command: 'projects', usage: ['projects [--json]'], about: ['with their environments'] },
      { command: 'projects create', usage: ['projects create <project> [--name <name>]'] },
      { command: 'projects rename', usage: ['projects rename <project> [--name <name>] [--slug <new-project>]'] },
      { command: 'projects archive', usage: ['projects archive <project>'], about: ['out of reach, and back with unarchive'] },
      { command: 'projects unarchive', usage: ['projects unarchive <project>'] },
      {
        command: 'projects delete',
        usage: ['projects delete <project> [--apply]'],
        about: ['an archived one, for good: what it erases and revokes;', '--apply deletes it, and frees its name'],
      },
      { command: 'move', usage: ['move <project> (<folder> | --none)'], about: ['into a folder of projects'] },
      { command: 'environments create', usage: [`environments create ${P} [--name <name>]`] },
      { command: 'environments rename', usage: [`environments rename ${P} [--name <name>] [--slug <new-environment>]`] },
      { command: 'environments archive', usage: [`environments archive ${P}`] },
      { command: 'environments unarchive', usage: [`environments unarchive ${P}`] },
      { command: 'environments delete', usage: [`environments delete ${P} [--apply]`], about: ['an archived one, for good, as a project'] },
    ],
  },
  {
    title: 'Access',
    entries: [
      { command: 'roles', usage: ['roles'] },
      {
        command: 'access',
        usage: ['access [<project>[/<environment>]] [--json]'],
        about: ["the members, or those who reach a place; '*' lists the grants", 'on every project'],
      },
      {
        command: 'admit',
        usage: ['admit <principal> [--service] [--owner | --no-owner]'],
        about: ['a member: a person by their email, or a service account,', 'service:<name> or --service; --owner makes a person an owner'],
      },
      {
        command: 'grant',
        usage: ['grant <project> <principal> --role <role> [--env <env>] [--service]', '      [--expires YYYY-MM-DD]'],
        about: [
          "a member, admitted first. '*' for every project, the ones made later",
          'too, and with --env, the environment of that name in each: owners only',
        ],
      },
      { command: 'revoke', usage: ['revoke <project> <principal> [--env <env>] [--service]'], about: ["their grant there, '*' too"] },
      {
        command: 'offboard',
        usage: ['offboard <principal> [--service] [--apply]'],
        about: ['what removing them revokes, and what to rotate'],
      },
    ],
  },
  {
    title: 'Service accounts, for CI and other machines: admit, grant, then OIDC or a bearer token',
    entries: [
      {
        command: 'trust',
        usage: ['trust <service> [--github … | --gitlab … | --issuer …] [--apply]'],
        about: ['OIDC, no stored secret: the CI runs that may sign in as', "it, by their platform's ID token; `coffre trust` alone says how"],
      },
      { command: 'untrust', usage: ['untrust <service> <binding-id> [--apply]'], about: ['the CI runs it would cut off; --apply removes it'] },
      { command: 'tokens', usage: ['tokens <service> [--json]'], about: ['its bearer tokens, for CI without OIDC'] },
      {
        command: 'tokens issue',
        usage: ['tokens issue <service> [--expires-in <days>] [--label <label>]', '             [--output-file <path>]'],
        about: ['a bearer token, on stdout or in a new 0600 file, shown once', 'and kept nowhere; 90 days unless told'],
      },
      { command: 'tokens revoke', usage: ['tokens revoke <service> <id> [--apply]'] },
    ],
  },
  {
    title: 'Audit',
    entries: [{ command: 'audit', usage: ['audit [--limit N] [--actor <id>] [--denied] [--detail] [--json]'] }],
  },
  {
    title: 'Verify',
    entries: [
      { command: 'verify', usage: ['verify'], about: ['asks which of these, on a terminal'] },
      { command: 'verify instance', usage: ['verify instance [<url>]'], about: ['the instance from outside: as no one, then as you, an owner'] },
      {
        command: 'verify keys',
        usage: ['verify keys [--vault-id <id>]'],
        about: ['the vault key and app key you keep, checked on this machine'],
      },
      { command: 'verify log', usage: ['verify log'], about: ['the whole audit log, as an owner'] },
    ],
  },
] as const satisfies readonly Section[];

/** Each command's words, as `coffre help` lists them: what main.ts runs, one to one. */
export type Command = (typeof SECTIONS)[number]['entries'][number]['command'];

export const ENTRIES: readonly Entry[] = SECTIONS.flatMap(({ entries }): readonly Entry[] => entries);

const SESSION_FLAGS = `  Session flags, before the command: coffre [flags] <command>, for that command alone
    --url <url>                     which instance to talk to; else the current one
    --service <name>                the service account a CI run signs in as, by OIDC: its ID token,
                                    which a trust binding accepts (coffre trust); on GitHub Actions, with
                                    \`permissions: id-token: write\`, nothing else
    --auth-mode signin|cloudflare   normally detected at login
    Without them, the session \`coffre login\` saved.

  A secret is asked for, at a hidden prompt, or piped in; never a flag or an argument:
    printf '%s' "$TOKEN" | coffre login https://coffre.example.com --token

  coffre <command> --help says more of each; coffre --version, which version this is.
`;

/** Where the line beside a synopsis starts. */
const COLUMN = 44;

/** An entry's lines, as `coffre help` shows them: the synopsis, and beside it or under it, what it does. */
function lines(entry: Entry): string[] {
  // A synopsis's later lines line up under its first's words, after `coffre `.
  const usage = entry.usage.map((line, i) => `    ${i === 0 ? 'coffre ' : '       '}${line}`);
  const about = entry.about ?? [];
  const last = usage.at(-1)!;
  if (about.length > 0 && last.length < COLUMN - 1) {
    return [...usage.slice(0, -1), `${last.padEnd(COLUMN)}${about[0]}`, ...about.slice(1).map((line) => `${' '.repeat(COLUMN)}${line}`)];
  }
  return [...usage, ...about.map((line) => `${' '.repeat(COLUMN)}${line}`)];
}

/** `coffre help`. */
export function usage(): string {
  const sections = SECTIONS.map(({ title, entries }) => [`  ${title}`, ...entries.flatMap(lines)].join('\n'));
  return `coffre - secrets, with an audit log\n\n${sections.join('\n\n')}\n\n${SESSION_FLAGS}`;
}

/**
 * What `argv` names: a command, its words the longest that match
 * (`projects create` before `projects`), and the arguments after them; or a
 * group of commands, `tokens` or `environments`, alone; or nothing.
 */
export function lookup(argv: readonly string[]): { command: Command; args: string[] } | { group: string } | null {
  for (let count = Math.min(argv.length, 2); count > 0; count--) {
    const words = argv.slice(0, count).join(' ');
    if (ENTRIES.some((entry) => entry.command === words)) return { command: words as Command, args: argv.slice(count) };
  }
  const [first] = argv;
  return first !== undefined && ENTRIES.some((entry) => entry.command.startsWith(`${first} `)) ? { group: first } : null;
}

/** `coffre <command> --help`: the command's entries, and those under it. */
export function help(command: string): string {
  const entries = ENTRIES.filter((entry) => entry.command === command || entry.command.startsWith(`${command} `));
  return `usage:\n${entries.flatMap(lines).join('\n')}\n`;
}

/** What a route of the API is for the CLI: the commands that call it, or why only a browser does. */
export type Reach = { commands: readonly Command[] } | { browser: string };

/**
 * Every route, and the commands that call it. Typed over the route table:
 * a route added to the server is an error here until it is listed.
 */
export const PARITY: { [K in RouteKey]: Reach } = {
  'GET /me': { commands: ['whoami'] },
  'GET /projects': { commands: ['projects'] },
  'PUT /projects/:project': { commands: ['projects create'] },
  'PATCH /projects/:project': { commands: ['projects rename', 'projects archive', 'projects unarchive', 'move'] },
  'DELETE /projects/:project': { commands: ['projects delete'] },
  'PUT /projects/:project/:environment': { commands: ['environments create'] },
  'PATCH /projects/:project/:environment': { commands: ['environments rename', 'environments archive', 'environments unarchive'] },
  'DELETE /projects/:project/:environment': { commands: ['environments delete'] },
  'GET /secrets/:project/:environment': { commands: ['list'] },
  'PATCH /secrets/:project/:environment': { commands: ['set', 'import'] },
  'PATCH /secrets/:project/:environment/:key': { commands: ['rename', 'archive', 'unarchive', 'move'] },
  'GET /secrets/:project/:environment/:key/versions': { commands: ['history'] },
  'POST /secrets/:project/:environment/:key/restore': { commands: ['rollback'] },
  'POST /reveals': { commands: ['get', 'run', 'export'] },
  'GET /members': { commands: ['access'] },
  'GET /members/:member': { commands: ['offboard'] },
  'PUT /members/:member': { commands: ['admit'] },
  'DELETE /members/:member': { commands: ['offboard'] },
  'GET /members/:member/tokens': { commands: ['tokens'] },
  'POST /members/:member/tokens': { commands: ['tokens issue'] },
  'DELETE /members/:member/tokens/:id': { commands: ['tokens revoke'] },
  'GET /members/:member/bindings': { commands: ['trust'] },
  'POST /members/:member/bindings': { commands: ['trust'] },
  'DELETE /members/:member/bindings/:id': { commands: ['untrust'] },
  'GET /workloads/lookup': { commands: ['trust'] },
  'PATCH /access/:member': { commands: ['grant', 'revoke'] },
  'GET /sessions': { commands: ['sessions'] },
  'DELETE /sessions/:id': { commands: ['sessions revoke'] },
  'GET /identities': { commands: ['identities'] },
  'DELETE /identities/:id': { commands: ['identities unlink'] },
  'GET /device-logins/:code': {
    browser: '`coffre login` shows its code, and a browser signed in to coffre approves it: a CLI approving a login would vouch for itself',
  },
  'POST /device-logins/:code': { browser: 'approving `coffre login`, in a browser signed in to coffre, as above' },
  'GET /audit': { commands: ['audit'] },
  'GET /audit/verification': { commands: ['verify log'] },
  'GET /audit/keys': { commands: ['verify keys'] },
};

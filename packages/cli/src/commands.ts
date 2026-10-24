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
        usage: ['setup [--reset-passwords] [--rotate-deploy-token] [--json]'],
        about: [
          'its database logins, migrations and keys in one go,',
          'shown once on a screen of their own; on Workers,',
          'Cloudflare too, and deploys on every push to GitHub;',
          'in an empty directory, the deployment first',
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
          "in a deployment's folder, its database to the schema of",
          "the version it pins; asks for the owner's connection",
          'string (piped in, and --yes, without a terminal)',
        ],
      },
    ],
  },
  {
    title: 'Session',
    entries: [
      { command: 'login', usage: ['login [<url>] [--no-browser]'], about: ['sign in; use <url> in this directory and below,', 'and by default'] },
      { command: 'login', usage: ['login <url> --token'], about: ["a CI run's or a script's sign-in: a bearer or personal", 'token, asked for or piped in'] },
      { command: 'login', usage: ['login <url> --access-client-id <id>'], about: ['the same, behind Cloudflare Access: its secret asked for'] },
      {
        command: 'login',
        usage: ['login <url> --service <name> [--id-token]'],
        about: ["the same, as a service account, by OIDC, the run's ID token:", "GitHub's runner gives it; elsewhere, --id-token asks for it"],
      },
      { command: 'logout', usage: ['logout [<url>]'] },
      { command: 'whoami', usage: ['whoami [--json]'] },
      { command: 'use', usage: ['use [<url>]'], about: ['list instances, or switch the default one'] },
      { command: 'sessions', usage: ['sessions [--json]'], about: ["where you are signed in, this CLI's session among them"] },
      { command: 'sessions revoke', usage: ['sessions revoke <id> [--apply]'], about: ['signs that session out'] },
      { command: 'apps', usage: ['apps [--json]'], about: ['the MCP clients you connected, such as Claude'] },
      { command: 'apps revoke', usage: ['apps revoke <id> [--apply]'], about: ['disconnects that app'] },
      { command: 'tokens', usage: ['tokens [--json]'], about: ['your personal tokens, which act as you'] },
      {
        command: 'tokens issue',
        usage: ['tokens issue --label <label> --scope <path>=<role>,…', '             [--expires-in <30m|4h|2d>] [--output-file <path>]'],
        about: [
          'a personal token, for a script or an agent: it acts as you',
          'on what --scope says, at most what you hold now and less',
          'whenever you hold less; never on access or sign-in. An hour',
          'unless told, a week at most; every entry it makes names it',
        ],
      },
      { command: 'tokens revoke', usage: ['tokens revoke <id> [--apply]'], about: ['ends that personal token; `coffre logout` with it, too'] },
      { command: 'identities', usage: ['identities [--json]'], about: ['the accounts you sign in with'] },
      { command: 'identities unlink', usage: ['identities unlink <id> [--apply]'], about: ['stops that account signing you in'] },
    ],
  },
  {
    title: 'Secrets',
    entries: [
      {
        command: 'list',
        usage: [`list      ${P} [--older-than <days>d | --stale] [--json]`],
        about: ['keys, versions, who changed them and when; no secret value,', 'a plain one as it is', "--stale: those unchanged past the instance's rotateAfterDays"],
      },
      { command: 'get', usage: [`get       ${P}/<KEY>`] },
      { command: 'set', usage: [`set       ${P}/<KEY>`], about: ['the value asked for, or piped in'] },
      {
        command: 'set',
        usage: [`set       ${P}/<KEY> [value] --plain`],
        about: [
          'a value that is no secret, an account id: shown to whoever lists',
          'the environment, and given to its apps as it is; written again',
          'without --plain, it is a secret again. In <env>@me, shown to you',
          'alone, and a value written saying nothing takes the level of the',
          'key it overrides, then of your own',
        ],
      },
      {
        command: 'set',
        usage: [`set       ${P}/<KEY> --sensitive`],
        about: [
          'a value shown to nobody, Owners included: people\'s apps use it',
          'through the credential proxy, and service accounts read it;',
          'written again, it stays sensitive unless --secret says otherwise',
        ],
      },
      {
        command: 'mark',
        usage: [`mark      ${P}[/<KEY>] <plain|secret|sensitive>`],
        about: [
          'a key, or every value of the environment\'s own, made stricter, its',
          'value kept: plain to secret, secret to sensitive; looser takes the',
          'value written again, coffre set … --secret, but an Owner of the',
          'project makes a sensitive value secret in place, never shown to',
          'them by it. A reference or an inherited key at another level is',
          'left, and named, to mark where it is held',
        ],
      },
      {
        command: 'set',
        usage: [`set       ${P}/<KEY> --ref <project>/<environment>/<KEY>`],
        about: ['a reference: whoever reads its environment reads that', "secret's current value through it; you need read on it"],
      },
      {
        command: 'set',
        usage: [`set       ${P}/<KEY> --generate <recipe> [--public-key <KEY>]`],
        about: [
          'a value made here and never shown, by a recipe: bytes:32,',
          'bytes:32:hex (or base64, base64url), aes:256, or a key pair,',
          'ecdsa:p-256 or ecdh:p-384, its public key in JWT_PUBLIC_KEY',
          'beside JWT_PRIVATE_KEY, or --public-key; kept, for regenerate',
        ],
      },
      {
        command: 'regenerate',
        usage: [`regenerate ${P}/<KEY>`],
        about: ['a new value by the recipe its value was made by, never shown;', 'a key pair, both its keys at once'],
      },
      {
        command: 'references',
        usage: ['references <project>[/<environment>[/<KEY>]] [--json]'],
        about: ['the references into and out of it, and who reads through them'],
      },
      {
        command: 'references break',
        usage: [`references break ${P}/<KEY> [--apply]`],
        about: ['who would stop reading through it; --apply breaks it'],
      },
      {
        command: 'run',
        usage: [`run       [--keep-existing] [--proof <proof>] ${P}... -- <command>`],
        about: [
          'several environments: their keys together, and a key in two',
          'of them stops it before anything is read; --keep-existing lets',
          'a variable already set in your shell, empty ones too, win',
          "over coffre's value for it; <environment>@me reads your",
          'personal config of it, or it while you have none; where the',
          'deployment generates, your own value of each key a recipe made,',
          'made once, in your personal config; as a --service, key-bound',
          'where the instance has it: --proof says how it proves itself (none:',
          "a GitHub Actions job's ID token), the environments are the session's",
          'unless named, and credentials go through a local listener',
        ],
      },
      {
        command: 'export',
        usage: [
          `export    ${P}... [--keys <KEY | PREFIX_*>...] [--format dotenv|json|shell|github]`,
          '          [--output-file <file> [--watch [--interval 60s] [--on-change <command>]]]',
        ],
        about: [
          'several, as run takes them; --keys reads only the keys it',
          'names, each one some environment must hold, and github',
          'needs it; --output-file writes them to a file only you can',
          'read, which --watch keeps current: it asks their version',
          'each interval, reads only once it changed, and runs',
          '--on-change after each new file',
        ],
      },
      {
        command: 'version',
        usage: [`version   ${P} [--json]`],
        about: ['what reading it would open, as a version that changes', 'whenever a read would; it reads no value, and is not logged'],
      },
      { command: 'history', usage: [`history   ${P}/<KEY> [--json]`] },
      { command: 'rollback', usage: [`rollback  ${P}/<KEY> <version>`] },
      { command: 'import', usage: [`import    ${P} [--file .env] [--apply]`] },
      { command: 'rename', usage: [`rename    ${P}/<KEY> <NEW_KEY>`], about: ['the key, with its versions'] },
      { command: 'archive', usage: [`archive   ${P}/<KEY>`], about: ['out of reads, runs and exports; its versions kept'] },
      { command: 'unarchive', usage: [`unarchive ${P}/<KEY>`] },
      {
        command: 'reset',
        usage: [`reset     ${P}/<KEY> [--undo]`],
        about: ["in a fork, back to its parent's value; its own is kept,", 'and --undo serves it again'],
      },
      {
        command: 'remove',
        usage: [`remove    ${P}/<KEY> [--undo]`],
        about: ["in a fork, does without its parent's key; --undo inherits it", 'again'],
      },
      { command: 'move', usage: [`move      ${P}/<KEY> (<folder> | --none)`], about: ['into a folder, to arrange the list; nothing else changes'] },
      {
        command: 'folders',
        usage: [`folders   ${P} [--json]`],
        about: ['its key folders, and the keys in each; move makes them'],
      },
      { command: 'folders rename', usage: [`folders rename ${P} <folder> <new-folder>`], about: ['every key in it moves; onto an existing folder, the two merge'] },
      { command: 'folders remove', usage: [`folders remove ${P} <folder> [--apply]`], about: ['every key out of it, into no folder; more than one is', 'shown first'] },
      {
        command: 'missing',
        usage: [`missing   ${P} [--dismissed | --check] [--json]`],
        about: [
          'keys its sibling environments have and it lacks, by name, read',
          'or not; --dismissed, those its team decided it does not need;',
          '--check exits 1 when one is missing, for CI',
        ],
      },
      { command: 'missing dismiss', usage: [`missing dismiss ${P}/<KEY>`, `missing dismiss ${P} --all`], about: ['for the whole team, logged; restore brings it back'] },
      { command: 'missing restore', usage: [`missing restore ${P}/<KEY>`] },
    ],
  },
  {
    title: 'Projects',
    entries: [
      { command: 'projects', usage: ['projects [--json]'], about: ['with their environments'] },
      { command: 'projects create', usage: ['projects create <project>'] },
      { command: 'projects rename', usage: ['projects rename <project> --slug <new-project>'] },
      { command: 'projects archive', usage: ['projects archive <project>'], about: ['out of reach, and back with unarchive'] },
      { command: 'projects unarchive', usage: ['projects unarchive <project>'] },
      {
        command: 'projects delete',
        usage: ['projects delete <project> [--apply]'],
        about: ['an archived one, for good: what it erases and revokes;', '--apply deletes it, and frees its name'],
      },
      { command: 'move', usage: ['move <project> (<folder> | --none)'], about: ['into a folder of projects'] },
      { command: 'folders', usage: ['folders [--json]'], about: ['the folders of projects, and the projects in each'] },
      {
        command: 'folders rename',
        usage: ['folders rename <folder> <new-folder>'],
        about: ['every project in it moves; you must manage each of them'],
      },
      { command: 'folders remove', usage: ['folders remove <folder> [--apply]'], about: ['every project out of it, each staying where it is'] },
      { command: 'environments create', usage: [`environments create ${P}`] },
      {
        command: 'fork',
        usage: [`fork ${P} <new-environment> [--reference | --inherit]`],
        about: [
          'a new environment beside it, each key a copy of its value,',
          'without history; --reference makes each key a reference',
          'to its parent instead; --inherit copies nothing: it reads',
          "its parent's keys live, but for those it sets or removes",
        ],
      },
      {
        command: 'personal',
        usage: ['personal  <project> [--json]'],
        about: [
          "its members' personal configs, <environment>@me: whose, of",
          'what, and their key names, never values; `environments delete',
          '<project>/<slug>` deletes one, as its owner deletes <env>@me',
        ],
      },
      { command: 'environments rename', usage: [`environments rename ${P} --slug <new-environment>`] },
      { command: 'environments archive', usage: [`environments archive ${P}`] },
      { command: 'environments unarchive', usage: [`environments unarchive ${P}`] },
      { command: 'environments delete', usage: [`environments delete ${P} [--apply]`], about: ['an archived one, for good, as a project'] },
      {
        command: 'environments protect',
        usage: [`environments protect ${P}`],
        about: ["each role holds its protected column there, for people:", "managing the project's environments does it"],
      },
      { command: 'environments unprotect', usage: [`environments unprotect ${P}`], about: ['an Owner of the project, or of the whole instance, only'] },
    ],
  },
  {
    title: 'Access',
    entries: [
      { command: 'roles', usage: ['roles [<role>] [--instance] [--json]'], about: ['every role, in two columns: anywhere, and in a protected', 'environment, where a person holds the second'] },
      {
        command: 'roles set',
        usage: ['roles set <role> [--name <name>] [--description <text>]', '          [--permissions <a,b>] [--protected <a,b>] [--instance] [--apply]'],
        about: [
          'a role edited, or one made, by an Owner of the whole instance:',
          'what it would change for whom, and --apply saves it',
        ],
      },
      { command: 'roles reset', usage: ['roles reset <role> [--instance] [--apply]'], about: ['a built-in role back as it ships, shown first'] },
      { command: 'roles remove', usage: ['roles remove <role>'], about: ['a role an Owner made, once no grant names it'] },
      {
        command: 'access',
        usage: ['access [<project>[/<environment>] | <member> [--service]] [--json]'],
        about: ['the members, their instance roles and grants; who reaches', 'a place; or what one member holds'],
      },
      {
        command: 'admit',
        usage: [
          'admit <principal> [--service] [--role <role>]',
          '      [--projects <a,b> | --except-projects <a,b>]',
          '      [--environments <a,b> | --except-environments <a,b>]',
          '      [--grant <project>[/<env>]=<role>,…]',
        ],
        about: [
          'a member: a person by their email, or a service account,',
          'service:<name> or --service. --role sets a person\'s',
          'instance role, member, auditor, developer, admin or owner,',
          'in every project and environment unless a scope flag',
          'narrows it; never your own. --grant gives a service',
          'account its first grants with it: refused, it is not added',
        ],
      },
      {
        command: 'grant',
        usage: ['grant <project> <principal> --role <role> [--env <env>] [--service]', '      [--expires YYYY-MM-DD]'],
        about: ['a member, admitted first: on a project, or one of its', 'environments with --env'],
      },
      { command: 'revoke', usage: ['revoke <project> <principal> [--env <env>] [--service]'], about: ['their grant there'] },
      {
        command: 'offboard',
        usage: ['offboard <principal> [--service] [--apply]'],
        about: ['what removing them revokes, and what to rotate'],
      },
      {
        command: 'settings',
        usage: [
          'settings [service-accounts [--projects <a,b> | --except-projects <a,b>]',
          '         [--environments <a,b> | --except-environments <a,b>]] [--json]',
        ],
        about: [
          'the instance\'s settings; with service-accounts, where anyone',
          'who holds access sets one up, giving it at most what they',
          'hold: no flag is everywhere',
        ],
      },
    ],
  },
  {
    title: 'Service accounts, for CI and other machines: admit, grant, then OIDC or a bearer token; anyone with access sets one up where `coffre settings` lets them',
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
        usage: ['tokens issue <service> [--expires-in <days>] [--label <label>]', '             [--scope <path>=<role>,…] [--output-file <path>]'],
        about: [
          'a bearer token, on stdout or in a new 0600 file, shown once',
          'and kept nowhere; 90 days unless told. It reaches what --scope',
          'says, at most what the account holds, all of it unless told,',
          'and nothing the account is given later',
        ],
      },
      { command: 'tokens revoke', usage: ['tokens revoke <service> <id> [--apply]'] },
    ],
  },
  {
    title: 'Workloads: apps that use secrets through coffre, with a session bound to a key they never export',
    entries: [
      {
        command: 'enroll',
        usage: ['enroll <service> [--binding <id>]'],
        about: ['an enrollment code, for one deploy of an app on a platform', 'that signs nothing: printed once, for the platform to hold'],
      },
      {
        command: 'enroll',
        usage: ['enroll <service> --promote <code-id> [--now]'],
        about: ["the binding's current code, once the deploy is up: older", "codes' sessions drain; --now ends them at once"],
      },
      { command: 'enroll', usage: ['enroll <service> --list [--json]'], about: ["the binding's live codes, and what each reaches"] },
      { command: 'approve', usage: ['approve <service> <session-id>'], about: ['a session its binding holds for a person to check'] },
      {
        command: 'freeze',
        usage: ['freeze [<target> --reason <text>]'],
        about: [
          'every use under the target refused from its next request,',
          'its sessions and codes kept: instance, service:<name>,',
          'binding:<id>, session:<id> or credential:<path>/<name>;',
          'alone, what is frozen',
        ],
      },
      { command: 'unfreeze', usage: ['unfreeze <target>'], about: ['lifts it'] },
      {
        command: 'serve',
        usage: ['serve --url <url> --service <name> --proof <proof> [--place <project>/<env>]', '      [--listen <address>] [--tunnel <name>=<address>]...'],
        about: [
          "a workload's sidecar: it holds the session and its key,",
          'and forwards what the app sends it, signed; --listen, 127.0.0.1:7300',
          'unless given, or unix:<path>; each --tunnel a Postgres listener;',
          '--proof kubernetes[:<file>], aws, gcp, azure:<audience>, fly,',
          'vercel, github, enrollment or oidc (those two read stdin); --place',
          "which of the session's environments its tunnels are in",
        ],
      },
    ],
  },
  {
    title: 'Audit',
    entries: [{ command: 'audit', usage: ['audit [<path>] [--limit N] [--actor <id>] [--denied] [--detail] [--json]'], about: ['a project, environment or KEY: market/prod/DATABASE_URL lists', 'who read or changed it, reads of several that listed it included'] }],
  },
  {
    title: 'Verify',
    entries: [
      { command: 'verify', usage: ['verify'], about: ['asks which of these, on a terminal'] },
      { command: 'verify instance', usage: ['verify instance [<url>]'], about: ['the instance from outside: as no one, then as you, an', 'admin or owner'] },
      {
        command: 'verify keys',
        usage: ['verify keys [--vault-id <id>]'],
        about: ['the vault key and app key you keep, checked on this machine'],
      },
      { command: 'verify log', usage: ['verify log'], about: ['the whole audit log, as an auditor, admin or owner of all of it'] },
    ],
  },
] as const satisfies readonly Section[];

/** Each command's words, as `coffre help` lists them: what main.ts runs, one to one. */
export type Command = (typeof SECTIONS)[number]['entries'][number]['command'];

export const ENTRIES: readonly Entry[] = SECTIONS.flatMap(({ entries }): readonly Entry[] => entries);

const SESSION_FLAGS = `  Session flags, before the command: coffre [flags] <command>, for that command alone
    --url <url>                     which instance to talk to; else the one this directory is pinned
                                    to, by a login in it or above it, or its repository's coffre.json
                                    names, { "url": "https://…" }, whichever is nearer; else the default
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
  'PUT /projects/:project/:environment': { commands: ['environments create', 'fork'] },
  'GET /projects/:project/:environment/missing': { commands: ['missing'] },
  'GET /personal/:project': { commands: ['personal'] },
  'GET /projects/:project/:environment/version': { commands: ['version', 'export'] },
  'PATCH /projects/:project/:environment/dismissals': { commands: ['missing dismiss', 'missing restore', 'remove'] },
  'PATCH /projects/:project/:environment': { commands: ['environments rename', 'environments archive', 'environments unarchive', 'environments protect', 'environments unprotect'] },
  'DELETE /projects/:project/:environment': { commands: ['environments delete'] },
  'GET /secrets/:project/:environment': { commands: ['list'] },
  'PATCH /secrets/:project/:environment': { commands: ['set', 'mark', 'regenerate', 'import'] },
  'DELETE /secrets/:project/:environment/:key/reference': { commands: ['references break'] },
  'PATCH /folders/:folder': { commands: ['folders rename'] },
  'DELETE /folders/:folder': { commands: ['folders remove'] },
  'PATCH /folders/:project/:environment/:folder': { commands: ['folders rename'] },
  'DELETE /folders/:project/:environment/:folder': { commands: ['folders remove'] },
  'GET /references': { commands: ['references', 'access'] },
  'PATCH /secrets/:project/:environment/:key': { commands: ['rename', 'archive', 'unarchive', 'move', 'reset'] },
  'GET /secrets/:project/:environment/:key/versions': { commands: ['history'] },
  'POST /secrets/:project/:environment/:key/restore': { commands: ['rollback'] },
  'POST /reveals': { commands: ['get', 'run', 'export'] },
  'GET /members': { commands: ['access'] },
  'GET /members/:member': { commands: ['offboard'] },
  'GET /members/:member/access': { commands: ['access'] },
  'PUT /members/:member': { commands: ['admit'] },
  'DELETE /members/:member': { commands: ['offboard'] },
  'GET /members/:member/tokens': { commands: ['tokens'] },
  'POST /members/:member/tokens': { commands: ['tokens issue'] },
  'DELETE /members/:member/tokens/:id': { commands: ['tokens revoke'] },
  'POST /handles': { commands: ['run', 'export'] },
  'DELETE /handles/:id': { commands: ['run'] },
  'GET /members/:member/bindings': { commands: ['trust'] },
  'POST /members/:member/bindings': { commands: ['trust'] },
  'POST /members/:member/bindings/keys': { commands: ['trust'] },
  'DELETE /members/:member/bindings/:id': { commands: ['untrust'] },
  'GET /workloads/lookup': { commands: ['trust'] },
  'GET /members/:member/bindings/:id/enrollments': { commands: ['enroll'] },
  'POST /members/:member/bindings/:id/enrollments': { commands: ['enroll'] },
  'POST /members/:member/bindings/:id/enrollments/:enrollment/promote': { commands: ['enroll'] },
  'POST /members/:member/tokens/:id/approve': { commands: ['approve'] },
  'GET /freezes': { commands: ['freeze'] },
  'POST /freezes': { commands: ['freeze'] },
  'DELETE /freezes/:target': { commands: ['unfreeze'] },
  'GET /workloads/repositories': {
    browser: "the pages' repository picker: `coffre trust` names its repository, which `GET /workloads/lookup` resolves through the same GitHub App",
  },
  'PATCH /access/:member': { commands: ['grant', 'revoke'] },
  'GET /roles': { commands: ['roles', 'roles set', 'roles reset', 'roles remove'] },
  'PUT /roles/:role': { commands: ['roles set'] },
  'DELETE /roles/:role': { commands: ['roles reset', 'roles remove'] },
  'PUT /instance-roles/:role': { commands: ['roles set'] },
  'DELETE /instance-roles/:role': { commands: ['roles reset'] },
  'GET /settings': { commands: ['settings'] },
  'PUT /settings': { commands: ['settings'] },
  'GET /sessions': { commands: ['sessions'] },
  'DELETE /sessions/:id': { commands: ['sessions revoke'] },
  'GET /identities': { commands: ['identities'] },
  'DELETE /identities/:id': { commands: ['identities unlink'] },
  'GET /device-logins/:code': {
    browser: '`coffre login` shows its code, and a browser signed in to coffre approves it: a CLI approving a login would vouch for itself',
  },
  'POST /device-logins/:code': { browser: 'approving `coffre login`, in a browser signed in to coffre, as above' },
  'GET /oauth/authorizations': {
    browser: 'an MCP client opens the consent page in a browser signed in to coffre, which shows what it asks for: a CLI approving an app would vouch for it',
  },
  'POST /oauth/authorizations': { browser: 'approving an MCP client, on that page, as above' },
  'GET /approvals/:id': {
    browser: "an MCP client's change waits for its person on coffre's own page, signed in as them: a terminal deciding it would be the agent's own",
  },
  'POST /approvals/:id': { browser: 'approving or denying that change, on that page, as above' },
  'GET /apps': { commands: ['apps'] },
  'DELETE /apps/:id': { commands: ['apps revoke'] },
  'GET /audit': { commands: ['audit'] },
  'GET /audit/verification': { commands: ['verify log'] },
  'GET /audit/keys': { commands: ['verify keys'] },
};

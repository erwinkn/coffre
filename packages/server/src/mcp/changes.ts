// The tools that change coffre (docs/design/mcp.md, sections 6 and 7). None
// changes anything when it is called: it asks for an approval, which its
// person reads and decides on coffre's own page, and Approve makes the
// change there and then, as the person, through the connection. So each is
// four plain functions over the API: a sentence for the prompt, a check as
// the connection before asking, what the page shows, and the change itself.
// No tool takes a value: the person types one on the page, or coffre makes it.
import { randomBytes } from 'node:crypto';

import { apiMember, CoffreError, shownMember, type CoffreClient, type RouteInput } from '@coffre/client';
import { INSTANCE_ROLES, INSTANCE_ROLE_NAMES, makesProjects, ROLE_NAMES, runsInstance, scopeInWords, type Permission } from '@coffre/core/access';
import {
  claimValues,
  defaultIssuer,
  EVENT_EXPOSURE,
  GITHUB_ISSUER,
  GITLAB_ISSUER,
  WORKLOAD_PROFILES,
  type BindingClaims,
  type WorkloadProfile,
} from '@coffre/core/identity';
import type { McpScope } from '@coffre/core/mcp';
import { instanceRole, scopeInput, secretKey, slug } from '@coffre/core/schemas';
import { z } from 'zod';

import { FetchRefused, type WorkloadTransport } from '../workloads/transport.ts';
import type { Tool, ToolContext } from './tools.ts';

/** A line of what the approval page shows: a label, what it is, and what that means, when coffre can say; `warn` when the person must check it. */
export type Detail = { label: string; value: string; kind?: 'mono' | 'time'; note?: string; warn?: true };

/** What a change replaces, read once: the page's lines for it, and the state they show, whose digest Approve reads again and compares. */
export type Replaced = { details: Detail[]; state: unknown };

/**
 * What a preview knows besides the API: whether the app holds Reveal
 * values, and so can read what the person can, and the transport trust
 * bindings fetch through, to name what an ID is.
 */
export type Viewing = { reveals: boolean; transport: WorkloadTransport };

/** What a change answered, once made: what the client reads, and what only the page shows, once. */
export type Applied = { result: Record<string, unknown>; text: string; shown?: Detail[] };

/** What the page asks the person for, beyond Approve: the value, for `request_secret_value`. */
export type Ask = { value: { label: string; note: string } };

export type Change<I extends z.ZodObject = z.ZodObject> = {
  /** What it does, in a phrase from its arguments alone: the client's prompt and the page's title. */
  summary: (args: z.infer<I>) => string;
  /** Before asking, as the connection: a call the person could not make fails here, not on the page. */
  check?: (ctx: ToolContext, args: z.infer<I>) => Promise<void>;
  /**
   * What the change replaces, read as the person: its lines go into the
   * page's preview, and Approve reads it again and is refused if its state
   * differs, so what is replaced is what the person read.
   */
  replaces?: (api: CoffreClient, args: z.infer<I>) => Promise<Replaced>;
  /** What the page shows, read as the person when they open it, with `replaces`' lines, `replaced`, where the tool has them. */
  preview: (api: CoffreClient, args: z.infer<I>, viewing: Viewing, replaced: Detail[]) => Promise<Detail[]>;
  asks?: (viewing: Viewing) => Ask;
  /**
   * A reveal: the page shows the person a value on Approve, which never goes
   * to the client. Its API call needs `reveal`, which the connection
   * need not hold, since the value reaches the person only.
   */
  reveal?: true;
  /** The change, as the person with the connection attached, when they approve it. */
  apply: (api: CoffreClient, args: z.infer<I>, given: { value?: string }) => Promise<Applied>;
};

const secret = z.string().min(1).max(300).describe('A secret, as project/environment/KEY: market/prod/STRIPE_KEY');
const environment = z.string().min(1).max(200).describe('An environment, as project/environment: market/prod');
const member = z.string().min(1).max(320).describe('A member: user:ada@acme.example, or service:ci-deploy for a service account');
const service = z.string().min(1).max(200).describe('A service account: service:ci-deploy, or ci-deploy');
const name = z.string().trim().min(1).max(100).describe('Its display name');

/** `market/prod/KEY` as its environment and key, or why not. */
function splitSecret(path: string): { environment: string; key: string } {
  const parts = path.replace(/^\/+|\/+$/g, '').split('/');
  if (parts.length !== 3 || !slug.safeParse(parts[0]).success || !slug.safeParse(parts[1]).success || !secretKey.safeParse(parts[2]).success) {
    throw new CoffreError(400, 'bad_request', `"${path}" is not a secret: name one as project/environment/KEY`);
  }
  return { environment: `${parts[0]}/${parts[1]}`, key: parts[2]! };
}

function splitEnvironment(path: string): { project: string; environment: string } {
  const parts = path.replace(/^\/+|\/+$/g, '').split('/');
  if (parts.length !== 2 || !slug.safeParse(parts[0]).success || !slug.safeParse(parts[1]).success) {
    throw new CoffreError(400, 'bad_request', `"${path}" is not an environment: name one as project/environment`);
  }
  return { project: parts[0]!, environment: parts[1]! };
}

/** A service account as the API names it, from `ci-deploy`, `service:ci-deploy` or `token:ci-deploy`. */
const serviceMember = (name: string) => apiMember(name.includes(':') ? name : `service:${name}`);
const shownService = (name: string) => shownMember(serviceMember(name));

/** Refuse now, as the API would on Approve, when the person lacks a permission at an environment. */
async function needs(api: CoffreClient, path: string, permission: Permission): Promise<void> {
  const { project, environment } = splitEnvironment(path);
  const me = await api.me();
  const here = me.environments.find((entry) => entry.project === project && entry.environment === environment);
  if (here === undefined) throw new CoffreError(404, 'not_found', `no environment "${path}" that you can see`);
  if (!here.permissions.includes(permission)) throw new CoffreError(403, 'forbidden', `you need ${permission} on ${path}`);
}

/** Refuse now, as the API would on Approve, when the person does not run the instance. */
async function instanceOnly({ connection }: ToolContext): Promise<void> {
  if (!runsInstance(connection.caller)) throw new CoffreError(403, 'forbidden', 'only an admin or owner of the whole instance can do this');
}

/** Refuse now, as the API would on Approve, when the person may not make a project. */
async function projectMakers({ connection }: ToolContext): Promise<void> {
  if (!makesProjects(connection.caller)) throw new CoffreError(403, 'forbidden', 'only an admin or owner whose scope takes in new projects can do this');
}

/** Refuse now, as the API would on Approve, when the person lacks a permission on each project. */
async function needsOn(api: CoffreClient, projects: string[], permission: Permission): Promise<void> {
  const { projects: theirs } = await api.projects.list();
  for (const project of new Set(projects)) {
    const here = theirs.find((entry) => entry.slug === project);
    if (here === undefined) throw new CoffreError(404, 'not_found', `no project "${project}" that you can see`);
    if (!here.permissions.includes(permission)) throw new CoffreError(403, 'forbidden', `you need ${permission} on ${project}`);
  }
}

/** A scope as the API takes it, with either filter left out as `all`. */
const fullScope = (scope: z.infer<typeof scopeInput> | undefined) => ({ projects: scope?.projects ?? 'all', environments: scope?.environments ?? 'all' });

/** What the page says of an app that holds Reveal values, beside a value it would otherwise never see. */
const READABLE: Detail = { label: 'The app', value: 'holds Reveal values: it can read values you can read, this one included' };

/** A secret's current version: who set it and when, or that there is none yet; the version is its state. */
async function current(api: CoffreClient, path: string): Promise<Replaced> {
  try {
    const { versions, archived } = await api.secrets.history(path);
    const now = versions.find((version) => version.current);
    if (now === undefined) return { state: { version: null }, details: [{ label: 'Now', value: 'no value yet' }] };
    return {
      state: { version: now.version },
      details: [
        { label: 'Now', value: `version ${now.version}${archived ? ', archived' : ''}, set by ${shownMember(now.createdBy)}` },
        { label: 'Set', value: now.createdAt, kind: 'time' },
      ],
    };
  } catch (error) {
    if (error instanceof CoffreError && error.status === 404) return { state: { version: null }, details: [{ label: 'Now', value: 'a new key: there is none yet' }] };
    throw error;
  }
}

/** What every change tool answers: where its approval stands, and once made, what the change answered. */
const CHANGE_OUTPUT = {
  type: 'object',
  properties: {
    status: { type: 'string', enum: ['pending', 'approved', 'denied', 'cancelled', 'failed', 'expired'] },
    message: { type: 'string' },
    approval: { type: 'object', properties: { id: { type: 'string' }, url: { type: 'string' }, expiresAt: { type: 'string' } } },
    result: { type: 'object' },
  },
  required: ['status', 'approval'],
};

type ChangeTool<I extends z.ZodObject> = Omit<Tool<I>, 'readOnly' | 'output' | 'run' | 'change'> & { change: Change<I>; readOnly?: boolean };

function changeTool<I extends z.ZodObject>(definition: ChangeTool<I>): Tool {
  return { readOnly: false, ...definition, output: CHANGE_OUTPUT } as unknown as Tool;
}

/** The alphabets `generate_secret_value` draws from, and how long a value is in each unless asked: 256 bits or so. */
export const ALPHABETS = {
  base64url: { characters: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_', length: 43 },
  hex: { characters: '0123456789abcdef', length: 64 },
  alphanumeric: { characters: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', length: 43 },
} as const;
export type Alphabet = keyof typeof ALPHABETS;

/** A random value of `length` characters from an alphabet, each uniform: bytes past the last whole multiple are drawn again. */
export function randomValue(alphabet: Alphabet, length: number = ALPHABETS[alphabet].length): string {
  const { characters } = ALPHABETS[alphabet];
  const limit = 256 - (256 % characters.length);
  let value = '';
  while (value.length < length) {
    for (const byte of randomBytes(length * 2)) {
      if (byte < limit && value.length < length) value += characters[byte % characters.length];
    }
  }
  return value;
}

/** What the page says of an ID github.com or gitlab.com did not name. */
const UNNAMED = 'private or unknown: check this ID yourself';
/** What the page says of an ID on any other issuer, whose answers coffre has no reason to believe. */
const UNCHECKED = "coffre can't check this host: check this ID yourself";

/** The claims that hold GitHub's or GitLab's numeric IDs. */
const ID_CLAIMS = new Set(['repository_id', 'repository_owner_id', 'project_id', 'namespace_id']);

/**
 * What a binding's numeric IDs name, read back from github.com's or
 * gitlab.com's API, the other way from `GET /workloads/lookup`, through
 * the same transport: a repository, project or owner by its path. Only
 * those two answer: the app chose the issuer, and a host it chose could
 * name its IDs anything. Each ID claim gets a note: what it names, that
 * coffre could not tell, or that it does not ask that host.
 */
async function namesOf(transport: WorkloadTransport, profile: WorkloadProfile, issuer: string | null, claims: BindingClaims): Promise<Record<string, string>> {
  const notes: Record<string, string> = {};
  const own = defaultIssuer(profile);
  if (own === null || (issuer ?? own) !== own) {
    for (const claim of Object.keys(claims)) if (ID_CLAIMS.has(claim)) notes[claim] = UNCHECKED;
    return notes;
  }
  const ask = async (url: string): Promise<Record<string, unknown> | null> => {
    try {
      const answer = await transport.json(new URL(url));
      return typeof answer === 'object' && answer !== null ? (answer as Record<string, unknown>) : null;
    } catch (error) {
      if (error instanceof FetchRefused) return null;
      throw error;
    }
  };
  const text = (value: unknown) => (typeof value === 'string' && value.length > 0 ? value.slice(0, 200) : null);
  const field = (object: Record<string, unknown> | null, key: string) => {
    const value = object?.[key];
    return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : null;
  };
  const id = (claim: string) => {
    const value = claims[claim];
    return typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value) ? value : null;
  };
  const name = (claim: string, what: string, path: string | null) => {
    if (claims[claim] !== undefined) notes[claim] = path === null ? UNNAMED : `the ${what} ${path}`;
  };

  if (profile.startsWith('github')) {
    const [repositoryId, ownerId] = [id('repository_id'), id('repository_owner_id')];
    const repository = repositoryId === null ? null : await ask(`https://api.github.com/repositories/${repositoryId}`);
    const owner = field(repository, 'owner');
    const ownerLogin =
      owner !== null && String(owner.id) === ownerId ? text(owner.login) : ownerId === null ? null : text((await ask(`https://api.github.com/user/${ownerId}`))?.login);
    name('repository_id', 'GitHub repository', text(repository?.full_name));
    name('repository_owner_id', 'GitHub account', ownerLogin);
  } else {
    const [projectId, namespaceId] = [id('project_id'), id('namespace_id')];
    const project = projectId === null ? null : await ask(`${GITLAB_ISSUER}/api/v4/projects/${projectId}`);
    const namespace = field(project, 'namespace');
    const namespacePath =
      namespace !== null && String(namespace.id) === namespaceId
        ? text(namespace.full_path)
        : namespaceId === null ? null : text((await ask(`${GITLAB_ISSUER}/api/v4/namespaces/${namespaceId}`))?.full_path);
    name('project_id', 'GitLab project', text(project?.path_with_namespace));
    name('namespace_id', 'GitLab namespace', namespacePath);
  }
  return notes;
}

const approved = 'Nothing changes until the person approves it on coffre.';

/** A binding's claims as the page's lines: each in full, what an ID names where coffre could tell, and what an event that runs unreviewed code exposes. */
function claimLines(claims: BindingClaims, names: Record<string, string>): Detail[] {
  return Object.entries(claims).map(([claim, value]) => {
    const exposed = claim === 'event_name' ? claimValues(value).flatMap((event) => (EVENT_EXPOSURE[event] === undefined ? [] : [EVENT_EXPOSURE[event]])) : [];
    const note = exposed.length > 0 ? exposed.join(' ') : names[claim];
    return { label: claim, value: claimValues(value).join(', '), kind: 'mono' as const, ...(note === undefined ? {} : { note }), ...(exposed.length > 0 ? { warn: true as const } : {}) };
  });
}

function secretTool<I extends z.ZodObject>(definition: Omit<ChangeTool<I>, 'scope' | 'names'> & { scope?: McpScope }): Tool {
  return changeTool({ scope: 'write', names: (args: { secret: string }) => [args.secret], ...definition } as ChangeTool<I>);
}

function archiving(archived: boolean): Tool {
  return secretTool({
    name: archived ? 'archive_secret' : 'unarchive_secret',
    needs: 'secret.archive',
    title: archived ? 'Archive a secret' : 'Unarchive a secret',
    description: archived
      ? `Archive a secret: coffre run and exports stop setting it, and every version stays restorable. ${approved}`
      : `Bring an archived secret back, as it was. ${approved}`,
    idempotent: true,
    destructive: archived,
    input: z.object({ secret }).strict(),
    change: {
      summary: ({ secret }) => `${archived ? 'archive' : 'unarchive'} ${secret}`,
      check: async ({ api }, { secret }) => needs(api, splitSecret(secret).environment, 'secret.archive'),
      preview: async (api, { secret }) => [
        { label: 'Secret', value: secret, kind: 'mono' },
        ...(await current(api, secret)).details,
        { label: 'Then', value: archived ? 'not set by coffre run or exports; every version stays restorable' : 'set again by coffre run and exports' },
      ],
      apply: async (api, { secret }) => {
        await api.secrets.update(secret, { archived });
        return { result: { secret, archived }, text: `${secret} is ${archived ? 'archived' : 'live again'}.` };
      },
    },
  });
}

const role = z.enum(ROLE_NAMES);
const accessChange = z.union([role, z.object({ role, until: z.string().max(40).nullable() }).strict(), z.null()]);
type AccessChange = z.infer<typeof accessChange>;
const shownAccess = (to: AccessChange) => (to === null ? 'nothing' : typeof to === 'string' ? to : `${to.role}${to.until === null ? '' : ` until ${to.until}`}`);

// A place as the API reads one, without spaces or slashes around it: market, or market/prod.
const placeOf = (raw: string) => raw.trim().replace(/^\/+|\/+$/g, '');

/** What `set_access` replaces: the role a member holds at each place, and until when, or nothing. */
async function heldAt(api: CoffreClient, member: string, changes: Record<string, AccessChange>): Promise<Replaced> {
  const named = apiMember(member);
  const held = (await api.members.list()).members.find((entry) => entry.member === named)?.grants ?? [];
  const now = Object.keys(changes).map((place) => {
    const grant = held.find((entry) => (entry.environment === null ? entry.project : `${entry.project}/${entry.environment}`) === placeOf(place));
    return [place, grant === undefined ? 'nothing' : `${grant.role}${grant.expiresAt === null ? '' : ` until ${grant.expiresAt}`}`] as const;
  });
  return { state: Object.fromEntries(now), details: now.map(([place, was]) => ({ label: place, value: `${was} → ${shownAccess(changes[place]!)}` })) };
}

/**
 * Showing a value to the person, on coffre's page, through an approval like
 * a change's: Read, since the value never reaches the client.
 */
export const SHOW_VALUE: Tool = changeTool({
  name: 'show_secret_value',
  needs: 'secret.read',
  title: "Show a secret's value to the person",
  description:
    "Show the person a secret's value on coffre's own page, after they press Reveal there. The value is never sent to you or this conversation: use this when the person wants to see a value; reveal_secret_values is the one that sends values to you.",
  scope: 'read',
  readOnly: true,
  idempotent: true,
  destructive: false,
  input: z.object({ secret }).strict(),
  names: ({ secret }) => [secret],
  change: {
    summary: ({ secret }) => `show you the value of ${secret}`,
    check: async ({ api }, { secret }) => needs(api, splitSecret(secret).environment, 'secret.read'),
    preview: async (api, { secret }) => [{ label: 'Secret', value: secret, kind: 'mono' }, ...(await current(api, secret)).details],
    reveal: true,
    apply: async (api, { secret }) => {
      const { key } = splitSecret(secret);
      const { values } = await api.secrets.reveal(secret);
      const at = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
      return { result: { secret, shownAt: at }, text: `The value of ${secret} was shown to the person on coffre at ${at}. It was not sent here.`, shown: [{ label: key, value: values[key] ?? '', kind: 'mono' }] };
    },
  },
});

/** The tools that change coffre, each through an approval: Write, then Manage access. */
export const CHANGE_TOOLS: readonly Tool[] = [
  secretTool({
    name: 'request_secret_value',
    needs: 'secret.write',
    title: 'Ask the person to set a value',
    description: `Set a secret to a value the person types on coffre's page: neither you nor this conversation ever see it. Use it whenever a value is needed; never ask for one in the conversation. ${approved}`,
    idempotent: false,
    destructive: true,
    input: z.object({ secret, note: z.string().trim().min(1).max(500).optional().describe('What the value is for, shown to the person on the page') }).strict(),
    change: {
      summary: ({ secret }) => `set ${secret} to a value you type on coffre`,
      check: async ({ api }, { secret }) => needs(api, splitSecret(secret).environment, 'secret.write'),
      replaces: async (api, { secret }) => current(api, secret),
      preview: async (_api, { secret, note }, { reveals }, replaced) => [
        { label: 'Secret', value: secret, kind: 'mono' },
        ...replaced,
        ...(note === undefined ? [] : [{ label: 'The app says', value: note }]),
        ...(reveals ? [READABLE] : []),
      ],
      asks: ({ reveals }) => ({ value: { label: 'Value', note: reveals ? 'It goes to coffre, and the app can read it.' : 'It goes to coffre only: the app never sees it.' } }),
      apply: async (api, { secret }, { value }) => {
        if (value === undefined) throw new CoffreError(400, 'bad_request', 'type the value to set');
        const { environment, key } = splitSecret(secret);
        const written = (await api.secrets.set(environment, { [key]: value })).keys[key];
        const version = written !== undefined && 'version' in written ? written.version : null;
        return { result: { secret, version }, text: `${secret} is set${version === null ? '' : `, version ${version}`}. Its value went to coffre only.` };
      },
    },
  }),
  secretTool({
    name: 'generate_secret_value',
    needs: 'secret.write',
    title: 'Set a secret to a new random value',
    description: `Set a secret to a random value coffre makes on its own server: neither you nor the person sees it, and whatever reads the secret gets it. 32 random bytes in base64url unless asked otherwise. ${approved}`,
    idempotent: false,
    destructive: true,
    input: z
      .object({
        secret,
        length: z.number().int().min(16).max(128).optional().describe('How many characters: 43 for base64url and alphanumeric, 64 for hex, unless asked'),
        alphabet: z.enum(['base64url', 'hex', 'alphanumeric']).optional().describe('base64url unless asked'),
      })
      .strict(),
    change: {
      summary: ({ secret }) => `set ${secret} to a new random value`,
      check: async ({ api }, { secret }) => needs(api, splitSecret(secret).environment, 'secret.write'),
      replaces: async (api, { secret }) => current(api, secret),
      preview: async (_api, { secret, length, alphabet = 'base64url' }, { reveals }, replaced) => [
        { label: 'Secret', value: secret, kind: 'mono' },
        ...replaced,
        {
          label: 'New value',
          value: `${length ?? ALPHABETS[alphabet].length} random ${alphabet} characters, made by coffre${reveals ? ',' : ': nobody sees it,'} and earlier versions stay restorable`,
        },
        ...(reveals ? [READABLE] : []),
      ],
      apply: async (api, { secret, length, alphabet = 'base64url' }) => {
        const { environment, key } = splitSecret(secret);
        const written = (await api.secrets.set(environment, { [key]: randomValue(alphabet, length) })).keys[key];
        const version = written !== undefined && 'version' in written ? written.version : null;
        return { result: { secret, version }, text: `${secret} is set to a new random value${version === null ? '' : `, version ${version}`}. Nobody saw it.` };
      },
    },
  }),
  secretTool({
    name: 'rename_secret',
    needs: 'secret.write',
    title: 'Rename a secret',
    description: `Rename a secret's key, keeping its versions. Whatever reads the old name stops finding it. ${approved}`,
    idempotent: true,
    destructive: true,
    input: z.object({ secret, newKey: secretKey.describe('The new key: letters, digits and underscores') }).strict(),
    change: {
      summary: ({ secret, newKey }) => `rename ${secret} to ${newKey}`,
      check: async ({ api }, { secret }) => needs(api, splitSecret(secret).environment, 'secret.write'),
      preview: async (api, { secret, newKey }) => [
        { label: 'Secret', value: secret, kind: 'mono' },
        { label: 'Becomes', value: `${splitSecret(secret).environment}/${newKey}`, kind: 'mono' },
        ...(await current(api, secret)).details,
      ],
      apply: async (api, { secret, newKey }) => {
        await api.secrets.rename(secret, newKey);
        const renamed = `${splitSecret(secret).environment}/${newKey}`;
        return { result: { secret: renamed }, text: `${secret} is now ${renamed}. Whatever reads the old name must read the new one.` };
      },
    },
  }),
  archiving(true),
  archiving(false),
  secretTool({
    name: 'restore_secret_version',
    needs: 'secret.write',
    title: 'Restore a version',
    description: `Make an earlier version of a secret current again, as a new version: secret_history lists them. ${approved}`,
    idempotent: false,
    destructive: true,
    input: z.object({ secret, version: z.number().int().positive() }).strict(),
    change: {
      summary: ({ secret, version }) => `restore ${secret} to version ${version}`,
      check: async ({ api }, { secret }) => needs(api, splitSecret(secret).environment, 'secret.write'),
      replaces: async (api, { secret }) => current(api, secret),
      preview: async (api, { secret, version }, _viewing, replaced) => {
        const { versions } = await api.secrets.history(secret);
        const old = versions.find((entry) => entry.version === version);
        return [
          { label: 'Secret', value: secret, kind: 'mono' },
          ...replaced,
          {
            label: 'Restores',
            value: old === undefined ? `version ${version}, which it does not have` : `version ${version}, set by ${shownMember(old.createdBy)}, as a new version`,
          },
          ...(old === undefined ? [] : [{ label: 'That version set', value: old.createdAt, kind: 'time' as const }]),
        ];
      },
      apply: async (api, { secret, version }) => {
        const restored = await api.secrets.restore(secret, version);
        return { result: { secret, version: restored.version }, text: `${secret} holds version ${version}'s value again, as version ${restored.version}.` };
      },
    },
  }),
  changeTool({
    name: 'create_project',
    needs: 'new-project',
    title: 'Create a project',
    description: `Create a project, with no environments yet. Admins and owners only. ${approved}`,
    scope: 'write',
    idempotent: true,
    destructive: false,
    input: z.object({ project: slug.describe('The project slug: market'), name }).strict(),
    names: ({ project }) => [project],
    change: {
      summary: ({ project, name }) => `create the project ${project} (${name})`,
      check: projectMakers,
      preview: async (_api, { project, name }) => [
        { label: 'Project', value: project, kind: 'mono' },
        { label: 'Name', value: name },
      ],
      apply: async (api, { project, name }) => {
        const made = await api.projects.create(project, { name });
        return {
          result: { project, created: made.created },
          text: made.created ? `The project ${project} is created, with no environments yet.` : `The project ${project} existed already: nothing changed.`,
        };
      },
    },
  }),
  changeTool({
    name: 'create_environment',
    needs: 'environment.manage',
    title: 'Create an environment',
    description: `Create an environment in a project, with no secrets yet. ${approved}`,
    scope: 'write',
    idempotent: true,
    destructive: false,
    input: z.object({ environment, name }).strict(),
    names: ({ environment }) => [environment],
    change: {
      summary: ({ environment, name }) => `create the environment ${environment} (${name})`,
      check: async ({ api }, { environment }) => needsOn(api, [splitEnvironment(environment).project], 'environment.manage'),
      preview: async (_api, { environment, name }) => [
        { label: 'Environment', value: environment, kind: 'mono' },
        { label: 'Name', value: name },
      ],
      apply: async (api, { environment, name }) => {
        const made = await api.environments.create(environment, { name });
        return {
          result: { environment, created: made.created },
          text: made.created ? `The environment ${environment} is created, with no secrets yet.` : `The environment ${environment} existed already: nothing changed.`,
        };
      },
    },
  }),

  changeTool({
    name: 'set_access',
    needs: 'grant.manage',
    title: 'Change a member’s access',
    description: `Grant, change or revoke a member's roles at projects and environments; list_access shows what they hold. ${approved}`,
    scope: 'manage-access',
    idempotent: true,
    destructive: true,
    input: z
      .object({
        member,
        changes: z
          .record(z.string().min(1).max(200), accessChange)
          .refine((changes) => Object.keys(changes).length > 0 && Object.keys(changes).length <= 50, 'name from 1 to 50 places')
          .describe(`Each place, a project or project/environment, with the role to hold there (${ROLE_NAMES.join(', ')}; { role, until } for one that ends), or null to revoke it`),
      })
      .strict(),
    names: ({ member, changes }) => [apiMember(member), ...Object.keys(changes)],
    change: {
      summary: ({ member, changes }) => {
        const places = Object.keys(changes);
        return `change ${shownMember(apiMember(member))}'s access at ${places.length === 1 ? places[0] : `${places.length} places`}`;
      },
      // Each place needs grant.manage there, as the API checks: on a project, all of it; on an environment, that one.
      check: async (ctx, { changes }) => {
        const places = Object.keys(changes).map(placeOf);
        if (places.some((place) => place.split('/')[0] === '*')) {
          throw new CoffreError(400, 'bad_request', 'grants are on a project or an environment: a person reaches every project by their instance role (admit_member)');
        }
        const projects = places.filter((place) => !place.includes('/'));
        await needsOn(ctx.api, projects, 'grant.manage');
        for (const place of places.filter((candidate) => candidate.includes('/'))) await needs(ctx.api, place, 'grant.manage');
      },
      replaces: async (api, { member, changes }) => heldAt(api, member, changes),
      preview: async (_api, { member }, _viewing, replaced) => [{ label: 'Member', value: shownMember(apiMember(member)), kind: 'mono' }, ...replaced],
      apply: async (api, { member, changes }) => {
        const named = apiMember(member);
        const { changes: done } = await api.access.set(named, changes as RouteInput<'PATCH /access/:member'>);
        return { result: { member: shownMember(named), changes: done }, text: `${shownMember(named)}'s access is changed.` };
      },
    },
  }),
  changeTool({
    name: 'admit_member',
    needs: 'instance',
    title: 'Admit a member, or set their role',
    description: `Admit a person, or a service account, as a member, with no access until granted some; or set a person's instance role and where it applies. ${INSTANCE_ROLE_NAMES.map((role) => `${role}: ${INSTANCE_ROLES[role].description.toLowerCase()}`).join(' ')} ${approved}`,
    scope: 'manage-access',
    idempotent: true,
    destructive: false,
    input: z.object({
      member,
      role: instanceRole.optional().describe('A person\'s instance role; left out, a new member is a member and an existing one keeps theirs'),
      scope: scopeInput.optional().describe('Where the role applies: projects and environments (by slug), each "all", { only: [...] } or { except: [...] }; left out, everywhere'),
    }).strict(),
    names: ({ member }) => [apiMember(member)],
    change: {
      summary: ({ member, role, scope }) => `admit ${shownMember(apiMember(member))}${role === undefined ? '' : ` as ${INSTANCE_ROLES[role].name}, ${scopeInWords(fullScope(scope))}`}`,
      check: instanceOnly,
      preview: async (_api, { member, role, scope }) => [
        { label: 'Member', value: shownMember(apiMember(member)), kind: 'mono' },
        role === undefined
          ? { label: 'As', value: 'a member, with no access until granted some, or as they are' }
          : { label: 'As', value: `${INSTANCE_ROLES[role].name}: ${INSTANCE_ROLES[role].description}` },
        ...(role === undefined || role === 'member' ? [] : [{ label: 'Where', value: scopeInWords(fullScope(scope)) }]),
      ],
      apply: async (api, { member, role, scope }) => {
        const made = await api.members.add(apiMember(member), role === undefined ? {} : { role, ...(scope === undefined ? {} : { scope }) });
        const as = `${INSTANCE_ROLES[made.instanceRole].name}, ${scopeInWords(made.scope)}`;
        return {
          result: { member: shownMember(made.member), instanceRole: made.instanceRole, scope: made.scope, created: made.created },
          text: `${shownMember(made.member)} is a member${made.created ? '' : ' already'}, as ${as}.`,
        };
      },
    },
  }),
  changeTool({
    name: 'offboard_member',
    needs: 'instance',
    title: 'Offboard a member',
    description: `Remove a member: their grants, sessions, tokens and linked accounts end, and the answer lists the secrets they read or wrote, to rotate. ${approved}`,
    scope: 'manage-access',
    idempotent: true,
    destructive: true,
    input: z.object({ member }).strict(),
    names: ({ member }) => [apiMember(member)],
    change: {
      summary: ({ member }) => `offboard ${shownMember(apiMember(member))}`,
      check: instanceOnly,
      preview: async (api, { member }) => {
        const report = await api.members.get(apiMember(member));
        return [
          { label: 'Member', value: shownMember(apiMember(member)), kind: 'mono' },
          { label: 'Ends', value: `${report.live.grants} grants, ${report.live.sessions} sessions, ${report.live.tokens} tokens, ${report.live.identities} linked accounts` },
          { label: 'To rotate after', value: `${report.exposed.length} secrets they read or wrote` },
        ];
      },
      apply: async (api, { member }) => {
        const removed = await api.members.remove(apiMember(member));
        const toRotate = removed.report.exposed.map((entry) => `${entry.project}/${entry.environment}/${entry.key}`);
        return {
          result: { member: shownMember(apiMember(member)), revoked: removed.revoked, toRotate },
          text: `${shownMember(apiMember(member))} is offboarded. ${toRotate.length === 0 ? 'Nothing they read needs rotating.' : `Rotate what they read or wrote: ${toRotate.join(', ')}.`}`,
        };
      },
    },
  }),
  changeTool({
    name: 'issue_service_token',
    needs: 'instance',
    title: 'Issue a service token',
    description: `Issue a bearer token for a service account. coffre shows the token to the person on its page, once; it never reaches you. ${approved}`,
    scope: 'manage-access',
    idempotent: false,
    destructive: false,
    input: z.object({ service, label: z.string().trim().min(1).max(120).optional(), expiresInDays: z.number().int().min(1).max(366) }).strict(),
    names: ({ service }) => [serviceMember(service)],
    change: {
      summary: ({ service, expiresInDays }) => `issue a token for ${shownService(service)}, good for ${expiresInDays} days`,
      check: instanceOnly,
      preview: async (_api, { service, label, expiresInDays }) => [
        { label: 'Service account', value: shownService(service), kind: 'mono' },
        ...(label === undefined ? [] : [{ label: 'The app calls it', value: label }]),
        { label: 'Good for', value: `${expiresInDays} days` },
        { label: 'The token', value: 'shown here once, after you approve; never to the app' },
      ],
      apply: async (api, { service, label, expiresInDays }) => {
        const issued = await api.tokens.issue(serviceMember(service), { label: label ?? null, expiresInDays });
        return {
          result: { service: shownService(service), id: issued.id, expiresAt: issued.expiresAt },
          text: `A token for ${shownService(service)} is issued, good until ${issued.expiresAt}. coffre showed it to the person, once; it is not here.`,
          shown: [{ label: 'Token', value: issued.token, kind: 'mono' }],
        };
      },
    },
  }),
  changeTool({
    name: 'revoke_service_token',
    needs: 'instance',
    title: 'Revoke a service token',
    description: `Revoke one of a service account's tokens, by the ID describe_member lists. ${approved}`,
    scope: 'manage-access',
    idempotent: true,
    destructive: true,
    input: z.object({ service, id: z.string().uuid() }).strict(),
    names: ({ service }) => [serviceMember(service)],
    change: {
      summary: ({ service }) => `revoke a token of ${shownService(service)}`,
      check: instanceOnly,
      preview: async (api, { service, id }) => {
        const token = (await api.tokens.list(serviceMember(service))).tokens.find((entry) => entry.id === id);
        return [
          { label: 'Service account', value: shownService(service), kind: 'mono' },
          { label: 'Token', value: token === undefined ? `${id}, which it does not hold` : `${token.label ?? 'unlabelled'} (…${token.hint})` },
          ...(token?.lastUsedAt == null ? [] : [{ label: 'Last used', value: token.lastUsedAt, kind: 'time' as const }]),
        ];
      },
      apply: async (api, { service, id }) => {
        await api.tokens.revoke(serviceMember(service), id);
        return { result: { service: shownService(service), id, revoked: true }, text: 'The token is revoked: whatever used it is refused from now on.' };
      },
    },
  }),
  changeTool({
    name: 'trust_workload',
    needs: 'instance',
    title: 'Trust a CI workload',
    description: `Let CI runs whose ID token has these claims sign in as a service account, with no stored token. event_name may list several events; a pull_request run matches by the branch it merges into. ${approved}`,
    scope: 'manage-access',
    idempotent: false,
    destructive: false,
    input: z
      .object({
        service,
        profile: z.enum(WORKLOAD_PROFILES),
        issuer: z.string().max(400).optional().describe("The issuer's URL, for a custom profile"),
        claims: z
          .record(z.string().max(64), z.union([z.string().max(1024), z.array(z.string().max(64)).min(1).max(16)]))
          .describe('The ID token claims a run must carry, such as repository_id and ref; event_name or pipeline_source may be a list, as ["push", "pull_request"]'),
        label: z.string().trim().min(1).max(120).optional(),
      })
      .strict(),
    names: ({ service }) => [serviceMember(service)],
    change: {
      summary: ({ service, profile }) => `let ${profile} CI runs sign in as ${shownService(service)}`,
      // The binding is checked, and its issuer asked where its keys are, before anyone is asked to approve it.
      check: async ({ api }, { service, profile, issuer, claims, label }) =>
        void (await api.bindings.preview(serviceMember(service), { profile, issuer: issuer ?? null, claims, label: label ?? null })),
      // The model picks the IDs: each is named back from GitHub or GitLab, where it can be, so the person reads what they trust.
      preview: async (_api, { service, profile, issuer, claims, label }, { transport }) => {
        const names = await namesOf(transport, profile, issuer ?? null, claims);
        // An issuer the app named that is not GitHub's or GitLab's own: whoever runs it signs the tokens.
        const unfamiliar = issuer !== undefined && issuer !== GITHUB_ISSUER && issuer !== GITLAB_ISSUER;
        return [
          { label: 'Service account', value: shownService(service), kind: 'mono' },
          unfamiliar
            ? { label: 'Runs from', value: issuer, kind: 'mono', note: "Not GitHub's or GitLab's own: whoever runs this host can sign in as the account. Approve only if it is yours.", warn: true }
            : { label: 'Runs from', value: issuer ?? `${profile}'s own issuer` },
          ...claimLines(claims, names),
          ...(label === undefined ? [] : [{ label: 'The app calls it', value: label }]),
        ];
      },
      apply: async (api, { service, profile, issuer, claims, label }) => {
        const made = await api.bindings.create(serviceMember(service), { profile, issuer: issuer ?? null, claims, label: label ?? null });
        return { result: { service: shownService(service), binding: made.binding.id }, text: `CI runs that match are trusted as ${shownService(service)}.` };
      },
    },
  }),
  changeTool({
    name: 'untrust_workload',
    needs: 'instance',
    title: 'Stop trusting a CI workload',
    description: `Remove one of a service account's trust bindings, by the ID describe_member lists. ${approved}`,
    scope: 'manage-access',
    idempotent: true,
    destructive: true,
    input: z.object({ service, id: z.string().uuid() }).strict(),
    names: ({ service }) => [serviceMember(service)],
    change: {
      summary: ({ service }) => `stop trusting a CI workload as ${shownService(service)}`,
      check: instanceOnly,
      preview: async (api, { service, id }) => {
        const binding = (await api.bindings.list(serviceMember(service))).bindings.find((entry) => entry.id === id);
        return [
          { label: 'Service account', value: shownService(service), kind: 'mono' },
          ...(binding === undefined
            ? [{ label: 'Binding', value: `${id}, which it does not hold` }]
            : [
                { label: 'Runs from', value: binding.issuer },
                ...Object.entries(binding.claims).map(([claim, value]) => ({ label: claim, value: claimValues(value).join(', '), kind: 'mono' as const })),
              ]),
        ];
      },
      apply: async (api, { service, id }) => {
        await api.bindings.remove(serviceMember(service), id);
        return { result: { service: shownService(service), id, removed: true }, text: 'The binding is removed: those CI runs are refused from now on.' };
      },
    },
  }),
];

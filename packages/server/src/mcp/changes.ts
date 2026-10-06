// The tools that change coffre (docs/design/mcp.md, sections 6 and 7). None
// changes anything when it is called: it asks for an approval, which its
// person reads and decides on coffre's own page, and Approve makes the
// change there and then, as the person, through the connection. So each is
// four plain functions over the API: a sentence for the prompt, a check as
// the connection before asking, what the page shows, and the change itself.
// No tool takes a value: the person types one on the page, or coffre makes it.
import { randomBytes } from 'node:crypto';

import { apiMember, CoffreError, shownMember, type CoffreClient, type RouteInput } from '@coffre/client';
import { ROLE_NAMES, type Permission } from '@coffre/core/access';
import { WORKLOAD_PROFILES } from '@coffre/core/identity';
import type { McpScope } from '@coffre/core/mcp';
import { secretKey, slug } from '@coffre/core/schemas';
import { z } from 'zod';

import type { Tool, ToolContext } from './tools.ts';

/** A line of what the approval page shows: a label, and what it is. */
export type Detail = { label: string; value: string; kind?: 'mono' | 'time' };

/** What a change answered, once made: what the client reads, and what only the page shows, once. */
export type Applied = { result: Record<string, unknown>; text: string; shown?: Detail[] };

/** What the page asks the person for, beyond Approve: the value, for `request_secret_value`. */
export type Ask = { value: { label: string; note: string } };

export type Change<I extends z.ZodObject = z.ZodObject> = {
  /** What it does, in a phrase from its arguments alone: the client's prompt and the page's title. */
  summary: (args: z.infer<I>) => string;
  /** Before asking, as the connection: a call the person could not make fails here, not on the page. */
  check?: (ctx: ToolContext, args: z.infer<I>) => Promise<void>;
  /** What the page shows, read as the person when they open it: what the change replaces. */
  preview: (api: CoffreClient, args: z.infer<I>) => Promise<Detail[]>;
  asks?: Ask;
  /**
   * A reveal: the page shows the person a value on Approve, which never goes
   * to the client. Its API call needs `read-values`, which the connection
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

/** A secret's current version, for the page: who set it and when, or that there is none yet. */
async function current(api: CoffreClient, path: string): Promise<Detail[]> {
  try {
    const { versions, archived } = await api.secrets.history(path);
    const now = versions.find((version) => version.current);
    if (now === undefined) return [{ label: 'Now', value: 'no value yet' }];
    return [
      { label: 'Now', value: `version ${now.version}${archived ? ', archived' : ''}, set by ${shownMember(now.createdBy)}` },
      { label: 'Set', value: now.createdAt, kind: 'time' },
    ];
  } catch (error) {
    if (error instanceof CoffreError && error.status === 404) return [{ label: 'Now', value: 'a new key: there is none yet' }];
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

const approved = 'Nothing changes until the person approves it on coffre.';

function secretTool<I extends z.ZodObject>(definition: Omit<ChangeTool<I>, 'scope' | 'names'> & { scope?: McpScope }): Tool {
  return changeTool({ scope: 'write', names: (args: { secret: string }) => [args.secret], ...definition } as ChangeTool<I>);
}

function archiving(archived: boolean): Tool {
  return secretTool({
    name: archived ? 'archive_secret' : 'unarchive_secret',
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
        ...(await current(api, secret)),
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

/**
 * Showing a value to the person, on coffre's page, through an approval like
 * a change's: Browse, since the value never reaches the client.
 */
export const SHOW_VALUE: Tool = changeTool({
  name: 'show_secret_value',
  title: "Show a secret's value to the person",
  description:
    "Show the person a secret's value on coffre's own page, after they press Reveal there. The value is never sent to you or this conversation: use this when the person wants to see a value; read_secret_values is the one that sends values to you.",
  scope: 'browse',
  readOnly: true,
  idempotent: true,
  destructive: false,
  input: z.object({ secret }).strict(),
  names: ({ secret }) => [secret],
  change: {
    summary: ({ secret }) => `show you the value of ${secret}`,
    check: async ({ api }, { secret }) => needs(api, splitSecret(secret).environment, 'secret.read'),
    preview: async (api, { secret }) => [{ label: 'Secret', value: secret, kind: 'mono' }, ...(await current(api, secret))],
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
    title: 'Ask the person to set a value',
    description: `Set a secret to a value the person types on coffre's page: neither you nor this conversation ever see it. Use it whenever a value is needed; never ask for one in the conversation. ${approved}`,
    idempotent: false,
    destructive: true,
    input: z.object({ secret, note: z.string().trim().min(1).max(500).optional().describe('What the value is for, shown to the person on the page') }).strict(),
    change: {
      summary: ({ secret }) => `set ${secret} to a value you type on coffre`,
      check: async ({ api }, { secret }) => needs(api, splitSecret(secret).environment, 'secret.write'),
      preview: async (api, { secret, note }) => [
        { label: 'Secret', value: secret, kind: 'mono' },
        ...(await current(api, secret)),
        ...(note === undefined ? [] : [{ label: 'The app says', value: note }]),
      ],
      asks: { value: { label: 'Value', note: 'It goes to coffre only: the app never sees it.' } },
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
      preview: async (api, { secret, length, alphabet = 'base64url' }) => [
        { label: 'Secret', value: secret, kind: 'mono' },
        ...(await current(api, secret)),
        { label: 'New value', value: `${length ?? ALPHABETS[alphabet].length} random ${alphabet} characters, made by coffre: nobody sees it, and earlier versions stay restorable` },
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
        ...(await current(api, secret)),
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
    title: 'Restore a version',
    description: `Make an earlier version of a secret current again, as a new version: secret_history lists them. ${approved}`,
    idempotent: false,
    destructive: true,
    input: z.object({ secret, version: z.number().int().positive() }).strict(),
    change: {
      summary: ({ secret, version }) => `restore ${secret} to version ${version}`,
      check: async ({ api }, { secret }) => needs(api, splitSecret(secret).environment, 'secret.write'),
      preview: async (api, { secret, version }) => {
        const { versions } = await api.secrets.history(secret);
        const old = versions.find((entry) => entry.version === version);
        return [
          { label: 'Secret', value: secret, kind: 'mono' },
          ...(await current(api, secret)),
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
    title: 'Create a project',
    description: `Create a project, with no environments yet. Instance owners only. ${approved}`,
    scope: 'write',
    idempotent: true,
    destructive: false,
    input: z.object({ project: slug.describe('The project slug: market'), name }).strict(),
    names: ({ project }) => [project],
    change: {
      summary: ({ project, name }) => `create the project ${project} (${name})`,
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
    title: 'Create an environment',
    description: `Create an environment in a project, with no secrets yet. ${approved}`,
    scope: 'write',
    idempotent: true,
    destructive: false,
    input: z.object({ environment, name }).strict(),
    names: ({ environment }) => [environment],
    change: {
      summary: ({ environment, name }) => `create the environment ${environment} (${name})`,
      check: async (_ctx, { environment }) => void splitEnvironment(environment),
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
      preview: async (api, { member, changes }) => {
        const named = apiMember(member);
        const held = (await api.members.list()).members.find((entry) => entry.member === named)?.grants ?? [];
        return [
          { label: 'Member', value: shownMember(named), kind: 'mono' },
          ...Object.entries(changes).map(([place, to]) => {
            const now = held.find((grant) => (grant.environment === null ? grant.project : `${grant.project}/${grant.environment}`) === place);
            return { label: place, value: `${now?.role ?? 'nothing'} → ${shownAccess(to)}` };
          }),
        ];
      },
      apply: async (api, { member, changes }) => {
        const named = apiMember(member);
        const { changes: done } = await api.access.set(named, changes as RouteInput<'PATCH /access/:member'>);
        return { result: { member: shownMember(named), changes: done }, text: `${shownMember(named)}'s access is changed.` };
      },
    },
  }),
  changeTool({
    name: 'admit_member',
    title: 'Admit a member',
    description: `Admit a person, or a service account, as a member, with no access until granted some. ${approved}`,
    scope: 'manage-access',
    idempotent: true,
    destructive: false,
    input: z.object({ member, owner: z.boolean().optional().describe('An instance owner: every project, every member') }).strict(),
    names: ({ member }) => [apiMember(member)],
    change: {
      summary: ({ member, owner }) => `admit ${shownMember(apiMember(member))}${owner === true ? ' as an instance owner' : ''}`,
      preview: async (_api, { member, owner }) => [
        { label: 'Member', value: shownMember(apiMember(member)), kind: 'mono' },
        { label: 'As', value: owner === true ? 'an instance owner: every project, every member' : 'a member, with no access until granted some' },
      ],
      apply: async (api, { member, owner }) => {
        const made = await api.members.add(apiMember(member), owner === undefined ? {} : { owner });
        return {
          result: { member: shownMember(made.member), instanceRole: made.instanceRole, created: made.created },
          text: made.created ? `${shownMember(made.member)} is a member.` : `${shownMember(made.member)} was a member already, as ${made.instanceRole}.`,
        };
      },
    },
  }),
  changeTool({
    name: 'offboard_member',
    title: 'Offboard a member',
    description: `Remove a member: their grants, sessions, tokens and linked accounts end, and the answer lists the secrets they read or wrote, to rotate. ${approved}`,
    scope: 'manage-access',
    idempotent: true,
    destructive: true,
    input: z.object({ member }).strict(),
    names: ({ member }) => [apiMember(member)],
    change: {
      summary: ({ member }) => `offboard ${shownMember(apiMember(member))}`,
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
    title: 'Issue a service token',
    description: `Issue a bearer token for a service account. coffre shows the token to the person on its page, once; it never reaches you. ${approved}`,
    scope: 'manage-access',
    idempotent: false,
    destructive: false,
    input: z.object({ service, label: z.string().trim().min(1).max(120).optional(), expiresInDays: z.number().int().min(1).max(366) }).strict(),
    names: ({ service }) => [serviceMember(service)],
    change: {
      summary: ({ service, expiresInDays }) => `issue a token for ${shownService(service)}, good for ${expiresInDays} days`,
      preview: async (_api, { service, label, expiresInDays }) => [
        { label: 'Service account', value: shownService(service), kind: 'mono' },
        ...(label === undefined ? [] : [{ label: 'Label', value: label }]),
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
    title: 'Revoke a service token',
    description: `Revoke one of a service account's tokens, by the ID describe_member lists. ${approved}`,
    scope: 'manage-access',
    idempotent: true,
    destructive: true,
    input: z.object({ service, id: z.string().uuid() }).strict(),
    names: ({ service }) => [serviceMember(service)],
    change: {
      summary: ({ service }) => `revoke a token of ${shownService(service)}`,
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
    title: 'Trust a CI workload',
    description: `Let CI runs whose ID token has these claims sign in as a service account, with no stored token. ${approved}`,
    scope: 'manage-access',
    idempotent: false,
    destructive: false,
    input: z
      .object({
        service,
        profile: z.enum(WORKLOAD_PROFILES),
        issuer: z.string().max(400).optional().describe("The issuer's URL, for a custom profile"),
        claims: z.record(z.string().max(64), z.string().max(1024)).describe('The ID token claims a run must carry, such as repository_id and ref'),
        label: z.string().trim().min(1).max(120).optional(),
      })
      .strict(),
    names: ({ service }) => [serviceMember(service)],
    change: {
      summary: ({ service, profile }) => `let ${profile} CI runs sign in as ${shownService(service)}`,
      // The binding is checked, and its issuer asked where its keys are, before anyone is asked to approve it.
      check: async ({ api }, { service, profile, issuer, claims, label }) =>
        void (await api.bindings.preview(serviceMember(service), { profile, issuer: issuer ?? null, claims, label: label ?? null })),
      preview: async (_api, { service, profile, issuer, claims, label }) => [
        { label: 'Service account', value: shownService(service), kind: 'mono' },
        { label: 'Runs from', value: issuer ?? `${profile}'s own issuer` },
        ...Object.entries(claims).map(([claim, value]) => ({ label: claim, value, kind: 'mono' as const })),
        ...(label === undefined ? [] : [{ label: 'Label', value: label }]),
      ],
      apply: async (api, { service, profile, issuer, claims, label }) => {
        const made = await api.bindings.create(serviceMember(service), { profile, issuer: issuer ?? null, claims, label: label ?? null });
        return { result: { service: shownService(service), binding: made.binding.id }, text: `CI runs that match are trusted as ${shownService(service)}.` };
      },
    },
  }),
  changeTool({
    name: 'untrust_workload',
    title: 'Stop trusting a CI workload',
    description: `Remove one of a service account's trust bindings, by the ID describe_member lists. ${approved}`,
    scope: 'manage-access',
    idempotent: true,
    destructive: true,
    input: z.object({ service, id: z.string().uuid() }).strict(),
    names: ({ service }) => [serviceMember(service)],
    change: {
      summary: ({ service }) => `stop trusting a CI workload as ${shownService(service)}`,
      preview: async (api, { service, id }) => {
        const binding = (await api.bindings.list(serviceMember(service))).bindings.find((entry) => entry.id === id);
        return [
          { label: 'Service account', value: shownService(service), kind: 'mono' },
          ...(binding === undefined
            ? [{ label: 'Binding', value: `${id}, which it does not hold` }]
            : [{ label: 'Runs from', value: binding.issuer }, ...Object.entries(binding.claims).map(([claim, value]) => ({ label: claim, value, kind: 'mono' as const }))]),
        ];
      },
      apply: async (api, { service, id }) => {
        await api.bindings.remove(serviceMember(service), id);
        return { result: { service: shownService(service), id, removed: true }, text: 'The binding is removed: those CI runs are refused from now on.' };
      },
    },
  }),
];

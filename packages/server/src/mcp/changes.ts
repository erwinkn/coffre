// The tools that change coffre, or show the person a value (docs/design/mcp.md,
// sections 6 and 7; docs/design/0.16.md, "An MCP client's changes"). None does
// anything when it is called: it asks for an approval, which its person reads
// and decides on coffre's own page, and Approve makes the change there and
// then, on the person's browser session, the connection named (`via`). So each
// is a few plain functions over the API's own handlers, in process: a phrase
// for the prompt, a check as the connection before asking, what the page shows,
// and the change itself. No tool takes a value: the person types one on the page.
import { shownMember } from '@coffre/client';
import type { Permission } from '@coffre/core/access';
import type { KeyWrite, Replaces } from '@coffre/core/vault';
import { encodedLength, formatRecipe, MIN_BYTES, randomValue, type Encoding, type Generation } from '@coffre/core/recipe';
import { secretKey, slug } from '@coffre/core/schemas';
import { z } from 'zod';

import type { ApiContext } from '../api/context.ts';
import { changed } from '../api/change.ts';
import { badRequest, conflict, forbidden } from '../api/errors.ts';
import { runRoute } from '../api/router.ts';
import type { WorkloadTransport } from '../workloads/transport.ts';
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

/** What a change made shows the person on the page, once, and never the client: a value shown. */
export type Applied = { shown?: Detail[] };

/** What the page asks the person for, beyond Approve: the value, for `request_secret_value`. */
export type Ask = { value: { label: string; note: string } };

/**
 * A tool's change. The page's functions run on the page's request: the
 * person's browser session, never the connection's token.
 */
export type Change<I extends z.ZodObject = z.ZodObject> = {
  /** What it does, in a phrase from its arguments alone: the client's prompt and the page's title. */
  summary: (args: z.infer<I>) => string;
  /** The place it is about, `project/environment/KEY` or less, which the vault's entry of the ask names, or none: never its other arguments. */
  place: (args: z.infer<I>) => string | null;
  /** What the client hears once the person approved it, at `at`, from its arguments alone: the vault keeps no answer of the change's. */
  done: (args: z.infer<I>, at: Date) => { text: string; result: Record<string, unknown> };
  /** Before asking, as the connection: a call the person could not make fails here, not on the page. */
  check?: (tool: ToolContext, args: z.infer<I>) => Promise<void>;
  /**
   * What the change replaces, read as the person: its lines go into the
   * page's preview, and Approve reads it again and is refused if its state
   * differs, so what is replaced is what the person read.
   */
  replaces?: (ctx: ApiContext, args: z.infer<I>) => Promise<Replaced>;
  /** What the page shows, read as the person when they open it, with `replaces`' lines, `replaced`, where the tool has them. */
  preview: (ctx: ApiContext, args: z.infer<I>, viewing: Viewing, replaced: Detail[]) => Promise<Detail[]>;
  asks?: (viewing: Viewing) => Ask;
  /** A reveal: the page shows the person a value on Approve, which never goes to the client, so the connection needs no Reveal values. */
  reveal?: true;
  /**
   * The change, on the person's session with the connection and the
   * approval named (`ctx.via`), when they approve it, which the vault
   * marks approved in the change's own write: with the value they typed, and what
   * it replaces as Approve read it again and found it as the page showed it.
   */
  apply: (ctx: ApiContext, args: z.infer<I>, given: { value?: string; replaced?: Replaced }) => Promise<Applied>;
};

export const secret = z.string().min(1).max(300).describe('A secret, as project/environment/KEY: market/prod/STRIPE_KEY');

/** A secret's path as the vault's entry names it. */
export const placeOf = (path: string) => {
  const { project, environment, key } = splitSecret(path);
  return `${project}/${environment}/${key}`;
};

/** `market/prod/KEY` as the route's parameters, or why not. */
export function splitSecret(path: string): { project: string; environment: string; key: string } {
  const [project, environment, key, ...rest] = path.replace(/^\/+|\/+$/g, '').split('/');
  if (rest.length > 0 || !slug.safeParse(project).success || !slug.safeParse(environment).success || !secretKey.safeParse(key).success) {
    throw badRequest(`"${path}" is not a secret: name one as project/environment/KEY`);
  }
  return { project: project!, environment: environment!, key: key! };
}

/** Refuse now, as the API would on Approve, when the person lacks a permission at the secret's environment: one statement, the listing's. */
export async function needs({ ctx }: ToolContext, path: string, permission: Permission): Promise<void> {
  const { project, environment } = splitSecret(path);
  const { permissions } = await runRoute('GET /secrets/:project/:environment', { project, environment }, undefined, ctx);
  if (!(permissions as readonly string[]).includes(permission)) throw forbidden(`you need ${permission} on ${project}/${environment}`);
}

/**
 * What a key reads now, as the environment's listing shows it to the
 * person: its version's id, which no other version of it or of any key
 * shares, or that it is new, a reference or archived. A key renamed and
 * another made under its name, at the same version number, is another
 * state. Approve changes the key over what this read found (`replacing`),
 * so a change between Approve's read and the vault's refuses it too.
 */
type Held = { absent: true } | { versionId: string | null; reference: { path: string; sourceId: string } | null; archived: boolean; parent: string | null };

export async function current(ctx: ApiContext, path: string): Promise<Replaced & { state: Held }> {
  const { project, environment, key } = splitSecret(path);
  const { keys } = await runRoute('GET /secrets/:project/:environment', { project, environment }, undefined, ctx);
  const listed = keys.find((row) => row.key === key);
  if (listed === undefined) return { state: { absent: true }, details: [{ label: 'Now', value: 'a new key: there is none yet' }] };
  const state: Held = { versionId: listed.versionId, reference: listed.reference === null ? null : { path: listed.reference.source, sourceId: listed.reference.sourceId }, archived: listed.archived, parent: listed.parent === null ? null : `${listed.parent.from} ${listed.parent.state}` };
  const inherited = listed.parent !== null && listed.parent.state !== 'overridden' ? `, from ${listed.parent.from}` : '';
  const now = listed.reference !== null ? `a reference to ${listed.reference.source}`
    : listed.version === null ? `no value${inherited}`
      : `version ${listed.version}${listed.archived ? ', archived' : ''}${inherited}${listed.updatedBy === null ? '' : `, set by ${shownMember(listed.updatedBy)}`}`;
  return { state, details: [{ label: 'Now', value: now }, ...(listed.updatedAt === null ? [] : [{ label: 'Set', value: new Date(listed.updatedAt).toISOString(), kind: 'time' as const }])] };
}

/**
 * What a key read when Approve read it again, as the page showed it, said
 * as the vault holds a change to it (`replaces`): the reference's source,
 * the version's id, or nothing, for a key that is not there or archived,
 * which reads nothing here (in a fork, a listing shows what a parent passes
 * down in its place). Anything else by the time the vault writes is
 * `stale`, and nothing is changed.
 */
function replacing(replaced: Replaced | undefined): Replaces {
  const held = replaced?.state as Held | undefined;
  if (held === undefined) throw conflict('coffre could not read what this replaces: open the approval again');
  return 'absent' in held || held.archived ? null : held.reference !== null ? { source: held.reference.sourceId } : held.versionId;
}

/**
 * A key's change made over what Approve read (`replacing`): the API's
 * routes take no `replaces` but a value's, so the change is made here, as
 * theirs, in one call to the vault.
 */
async function written(ctx: ApiContext, secret: string, write: Omit<KeyWrite, 'key' | 'replaces' | 'inherit'>, replaced: Replaced | undefined): Promise<void> {
  const { project, environment, key } = splitSecret(secret);
  await changed(ctx, { op: 'secret.write', project, environment, mine: false, keys: [{ key, ...write, replaces: replacing(replaced) } as KeyWrite] }, secret);
}

/** What every change tool answers: where its approval stands, and once made, what the change answered. */
const CHANGE_OUTPUT = {
  type: 'object',
  properties: {
    status: { type: 'string', enum: ['pending', 'approved', 'denied', 'expired'] },
    message: { type: 'string' },
    approval: { type: 'object', properties: { id: { type: 'string' }, url: { type: 'string' }, expiresAt: { type: 'string' } } },
    result: { type: 'object' },
  },
  required: ['status', 'approval'],
};

export type ChangeTool<I extends z.ZodObject> = Omit<Tool<I>, 'readOnly' | 'output' | 'run' | 'change'> & { change: Change<I>; readOnly?: boolean };

/**
 * The approval a call names, by its id, to hear how it ended: what a client
 * that cannot hold `requestState` sends back. Never part of the call's
 * digest: the call is the other arguments.
 */
const APPROVAL = z
  .string()
  .regex(/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/)
  .optional()
  .describe("The approval's id from this tool's earlier answer, to hear what became of it: call again with the same arguments and this. Leave it out to ask anew.");

export function changeTool<I extends z.ZodObject>(definition: ChangeTool<I>): Tool {
  return { readOnly: false, ...definition, input: definition.input.extend({ approval: APPROVAL }), output: CHANGE_OUTPUT } as unknown as Tool;
}

export const approved = 'Nothing changes until the person approves it on coffre.';

/** What the page says of an app that holds Reveal values, beside a value it would otherwise never see. */
export const READABLE: Detail = { label: 'The app', value: 'holds Reveal values: it can read values you can read, this one included' };

/**
 * Showing a value to the person, on coffre's page, through an approval like
 * a change's: Read, since the value never reaches the client. The page's
 * request reads it, on the person's session, and the page alone shows it:
 * neither the stored outcome nor the client's answer holds it.
 */
const SHOW_VALUE = changeTool({
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
  change: {
    summary: ({ secret }) => `show you the value of ${secret}`,
    place: ({ secret }) => placeOf(secret),
    done: ({ secret }, at) => {
      const shownAt = at.toISOString().replace(/\.\d+Z$/, 'Z');
      return { result: { secret, shownAt }, text: `The value of ${secret} was shown to the person on coffre at ${shownAt}. It was not sent here.` };
    },
    check: async (tool, { secret }) => needs(tool, secret, 'secret.read'),
    preview: async (ctx, { secret }) => [{ label: 'Secret', value: secret, kind: 'mono' }, ...(await current(ctx, secret)).details],
    reveal: true,
    apply: async (ctx, { secret }) => {
      const { key } = splitSecret(secret);
      const { values } = await runRoute('POST /reveals', {}, { path: secret }, ctx);
      return { shown: [{ label: key, value: values[key] ?? '', kind: 'mono' }] };
    },
  },
});

/** Setting a secret to a value the person types on the page: the one way a value reaches coffre through MCP. */
const REQUEST_VALUE = changeTool({
  name: 'request_secret_value',
  needs: 'secret.write',
  title: 'Ask the person to set a value',
  description: `Set a secret to a value the person types on coffre's page: neither you nor this conversation ever see it. Use it whenever a value is needed; never ask for one in the conversation. ${approved}`,
  scope: 'write',
  idempotent: false,
  destructive: true,
  input: z.object({ secret, note: z.string().trim().min(1).max(500).optional().describe('What the value is for, shown to the person on the page') }).strict(),
  change: {
    summary: ({ secret }) => `set ${secret} to a value you type on coffre`,
    place: ({ secret }) => placeOf(secret),
    done: ({ secret }) => ({ result: { secret }, text: `${secret} is set to the value the person typed on coffre. It went to coffre only.` }),
    check: async (tool, { secret }) => needs(tool, secret, 'secret.write'),
    replaces: async (ctx, { secret }) => current(ctx, secret),
    preview: async (_ctx, { secret, note }, { reveals }, replaced) => [
      { label: 'Secret', value: secret, kind: 'mono' },
      ...replaced,
      ...(note === undefined ? [] : [{ label: 'The app says', value: note }]),
      ...(reveals ? [READABLE] : []),
    ],
    asks: ({ reveals }) => ({ value: { label: 'Value', note: reveals ? 'It goes to coffre, and the app can read it.' : 'It goes to coffre only: the app never sees it.' } }),
    apply: async (ctx, { secret }, { value, replaced }) => {
      if (value === undefined) throw badRequest('type the value to set');
      await written(ctx, secret, { value }, replaced);
      return {};
    },
  },
});

/** The alphabets `generate_secret_value` draws from, each a recipe's encoding, and how long a value is in each unless asked: 32 bytes' worth. */
const ALPHABETS = { base64url: 'base64url', hex: 'hex', alphanumeric: 'base62' } as const satisfies Record<string, Encoding>;
type Alphabet = keyof typeof ALPHABETS;
const lengthOf = (alphabet: Alphabet, length: number | undefined) => length ?? encodedLength(ALPHABETS[alphabet], 32);

/**
 * A random value of `length` characters of an alphabet, each uniform: the
 * value of the recipe of as many bytes as encode to exactly that length,
 * which the key keeps, so that Regenerate makes the next one alike; or,
 * where no number of bytes does (base64url's 17 characters), the first
 * `length` characters of the shortest recipe's value longer, each whole,
 * and no recipe kept.
 */
export function randomOf(alphabet: Alphabet, length?: number): { value: string; generated?: Generation } {
  const encoding = ALPHABETS[alphabet];
  const wanted = lengthOf(alphabet, length);
  let bytes = MIN_BYTES;
  while (encodedLength(encoding, bytes) < wanted) bytes += 1;
  const value = randomValue(encoding, bytes);
  return encodedLength(encoding, bytes) === wanted ? { value, generated: { recipe: formatRecipe({ kind: 'random', encoding, bytes }) } } : { value: value.slice(0, wanted) };
}

/** A key's tool, about one secret: Write unless said, and its place the secret's. */
function secretTool<I extends z.ZodObject<{ secret: typeof secret }>>(definition: Omit<ChangeTool<I>, 'scope' | 'change'> & { scope?: Tool['scope']; change: Omit<Change<I>, 'place'> }): Tool {
  return changeTool({ scope: 'write', ...definition, change: { place: ({ secret }: { secret: string }) => placeOf(secret), ...definition.change } } as ChangeTool<I>);
}

const GENERATE_VALUE = secretTool({
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
    done: ({ secret }) => ({ result: { secret }, text: `${secret} is set to a new random value. Nobody saw it.` }),
    check: async (tool, { secret }) => needs(tool, secret, 'secret.write'),
    replaces: async (ctx, { secret }) => current(ctx, secret),
    preview: async (_ctx, { secret, length, alphabet = 'base64url' }, { reveals }, replaced) => [
      { label: 'Secret', value: secret, kind: 'mono' },
      ...replaced,
      { label: 'New value', value: `${lengthOf(alphabet, length)} random ${alphabet} characters, made by coffre${reveals ? ',' : ': nobody sees it,'} and earlier versions stay restorable` },
      ...(reveals ? [READABLE] : []),
    ],
    apply: async (ctx, { secret, length, alphabet = 'base64url' }, { replaced }) => {
      await written(ctx, secret, randomOf(alphabet, length), replaced);
      return {};
    },
  },
});

const RENAME = secretTool({
  name: 'rename_secret',
  needs: 'secret.write',
  title: 'Rename a secret',
  description: `Rename a secret's key, keeping its versions. Whatever reads the old name stops finding it. ${approved}`,
  idempotent: true,
  destructive: true,
  input: z.object({ secret, newKey: secretKey.describe('The new key: letters, digits and underscores') }).strict(),
  change: {
    summary: ({ secret, newKey }) => `rename ${secret} to ${newKey}`,
    done: ({ secret, newKey }) => {
      const { project, environment } = splitSecret(secret);
      const renamed = `${project}/${environment}/${newKey}`;
      return { result: { secret: renamed }, text: `${secret} is now ${renamed}. Whatever reads the old name must read the new one.` };
    },
    check: async (tool, { secret }) => needs(tool, secret, 'secret.write'),
    replaces: async (ctx, { secret }) => current(ctx, secret),
    preview: async (_ctx, { secret, newKey }, _viewing, replaced) => {
      const { project, environment } = splitSecret(secret);
      return [{ label: 'Secret', value: secret, kind: 'mono' }, { label: 'Becomes', value: `${project}/${environment}/${newKey}`, kind: 'mono' }, ...replaced];
    },
    // PATCH's rename, of the key the page showed: another made under its name since is `stale`.
    apply: async (ctx, { secret, newKey }, { replaced }) => {
      const { project, environment, key } = splitSecret(secret);
      await changed(ctx, { op: 'secret.rename', project, environment, mine: false, key, to: newKey, replaces: replacing(replaced) }, secret);
      return {};
    },
  },
});

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
      done: ({ secret }) => ({ result: { secret, archived }, text: `${secret} is ${archived ? 'archived' : 'live again'}.` }),
      check: async (tool, { secret }) => needs(tool, secret, 'secret.archive'),
      replaces: async (ctx, { secret }) => current(ctx, secret),
      preview: async (_ctx, { secret }, _viewing, replaced) => [
        { label: 'Secret', value: secret, kind: 'mono' },
        ...replaced,
        { label: 'Then', value: archived ? 'not set by coffre run or exports; every version stays restorable' : 'set again by coffre run and exports' },
      ],
      // PATCH's archiving, or return, of the key the page showed.
      apply: async (ctx, { secret }, { replaced }) => {
        await written(ctx, secret, { archived }, replaced);
        return {};
      },
    },
  });
}

const RESTORE = secretTool({
  name: 'restore_secret_version',
  needs: 'secret.write',
  title: 'Restore a version',
  description: `Make an earlier version of a secret current again, as a new version: secret_history lists them. ${approved}`,
  idempotent: false,
  destructive: true,
  input: z.object({ secret, version: z.number().int().positive().max(2 ** 31 - 1) }).strict(),
  change: {
    summary: ({ secret, version }) => `restore ${secret} to version ${version}`,
    done: ({ secret, version }) => ({ result: { secret, restored: version }, text: `${secret} holds version ${version}'s value again, as a new version.` }),
    check: async (tool, { secret }) => needs(tool, secret, 'secret.write'),
    replaces: async (ctx, { secret }) => current(ctx, secret),
    preview: async (ctx, { secret, version }, _viewing, replaced) => {
      const { versions } = await runRoute('GET /secrets/:project/:environment/:key/versions', splitSecret(secret), {}, ctx);
      const old = versions.find((entry) => entry.version === version);
      return [
        { label: 'Secret', value: secret, kind: 'mono' },
        ...replaced,
        { label: 'Restores', value: old === undefined ? `version ${version}, which it does not have` : `version ${version}, set by ${shownMember(old.createdBy)}, as a new version` },
        ...(old === undefined ? [] : [{ label: 'That version set', value: old.createdAt, kind: 'time' as const }]),
      ];
    },
    // The restore route's change, over the version the page showed: a rotation since is `stale`.
    apply: async (ctx, { secret, version }, { replaced }) => {
      await written(ctx, secret, { restore: version }, replaced);
      return {};
    },
  },
});

/** The tools about one secret, each through an approval: show a value to the person, then Write. */
export const SECRET_TOOLS: readonly Tool[] = [SHOW_VALUE, REQUEST_VALUE, GENERATE_VALUE, RENAME, archiving(true), archiving(false), RESTORE];

// The tools MCP clients call (docs/design/mcp.md, section 6; docs/design/0.16.md,
// "`/mcp`"): each runs the API's own handlers in process, as its connection,
// with the vault's answer about it, so a tool can do no more than its person
// could with the CLI, and the vault holds each use to the connection's own
// rules: a value only with `reveal`, no change at all. Read, here: what is
// there, and values only to a connection with Reveal values; the changes,
// which wait for the person's approval, are in changes.ts.
import { apiMember } from '@coffre/client';
import { PERMISSIONS, runsInstance, type Permission } from '@coffre/core/access';
import type { McpScope } from '@coffre/core/mcp';
import type { Called, Presented } from '@coffre/core/vault';
import { z } from 'zod';

import { canAnywhere } from '../api/caller.ts';
import type { ApiContext } from '../api/context.ts';
import { badRequest } from '../api/errors.ts';
import { runRoute } from '../api/router.ts';
import { CHANGE_TOOLS, type Change } from './changes.ts';

/** What a tool answers: its structured result, and the text a model reads. */
export type ToolResult = { structured: Record<string, unknown>; text?: string };

/** The connection a call comes on: what its request showed, the vault's answer about its access token, and the connection and scopes that answer gave. */
export type Connection = { called: Called; id: string; scopes: McpScope[]; shown: Presented };

/** What a tool runs with: the API's context as the connection, and the connection. */
export type ToolContext = { ctx: ApiContext; connection: Connection };

export type Tool<I extends z.ZodObject = z.ZodObject> = {
  name: string;
  title: string;
  description: string;
  scope: McpScope;
  /** Who could ever use it, by their roles (`usable`): `tools/list` leaves it out for anyone else. */
  needs: Need;
  /** The hints, for the client: coffre does not rely on them. */
  readOnly: boolean;
  idempotent: boolean;
  destructive: boolean;
  input: I;
  /** The result's top-level fields, which `structuredContent` holds. */
  output: Record<string, unknown>;
  /** A Read tool's call, made there and then. */
  run?: (tool: ToolContext, args: z.infer<I>) => Promise<ToolResult>;
  /** Or a change, or a value shown to the person, which waits for the person's approval on coffre's page (`changes.ts`). */
  change?: Change<I>;
};

const environment = z.string().min(1).max(200).describe('An environment, as project/environment: market/prod');
const secret = z.string().min(1).max(300).describe('A secret, as project/environment/KEY: market/prod/STRIPE_KEY');
const member = z.string().min(1).max(320).describe('A member: user:ada@acme.example, or service:ci-deploy for a service account');

const object = (properties: Record<string, unknown>, required = Object.keys(properties)) => ({ type: 'object', properties, required });
const list = { type: 'array' };

function tool<I extends z.ZodObject>(definition: Tool<I>): Tool {
  return definition as unknown as Tool;
}

/** A path's slash-separated parts, exactly `count` of them, as the route's segments: what each holds, the route checks. */
function split(path: string, count: 2 | 3, shape: string): string[] {
  const parts = path.split('/');
  if (parts.length !== count || parts.some((part) => part === '')) throw badRequest(`${path} is no ${shape}`);
  return parts;
}

/** The Read tools: every one read-only, idempotent, and about this instance only. */
const READ_TOOLS: readonly Tool[] = [
  tool({
    name: 'whoami',
    needs: 'anyone',
    title: 'Who am I',
    description: 'The person this connection acts as, their role, every project and environment they can reach, and what this connection may do.',
    scope: 'read',
    readOnly: true,
    idempotent: true,
    destructive: false,
    input: z.object({}).strict(),
    output: object({ me: { type: 'object' }, connection: { type: 'object' } }),
    run: async ({ ctx, connection }) => ({
      structured: { me: await runRoute('GET /me', {}, undefined, ctx), connection: { id: connection.id, scopes: connection.scopes } },
    }),
  }),
  tool({
    name: 'list_projects',
    needs: 'anyone',
    title: 'List projects',
    description: 'The projects and environments the person can see, with their folders and whether they are archived.',
    scope: 'read',
    readOnly: true,
    idempotent: true,
    destructive: false,
    input: z.object({}).strict(),
    output: object({ projects: list }),
    run: async ({ ctx }) => ({ structured: await runRoute('GET /projects', {}, undefined, ctx) }),
  }),
  tool({
    name: 'list_secrets',
    // Listing takes use, which every role that reads holds too: a Contributor lists what it never reads.
    needs: 'secret.use',
    title: 'List secrets',
    description: "An environment's keys: each one's version, folder, who last changed it and when (`updatedAt`; a reference's value is its source's), and whether it is a reference to another secret; and `rotateAfterDays`, the days a value may go unchanged before it is due for rotation. In a fork, `parents` names the environments it inherits from, and each key's `parent` says whether it is inherited, overridden or removed, and from where. Never a value.",
    scope: 'read',
    readOnly: true,
    idempotent: true,
    destructive: false,
    input: z.object({ environment }).strict(),
    output: object({ keys: list, permissions: list }),
    run: async ({ ctx }, args) => {
      const [project, environment] = split(args.environment, 2, 'project/environment');
      return { structured: await runRoute('GET /secrets/:project/:environment', { project: project!, environment: environment! }, undefined, ctx) };
    },
  }),
  tool({
    name: 'secret_history',
    // Listing takes use, which every role that reads holds too: a Contributor lists what it never reads.
    needs: 'secret.use',
    title: 'Secret history',
    description: "A secret's versions, newest first: who made each and when. Never a value.",
    scope: 'read',
    readOnly: true,
    idempotent: true,
    destructive: false,
    input: z.object({ secret }).strict(),
    output: object({ versions: list }),
    run: async ({ ctx }, args) => {
      const [project, environment, key] = split(args.secret, 3, 'project/environment/KEY');
      return { structured: await runRoute('GET /secrets/:project/:environment/:key/versions', { project: project!, environment: environment!, key: key! }, {}, ctx) };
    },
  }),
  tool({
    name: 'list_access',
    needs: 'services',
    title: 'List access',
    description: "Who is a member, their instance role and its scope, and their grants: those you manage access for, and the service accounts you manage. Given a place, a project or project/environment, only those who reach it: by a grant there, or by their instance role.",
    scope: 'read',
    readOnly: true,
    idempotent: true,
    destructive: false,
    input: z.object({ place: z.string().min(1).max(200).optional().describe('A project or project/environment: market, market/prod') }).strict(),
    output: object({ members: list }),
    run: async ({ ctx }, { place }) => ({ structured: await runRoute('GET /members', {}, place === undefined ? {} : { path: place }, ctx) }),
  }),
  tool({
    name: 'describe_member',
    needs: 'services',
    title: 'Describe a member',
    description: "What a member holds: their grants, and what they have read. For a service account, also its tokens and the CI workloads it trusts. Those who run the instance describe anyone; anyone else, the service accounts they manage, without what they read.",
    scope: 'read',
    readOnly: true,
    idempotent: true,
    destructive: false,
    input: z.object({ member }).strict(),
    output: object({ member: { type: 'object' } }),
    run: async ({ ctx, connection }, args) => {
      const name = apiMember(args.member);
      const params = { member: name };
      // What it read anywhere is the instance's to know; its manager reads what it holds.
      const report = runsInstance(connection.called.holds) || !name.startsWith('token:') ? await runRoute('GET /members/:member', params, undefined, ctx) : await runRoute('GET /members/:member/access', params, undefined, ctx);
      if (!name.startsWith('token:')) return { structured: { member: report } };
      const { tokens } = await runRoute('GET /members/:member/tokens', params, undefined, ctx);
      // An instance that trusts no workload has no bindings to list.
      const workloads = ctx.auth.mode === 'signin' && ctx.auth.signin.workloads !== null;
      const { bindings } = workloads ? await runRoute('GET /members/:member/bindings', params, undefined, ctx) : { bindings: [] };
      return { structured: { member: report, tokens, bindings } };
    },
  }),
];

/** Values to the model: only with Reveal values, which the person ticked under its warning, and which the vault holds the use to. */
const REVEAL_VALUES = tool({
  name: 'reveal_secret_values',
  needs: 'secret.read',
  title: 'Reveal secret values',
  description: 'Read the values of one secret or of a whole environment into this conversation. Use it only when the person wants you to see the values.',
  scope: 'reveal',
  readOnly: true,
  idempotent: true,
  destructive: false,
  input: z.object({ path: z.string().min(1).max(300).describe('An environment, market/prod, or one secret, market/prod/STRIPE_KEY') }).strict(),
  output: object({ path: { type: 'string' }, values: { type: 'object' }, sensitive: list }),
  run: async ({ ctx }, { path }) => {
    // A whole environment's sensitive values are left out, by name: nobody is handed one.
    const { values, sensitive } = await runRoute('POST /reveals', {}, { path }, ctx);
    const left = sensitive.length === 0 ? '' : `\n\nLeft out, sensitive, which nobody sees and apps use through the credential proxy: ${sensitive.join(', ')}`;
    return {
      structured: { path, values, sensitive },
      text: `These values are now part of this conversation and its history.\n\n${JSON.stringify(values, null, 2)}${left}`,
    };
  },
});

export const TOOLS: readonly Tool[] = [...READ_TOOLS, REVEAL_VALUES, ...CHANGE_TOOLS];

export const TOOL_BY_NAME = new Map(TOOLS.map((entry) => [entry.name, entry]));

/**
 * Who could ever use a tool, by their roles: every member (`anyone`), those
 * who may set up a service
 * account (`services`: who runs the instance, or a person who holds
 * anything anywhere, as the instance's setting allows, which the API
 * applies), or whoever holds a permission somewhere, by a grant or their
 * instance role.
 */
export type Need = 'anyone' | 'services' | Permission;

/**
 * Whether the person's roles, as they are now, let them use `tool`
 * anywhere: what `tools/list` shows them. Their connection's scopes do not
 * count: a tool they lack the scope for stays listed, and its call asks for
 * the scope. Nor is this a check: each call is held to the API's, as ever.
 */
export function usable(called: Called, tool: Tool): boolean {
  const { needs } = tool;
  const person = called.principal.startsWith('user:');
  if (needs === 'anyone') return true;
  if (needs === 'services') return runsInstance(called.holds) || (person && PERMISSIONS.some((permission) => canAnywhere(called, permission)));
  // Reading takes read, or, of a person's own personal config, use of the environment it configures (R8).
  return canAnywhere(called, needs) || (needs === 'secret.read' && person && canAnywhere(called, 'secret.use'));
}

/** A tool as `tools/list` describes it, in either era. */
export function listed(entry: Tool): Record<string, unknown> {
  return {
    name: entry.name,
    title: entry.title,
    description: entry.description,
    inputSchema: z.toJSONSchema(entry.input),
    outputSchema: entry.output,
    annotations: {
      title: entry.title,
      readOnlyHint: entry.readOnly,
      destructiveHint: entry.destructive,
      idempotentHint: entry.idempotent,
      openWorldHint: false,
    },
  };
}

/** What clients pass the model about coffre, once. */
export const INSTRUCTIONS = [
  "coffre keeps this team's secrets. These tools act as the person who connected them, and never beyond their access.",
  'Never ask the person to paste a secret into the conversation.',
  'To use secrets in a command, run it in the person\'s terminal as `coffre run <project>/<env> [<project>/<env> …] -- <command>`, with the CLI signed in: the values go to the process, never the conversation, so avoid commands that print them.',
  'reveal_secret_values puts values into the conversation: use it only when the person wants you to see them.',
].join(' ');

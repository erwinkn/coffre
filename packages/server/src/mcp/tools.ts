// The tools MCP clients call (docs/design/mcp.md, section 6): each is plain
// API calls, as its person, through the same route table, checks and vault
// as a page's render. A tool can do no more than its person could with the
// CLI; the scope it declares, and the API's own table (`ROUTE_SCOPES`), hold
// it to its connection's. Browse, here: what is there, never a value.
import { apiMember, type CoffreClient } from '@coffre/client';
import type { McpScope } from '@coffre/core/mcp';
import { z } from 'zod';

import type { McpConnection } from './service.ts';

/** What a tool answers: its structured result, and the text a model reads. */
export type ToolResult = { structured: Record<string, unknown>; text?: string };

/** What a tool runs with: the API as its person, and where coffre is. */
export type ToolContext = { api: CoffreClient; connection: McpConnection; publicUrl: string };

export type Tool<I extends z.ZodObject = z.ZodObject> = {
  name: string;
  title: string;
  description: string;
  scope: McpScope;
  /** The hints, for the client: coffre does not rely on them. */
  readOnly: boolean;
  idempotent: boolean;
  destructive: boolean;
  input: I;
  /** The result's top-level fields, which `structuredContent` holds. */
  output: Record<string, unknown>;
  /** The places and members the call names, for its audit entry: never a value. */
  names: (args: z.infer<I>) => string[];
  run: (ctx: ToolContext, args: z.infer<I>) => Promise<ToolResult>;
};

const environment = z.string().min(1).max(200).describe('An environment, as project/environment: market/prod');
const secret = z.string().min(1).max(300).describe('A secret, as project/environment/KEY: market/prod/STRIPE_KEY');
const member = z.string().min(1).max(320).describe('A member: user:ada@acme.example, or service:ci-deploy for a service account');

const object = (properties: Record<string, unknown>, required = Object.keys(properties)) => ({ type: 'object', properties, required });
const list = { type: 'array' };

function tool<I extends z.ZodObject>(definition: Tool<I>): Tool {
  return definition as unknown as Tool;
}

/** The Browse tools: every one read-only, idempotent, and about this instance only. */
export const TOOLS: readonly Tool[] = [
  tool({
    name: 'whoami',
    title: 'Who am I',
    description: 'The person this connection acts as, their role, every project and environment they can reach, and what this connection may do.',
    scope: 'browse',
    readOnly: true,
    idempotent: true,
    destructive: false,
    input: z.object({}).strict(),
    output: object({ me: { type: 'object' }, connection: { type: 'object' } }),
    names: () => [],
    run: async ({ api, connection }) => ({
      structured: { me: await api.me(), connection: { client: connection.clientName, scopes: connection.scopes } },
    }),
  }),
  tool({
    name: 'list_projects',
    title: 'List projects',
    description: 'The projects and environments the person can see, with their folders and whether they are archived.',
    scope: 'browse',
    readOnly: true,
    idempotent: true,
    destructive: false,
    input: z.object({}).strict(),
    output: object({ projects: list }),
    names: () => [],
    run: async ({ api }) => ({ structured: await api.projects.list() }),
  }),
  tool({
    name: 'list_secrets',
    title: 'List secrets',
    description: "An environment's keys: each one's version, folder, who last changed it and when, and whether it is a reference to another secret. Never a value.",
    scope: 'browse',
    readOnly: true,
    idempotent: true,
    destructive: false,
    input: z.object({ environment }).strict(),
    output: object({ keys: list, permissions: list }),
    names: ({ environment }) => [environment],
    run: async ({ api }, { environment }) => ({ structured: await api.secrets.list(environment) }),
  }),
  tool({
    name: 'secret_history',
    title: 'Secret history',
    description: "A secret's versions, newest first: who made each and when. Never a value.",
    scope: 'browse',
    readOnly: true,
    idempotent: true,
    destructive: false,
    input: z.object({ secret }).strict(),
    output: object({ versions: list }),
    names: ({ secret }) => [secret],
    run: async ({ api }, { secret }) => ({ structured: await api.secrets.history(secret) }),
  }),
  tool({
    name: 'list_access',
    title: 'List access',
    description: "Who is a member, and their access. Given a place, a project or project/environment, only those who reach it, and through which grant.",
    scope: 'browse',
    readOnly: true,
    idempotent: true,
    destructive: false,
    input: z.object({ place: z.string().min(1).max(200).optional().describe('A project or project/environment: market, market/prod') }).strict(),
    output: object({ members: list }),
    names: ({ place }) => (place === undefined ? [] : [place]),
    run: async ({ api }, { place }) => ({ structured: await api.members.list(place) }),
  }),
  tool({
    name: 'describe_member',
    title: 'Describe a member',
    description: "What a member holds: their grants, and what they have read. For a service account, also its tokens and the CI workloads it trusts.",
    scope: 'browse',
    readOnly: true,
    idempotent: true,
    destructive: false,
    input: z.object({ member }).strict(),
    output: object({ member: { type: 'object' } }),
    names: ({ member }) => [apiMember(member)],
    run: async ({ api }, args) => {
      const name = apiMember(args.member);
      const report = await api.members.get(name);
      if (!name.startsWith('token:')) return { structured: { member: report } };
      const [{ tokens }, { bindings }] = await Promise.all([api.tokens.list(name), api.bindings.list(name)]);
      return { structured: { member: report, tokens, bindings } };
    },
  }),
  tool({
    name: 'read_audit_log',
    title: 'Read the audit log',
    description: 'The audit log, newest first: what was done, by whom, where, allowed or refused. 50 entries a call unless asked; page back with `before`, the oldest seq seen.',
    scope: 'browse',
    readOnly: true,
    idempotent: true,
    destructive: false,
    input: z
      .object({
        path: z.string().min(1).max(300).optional().describe('Only entries about a project, environment or secret'),
        actor: z.string().min(1).max(320).optional().describe('Only entries by this member'),
        decision: z.enum(['allow', 'deny']).optional(),
        before: z.number().int().min(1).optional().describe('Only entries older than this seq'),
        limit: z.number().int().min(1).max(200).optional(),
      })
      .strict(),
    output: object({ entries: list }),
    names: ({ path, actor }) => [...(path === undefined ? [] : [path]), ...(actor === undefined ? [] : [apiMember(actor)])],
    run: async ({ api }, { actor, limit, ...rest }) => ({
      structured: await api.audit.list({ ...rest, ...(actor === undefined ? {} : { actor: apiMember(actor) }), limit: limit ?? 50 }),
    }),
  }),
  tool({
    name: 'run_with_secrets',
    title: 'Run a command with secrets',
    description:
      "How to run a command with an environment's secrets as environment variables, through coffre's CLI, so that no value enters this conversation. Checks the person may read the environment, and names the variables it would set.",
    scope: 'browse',
    readOnly: true,
    idempotent: true,
    destructive: false,
    input: z.object({ environment, command: z.string().min(1).max(2000).optional().describe('The command to run, such as npm test') }).strict(),
    output: object({ environment: { type: 'string' }, keys: list, readable: { type: 'boolean' }, commands: list }),
    names: ({ environment }) => [environment],
    run: async ({ api, publicUrl }, { environment, command }) => {
      const { keys, permissions } = await api.secrets.list(environment);
      const live = keys.filter((key) => !key.archived && key.version !== null).map((key) => key.key);
      const readable = permissions.includes('secret.read');
      const commands = [`coffre login ${publicUrl}`, `coffre run ${environment} -- ${command ?? '<command>'}`];
      const text = readable
        ? [
            `Run it with coffre's CLI. It sets these ${live.length} environment variables for the command only, and none of them enter this conversation:`,
            `  ${live.join(', ') || '(none yet)'}`,
            '',
            `  ${commands[0]}   # once per machine; approve in the browser`,
            `  ${commands[1]}`,
            '',
            'Install the CLI with `npm install -g @coffre/cli`, or prefix each command with `npx @coffre/cli`. Without a shell here, the person runs these themselves.',
          ].join('\n')
        : `The person cannot read ${environment}'s values, so coffre run would be refused: ask someone who manages its access for a grant.`;
      return { structured: { environment, keys: live, readable, commands }, text };
    },
  }),
];

export const TOOL_BY_NAME = new Map(TOOLS.map((entry) => [entry.name, entry]));

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
  'With a shell, give a command its secrets with `coffre run <project>/<environment> -- <command>`: run_with_secrets says how, and no value enters the conversation.',
].join(' ');

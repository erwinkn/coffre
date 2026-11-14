// The vault's share of a reveal's CPU: a Worker that does the least the app
// does, the token hashed and one `use` over the same service binding, and
// nothing of coffre's routing, middleware or answer. Driven alone at a rate,
// what workerd spends on it is the vault's cost plus this floor; the app's
// is the full reveal's minus that.
type Use = (input: Record<string, unknown>) => Promise<{ refused?: string; values?: unknown[] }>;
type Env = { VAULT: { use: Use } };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const bearer = /^Bearer (\S+)$/.exec(request.headers.get('authorization') ?? '')?.[1] ?? '';
    const { path } = (await request.json()) as { path: string };
    const [project, environment, key] = path.split('/') as [string, string, string];
    const token = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(bearer))).toString('hex');
    try {
      const answer = await env.VAULT.use({ token, proof: null, request: crypto.randomUUID(), ip: null, project, environment, mine: false, keys: [key], purpose: 'reveal', upstream: null });
      return Response.json(answer, { status: answer.refused === undefined ? 200 : 403 });
    } catch (error) {
      const code = (error as { code?: unknown }).code;
      return Response.json({ error: { code: typeof code === 'string' ? code : 'error', message: String(error) } }, { status: 503 });
    }
  },
};

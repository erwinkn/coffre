// An app Worker of the account, which binds coffre's `CoffreWorkload`
// several times, each binding with its own props (the harness's config):
// `COFFRE`, props naming a service with a cloudflare binding; `UNBOUND`, a
// service without one; `NO_PROPS`, `EXTRA` and `NUMBER`, props coffre must
// refuse. The suite asks it, `/?binding=COFFRE&op=sign`, to call one, and it
// answers what the call returned or threw.
type Workload = {
  fetch(request: Request): Promise<Response>;
  sign(credential: string, message: string | Uint8Array, options?: { place?: string }): Promise<unknown>;
  verify(credential: string, message: string | Uint8Array, signature: string, options?: { place?: string }): Promise<unknown>;
  presign(credential: string, path: string, options?: { place?: string; expiresIn?: number }): Promise<unknown>;
};

export default {
  async fetch(request: Request, env: Record<string, Workload>): Promise<Response> {
    const asked = new URL(request.url).searchParams;
    const coffre = env[asked.get('binding') ?? '']!;
    const place = asked.get('place') ?? undefined;
    const message = asked.get('message') ?? 'challenge';
    try {
      switch (asked.get('op')) {
        case 'fetch': {
          // As an SDK would send it, a placeholder key included: the binding is the route, and the host any.
          const answered = await coffre.fetch(new Request(`https://coffre${asked.get('path') ?? '/use/echo/v1/ping'}`, { headers: { authorization: 'Bearer coffre' } }));
          return Response.json({ status: answered.status, body: await answered.text() });
        }
        case 'sign':
          return Response.json({ answer: await coffre.sign(asked.get('credential') ?? 'dfns-key', message, { place }) });
        case 'verify':
          return Response.json({ answer: await coffre.verify(asked.get('credential') ?? 'stripe-webhook', message, asked.get('signature') ?? '', { place }) });
        case 'presign':
          return Response.json({ answer: await coffre.presign(asked.get('credential') ?? 's3', asked.get('path') ?? '/bucket/key', { place }) });
        default:
          return new Response('op is fetch, sign, verify or presign', { status: 400 });
      }
    } catch (error) {
      return Response.json({ threw: (error as Error).message });
    }
  },
};

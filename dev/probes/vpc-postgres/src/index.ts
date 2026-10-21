// A throwaway probe: does a Workers VPC Network binding's connect() work from
// a Worker and from a Durable Object, and does a plaintext Postgres session
// through it log in with SCRAM and run `select 1`? See README.md.
import { DurableObject } from 'cloudflare:workers';
import { describe, probe, type Dial, type Report } from './pg.ts';

export interface Env {
  /** A VPC Network binding (`vpc_networks`): workers-types has no type for it yet. */
  VPC: { connect: Dial };
  PROBE: DurableObjectNamespace<Probe>;
  PG_HOST: string;
  PG_PORT: string;
  PG_DATABASE: string;
  PG_USER: string;
  DEBUG_RO_PASSWORD: string;
  PROBE_KEY: string;
}

const MAX_HOLD_SECONDS = 600;
/** A byte every so often while a hold runs, so no proxy on the way gives up on a silent response. */
const HEARTBEAT_MS = 20_000;

const encoder = new TextEncoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const route = request.method === 'GET' && (url.pathname === '/worker' || url.pathname === '/do') ? url.pathname : null;
    // The key is checked before the route, so without it every request looks the same: an empty 404.
    if (!(await authorized(request, env.PROBE_KEY)) || route === null) return new Response(null, { status: 404 });

    const hold = url.searchParams.get('hold') ?? '0';
    if (!/^\d{1,3}$/.test(hold) || Number(hold) > MAX_HOLD_SECONDS) {
      return Response.json({ ok: false, error: `hold is whole seconds, 0 to ${MAX_HOLD_SECONDS}` }, { status: 400 });
    }
    const seconds = Number(hold);
    const report =
      route === '/worker'
        ? probe((address) => env.VPC.connect(address), target(env), seconds)
        : env.PROBE.get(env.PROBE.idFromName('probe'))
            .run(seconds)
            .catch((error: unknown): Report => ({ ok: false, stage: 'durable-object', error: describe(error) }));
    return stream(route.slice(1), request.cf?.colo, report);
  },
} satisfies ExportedHandler<Env>;

/** The Durable Object: the same probe, dialed from inside it. */
export class Probe extends DurableObject<Env> {
  run(seconds: number): Promise<Report> {
    return probe((address) => this.env.VPC.connect(address), target(this.env), seconds);
  }
}

function target(env: Env) {
  return { host: env.PG_HOST, port: env.PG_PORT, database: env.PG_DATABASE, user: env.PG_USER, password: env.DEBUG_RO_PASSWORD };
}

/** `Authorization: Bearer <PROBE_KEY>`, compared in constant time; a missing or short key opens nothing. */
async function authorized(request: Request, key: string | undefined): Promise<boolean> {
  if (!key || key.length < 32) return false;
  const digest = async (value: string) => crypto.subtle.digest('SHA-256', encoder.encode(value));
  const [given, expected] = await Promise.all([digest(request.headers.get('authorization') ?? ''), digest(`Bearer ${key}`)]);
  return crypto.subtle.timingSafeEqual(given, expected);
}

/** The report as JSON once it settles, after a space every HEARTBEAT_MS until then. */
function stream(route: string, colo: unknown, report: Promise<Report>): Response {
  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
  const writer = writable.getWriter();
  const beat = setInterval(() => void writer.write(encoder.encode(' ')).catch(() => {}), HEARTBEAT_MS);
  void report
    .then((settled) => writer.write(encoder.encode(`${JSON.stringify({ route, colo, ...settled }, null, 2)}\n`)))
    .catch(() => {})
    .finally(() => {
      clearInterval(beat);
      void writer.close().catch(() => {});
    });
  return new Response(readable, { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
}

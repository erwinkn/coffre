// A throwaway probe: does a Workers VPC Network binding's connect() work from
// a Worker and from a Durable Object, does a plaintext Postgres session
// through it log in with SCRAM and run `select 1`, and do its open sockets
// count toward Workers' six simultaneous connections? See README.md.
import { DurableObject } from 'cloudflare:workers';
import { describe, probe, type Dial, type Report } from './pg.ts';
import { holdSockets, type SocketsReport } from './sockets.ts';

export interface Env {
  /** A VPC Network binding (`vpc_networks`): workers-types has no type for it yet. */
  VPC: { connect: Dial };
  PROBE: DurableObjectNamespace<Probe>;
  PG_HOST: string;
  PG_PORT: string;
  PG_DATABASE: string;
  PG_USER: string;
  DEV_READONLY_PASSWORD: string;
  PROBE_KEY: string;
}

const ROUTES = new Set(['/worker', '/do', '/sockets']);
const MAX_HOLD_SECONDS = 600;
const MAX_SOCKETS = 20;
/** A byte every so often while a hold runs, so no proxy on the way gives up on a silent response. */
const HEARTBEAT_MS = 20_000;

const encoder = new TextEncoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const route = request.method === 'GET' && ROUTES.has(url.pathname) ? url.pathname : null;
    // The key is checked before the route, so without it every request looks the same: an empty 404.
    if (!(await authorized(request, env.PROBE_KEY)) || route === null) return new Response(null, { status: 404 });

    // /sockets holds past two minutes unless told otherwise; the others do not hold.
    const hold = url.searchParams.get('hold') ?? (route === '/sockets' ? '150' : '0');
    if (!/^\d{1,3}$/.test(hold) || Number(hold) > MAX_HOLD_SECONDS) {
      return Response.json({ ok: false, error: `hold is whole seconds, 0 to ${MAX_HOLD_SECONDS}` }, { status: 400 });
    }
    const seconds = Number(hold);
    const n = url.searchParams.get('n') ?? '6';
    if (route === '/sockets' && (!/^\d{1,2}$/.test(n) || Number(n) < 1 || Number(n) > MAX_SOCKETS)) {
      return Response.json({ ok: false, error: `n is a whole number of sockets, 1 to ${MAX_SOCKETS}` }, { status: 400 });
    }
    const failedCall = (error: unknown) => ({ ok: false, stage: 'durable-object', error: describe(error) });
    const report: Promise<object> =
      route === '/worker'
        ? probe((address) => env.VPC.connect(address), target(env), seconds)
        : route === '/do'
          ? env.PROBE.get(env.PROBE.idFromName('probe')).run(seconds).catch(failedCall)
          : env.PROBE.get(env.PROBE.idFromName('sockets')).sockets(Number(n), seconds).catch(failedCall);
    return stream(route.slice(1), request.cf?.colo, report);
  },
} satisfies ExportedHandler<Env>;

/** The Durable Object: the same probe, dialed from inside it. */
export class Probe extends DurableObject<Env> {
  run(seconds: number): Promise<Report> {
    return probe((address) => this.env.VPC.connect(address), target(this.env), seconds);
  }

  sockets(count: number, seconds: number): Promise<SocketsReport> {
    return holdSockets((address) => this.env.VPC.connect(address), target(this.env), count, seconds);
  }
}

function target(env: Env) {
  return { host: env.PG_HOST, port: env.PG_PORT, database: env.PG_DATABASE, user: env.PG_USER, password: env.DEV_READONLY_PASSWORD };
}

/** `Authorization: Bearer <PROBE_KEY>`, compared in constant time; a missing or short key opens nothing. */
async function authorized(request: Request, key: string | undefined): Promise<boolean> {
  if (!key || key.length < 32) return false;
  const digest = async (value: string) => crypto.subtle.digest('SHA-256', encoder.encode(value));
  const [given, expected] = await Promise.all([digest(request.headers.get('authorization') ?? ''), digest(`Bearer ${key}`)]);
  return crypto.subtle.timingSafeEqual(given, expected);
}

/** The report as JSON once it settles, after a space every HEARTBEAT_MS until then. */
function stream(route: string, colo: unknown, report: Promise<object>): Response {
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

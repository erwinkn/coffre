// The Postgres tunnel in workerd, as on Cloudflare: the Worker sends each
// WebSocket to its Durable Object (`forwardSocket`), whose class is the one
// a deployment exports (`socketsObject`), and the credential proxy admits
// it there and runs its session. coffre's side is a stand-in that opens the
// suite's database URL for every handle; the replica's tunnel dials through
// a stand-in VPC Network binding, which local workerd cannot run: it says
// it is asked for the replica's address, and connects to the suite's database.
import { CoffreError } from '@coffre/client';

import { forwardSocket, socketsObject, type SocketsNamespace } from '../../src/cloudflare-sockets.ts';
import { inTime } from '../../src/socket-admission.ts';
import type { PluginContext } from '../../src/plugins.ts';
import type { WorkersSocket } from '../../src/workers-socket.ts';
import { credentialProxy, postgres, type Network } from '../../src/plugins/credential-proxy.ts';

type Env = { SOCKETS: SocketsNamespace; DATABASE_URL: string };

/** The handle the stand-in revokes after its third use: a recheck of the group's finds it refused. */
const REVOKED = `coffre_use_${'r'.repeat(43)}`;

/** The handle the stand-in refuses at its first 33 admissions, then lets in. */
const REFUSED = `coffre_use_${'f'.repeat(43)}`;

/** The handle the stand-in refuses at once, as a timed-out admission is, while its decision goes on a second. */
const SLOW = `coffre_use_${'s'.repeat(43)}`;

/** The handle whose URL each admission reads in turn, half a second each, as on the object's one database client. */
const TURNS = `coffre_use_${'t'.repeat(43)}`;

/** The handle the stand-in takes 20 s to check, as an instance under a burst of runs does, then lets in. */
const LOADED = `coffre_use_${'l'.repeat(43)}`;

/** The private address the replica's URL names, and the binding's stand-in. */
const REPLICA = '10.9.8.7';

export const CoffreSockets = socketsObject<Env>((env) => {
  const port = Number(new URL(env.DATABASE_URL).port);
  const network: Network = {
    // The replica answers only through it: a direct dial to 10.9.8.7 reaches nothing.
    connect: async (address) => {
      if (address !== `${REPLICA}:5432`) throw new Error(`the binding reaches ${REPLICA}:5432 only, not ${address}`);
      const { connect } = (await import('cloudflare:sockets' as string)) as { connect: (address: { hostname: string; port: number }) => WorkersSocket };
      return connect({ hostname: '127.0.0.1', port });
    },
  };
  // A database that never takes a byte: the session waits on it, and reads nothing more from the app.
  const stalled: Network = {
    connect: () => ({
      readable: new ReadableStream(),
      writable: new WritableStream({ write: () => new Promise(() => undefined) }),
      opened: Promise.resolve(),
      closed: new Promise(() => undefined),
      close: async () => undefined,
      startTls: () => {
        throw new Error('plaintext only');
      },
    }),
  };
  const proxy = credentialProxy({
    credentials: {},
    tunnels: {
      db: postgres('DATABASE_URL'),
      replica: postgres('REPLICA_URL', { hosts: [REPLICA], connect: network }),
      stall: postgres('STALL_URL', { hosts: ['10.9.8.9'], connect: stalled }),
    },
    // The suite's database is on loopback: only the direct tunnel needs this, never the replica's.
    insecureUpstreams: true,
    recheckSeconds: 0.5,
    cacheSeconds: 0,
  });
  const uses = new Map<string, number>();
  let refusals = 0;
  /** The reads of `TURNS`'s URL, one after another. */
  let reading: Promise<void> = Promise.resolve();
  const real = new URL(env.DATABASE_URL);
  const replica = `postgres://${real.username}:${real.password}@${REPLICA}:5432${real.pathname}?sslmode=disable`;
  const coffre = {
    publicUrl: 'https://secrets.acme.example',
    // As coffre's, a database read away: admissions in a burst overlap, as on Cloudflare.
    handle: async (handle: string) => {
      await new Promise((resolve) => setTimeout(resolve, handle === LOADED ? 20_000 : 20));
      if (handle === REFUSED && (refusals += 1) <= 33) throw new CoffreError(401, 'unauthorized', 'not yet');
      return { expiresAt: new Date(Date.now() + 3_600_000).toISOString(), paths: ['market/dev'] };
    },
    use: async (handle: string) => {
      if (handle === TURNS) await (reading = reading.then(() => new Promise((resolve) => setTimeout(resolve, 500))));
      const used = (uses.get(handle) ?? 0) + 1;
      uses.set(handle, used);
      if (handle === REVOKED && used > 3) throw new CoffreError(401, 'unauthorized', 'the handle was revoked');
      return {
        values: { DATABASE_URL: `${env.DATABASE_URL}?sslmode=disable`, REPLICA_URL: replica, STALL_URL: 'postgres://u:p@10.9.8.9:5432/d?sslmode=disable' },
        plain: [],
        keys: ['DATABASE_URL', 'REPLICA_URL', 'STALL_URL'],
        environment: { path: 'market/dev', personal: false },
        expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      };
    },
  } as unknown as PluginContext;
  return (request, _, hold) => {
    if (request.headers.get('authorization') === `Bearer ${SLOW}`) {
      hold(new Promise((resolve) => setTimeout(resolve, 1000)));
      return Promise.resolve(new Response('coffre took too long to decide', { status: 503 }));
    }
    // In the time coffre gives an admission, as `admitSocket` gives it.
    return inTime(proxy.routes!.socket!(request, coffre), hold);
  };
});

export default {
  fetch: (request: Request, env: Env) => forwardSocket(request, env.SOCKETS),
};

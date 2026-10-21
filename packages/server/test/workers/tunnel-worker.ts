// The Postgres tunnel in workerd, as on Cloudflare: the Worker sends each
// WebSocket to its Durable Object (`forwardSocket`), whose class is the one
// a deployment exports (`socketsObject`), and the credential proxy admits
// it there and runs its session. coffre's side is a stand-in that opens the
// suite's database URL for every handle; the replica's tunnel dials through
// a stand-in VPC Network binding, which local workerd cannot run: it says
// it is asked for the replica's address, and connects to the suite's database.
import { CoffreError } from '@coffre/client';

import { forwardSocket, socketsObject, type SocketsNamespace } from '../../src/cloudflare-sockets.ts';
import type { PluginContext } from '../../src/plugins.ts';
import type { WorkersSocket } from '../../src/workers-socket.ts';
import { credentialProxy, postgres, type Network } from '../../src/plugins/credential-proxy.ts';

type Env = { SOCKETS: SocketsNamespace; DATABASE_URL: string };

/** The handle the stand-in revokes after its third use: a recheck of the group's finds it refused. */
const REVOKED = `coffre_use_${'r'.repeat(43)}`;

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
  const proxy = credentialProxy({
    credentials: {},
    tunnels: { db: postgres('DATABASE_URL'), replica: postgres('REPLICA_URL', { hosts: [REPLICA], connect: network }) },
    // The suite's database is on loopback: only the direct tunnel needs this, never the replica's.
    insecureUpstreams: true,
    recheckSeconds: 0.5,
    cacheSeconds: 0,
  });
  const uses = new Map<string, number>();
  const real = new URL(env.DATABASE_URL);
  const replica = `postgres://${real.username}:${real.password}@${REPLICA}:5432${real.pathname}?sslmode=disable`;
  const coffre = {
    publicUrl: 'https://secrets.acme.example',
    handle: async () => ({ expiresAt: new Date(Date.now() + 3_600_000).toISOString(), paths: ['market/dev'] }),
    use: async (handle: string) => {
      const used = (uses.get(handle) ?? 0) + 1;
      uses.set(handle, used);
      if (handle === REVOKED && used > 3) throw new CoffreError(401, 'unauthorized', 'the handle was revoked');
      return {
        values: { DATABASE_URL: `${env.DATABASE_URL}?sslmode=disable`, REPLICA_URL: replica },
        plain: [],
        keys: ['DATABASE_URL', 'REPLICA_URL'],
        environment: { path: 'market/dev', personal: false },
        expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      };
    },
  } as unknown as PluginContext;
  return (request) => proxy.routes!.socket!(request, coffre);
});

export default {
  fetch: (request: Request, env: Env) => forwardSocket(request, env.SOCKETS),
};

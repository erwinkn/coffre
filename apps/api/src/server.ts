import pg from 'pg';
import { loadConfig } from './config.ts';
import { buildApp } from './app.ts';
import { AccessIdentityVerifier } from '../../../packages/core/src/identity/verifier.ts';
import { startHeartbeat } from './heartbeat.ts';

const config = loadConfig();
const pool = new pg.Pool({ connectionString: config.databaseUrl });

const app = buildApp({
  pool,
  verifier: new AccessIdentityVerifier(config.auth.access),
  authMode: config.auth.mode,
  keks: config.keks,
  auditChainKey: config.auditChainKey,
  rootAdmins: config.rootAdmins,
  logger: true,
});

const heartbeat = startHeartbeat(pool, app.log);

await app.listen({ port: config.port, host: '0.0.0.0' });

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    heartbeat.stop();
    void app.close().then(() => pool.end()).then(() => process.exit(0));
  });
}

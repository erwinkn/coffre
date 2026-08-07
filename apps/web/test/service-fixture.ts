import { randomUUID } from 'node:crypto';
import type pg from 'pg';

import type { KekRegistry } from '../../../packages/core/src/kek/registry.ts';
import { AdminService } from '../src/server/services/admin.ts';
import { AuditService } from '../src/server/services/audit.ts';
import {
  SecretsService,
  type RequestContext,
} from '../src/server/services/secrets.ts';

export function requestContext(
  id: string,
  type: 'user' | 'service' = 'user',
): RequestContext {
  return {
    principal: { type, id },
    requestId: randomUUID(),
    sourceIp: null,
  };
}

export function serviceFixture(options: {
  pool: pg.Pool;
  keks: KekRegistry;
  auditChainKey: Buffer;
  rootAdmins: readonly string[];
}) {
  return {
    admin: new AdminService({
      pool: options.pool,
      auditChainKey: options.auditChainKey,
      rootAdmins: options.rootAdmins,
    }),
    audit: new AuditService({
      pool: options.pool,
      chainKey: options.auditChainKey,
      rootAdmins: options.rootAdmins,
    }),
    secrets: new SecretsService({
      pool: options.pool,
      keks: options.keks,
      auditChainKey: options.auditChainKey,
      rootAdmins: options.rootAdmins,
    }),
  };
}

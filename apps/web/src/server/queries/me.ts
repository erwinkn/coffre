import '@tanstack/react-start/server-only';

import type { Me } from '../../shared/models.ts';
import type { CoffreRuntime } from '../runtime.ts';
import { isRootAdmin } from '../services/permissions.ts';
import type { RequestContext } from '../services/secrets.ts';

/** Shared identity query used by both the native API and server functions. */
export async function getMe(
  runtime: CoffreRuntime,
  ctx: RequestContext,
): Promise<Me> {
  const [environments, instanceRole, canReadAudit] = await Promise.all([
    runtime.secrets.listAccessible(ctx),
    runtime.admin.instanceRole(ctx.principal),
    runtime.audit.canRead(ctx),
  ]);

  return {
    principal: { type: ctx.principal.type, id: ctx.principal.id },
    instanceRole,
    isRootAdmin: isRootAdmin(ctx.principal, runtime.rootAdmins),
    canReadAudit,
    environments,
  };
}

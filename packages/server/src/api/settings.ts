import { randomUUID } from 'node:crypto';

import { runsInstance, type Scope } from '@coffre/core/access';

import { places } from '../db/queries.ts';
import { requireInstance, withRefusals, type ApiContext } from './context.ts';
import { forbidden, vaultRefused } from './errors.ts';
import { scopeIds, scopeView, type FilterInput } from './members.ts';
import { formatMember } from './paths.ts';

/**
 * The instance's settings, as the API shows them, projects by slug: where
 * people set up service accounts themselves (`ServiceSetting`).
 */
export type SettingsView = { serviceAccounts: Scope };

/** For those who run the instance: a scope names projects others may not see. */
export async function getSettings(ctx: ApiContext): Promise<SettingsView> {
  if (!runsInstance(ctx.caller)) throw forbidden("only admins and owners of the whole instance read its settings");
  const [settings, known] = await Promise.all([ctx.vault.settings(), places(ctx.db)]);
  return { serviceAccounts: scopeView(settings.serviceAccounts, known) };
}

/**
 * Change them: those who run the instance, and the vault logs it as
 * `settings.change`, with what it was. Either filter left out is `all`.
 *
 *   { "serviceAccounts": { "environments": { "except": ["prod"] } } }
 */
export async function putSettings(
  ctx: ApiContext,
  input: { serviceAccounts: { projects?: FilterInput; environments?: FilterInput } },
): Promise<SettingsView> {
  return withRefusals(ctx, async () => {
    requireInstance(ctx, 'settings.change', {}, 'change its settings');
    const known = await places(ctx.db);
    const result = await ctx.vault.setSettings({
      actor: formatMember(ctx.caller.principal),
      settings: { serviceAccounts: scopeIds(input.serviceAccounts, known) },
      requestId: ctx.requestId,
      operationId: randomUUID(),
      credentialId: ctx.provenance,
    });
    if (!result.ok) throw vaultRefused(result.refusal);
    return { serviceAccounts: scopeView(result.settings.serviceAccounts, known) };
  });
}

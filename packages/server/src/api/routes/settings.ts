import { isScope, normalScope, runsInstance, type Scope } from '@coffre/core/access';
import { scopeInput } from '@coffre/core/schemas';
import { z } from 'zod';

import { settingsRow } from '../../db/queries/policy.ts';
import { changed } from '../change.ts';
import { refusal } from '../errors.ts';
import { route } from '../route.ts';
import { scopeView } from './members.ts';

/**
 * The instance's settings (docs/design/0.16.md, "The server"), in 0.14.7's
 * shapes: where people set up service accounts themselves
 * (`ServiceSetting`), projects by slug. For whoever runs the instance: a
 * scope names projects others may not see. Reading them is `caller` and
 * one statement; changing them is one `settings.change` and no statement.
 */

/** The setting as the row keeps it; one that does not read as a scope lets nobody set one up anywhere, as the vault takes it. */
function settingOf(text: string): Scope {
  try {
    const setting: unknown = JSON.parse(text);
    if (isScope(setting)) return setting;
  } catch {
    // As below.
  }
  return { projects: { only: [] }, environments: { only: [] } };
}

/** The instance's settings: where people set up service accounts themselves, projects by slug. */
export type SettingsView = { serviceAccounts: Scope };

export const settingsRoutes = {
  ...route('GET /settings', {
    run: async (ctx): Promise<SettingsView> => {
      const who = await ctx.caller();
      if (!runsInstance(who.holds)) throw refusal('no_access');
      const row = await settingsRow(ctx.db);
      // The instance's policy row is always there: without it, every change of the policy's is refused, as the vault refuses it.
      if (row === null) throw refusal('tampered');
      return { serviceAccounts: scopeView(settingOf(row.serviceAccounts), row.slugs) };
    },
  }),

  /**
   * Change them, as one change of the vault's, which logs it as
   * `settings.change` with what it was. Either filter left out is `all`.
   * Answered as asked, projects by slug: the vault took each of them.
   *
   *   { "serviceAccounts": { "environments": { "except": ["prod"] } } }
   */
  ...route('PUT /settings', {
    input: z.object({ serviceAccounts: scopeInput }).strict(),
    run: async (ctx, { input }): Promise<SettingsView> => {
      const serviceAccounts = normalScope({ projects: input.serviceAccounts.projects ?? 'all', environments: input.serviceAccounts.environments ?? 'all' });
      await changed(ctx, { op: 'settings.change', serviceAccounts }, 'settings');
      return { serviceAccounts };
    },
  }),
};

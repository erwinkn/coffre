import type { RolesView } from '@coffre/client';
import { useQuery } from '@tanstack/react-query';

import { useCoffre } from './coffre';
import { queries } from './queries';
import { SHIPPED_ROLES } from './roles';

/**
 * The instance's roles, for a picker or a name: as an Owner edited and made
 * them once read, and as they ship until then, or where they cannot be read,
 * so a picker never waits for them. The server decides every grant: a role
 * shown here a moment stale is one it refuses, never one it gives.
 */
export function useRoles(): RolesView {
  const { data } = useQuery({ ...queries.roles(useCoffre()), placeholderData: { ok: true as const, ...SHIPPED_ROLES } });
  return data?.ok === true ? data : SHIPPED_ROLES;
}

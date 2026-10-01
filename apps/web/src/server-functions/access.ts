import { z } from 'zod';

import type { Role } from '../../../../packages/core/src/access.ts';
import { conflict, notFound } from '../server/api/errors.ts';
import { formatMember } from '../server/api/paths.ts';
import { registeredServerFn } from '../server/server-fn.ts';
import {
  grantId,
  instanceRole,
  isoDateTime,
  principalId,
  principalType,
  slug,
} from '../shared/schemas.ts';
import { api, currentRequestContext } from './session.ts';
import { statusOf, uiFailure, uiMutation } from './result.ts';

const memberOf = (principalType: 'user' | 'service', principalId: string) =>
  formatMember({ type: principalType, id: principalId });

export const listDirectoryPrincipals = registeredServerFn({ method: 'GET' }).handler(async () => {
  // The API shows grant managers the members of their projects; the
  // directory page stays the owners' own.
  if (!currentRequestContext().caller.isOwner) {
    return { ok: false as const, error: 'Only owners can manage users and service accounts.' };
  }
  try {
    const { members, removed } = await api().members.list();
    const principals = members.map(({ principalType, principalId, instanceRole, isRootAdmin }) => ({
      principalType,
      principalId,
      instanceRole,
      isRootAdmin,
    }));
    return { ok: true as const, principals, removed };
  } catch (error) {
    return uiFailure(error);
  }
});

/** One principal's report for their page. `report` is null when there is no such principal. */
export const getPrincipalReport = registeredServerFn({ method: 'GET' })
  .validator(z.object({ principalType, principalId }))
  .handler(async ({ data }) => {
    try {
      const report = await api().members.get(memberOf(data.principalType, data.principalId));
      return { ok: true as const, report };
    } catch (error) {
      if (statusOf(error) === 404) return { ok: true as const, report: null };
      return uiFailure(error);
    }
  });

export const createGrant = registeredServerFn({ method: 'POST' })
  .validator(z.object({
    project: slug,
    principalType,
    principalId,
    role: slug,
    environmentSlug: slug.nullable(),
    expiresAt: isoDateTime.nullable(),
  }))
  .handler(async ({ data }) => {
    const place = data.environmentSlug === null ? data.project : `${data.project}/${data.environmentSlug}`;
    const role = data.role as Role;
    return uiMutation(() =>
      api().access.set(memberOf(data.principalType, data.principalId), {
        [place]: data.expiresAt === null ? role : { role, until: data.expiresAt },
      }),
    );
  });

export const revokeGrant = registeredServerFn({ method: 'POST' })
  .validator(z.object({ project: slug, grantId }))
  .handler(async ({ data }) =>
    uiMutation(async () => {
      const coffre = api();
      const { members } = await coffre.members.list(data.project);
      for (const member of members) {
        const grant = member.grants.find((entry) => entry.id === data.grantId);
        if (grant === undefined) continue;
        const place = grant.environment === null ? grant.project : `${grant.project}/${grant.environment}`;
        return coffre.access.set(member.member, { [place]: null });
      }
      throw notFound('no such grant');
    }),
  );

export const createDirectoryPrincipal = registeredServerFn({ method: 'POST' })
  .validator(z.object({
    principalType,
    principalId,
    instanceRole,
  }))
  .handler(async ({ data }) =>
    uiMutation(async () => {
      // Adding is an idempotent PUT that would also set the role of someone
      // already here; this form is only for someone new.
      const coffre = api();
      const member = memberOf(data.principalType, data.principalId);
      const { members } = await coffre.members.list();
      if (members.some((entry) => entry.member === member)) throw conflict('that principal already exists');
      await coffre.members.add(member, { owner: data.instanceRole === 'owner' });
    }),
  );

export const updateDirectoryPrincipalRole = registeredServerFn({ method: 'POST' })
  .validator(z.object({ principalId, instanceRole }))
  .handler(async ({ data }) =>
    uiMutation(() => api().members.add(memberOf('user', data.principalId), { owner: data.instanceRole === 'owner' })),
  );

export const removeDirectoryPrincipal = registeredServerFn({ method: 'POST' })
  .validator(z.object({ principalType, principalId }))
  .handler(async ({ data }) =>
    uiMutation(() => api().members.remove(memberOf(data.principalType, data.principalId))),
  );

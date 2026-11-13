import { ownerKey, type NumberedContext } from '@coffre/core/envelope';
import type { secrets, secretVersions } from '@coffre/db/schema';

import type { Row } from './rows.ts';

/** The secret a value is held by, as far as its encryption names it. */
export type Held = Pick<Row<typeof secrets>, 'id' | 'projectId' | 'environmentId'>;

/**
 * What a version's encryption names (docs/design/0.16.md, "Value
 * encryption"): its secret and where it lives, its number, a personal
 * config's owner, and its nature as its row says it, sensitive or plain.
 * One function for the write that seals a value and the use that opens it,
 * so a version relabelled in its row opens as nothing.
 */
export function contextOf(secret: Held, version: Pick<Row<typeof secretVersions>, 'version' | 'sensitive' | 'plaintext'>, owner: string | null): NumberedContext {
  const nature = version.sensitive ? { sensitive: true as const } : version.plaintext !== null ? { plain: true as const } : {};
  return { projectId: secret.projectId, environmentId: secret.environmentId, secretId: secret.id, version: version.version, ...(owner === null ? {} : { owner: ownerKey(owner) }), ...nature };
}

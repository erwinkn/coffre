import { ownerKey, type NumberedContext } from '@coffre/core/envelope';
import type { secrets, secretVersions } from '@coffre/db/schema';

import type { Row } from './rows.ts';

/** The secret a value is held by, as far as its encryption names it. */
export type Held = Pick<Row<typeof secrets>, 'id' | 'projectId' | 'environmentId'>;

/** What a version's row says of its value, which its encryption names. */
type Labelled = Pick<Row<typeof secretVersions>, 'sensitive' | 'plaintext'>;

/**
 * A version's nature as its row labels it: what its encryption names, and
 * what its secret's row says of it, which the engine holds the two to
 * (`prepare` in change.ts).
 */
export function natureOf(version: Labelled): NonNullable<Row<typeof secrets>['nature']> {
  return version.sensitive ? 'sensitive' : version.plaintext !== null ? 'plain' : 'secret';
}

/**
 * What a version's encryption names (docs/design/0.16.md, "Value
 * encryption"): its secret and where it lives, its number, a personal
 * config's owner, and its nature as its row says it, sensitive or plain.
 * One function for the write that seals a value and the use that opens it,
 * so a version relabelled in its row opens as nothing.
 */
export function contextOf(secret: Held, version: Labelled & Pick<Row<typeof secretVersions>, 'version'>, owner: string | null): NumberedContext {
  const nature = { sensitive: { sensitive: true as const }, plain: { plain: true as const }, secret: {} }[natureOf(version)];
  return { projectId: secret.projectId, environmentId: secret.environmentId, secretId: secret.id, version: version.version, ...(owner === null ? {} : { owner: ownerKey(owner) }), ...nature };
}

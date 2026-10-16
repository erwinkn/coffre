/**
 * PROTOTYPE (W109): the part rotation and dynamic secrets would share.
 *
 * A provider makes and revokes one kind of credential at a third party: an
 * AWS access key, a Cloudflare API token, a Postgres login. Rotation asks
 * for a long-lived one and revokes the one it replaces once its consumers
 * have moved; a dynamic secret asks for a short-lived one per job, and
 * revokes it when the job ends or lets the provider expire it.
 *
 * A credential's value is shown once, by `issue`, and is never asked for
 * again: coffre stores it encrypted, or hands it to the job, and forgets it.
 * What coffre keeps is its handle, which names it at the provider without
 * opening anything (an access key ID, a token ID, a role name).
 */
export type Credential = {
  /** The provider's own ID for it. */
  id: string;
  /** The name coffre gave it, which starts with the operation's ID: how an orphan is found. */
  name: string;
};

export interface CredentialProvider {
  /** `aws-iam-user`, `cloudflare-token`, `postgres-role`: recorded on every entry. */
  readonly kind: string;
  /**
   * Make a new credential named `name`. Its value is in the answer and
   * nowhere else. A call that fails may still have made one, whose answer
   * was lost: `list` finds it by its name.
   */
  issue(name: string, options?: { expiresInSeconds?: number }): Promise<{ credential: Credential; value: string }>;
  /** Stop it working. One already gone is revoked: a retry after a lost answer succeeds. */
  revoke(credential: Credential): Promise<void>;
  /** The credentials whose names start with `prefix`, live ones only. */
  list(prefix: string): Promise<Credential[]>;
  /** When it last authenticated, where the provider says (AWS does), or null when never. */
  lastUsed?(credential: Credential): Promise<number | null>;
}

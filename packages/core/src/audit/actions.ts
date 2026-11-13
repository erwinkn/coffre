/**
 * Technical steps and sign-ins: in the log and its chain like everything
 * else, but not what someone did with secrets or access, so a page leaves
 * them out unless asked. The audit projection's `shown` is false for them
 * (@coffre/vault's projection.ts), and the server's pages hide them.
 */
export const DETAIL_ACTIONS = [
  'sign_in',
  'sign_out',
  'token.create',
  'token.revoke',
  'device.approve',
  'device.deny',
  // An MCP client's code redeemed, or its tokens refreshed: every hour of its use.
  'mcp.token',
  // A read-only tool's call through MCP that went through, as written before 0.16: a call that returns no value writes
  // nothing of its own now, as a page view does not.
  'mcp.read',
  'account.link',
  'account.unlink',
  // A touch that stepped a session up (docs/design/passkeys.md, section 6.2): one per five minutes at most, in PR 5.
  'passkey.check',
  'key.wrap',
  'key.rewrap',
  // The vault's seal of a reference: the app's `secret.reference` says it in words.
  'reference.create',
  'key.intent',
  'key.check',
  'audit.heartbeat',
  'audit.checkpoint',
  // A step of the app key's rotation, a hundred rows signed again; its `key.rotate` is shown.
  'key.reseal',
] as const;

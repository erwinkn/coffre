/**
 * How members are named, to people and to the API. A service account, a
 * machine identity that signs in by OIDC (trust bindings) or with bearer
 * tokens, is `service:<name>` wherever a person reads or types one. The
 * API, the vault and the audit log keep `token:<name>`, which the log's
 * signed entries hold: so the rename is here, at the edges, and nothing
 * stored or verified changes.
 */

/** A member as people read it: `service:deploy` for the API's `token:deploy`; anyone else as they are. */
export function shownMember(member: string): string {
  return member.startsWith('token:') ? `service:${member.slice('token:'.length)}` : member;
}

/** A member as the API takes it, from what a person typed: `service:deploy` and `token:deploy` alike name a service account. */
export function apiMember(member: string): string {
  return member.startsWith('service:') ? `token:${member.slice('service:'.length)}` : member;
}

/** A service account's name alone, from any of its forms: `deploy`, `service:deploy` or `token:deploy`. */
export function serviceName(member: string): string {
  return member.replace(/^(?:service|token):/, '');
}

/** Text from the API, a refusal's message say, its service accounts as people read them. */
export function shownText(text: string): string {
  return text.replace(/(?<![\w-])token:(?=[A-Za-z0-9])/g, 'service:');
}

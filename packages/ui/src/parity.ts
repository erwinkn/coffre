/**
 * Every route of the API, and where a person does it in coffre's pages: the
 * counterpart of the CLI's PARITY (`packages/cli/src/commands.ts`). The map
 * is typed over the route table, so a route added to the server fails the
 * typecheck here until it names the page that performs it, or says why no
 * page does, or which work in flight brings its page. `test/parity.test.ts`
 * holds each entry to it: the file exists, the pages make the call, and the
 * call sends that route.
 */
import type { CoffreClient, RouteKey } from '@coffre/client';

/** A client call, as the pages make it: `secrets.reveal`, `me`. */
export type ClientCall = {
  [N in keyof CoffreClient & string]: CoffreClient[N] extends (...args: never[]) => unknown
    ? N
    : `${N}.${keyof CoffreClient[N] & string}`;
}[keyof CoffreClient & string];

/** Where a person does it: the control, in words, its file under `src/`, and the call it makes. */
export type Affordance = { readonly does: string; readonly in: string; readonly call: ClientCall };

export type Reach =
  | { readonly ui: readonly Affordance[] }
  /** No page performs it, and why not. */
  | { readonly not: string }
  /** Its page is being built elsewhere: the pull request or thread that brings it. */
  | { readonly inFlight: string };

export const UI_PARITY: { [K in RouteKey]: Reach } = {
  'GET /me': { ui: [{ does: 'every page: who is signed in, in the sidebar', in: 'components/shell.tsx', call: 'me' }] },
  'GET /projects': { ui: [{ does: 'Projects', in: 'pages/projects.tsx', call: 'projects.list' }] },
  'PUT /projects/:project': { ui: [{ does: 'Projects › New project', in: 'pages/projects.tsx', call: 'projects.create' }] },
  'PATCH /projects/:project': {
    ui: [
      { does: 'a project › Settings › Save (slug, name)', in: 'pages/project.tsx', call: 'projects.update' },
      { does: 'a project › Settings › Archive …, Restore …', in: 'pages/project.tsx', call: 'projects.update' },
    ],
  },
  'DELETE /projects/:project': {
    ui: [
      { does: 'an archived project › Settings › Delete …, its slug typed out', in: 'components/delete-place.tsx', call: 'projects.delete' },
      { does: 'the same dialog: what deleting would erase and revoke', in: 'lib/queries.ts', call: 'projects.previewDelete' },
    ],
  },
  'PUT /projects/:project/:environment': {
    ui: [{ does: 'a project › Environments › Add environment', in: 'pages/project.tsx', call: 'environments.create' }],
  },
  'PATCH /projects/:project/:environment': {
    ui: [{ does: "an environment's card › ⋯ › Rename, Archive…, Restore", in: 'pages/project.tsx', call: 'environments.update' }],
  },
  'DELETE /projects/:project/:environment': {
    ui: [
      { does: "an archived environment's card › ⋯ › Delete…, its path typed out", in: 'components/delete-place.tsx', call: 'environments.delete' },
      { does: 'the same dialog: what deleting would erase and revoke', in: 'lib/queries.ts', call: 'environments.previewDelete' },
    ],
  },
  'GET /secrets/:project/:environment': { ui: [{ does: 'an environment: its secrets', in: 'pages/environment.tsx', call: 'secrets.list' }] },
  'PATCH /secrets/:project/:environment': {
    ui: [
      { does: 'an environment › New secret, Edit, then Save', in: 'pages/environment.tsx', call: 'secrets.set' },
      { does: 'an environment › Import .env, after its plan', in: 'pages/environment.tsx', call: 'secrets.set' },
    ],
  },
  'PATCH /secrets/:project/:environment/:key': {
    ui: [
      { does: "a secret › Edit: its name, then Save", in: 'pages/environment.tsx', call: 'secrets.rename' },
      { does: 'a secret › ⋯ › Archive; an archived one › ⋯ › Restore', in: 'pages/environment.tsx', call: 'secrets.update' },
    ],
  },
  'GET /secrets/:project/:environment/:key/versions': {
    ui: [{ does: 'a secret › ⋯ › Version history', in: 'pages/environment.tsx', call: 'secrets.history' }],
  },
  'POST /secrets/:project/:environment/:key/restore': {
    ui: [{ does: 'a secret › Version history › Restore a version', in: 'pages/environment.tsx', call: 'secrets.restore' }],
  },
  'POST /reveals': { ui: [{ does: 'a secret › Reveal, and Edit, which starts from the value', in: 'pages/environment.tsx', call: 'secrets.reveal' }] },
  'GET /members': {
    ui: [
      { does: 'Users, Service accounts', in: 'components/directory.tsx', call: 'members.list' },
      { does: "a project › Users, Service accounts: who holds access there", in: 'pages/project.tsx', call: 'members.list' },
    ],
  },
  'GET /members/:member': {
    ui: [
      { does: "a user's or service account's page: what it holds, and Offboarding", in: 'components/principal-page.tsx', call: 'members.get' },
      { does: '⋯ › Remove…: what removing would revoke, before it does', in: 'components/directory.tsx', call: 'members.get' },
    ],
  },
  'PUT /members/:member': {
    ui: [
      { does: 'Users › Add user; Service accounts › Add service account', in: 'components/directory.tsx', call: 'members.add' },
      { does: 'a user › ⋯ › Change role', in: 'components/directory.tsx', call: 'members.add' },
    ],
  },
  'DELETE /members/:member': { ui: [{ does: 'a user or service account › ⋯ › Remove…', in: 'components/directory.tsx', call: 'members.remove' }] },
  'GET /members/:member/tokens': { ui: [{ does: 'a service account › Sign-in › Bearer tokens', in: 'components/service-tokens.tsx', call: 'tokens.list' }] },
  'POST /members/:member/tokens': { ui: [{ does: 'a service account › Sign-in › Issue token', in: 'components/service-tokens.tsx', call: 'tokens.issue' }] },
  'DELETE /members/:member/tokens/:id': { ui: [{ does: 'a bearer token › Revoke', in: 'components/service-tokens.tsx', call: 'tokens.revoke' }] },
  'GET /members/:member/bindings': { ui: [{ does: 'a service account › Sign-in › Sign in with OIDC', in: 'components/trusted-workloads.tsx', call: 'bindings.list' }] },
  'POST /members/:member/bindings': {
    ui: [
      { does: 'Trust a workload: the binding reviewed first', in: 'components/trusted-workloads.tsx', call: 'bindings.preview' },
      { does: 'Trust a workload › Trust', in: 'components/trusted-workloads.tsx', call: 'bindings.create' },
    ],
  },
  'DELETE /members/:member/bindings/:id': { ui: [{ does: 'a trust binding › Remove', in: 'components/trusted-workloads.tsx', call: 'bindings.remove' }] },
  'GET /workloads/lookup': { ui: [{ does: 'Trust a workload: a repository named, its IDs looked up', in: 'components/trusted-workloads.tsx', call: 'bindings.lookup' }] },
  'PATCH /access/:member': {
    ui: [
      { does: 'a project › Users, Service accounts › Add user, Add service account', in: 'pages/project.tsx', call: 'access.set' },
      { does: 'a grant › Revoke', in: 'components/grants.tsx', call: 'access.set' },
      { does: "a user's or service account's page › Edit access", in: 'components/principal-page.tsx', call: 'access.set' },
      { does: "an owner, on a user's or service account's Access tab › Grant on every project, and its Revoke", in: 'components/every-project.tsx', call: 'access.set' },
    ],
  },
  'GET /sessions': { ui: [{ does: 'Account › Sessions', in: 'pages/account.tsx', call: 'sessions.list' }] },
  'DELETE /sessions/:id': { ui: [{ does: 'Account › a session › End', in: 'pages/account.tsx', call: 'sessions.revoke' }] },
  'GET /identities': { ui: [{ does: 'Account › Sign-in accounts', in: 'pages/account.tsx', call: 'identities.list' }] },
  'DELETE /identities/:id': { ui: [{ does: 'Account › a sign-in account › Unlink', in: 'pages/account.tsx', call: 'identities.unlink' }] },
  'GET /device-logins/:code': { ui: [{ does: "the page `coffre login` opens: the login's code", in: 'pages/device-login.tsx', call: 'deviceLogins.get' }] },
  'POST /device-logins/:code': { ui: [{ does: 'that page › Approve, Deny', in: 'pages/device-login.tsx', call: 'deviceLogins.decide' }] },
  'GET /audit': {
    ui: [
      { does: 'Audit', in: 'pages/audit.tsx', call: 'audit.list' },
      { does: "a user's or service account's page › Activity", in: 'components/actions-log.tsx', call: 'audit.list' },
    ],
  },
  'GET /audit/verification': { ui: [{ does: "Audit: the log's seal, verified on every visit", in: 'pages/audit.tsx', call: 'audit.verify' }] },
  'GET /audit/keys': { ui: [{ does: 'Settings › Keys: what the keys you keep are checked against', in: 'pages/settings.tsx', call: 'audit.keys' }] },
};

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
      { does: 'a project › Settings › Save (slug, name)', in: 'pages/project-settings.tsx', call: 'projects.update' },
      { does: 'a project › Settings › Archive …, Restore …', in: 'pages/project-settings.tsx', call: 'projects.update' },
    ],
  },
  'DELETE /projects/:project': {
    ui: [
      { does: 'an archived project › Settings › Delete …, its slug typed out', in: 'components/delete-place.tsx', call: 'projects.delete' },
      { does: 'the same dialog: what deleting would erase and revoke', in: 'lib/queries.ts', call: 'projects.previewDelete' },
    ],
  },
  'PUT /projects/:project/:environment': {
    ui: [{ does: 'a project › Environments › Add environment', in: 'pages/project-environments.tsx', call: 'environments.create' }],
  },
  'PATCH /projects/:project/:environment': {
    ui: [{ does: "an environment's card › ⋯ › Rename, Archive…, Restore", in: 'pages/project-environments.tsx', call: 'environments.update' }],
  },
  'DELETE /projects/:project/:environment': {
    ui: [
      { does: "an archived environment's card › ⋯ › Delete…, its path typed out", in: 'components/delete-place.tsx', call: 'environments.delete' },
      { does: 'the same dialog: what deleting would erase and revoke', in: 'lib/queries.ts', call: 'environments.previewDelete' },
    ],
  },
  'GET /projects/:project/:environment/missing': {
    ui: [{ does: "an environment: the keys its siblings you read have and it lacks", in: 'lib/queries.ts', call: 'environments.missing' }],
  },
  'PATCH /projects/:project/:environment/dismissals': {
    ui: [{ does: 'an environment › Missing keys › Dismiss, Dismiss all, Restore', in: 'components/missing.tsx', call: 'environments.dismiss' }],
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
  'PATCH /folders/:folder': { ui: [{ does: 'Projects › a folder › ⋯ › Rename folder…', in: 'pages/projects.tsx', call: 'folders.rename' }] },
  'DELETE /folders/:folder': { ui: [{ does: 'Projects › a folder › ⋯ › Remove folder…', in: 'pages/projects.tsx', call: 'folders.remove' }] },
  'PATCH /folders/:project/:environment/:folder': { ui: [{ does: "an environment's keys › a folder › ⋯ › Rename folder…", in: 'pages/environment.tsx', call: 'folders.renameKeys' }] },
  'DELETE /folders/:project/:environment/:folder': { ui: [{ does: "an environment's keys › a folder › ⋯ › Remove folder…", in: 'pages/environment.tsx', call: 'folders.removeKeys' }] },
  'DELETE /secrets/:project/:environment/:key/reference': {
    ui: [
      { does: "a reference's row › ⋯ › Break reference…, or the Read elsewhere list's Break", in: 'pages/environment.tsx', call: 'references.break' },
      { does: "a project's references › Break", in: 'components/references.tsx', call: 'references.break' },
      { does: 'Archive a project, an environment or a key, while references read it › Break, in the dialog', in: 'components/references.tsx', call: 'references.break' },
    ],
  },
  'GET /references': {
    ui: [
      { does: "an environment: what reads its secrets from elsewhere; a project's references", in: 'lib/queries.ts', call: 'references.list' },
      { does: 'a project › Settings › Archive …: the references that would stop reading it', in: 'pages/project-settings.tsx', call: 'references.list' },
      { does: "an environment's card › ⋯ › Archive…: the references that would stop reading it", in: 'pages/project-environments.tsx', call: 'references.list' },
    ],
  },
  'POST /reveals': { ui: [{ does: 'a secret › Reveal, and Edit, which starts from the value', in: 'pages/environment.tsx', call: 'secrets.reveal' }] },
  'GET /members': {
    ui: [
      { does: 'Users, Service accounts', in: 'components/directory.tsx', call: 'members.list' },
      { does: "a project › Users, Service accounts: who holds access there", in: 'pages/project-access.tsx', call: 'members.list' },
    ],
  },
  'GET /members/:member': {
    ui: [
      { does: "a user's or service account's page: what it holds, and Offboarding", in: 'components/principal-page.tsx', call: 'members.get' },
      { does: '⋯ › Remove…: what removing would revoke, before it does', in: 'components/directory.tsx', call: 'members.get' },
    ],
  },
  'GET /members/:member/access': {
    ui: [{ does: "a user's or service account's page › Access: their role and the grants you manage, in one read", in: 'components/principal-page.tsx', call: 'members.access' }],
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
      { does: 'a project › Users, Service accounts › Add user, Add service account', in: 'pages/project-access.tsx', call: 'access.set' },
      { does: 'a grant › Revoke', in: 'components/grants.tsx', call: 'access.set' },
      { does: "a user's or service account's page › Edit access", in: 'components/principal-page.tsx', call: 'access.set' },
    ],
  },
  'GET /sessions': { ui: [{ does: 'Account › Sessions', in: 'pages/account.tsx', call: 'sessions.list' }] },
  'DELETE /sessions/:id': { ui: [{ does: 'Account › Sessions › a session › End', in: 'pages/account.tsx', call: 'sessions.revoke' }] },
  'GET /identities': { ui: [{ does: 'Account › Profile › Sign-in accounts', in: 'pages/account.tsx', call: 'identities.list' }] },
  'DELETE /identities/:id': { ui: [{ does: 'Account › Profile › a sign-in account › Unlink', in: 'pages/account.tsx', call: 'identities.unlink' }] },
  'GET /device-logins/:code': { ui: [{ does: "the page `coffre login` opens: the login's code", in: 'pages/device-login.tsx', call: 'deviceLogins.get' }] },
  'POST /device-logins/:code': { ui: [{ does: 'that page › Approve, Deny', in: 'pages/device-login.tsx', call: 'deviceLogins.decide' }] },
  'GET /oauth/authorizations': { ui: [{ does: 'the page an MCP client opens to connect: what it asks for', in: 'pages/oauth-authorize.tsx', call: 'oauth.describe' }] },
  'POST /oauth/authorizations': { ui: [{ does: 'that page › Approve, Deny', in: 'pages/oauth-authorize.tsx', call: 'oauth.decide' }] },
  'GET /approvals/:id': { ui: [{ does: 'the page an MCP client sends you to, to decide a change it asked for', in: 'pages/approval.tsx', call: 'approvals.get' }] },
  'POST /approvals/:id': { ui: [{ does: 'that page › Approve, Deny', in: 'pages/approval.tsx', call: 'approvals.decide' }] },
  'GET /apps': { ui: [{ does: 'Account › Connected apps', in: 'pages/account.tsx', call: 'apps.list' }] },
  'DELETE /apps/:id': { ui: [{ does: 'Account › Connected apps › a connected app › Disconnect', in: 'pages/account.tsx', call: 'apps.disconnect' }] },
  'GET /audit': {
    ui: [
      { does: 'Audit', in: 'pages/audit.tsx', call: 'audit.list' },
      { does: "a user's or service account's page › Activity", in: 'components/actions-log.tsx', call: 'audit.list' },
    ],
  },
  'GET /audit/verification': { ui: [{ does: "Audit: the log's seal, verified on every visit", in: 'pages/audit.tsx', call: 'audit.verify' }] },
  'GET /settings': { ui: [{ does: 'Settings › Service accounts: where people set them up', in: 'pages/settings.tsx', call: 'settings.get' }] },
  'PUT /settings': { ui: [{ does: 'Settings › Service accounts › Edit', in: 'pages/settings.tsx', call: 'settings.set' }] },
  'GET /audit/keys': { ui: [{ does: 'Settings › Keys: what the keys you keep are checked against', in: 'pages/settings.tsx', call: 'audit.keys' }] },
};

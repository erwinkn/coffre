import { Fragment, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Menu } from '@base-ui/react/menu';
import { EVERYWHERE, INSTANCE_ROLES, scopeInWords, unscoped } from '@coffre/core/access';
import { changeRole, directoryList, invite, removeMember, type InviteVars, type RoleVars } from '../lib/changes';
import { memberRef, useCoffre } from '../lib/coffre';
import { scopeComplete } from '../lib/validation';
import { queries, waysFor } from '../lib/queries';
import { useShell } from '../lib/use-shell';
import { useChange, useChangeStatus } from '../lib/use-change';
import type { DirectoryPrincipal } from '../shared/models';
import { setByDeployment } from './affordances';
import { RowFailure, RowPending, rowClass } from './row-state';
import { ConfirmDialog, EmptyState, MenuPopup, Modal, Spinner, Timestamp, Toggletip } from './ui';
import { PrincipalLink } from './principal';
import { RoleField } from './role-field';
import { Clock, Folder, GitHub, Key, Link, Lock, MoreHorizontal, Pencil, Plus, ShieldCheck, User, X } from './icons';

/**
 * The instance directory, shared by the Users and Service accounts pages.
 *
 * Both are rows in the same table on the server (principals, typed user or
 * service); the pages split them because people and machines are looked after
 * differently, not because the model does.
 */

type PrincipalType = DirectoryPrincipal['principalType'];

/** How the directory, and its changes, name someone to the API: `user:…`, `token:…` (shown `service:…`). */
export const memberOf = (principal: Pick<DirectoryPrincipal, 'principalType' | 'principalId'>) =>
  memberRef(principal.principalType, principal.principalId);

/** A new person's role: a Member, everywhere. */
const MEMBER: RoleVars = { role: 'member', scope: EVERYWHERE };

/** The role a principal holds, as the role field edits it. */
const roleOf = (principal: DirectoryPrincipal): RoleVars => ({ role: principal.instanceRole, scope: principal.scope ?? EVERYWHERE });

/** What each kind of principal is called in the interface. */
export const KIND: Record<PrincipalType, string> = {
  user: 'user',
  service: 'service account',
};

export function DirectoryTable({
  principalType,
  principals,
  hasRemoved = false,
}: {
  principalType: PrincipalType;
  principals: DirectoryPrincipal[];
  /** Whether some were removed, listed beneath, so an empty table is not "yet". */
  hasRemoved?: boolean;
}) {
  const users = principalType === 'user';
  const columns = users ? 4 : 6;
  const { capabilities } = useShell();
  const { status, failedAdds, dismiss } = useChangeStatus(directoryList.queryKey);
  const refused = failedAdds<InviteVars>(principals.map(memberOf)).filter(
    ({ vars }) => vars.principalType === principalType,
  );
  return (
    <>
      <section className="card" aria-label={users ? 'Users' : 'Service accounts'}>
        {principals.length === 0 && refused.length === 0 ? (
          <EmptyState
            title={
              hasRemoved
                ? `No active ${KIND[principalType]}s`
                : users
                  ? 'Nobody is registered'
                  : 'No service accounts yet'
            }
          >
            {hasRemoved ? `Add a ${KIND[principalType]}` : `Add the first ${KIND[principalType]}`}, then
            grant it project access from each project's page.
          </EmptyState>
        ) : (
          <div className="dt-wrap">
            <table className={`dt directory directory-${principalType} stacks${users ? '' : ' stacks-inline'}`}>
              <thead>
                <tr>
                  <th className="n">#</th>
                  <th className="col-principal">
                    <span className="th">
                      {users ? <User size={14} /> : <Key size={14} />}
                      {users ? 'Email' : 'Name'}
                    </span>
                  </th>
                  {users ? (
                    <th className="col-role">
                      <span className="th">
                        <ShieldCheck size={14} />
                        Role
                      </span>
                    </th>
                  ) : (
                    <>
                      <th className="col-signin">
                        <span className="th">
                          <Link size={14} />
                          Signs in with
                        </span>
                      </th>
                      <th className="col-access">
                        <span className="th">
                          <Folder size={14} />
                          Access
                        </span>
                      </th>
                      <th className="col-used">
                        <span className="th">
                          <Clock size={14} />
                          Last used
                        </span>
                      </th>
                    </>
                  )}
                  <th className="col-actions">
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {principals.map((principal, index) => {
                  const state = status(memberOf(principal));
                  return (
                    <Fragment key={principal.principalId}>
                      <tr className={`row-link ${rowClass(state)}`}>
                        <td className="n">{index + 1}</td>
                        <td
                          className="col-lead"
                          data-label={principal.principalType === 'user' ? 'Email' : 'Name'}
                        >
                          <PrincipalLink
                            type={principal.principalType}
                            id={principal.principalId}
                            stretch
                          />
                        </td>
                        {users ? (
                          <td className="col-role" data-label="Role">
                            <InstanceRole principal={principal} />
                          </td>
                        ) : (
                          <ServiceCells principal={principal} adding={state.state === 'pending' && state.kind === 'saving'} />
                        )}
                        <td className="col-actions">
                          {state.state === 'pending' ? (
                            <RowPending status={state} />
                          ) : (
                            <PrincipalActions principal={principal} />
                          )}
                        </td>
                      </tr>
                      <RowFailure
                        status={state}
                        columns={columns}
                        onDismiss={() => state.state === 'failed' && dismiss(state.mutationId)}
                      />
                    </Fragment>
                  );
                })}
                {refused.map(({ mutationId, vars, status: failed }) => (
                  <RowFailure
                    key={mutationId}
                    status={failed}
                    columns={columns}
                    onDismiss={() => dismiss(mutationId)}
                  >
                    {vars.principalId} was not added.
                  </RowFailure>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {(capabilities.runsInstance || (!users && capabilities.setsUpServices)) && (
        <div className="table-actions">
          <AddPrincipal principalType={principalType} />
        </div>
      )}
    </>
  );
}

const PLATFORM: Record<string, string> = {
  github: 'GitHub',
  'github-reusable': 'GitHub',
  'github-reusable-organization': 'GitHub',
  gitlab: 'GitLab',
  custom: 'OIDC',
};

/**
 * What someone scanning service accounts wants of each: how it signs in, where
 * it reaches, and whether it is still in use. Access comes with the list; the
 * bindings and tokens are read per row, as its own page reads them.
 */
function ServiceCells({ principal, adding }: { principal: DirectoryPrincipal; adding: boolean }) {
  const client = useCoffre();
  const shell = useShell();
  const member = memberOf(principal);
  // As `loadServiceDirectory` read them, so these come from its cache; an account just added is yours.
  const ways = waysFor(shell, principal.managed !== false);
  // Not suspended: an account added here is shown at once, its facts once it is made, and not asked for before.
  const { data: bindings } = useQuery({ ...queries.bindings(client, member, ways.workloads), enabled: !adding });
  const { data: credentials } = useQuery({ ...queries.credentials(client, member, ways.tokens), enabled: !adding });

  const platforms = new Map<string, number>();
  const bindingList = bindings?.ok === true ? bindings.bindings : [];
  for (const binding of bindingList) {
    const platform = PLATFORM[binding.profile] ?? 'OIDC';
    platforms.set(platform, (platforms.get(platform) ?? 0) + 1);
  }
  const now = Date.now();
  const tokenList = credentials?.ok === true ? credentials.tokens : [];
  const activeTokens = tokenList.filter((token) => new Date(token.expiresAt).getTime() > now).length;
  const lastUsed = [...bindingList, ...tokenList]
    .map((credential) => credential.lastUsedAt)
    .filter((at): at is string => at !== null)
    .sort()
    .at(-1);

  const places = [
    ...new Set(
      (principal.grants ?? []).map(({ project, environment }) =>
        environment === null ? project : `${project}/${environment}`,
      ),
    ),
  ];
  const projects = new Set((principal.grants ?? []).map((grant) => grant.project));
  const loaded = bindings !== undefined && credentials !== undefined;

  return (
    <>
      <td className="col-signin" data-label="Signs in with">
        {!loaded ? null : platforms.size === 0 && activeTokens === 0 ? (
          <span className="cell-muted">Nothing yet</span>
        ) : (
          <span className="signin-list">
            {[...platforms].map(([platform, count]) => (
              <span key={platform} className="signin-item">
                {platform === 'GitHub' && <GitHub size={12} />}
                {platform}
                {count > 1 && ` ×${count}`}
              </span>
            ))}
            {activeTokens > 0 && (
              <span className="signin-item">
                <Key size={12} />
                {activeTokens} token{activeTokens === 1 ? '' : 's'}
              </span>
            )}
          </span>
        )}
      </td>
      <td className="col-access" data-label="Access" title={places.join(', ')}>
        {places.length === 0 ? (
          <span className="cell-muted">None</span>
        ) : places.length <= 2 ? (
          <span className="mono">{places.join(', ')}</span>
        ) : (
          `${projects.size} project${projects.size === 1 ? '' : 's'}`
        )}
      </td>
      <td className="col-used cell-muted" data-label="Last used">
        {!loaded ? null : lastUsed === undefined ? 'Never' : <Timestamp iso={lastUsed} display="relative" />}
      </td>
    </>
  );
}

/**
 * A user's instance role. Service accounts have none worth showing: every one is a
 * plain member.
 */
export function InstanceRole({ principal }: { principal: DirectoryPrincipal }) {
  const { capabilities } = useShell();
  if (principal.tampered === true) {
    return (
      <Toggletip
        label={
          <>
            Their record was changed outside coffre, so the vault refuses them
            everything. To start over, remove them and add them again.
          </>
        }
      >
        <button type="button" className="tag tag-red tag-button">
          <Lock size={11} />
          Integrity check failed
        </button>
      </Toggletip>
    );
  }
  const name = INSTANCE_ROLES[principal.instanceRole].name;
  return (
    <>
      {setByDeployment(principal, capabilities) ? (
        <Toggletip label="Set by deployment">
          <button type="button" className="tag tag-button" aria-label={`${name}, set by deployment`}>
            {name}
          </button>
        </Toggletip>
      ) : (
        <span className={`tag${principal.instanceRole === 'member' ? '' : ' tag-violet'}`}>{name}</span>
      )}
      {principal.instanceRole !== 'member' && principal.scope !== null && !unscoped(principal.scope) && (
        <span className="role-scope">{scopeInWords(principal.scope)}</span>
      )}
    </>
  );
}

/**
 * Change role and Remove, behind one menu, for those who run the instance;
 * Remove, for a service account you manage. Nobody changes their own role
 * but an Owner of the whole instance, who alone changes or removes an
 * Owner: to anyone else, an Owner's row says so instead. Nobody changes or
 * removes an Owner the deployment names: their row says where they are named.
 */
export function PrincipalActions({
  principal,
  trigger = 'act act-quiet act-menu',
}: {
  principal: DirectoryPrincipal;
  /** The menu button's classes: a row action in tables, a button in a page head. */
  trigger?: string;
}) {
  const [editing, setEditing] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [role, setRole] = useState<RoleVars>(roleOf(principal));
  const { capabilities, principal: me } = useShell();
  const coffre = useCoffre();
  const saveRole = useChange(changeRole(coffre));
  const remove = useChange(removeMember(coffre));
  const { status } = useChangeStatus(directoryList.queryKey);
  const pending = status(memberOf(principal)).state === 'pending';
  const kind = KIND[principal.principalType];

  const self = me?.type === principal.principalType && me.id === principal.principalId;
  const yours = principal.principalType === 'service' && principal.managed === true;
  if (!(capabilities.runsInstance || yours)) return null;
  if (principal.declared === true) {
    return (
      <Toggletip label="Owner defined by the deployment configuration." align="end">
        <button type="button" className={trigger} aria-label={`Why ${principal.principalId} can't be changed`}>
          <Lock size={14} />
        </button>
      </Toggletip>
    );
  }
  if (principal.instanceRole === 'owner' && !capabilities.ownsInstance) {
    return (
      <Toggletip label="Only an Owner of the whole instance changes or removes an Owner." align="end">
        <button type="button" className={trigger} aria-label={`Why ${principal.principalId} can't be changed`}>
          <Lock size={14} />
        </button>
      </Toggletip>
    );
  }

  return (
    <>
      <Menu.Root>
        <Menu.Trigger
          className={trigger}
          aria-label={`Actions for ${principal.principalId}`}
          disabled={pending}
        >
          {pending ? <Spinner size={13} /> : <MoreHorizontal size={16} />}
        </Menu.Trigger>
        <MenuPopup align="end">
          {principal.principalType === 'user' && (!self || capabilities.ownsInstance) && capabilities.runsInstance && (
            <>
              <Menu.Item
                className="menu-item"
                onClick={() => {
                  setRole(roleOf(principal));
                  setEditing(true);
                }}
              >
                <Pencil size={14} />
                Change role
              </Menu.Item>
              <Menu.Separator className="menu-sep" />
            </>
          )}
          <Menu.Item
            className="menu-item menu-item-danger"
            onClick={() => setConfirming(true)}
          >
            <X size={14} />
            Remove {kind}…
          </Menu.Item>
        </MenuPopup>
      </Menu.Root>

      {principal.principalType === 'user' && (
        <Modal
          open={editing}
          onOpenChange={setEditing}
          title={
            <>
              Role of <span className="mono">{principal.principalId}</span>
            </>
          }
        >
          <form
            className="form"
            onSubmit={(event) => {
              event.preventDefault();
              // Shown in the list at once; the row says if the server refuses.
              saveRole({ principalId: principal.principalId, ...role });
              setEditing(false);
            }}
          >
            <RoleField value={role} onChange={setRole} />
            <div className="dialog-actions">
              <button className="btn" type="button" onClick={() => setEditing(false)}>
                Cancel
              </button>
              <button className="btn btn-primary" type="submit" disabled={!scopeComplete(role)}>
                Save
              </button>
            </div>
          </form>
        </Modal>
      )}

      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title={
          <>
            Remove <span className="mono">{principal.principalId}</span>?
          </>
        }
        body={<RemovalPreview principal={principal} open={confirming} />}
        confirmLabel={`Remove ${kind}`}
        onConfirm={() => remove(principal)}
      />
    </>
  );
}

const plural = (count: number, one: string) => `${count} ${one}${count === 1 ? '' : 's'}`;

/**
 * What removing someone would do, read when its dialog opens, as `coffre
 * offboard` previews it before `--apply`: every way in it revokes, and what
 * they leave behind to rotate.
 */
function RemovalPreview({ principal, open }: { principal: DirectoryPrincipal; open: boolean }) {
  const { capabilities, features } = useShell();
  const person = principal.principalType === 'user';
  const { data, isPending } = useQuery({
    ...queries.report(useCoffre(), memberOf(principal), capabilities.runsInstance),
    enabled: open,
  });
  const report = data?.ok === true ? data.report : null;
  if (isPending) {
    return (
      <>
        <Spinner size={13} /> Reading what {person ? 'they hold' : 'it holds'}…
      </>
    );
  }
  if (report === null) {
    return person
      ? 'They are signed out everywhere, and their sign-in accounts and project access are revoked at once.'
      : 'Its bearer tokens and trust bindings stop working, and its project access is revoked at once.';
  }
  const { live } = report;
  // Named, as an app's name is what its person knows it by: "2 connected apps (Claude, Cursor)".
  const apps = `${plural(live.apps, 'connected app')}${report.apps.length > 0 ? ` (${report.apps.map((app) => app.name).join(', ')})` : ''}`;
  const revokes = person
    ? [
        plural(live.grants, 'grant'),
        plural(live.sessions, 'session'),
        plural(live.identities, 'linked sign-in account'),
        ...(features.mcp ? [apps] : []),
      ]
    : [plural(live.grants, 'grant'), plural(live.tokens, 'bearer token')];
  return (
    <>
      Removing revokes {revokes.join(', ')} at once
      {person ? '' : ', and its trust bindings, including for anything running as it now'}.{' '}
      {report.exposed.length === 0
        ? `No value ${person ? 'they' : 'it'} saw is still current.`
        : `${plural(report.exposed.length, 'value')} ${person ? 'they' : 'it'} saw ${report.exposed.length === 1 ? 'is' : 'are'} still current: ${person ? 'their' : 'its'} page lists them, to rotate.`}
      {report.issuedTokens.length > 0 &&
        ` ${plural(report.issuedTokens.length, 'bearer token')} ${person ? 'they' : 'it'} issued still ${report.issuedTokens.length === 1 ? 'works' : 'work'}.`}{' '}
      {person ? 'Their' : 'Its'} past actions stay in the audit log.
    </>
  );
}

export function AddPrincipal({ principalType }: { principalType: PrincipalType }) {
  const [open, setOpen] = useState(false);
  const [principalId, setPrincipalId] = useState('');
  const [role, setRole] = useState<RoleVars>(MEMBER);
  const add = useChange(invite(useCoffre()));
  const kind = KIND[principalType];

  function close() {
    setOpen(false);
    setPrincipalId('');
    setRole(MEMBER);
  }

  return (
    <>
      <button className="btn btn-primary" onClick={() => setOpen(true)}>
        <Plus size={14} />
        Add {kind}
      </button>

      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title={`Add a ${kind}`}
        description={
          principalType === 'user'
            ? undefined
            : 'This gives the service account no project access. Grant it afterwards, from its page or a project\'s.'
        }
      >
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            // Shown in the list at once; the list says if the server refuses.
            add({ principalType, principalId: principalId.trim(), ...role });
            close();
          }}
        >
          <label className="field">
            <span className="label">
              {principalType === 'user' ? 'Email' : 'Service account name'}
            </span>
            <input
              className="input input-mono"
              autoFocus
              spellCheck={false}
              autoComplete="off"
              value={principalId}
              placeholder={
                principalType === 'user' ? 'someone@acme.example' : 'ci-deploy'
              }
              onChange={(event) => setPrincipalId(event.target.value)}
            />
          </label>

          {principalType === 'user' && <RoleField value={role} onChange={setRole} />}

          <div className="dialog-actions">
            <button className="btn" type="button" onClick={close}>
              Cancel
            </button>
            <button className="btn btn-primary" type="submit" disabled={principalId.trim() === '' || !scopeComplete(role)}>
              Add {kind}
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
}

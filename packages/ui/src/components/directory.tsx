import { Fragment, useState } from 'react';
import { DropdownMenu } from 'radix-ui';
import { changeRole, directoryList, invite, removeMember, type InviteVars } from '../lib/changes';
import { memberRef, useCoffre } from '../lib/coffre';
import { useChange, useChangeStatus } from '../lib/use-change';
import type { DirectoryPrincipal } from '../shared/models';
import { RowFailure, RowPending, rowClass } from './row-state';
import { ConfirmDialog, EmptyState, Modal, Spinner, Toggletip } from './ui';
import { PrincipalLink } from './principal';
import { Key, Lock, MoreHorizontal, Pencil, Plus, ShieldCheck, User, X } from './icons';

/**
 * The instance directory, shared by the Users and Tokens pages.
 *
 * Both are rows in the same table on the server (principals, typed user or
 * service); the pages split them because people and machines are looked after
 * differently, not because the model does.
 */

type PrincipalType = DirectoryPrincipal['principalType'];

/** How the directory, and its changes, name someone: `user:…`, `token:…`. */
export const memberOf = (principal: Pick<DirectoryPrincipal, 'principalType' | 'principalId'>) =>
  memberRef(principal.principalType, principal.principalId);

export const ROLE_LABEL: Record<DirectoryPrincipal['instanceRole'], string> = {
  'root-admin': 'Root admin',
  owner: 'Owner',
  user: 'Member',
};

/** What each kind of principal is called in the interface. */
export const KIND: Record<PrincipalType, string> = {
  user: 'user',
  service: 'token',
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
  const columns = users ? 4 : 3;
  const { status, failedAdds, dismiss } = useChangeStatus(directoryList.queryKey);
  const refused = failedAdds<InviteVars>(principals.map(memberOf)).filter(
    ({ vars }) => vars.principalType === principalType,
  );
  return (
    <section className="card" aria-label={users ? 'Users' : 'Tokens'}>
      {principals.length === 0 && refused.length === 0 ? (
        <EmptyState
          title={
            hasRemoved
              ? `No active ${KIND[principalType]}s`
              : users
                ? 'Nobody is registered'
                : 'No tokens yet'
          }
        >
          {hasRemoved ? `Add a ${KIND[principalType]}` : `Add the first ${KIND[principalType]}`} to let
          it through the door. Project access is a separate step, granted from each project's page.
        </EmptyState>
      ) : (
        <div className="dt-wrap">
          <table className={`dt directory directory-${principalType} stacks`}>
            <thead>
              <tr>
                <th className="n">#</th>
                <th className="col-principal">
                  <span className="th">
                    {users ? <User size={14} /> : <Key size={14} />}
                    {users ? 'Email' : 'Name'}
                  </span>
                </th>
                {users && (
                  <th className="col-role">
                    <span className="th">
                      <ShieldCheck size={14} />
                      Instance role
                    </span>
                  </th>
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
                      {users && (
                        <td className="col-role" data-label="Instance role">
                          <InstanceRole principal={principal} />
                        </td>
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
  );
}

/**
 * A user's instance role. Tokens have none worth showing: every one is a
 * plain member. A root admin's role comes from the deployment, so its tag says
 * so on hover or tap instead of offering a menu that could not work.
 */
export function InstanceRole({ principal }: { principal: DirectoryPrincipal }) {
  if (principal.tampered === true) {
    return (
      <Toggletip
        label={
          <>
            Their record was changed outside coffre, so the vault refuses them
            everything. Remove them to start them over, then add them again.
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
  if (principal.isRootAdmin) {
    return (
      <Toggletip
        label={
          <>
            Set by <code>rootAdmins</code> in the vault's configuration, so it
            cannot be changed or removed here.
          </>
        }
      >
        <button type="button" className="tag tag-violet tag-button">
          <Lock size={11} />
          Root admin
        </button>
      </Toggletip>
    );
  }
  return (
    <span className={`tag${principal.instanceRole === 'user' ? '' : ' tag-violet'}`}>
      {ROLE_LABEL[principal.instanceRole]}
    </span>
  );
}

/**
 * Change role and Remove, behind one menu. Root admins get none: the
 * deployment's configuration owns them.
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
  const [instanceRole, setInstanceRole] = useState<'user' | 'owner'>(
    principal.instanceRole === 'owner' ? 'owner' : 'user',
  );
  const coffre = useCoffre();
  const setRole = useChange(changeRole(coffre));
  const remove = useChange(removeMember(coffre));
  const { status } = useChangeStatus(directoryList.queryKey);
  const pending = status(memberOf(principal)).state === 'pending';
  const kind = KIND[principal.principalType];

  if (principal.isRootAdmin) return null;

  return (
    <>
      <DropdownMenu.Root>
        <DropdownMenu.Trigger asChild>
          <button
            className={trigger}
            aria-label={`Actions for ${principal.principalId}`}
            disabled={pending}
          >
            {pending ? <Spinner size={13} /> : <MoreHorizontal size={16} />}
          </button>
        </DropdownMenu.Trigger>
        <DropdownMenu.Portal>
          <DropdownMenu.Content className="menu" sideOffset={6} align="end">
            {principal.principalType === 'user' && (
              <>
                <DropdownMenu.Item
                  className="menu-item"
                  onSelect={() => {
                    setInstanceRole(principal.instanceRole === 'owner' ? 'owner' : 'user');
                    setEditing(true);
                  }}
                >
                  <Pencil size={14} />
                  Change role
                </DropdownMenu.Item>
                <DropdownMenu.Separator className="menu-sep" />
              </>
            )}
            <DropdownMenu.Item
              className="menu-item menu-item-danger"
              onSelect={() => setConfirming(true)}
            >
              <X size={14} />
              Remove {kind}…
            </DropdownMenu.Item>
          </DropdownMenu.Content>
        </DropdownMenu.Portal>
      </DropdownMenu.Root>

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
              setRole({ principalId: principal.principalId, owner: instanceRole === 'owner' });
              setEditing(false);
            }}
          >
            <RoleField value={instanceRole} onChange={setInstanceRole} />
            <div className="dialog-actions">
              <button className="btn" type="button" onClick={() => setEditing(false)}>
                Cancel
              </button>
              <button className="btn btn-primary" type="submit">
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
        body={
          principal.principalType === 'user' ? (
            <>
              They are signed out everywhere, and their CLI logins, linked sign-in accounts and
              project permissions are revoked at once. Their past actions stay in the audit log,
              and their page then lists the values they saw, to rotate.
            </>
          ) : (
            <>
              Every token issued to it stops working and its project permissions are revoked at
              once, including for anything running with it right now. Its past actions stay in
              the audit log, and its page then lists the values it read, to rotate.
            </>
          )
        }
        confirmLabel={`Remove ${kind}`}
        onConfirm={() => remove(principal)}
      />
    </>
  );
}

export function AddPrincipal({ principalType }: { principalType: PrincipalType }) {
  const [open, setOpen] = useState(false);
  const [principalId, setPrincipalId] = useState('');
  const [instanceRole, setInstanceRole] = useState<'user' | 'owner'>('user');
  const add = useChange(invite(useCoffre()));
  const kind = KIND[principalType];

  function close() {
    setOpen(false);
    setPrincipalId('');
    setInstanceRole('user');
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
        description={`This lets the ${kind} through the door and nothing more. Grant project access from its page or from each project's.`}
      >
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            // Shown in the list at once; the list says if the server refuses.
            add({ principalType, principalId: principalId.trim(), owner: instanceRole === 'owner' });
            close();
          }}
        >
          <label className="field">
            <span className="label">
              {principalType === 'user' ? 'Cloudflare Access email' : 'Service token common name'}
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

          {principalType === 'user' && (
            <RoleField value={instanceRole} onChange={setInstanceRole} />
          )}

          <div className="dialog-actions">
            <button className="btn" type="button" onClick={close}>
              Cancel
            </button>
            <button className="btn btn-primary" type="submit" disabled={principalId.trim() === ''}>
              Add {kind}
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
}

function RoleField({
  value,
  onChange,
}: {
  value: 'user' | 'owner';
  onChange: (value: 'user' | 'owner') => void;
}) {
  return (
    <label className="field">
      <span className="label">Instance role</span>
      <select
        className="select"
        value={value}
        onChange={(event) => onChange(event.target.value as 'user' | 'owner')}
      >
        <option value="user">Member</option>
        <option value="owner">Owner</option>
      </select>
      <span className="hint">
        Owners manage users and tokens, can create projects, and read the whole audit log.
        Neither role reads a secret without a project grant.
      </span>
    </label>
  );
}

import { useEffect, useState } from 'react';
import { DropdownMenu } from 'radix-ui';
import { toast } from 'sonner';
import type { CoffreClient } from '../../../client/src/index.ts';
import { memberRef, Refusal, uiResult, useCoffre } from '../lib/coffre';
import { useAction } from '../lib/use-action';
import type { DirectoryPrincipal } from '../shared/models';
import { ConfirmDialog, EmptyState, ErrorLine, Modal, Spinner, Toggletip } from './ui';
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

/**
 * Everyone in the directory, and who was removed. The API shows grant
 * managers the members of their projects; the directory pages stay the
 * owners' own, and asking for anyone else would only log a refusal.
 */
export async function loadDirectory(client: CoffreClient, canManage: boolean) {
  if (!canManage) return { ok: false as const, error: 'Only owners can manage users and service accounts.' };
  return uiResult(async () => {
    const { members, removed } = await client.members.list();
    const principals: DirectoryPrincipal[] = members.map(
      ({ principalType, principalId, instanceRole, isRootAdmin }) => ({ principalType, principalId, instanceRole, isRootAdmin }),
    );
    return { principals, removed };
  });
}

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
}: {
  principalType: PrincipalType;
  principals: DirectoryPrincipal[];
}) {
  const users = principalType === 'user';
  return (
    <section className="card" aria-label={users ? 'Users' : 'Tokens'}>
      {principals.length === 0 ? (
        <EmptyState title={users ? 'Nobody is registered' : 'No tokens yet'}>
          Add the first {KIND[principalType]} to let it through the door. Project access is a
          separate step, granted from each project's page.
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
                    {users ? 'Email' : 'Common name'}
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
              {principals.map((principal, index) => (
                <tr key={principal.principalId} className="row-link">
                  <td className="n">{index + 1}</td>
                  <td
                    className="col-lead"
                    data-label={principal.principalType === 'user' ? 'Email' : 'Common name'}
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
                    <PrincipalActions principal={principal} />
                  </td>
                </tr>
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
  if (principal.isRootAdmin) {
    return (
      <Toggletip
        label={
          <>
            Set by <code>COFFRE_ROOT_ADMINS</code> in the deployment's configuration, so it
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
  onRemoved,
}: {
  principal: DirectoryPrincipal;
  /** The menu button's classes: a row action in tables, a button in a page head. */
  trigger?: string;
  onRemoved?: () => unknown;
}) {
  const [editing, setEditing] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [instanceRole, setInstanceRole] = useState<'user' | 'owner'>(
    principal.instanceRole === 'owner' ? 'owner' : 'user',
  );
  const coffre = useCoffre();
  const { pending, error, setError, run } = useAction();
  const kind = KIND[principal.principalType];

  useEffect(() => {
    if (error !== null && !editing) toast.error(error);
  }, [editing, error]);

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
          onOpenChange={(open) => {
            setEditing(open);
            if (!open) setError(null);
          }}
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
              void run(
                () =>
                  coffre.members.add(memberRef('user', principal.principalId), {
                    owner: instanceRole === 'owner',
                  }),
                () => {
                  toast.success(
                    `${principal.principalId} is now ${ROLE_LABEL[instanceRole].toLowerCase()}`,
                  );
                  setEditing(false);
                },
              );
            }}
          >
            <RoleField value={instanceRole} onChange={setInstanceRole} />
            <ErrorLine error={error} />
            <div className="dialog-actions">
              <button className="btn" type="button" onClick={() => setEditing(false)}>
                Cancel
              </button>
              <button className="btn btn-primary" type="submit" disabled={pending}>
                {pending && <Spinner />}
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
        onConfirm={() =>
          void run(
            () => coffre.members.remove(memberRef(principal.principalType, principal.principalId)),
            async () => {
              toast.success(`${principal.principalId} removed`);
              await onRemoved?.();
            },
          )
        }
      />
    </>
  );
}

export function AddPrincipal({ principalType }: { principalType: PrincipalType }) {
  const [open, setOpen] = useState(false);
  const [principalId, setPrincipalId] = useState('');
  const [instanceRole, setInstanceRole] = useState<'user' | 'owner'>('user');
  const coffre = useCoffre();
  const { pending, error, setError, run } = useAction();
  const kind = KIND[principalType];

  function close() {
    setOpen(false);
    setPrincipalId('');
    setInstanceRole('user');
    setError(null);
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
            void run(
              async () => {
                // Adding is an idempotent PUT that would also set the role of
                // someone already here; this form is only for someone new.
                const member = memberRef(principalType, principalId.trim());
                const { members } = await coffre.members.list();
                if (members.some((entry) => entry.member === member)) {
                  throw new Refusal('That principal already exists.');
                }
                await coffre.members.add(member, { owner: principalType === 'user' && instanceRole === 'owner' });
              },
              () => {
                toast.success(`${principalId.trim()} added`);
                close();
              },
            );
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
                principalType === 'user' ? 'someone@acme.example' : 'ci-deploy.access'
              }
              onChange={(event) => setPrincipalId(event.target.value)}
            />
          </label>

          {principalType === 'user' && (
            <RoleField value={instanceRole} onChange={setInstanceRole} />
          )}

          <ErrorLine error={error} />
          <div className="dialog-actions">
            <button className="btn" type="button" onClick={close}>
              Cancel
            </button>
            <button
              className="btn btn-primary"
              type="submit"
              disabled={pending || principalId.trim() === ''}
            >
              {pending && <Spinner />}
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

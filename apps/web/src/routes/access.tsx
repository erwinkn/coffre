import { useEffect, useState } from 'react';
import { createFileRoute } from '@tanstack/react-router';
import { DropdownMenu } from 'radix-ui';
import { toast } from 'sonner';
import {
  createDirectoryPrincipal,
  listDirectoryPrincipals,
  removeDirectoryPrincipal,
  updateDirectoryPrincipalRole,
} from '../server-functions/access';
import { useAction } from '../lib/use-action';
import type { DirectoryPrincipal } from '../shared/models';
import {
  ConfirmDialog,
  EmptyState,
  ErrorLine,
  Modal,
  Notice,
  Spinner,
} from '../components/ui';
import { Key, MoreHorizontal, Pencil, Plus, Users, X } from '../components/icons';

export const Route = createFileRoute('/access')({
  loader: () => listDirectoryPrincipals(),
  component: AccessPage,
});

function AccessPage() {
  const result = Route.useLoaderData();

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Access</h1>
          <p className="sub">
            Manage who can use Coffre. Project permissions are managed from each project.
          </p>
        </div>
      </div>

      {!result.ok ? (
        <Notice tone="bad">{result.error}</Notice>
      ) : (
        <>
          <PrincipalSection
            title="Users"
            description="People authenticated by their Cloudflare Access email."
            principalType="user"
            principals={result.principals.filter(
              (principal) => principal.principalType === 'user',
            )}
          />
          <PrincipalSection
            title="Service accounts"
            description="Machine callers matched on their Access service-token common name."
            principalType="service"
            principals={result.principals.filter(
              (principal) => principal.principalType === 'service',
            )}
          />
        </>
      )}
    </>
  );
}

function PrincipalSection({
  title,
  description,
  principalType,
  principals,
}: {
  title: string;
  description: string;
  principalType: 'user' | 'service';
  principals: DirectoryPrincipal[];
}) {
  return (
    <section className="section">
      <div className="section-head">
        <div>
          <h2>{title}</h2>
          <p className="sub">{description}</p>
        </div>
        <AddPrincipal principalType={principalType} />
      </div>

      <div className="card">
        {principals.length === 0 ? (
          <EmptyState
            icon={principalType === 'user' ? <Users size={26} /> : <Key size={26} />}
            title={`No ${title.toLowerCase()}`}
          >
            Add the first {principalType === 'user' ? 'user' : 'service account'}.
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{principalType === 'user' ? 'Email' : 'Common name'}</th>
                  {principalType === 'user' && <th>Role</th>}
                  <th className="shrink" />
                </tr>
              </thead>
              <tbody>
                {principals.map((principal) => (
                  <PrincipalRow key={principal.principalId} principal={principal} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}

function PrincipalRow({ principal }: { principal: DirectoryPrincipal }) {
  const [editing, setEditing] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [instanceRole, setInstanceRole] = useState<'user' | 'owner'>(
    principal.instanceRole === 'owner' ? 'owner' : 'user',
  );
  const { pending, error, setError, run } = useAction();

  useEffect(() => {
    if (error !== null && !editing) toast.error(error);
  }, [editing, error]);

  const roleLabel =
    principal.instanceRole === 'root-admin'
      ? 'Root admin'
      : principal.instanceRole === 'owner'
        ? 'Owner'
        : 'User';

  return (
    <tr>
      <td className="mono">{principal.principalId}</td>
      {principal.principalType === 'user' && (
        <td>
          <span
            className={`pill${principal.instanceRole === 'user' ? '' : ' pill-accent'}`}
          >
            {roleLabel}
          </span>
        </td>
      )}
      <td className="shrink">
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <button
              className="btn btn-sm btn-quiet btn-icon"
              aria-label={`Actions for ${principal.principalId}`}
              disabled={pending}
            >
              <MoreHorizontal size={16} />
            </button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content className="menu" sideOffset={6} align="end">
              {principal.isRootAdmin ? (
                <DropdownMenu.Item className="menu-item" disabled>
                  Managed in configuration
                </DropdownMenu.Item>
              ) : (
                <>
                  {principal.principalType === 'user' && (
                    <>
                      <DropdownMenu.Item
                        className="menu-item"
                        onSelect={() => {
                          setInstanceRole(
                            principal.instanceRole === 'owner' ? 'owner' : 'user',
                          );
                          setEditing(true);
                        }}
                      >
                        <Pencil size={14} />
                        Edit role
                      </DropdownMenu.Item>
                      <DropdownMenu.Separator className="menu-sep" />
                    </>
                  )}
                  <DropdownMenu.Item
                    className="menu-item menu-item-danger"
                    onSelect={() => setConfirming(true)}
                  >
                    <X size={14} />
                    Delete
                  </DropdownMenu.Item>
                </>
              )}
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>

        {principal.principalType === 'user' && !principal.isRootAdmin && (
          <Modal
            open={editing}
            onOpenChange={(open) => {
              setEditing(open);
              if (!open) setError(null);
            }}
            title={`Edit ${principal.principalId}`}
            description="Owners can manage users and service accounts and access the full audit log."
          >
            <form
              className="dialog-form stack"
              onSubmit={(event) => {
                event.preventDefault();
                void run(
                  () =>
                    updateDirectoryPrincipalRole({
                      data: { principalId: principal.principalId, instanceRole },
                    }),
                  () => {
                    toast.success(`${principal.principalId} is now ${instanceRole}`);
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

        {!principal.isRootAdmin && (
          <ConfirmDialog
            open={confirming}
            onOpenChange={setConfirming}
            title={`Delete ${principal.principalId}?`}
            body="This removes the identity and immediately revokes all of its project permissions."
            confirmLabel={`Delete ${
              principal.principalType === 'user' ? 'user' : 'service account'
            }`}
            onConfirm={() =>
              void run(
                () =>
                  removeDirectoryPrincipal({
                    data: {
                      principalType: principal.principalType,
                      principalId: principal.principalId,
                    },
                  }),
                () => toast.success(`${principal.principalId} deleted`),
              )
            }
          />
        )}
      </td>
    </tr>
  );
}

function AddPrincipal({ principalType }: { principalType: 'user' | 'service' }) {
  const [open, setOpen] = useState(false);
  const [principalId, setPrincipalId] = useState('');
  const [instanceRole, setInstanceRole] = useState<'user' | 'owner'>('user');
  const { pending, error, setError, run } = useAction();

  function close() {
    setOpen(false);
    setPrincipalId('');
    setInstanceRole('user');
    setError(null);
  }

  const kind = principalType === 'user' ? 'user' : 'service account';

  return (
    <>
      <button className="btn btn-sm" onClick={() => setOpen(true)}>
        <Plus size={13} />
        Add
      </button>

      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title={`Add ${kind}`}
        description={
          principalType === 'user'
            ? 'Add a user to Coffre. Project permissions are assigned from each project.'
            : 'Add a service account to Coffre. Project permissions are assigned from each project.'
        }
      >
        <form
          className="dialog-form stack"
          onSubmit={(event) => {
            event.preventDefault();
            void run(
              () =>
                createDirectoryPrincipal({
                  data: {
                    principalType,
                    principalId: principalId.trim(),
                    instanceRole: principalType === 'user' ? instanceRole : 'user',
                  },
                }),
              () => {
                toast.success(`${principalId.trim()} added`);
                close();
              },
            );
          }}
        >
          <label className="field">
            <span className="label">
              {principalType === 'user' ? 'Email' : 'Service token common name'}
            </span>
            <input
              className="input"
              autoFocus
              value={principalId}
              placeholder={
                principalType === 'user' ? 'someone@equisafe.io' : 'ci-deploy.access'
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
              Add
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
      <span className="label">Role</span>
      <select
        className="select"
        value={value}
        onChange={(event) => onChange(event.target.value as 'user' | 'owner')}
      >
        <option value="user">User</option>
        <option value="owner">Owner</option>
      </select>
      <span className="meta">
        Owners can manage users and service accounts and access the full audit log.
      </span>
    </label>
  );
}

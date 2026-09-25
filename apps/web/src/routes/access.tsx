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
  Spinner,
} from '../components/ui';
import { Card, ClosedDoor, PageHeader } from '../components/page';
import { Key, MoreHorizontal, Pencil, Plus, ShieldCheck, User, Users, X } from '../components/icons';

export const Route = createFileRoute('/access')({
  loader: () => listDirectoryPrincipals(),
  component: DirectoryPage,
});

function DirectoryPage() {
  const result = Route.useLoaderData();

  if (!result.ok) {
    return (
      <ClosedDoor icon={<Users size={18} />} label="Directory" title="The directory is closed to you">
        {result.error}
      </ClosedDoor>
    );
  }

  const people = result.principals.filter((principal) => principal.principalType === 'user');
  const services = result.principals.filter(
    (principal) => principal.principalType === 'service',
  );

  return (
    <>
      <PageHeader
        title="Directory"
        description="Who may use coffre at all. Being listed here grants nothing by itself: what each identity can do is granted per project, from that project's page."
        meta={
          <>
            <span>
              <strong>{people.length}</strong> {people.length === 1 ? 'person' : 'people'}
            </span>
            <span>
              <strong>{services.length}</strong> service account
              {services.length === 1 ? '' : 's'}
            </span>
          </>
        }
      />

      <PrincipalSection
        title="People"
        description="Matched on the email Cloudflare Access authenticates."
        principalType="user"
        principals={people}
      />
      <PrincipalSection
        title="Service accounts"
        description="Machine callers, matched on their Access service-token common name, because those tokens carry no email at all."
        principalType="service"
        principals={services}
      />
    </>
  );
}

const ROLE_LABEL: Record<DirectoryPrincipal['instanceRole'], string> = {
  'root-admin': 'Root admin',
  owner: 'Owner',
  user: 'User',
};

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
  const people = principalType === 'user';
  return (
    <Card
      labelledBy={`directory-${principalType}`}
      title={title}
      description={description}
      actions={<AddPrincipal principalType={principalType} />}
    >
      {principals.length === 0 ? (
        <EmptyState title={people ? 'Nobody is registered' : 'No service accounts'}>
          Add the first {people ? 'person' : 'service account'} to let it through the door.
          Project access is a separate step.
        </EmptyState>
      ) : (
        <div className="dt-wrap">
          <table className="dt grants stacks">
            <thead>
              <tr>
                <th className="n">#</th>
                <th className="col-principal">
                  <span className="th">
                    {people ? <User size={14} /> : <Key size={14} />}
                    {people ? 'Email' : 'Common name'}
                  </span>
                </th>
                <th>
                  <span className="th">
                    <ShieldCheck size={14} />
                    {people ? 'Instance role' : 'Kind'}
                  </span>
                </th>
                <th className="col-actions">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {principals.map((principal, index) => (
                <PrincipalRow
                  key={principal.principalId}
                  number={index + 1}
                  principal={principal}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function PrincipalRow({
  number,
  principal,
}: {
  number: number;
  principal: DirectoryPrincipal;
}) {
  const [editing, setEditing] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [instanceRole, setInstanceRole] = useState<'user' | 'owner'>(
    principal.instanceRole === 'owner' ? 'owner' : 'user',
  );
  const { pending, error, setError, run } = useAction();
  const kind = principal.principalType === 'user' ? 'person' : 'service account';

  useEffect(() => {
    if (error !== null && !editing) toast.error(error);
  }, [editing, error]);

  return (
    <tr>
      <td className="n">{number}</td>
      <td
        className="cell-mono"
        data-label={principal.principalType === 'user' ? 'Email' : 'Common name'}
      >
        {principal.principalId}
      </td>
      {principal.principalType === 'user' ? (
        <td data-label="Instance role">
          <span className={`tag${principal.instanceRole === 'user' ? '' : ' tag-violet'}`}>
            {ROLE_LABEL[principal.instanceRole]}
          </span>
          {principal.isRootAdmin && <span className="hint"> · set in deployment config</span>}
        </td>
      ) : (
        <td className="cell-muted" data-label="Kind">
          Service token
        </td>
      )}
      <td className="col-actions">
        {principal.isRootAdmin ? (
          <span className="cell-muted" style={{ fontSize: '0.8125rem' }}>
            —
          </span>
        ) : (
          <DropdownMenu.Root>
            <DropdownMenu.Trigger asChild>
              <button
                className="act act-quiet"
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
                  Remove from directory…
                </DropdownMenu.Item>
              </DropdownMenu.Content>
            </DropdownMenu.Portal>
          </DropdownMenu.Root>
        )}

        {principal.principalType === 'user' && !principal.isRootAdmin && (
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
                    updateDirectoryPrincipalRole({
                      data: { principalId: principal.principalId, instanceRole },
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

        {!principal.isRootAdmin && (
          <ConfirmDialog
            open={confirming}
            onOpenChange={setConfirming}
            title={
              <>
                Remove <span className="mono">{principal.principalId}</span>?
              </>
            }
            body={
              <>
                The {kind} can no longer use coffre, and every project permission it holds is
                revoked at once, including for anything running with it right now. Its past
                actions stay in the audit log.
              </>
            }
            confirmLabel={`Remove ${kind}`}
            onConfirm={() =>
              void run(
                () =>
                  removeDirectoryPrincipal({
                    data: {
                      principalType: principal.principalType,
                      principalId: principal.principalId,
                    },
                  }),
                () => toast.success(`${principal.principalId} removed`),
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

  const kind = principalType === 'user' ? 'person' : 'service account';

  return (
    <>
      <button className="btn btn-sm" onClick={() => setOpen(true)}>
        <Plus size={13} />
        Add {kind}
      </button>

      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title={`Add a ${kind}`}
        description={`This lets the ${kind} through the door and nothing more. Grant project access from each project's page.`}
      >
        <form
          className="form"
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
              {principalType === 'user' ? 'Cloudflare Access email' : 'Service token common name'}
            </span>
            <input
              className="input input-mono"
              autoFocus
              spellCheck={false}
              autoComplete="off"
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
        <option value="user">User</option>
        <option value="owner">Owner</option>
      </select>
      <span className="hint">
        Owners manage this directory, can create projects, and read the whole audit log.
        Neither role reads a secret without a project grant.
      </span>
    </label>
  );
}

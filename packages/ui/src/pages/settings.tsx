import { useState } from 'react';
import type { RouteOutput } from '@coffre/client';
import { scopeInWords, unscoped, type Scope } from '@coffre/core/access';
import { useSuspenseQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { toast } from 'sonner';
import { useCoffre } from '../lib/coffre';
import { affects, queries } from '../lib/queries';
import { useAction } from '../lib/use-action';
import { useShell } from '../lib/use-shell';
import { Card, Fact, PageHeader } from '../components/page';
import { ScopeField } from '../components/role-field';
import { ErrorLine, Modal, Spinner, Toggletip } from '../components/ui';
import { Info, Pencil } from '../components/icons';

/** The instance's settings. Your own are under Account, at the sidebar's foot. */

export function SettingsPage() {
  const { auth, capabilities } = useShell();
  const client = useCoffre();
  const { data: directory } = useSuspenseQuery(queries.directory(client, capabilities.canManageGrants));
  const { data: keys } = useSuspenseQuery(queries.auditKeys(client, capabilities.runsInstance));
  const { data: settings } = useSuspenseQuery(queries.settings(client, capabilities.runsInstance));
  const providers = auth?.signin?.providers.map((provider) => provider.label) ?? [];

  const principals = directory?.ok === true ? directory.principals : null;
  const rootAdmins = principals?.filter((entry) => entry.isRootAdmin) ?? [];
  const users = principals?.filter((entry) => entry.principalType === 'user').length ?? 0;
  const tokens = principals?.filter((entry) => entry.principalType === 'service').length ?? 0;

  return (
    <>
      <PageHeader title="Settings" />

      <Card
        labelledBy="instance"
        title="Instance"
        description="Set in the deployment's configuration, not here."
      >
        <dl className="facts">
          <Fact label="Sign-in">
            <span>
              {auth?.signin ? providers.join(', ') : 'Cloudflare Access'}
              <Toggletip
                label={
                  auth?.signin
                    ? 'coffre’s own sign-in. Only invited members get in.'
                    : 'Cloudflare Access signs people in, and coffre verifies each request.'
                }
              >
                <button type="button" className="fact-tip" aria-label="About sign-in">
                  <Info size={14} />
                </button>
              </Toggletip>
            </span>
          </Fact>
          {principals !== null && (
            <>
              <Fact label="Root admins">
                <span className="fact-list">
                  {rootAdmins.map((admin) => (
                    <span key={admin.principalId} className="mono">
                      {admin.principalId}
                    </span>
                  ))}
                </span>
              </Fact>
              <Fact label="Directory">
                <span>
                  <Link to="/users">
                    {users} user{users === 1 ? '' : 's'}
                  </Link>
                  {' · '}
                  <Link to="/service-accounts">
                    {tokens} service account{tokens === 1 ? '' : 's'}
                  </Link>
                </span>
              </Fact>
            </>
          )}
        </dl>
      </Card>

      {settings?.ok === true && <ServiceSetup scope={settings.serviceAccounts} />}
      {keys?.ok === true && <Keys keys={keys} />}
    </>
  );
}

/**
 * Who sets up service accounts without running the instance: anyone who
 * holds access, inside this scope, giving one at most what they hold there.
 * Narrowed, the rest takes an Admin whose own scope reaches it.
 */
function ServiceSetup({ scope }: { scope: Scope }) {
  const client = useCoffre();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(scope);
  const { pending, error, setError, run } = useAction();
  const close = () => {
    setOpen(false);
    setDraft(scope);
    setError(null);
  };
  return (
    <Card
      labelledBy="service-setup"
      title="Service accounts"
      description="Anyone who holds access sets up service accounts for CI where this lets them: the account, its tokens and its OIDC trust, giving it at most what they hold. Elsewhere, an Admin whose scope reaches it does."
      actions={
        <button className="btn" type="button" onClick={() => setOpen(true)}>
          <Pencil size={14} />
          Edit
        </button>
      }
    >
      <dl className="facts">
        <Fact label="Set up by people in">
          <span>{unscoped(scope) ? 'Every project and environment' : scopeInWords(scope)}</span>
        </Fact>
      </dl>
      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title="Who sets up service accounts"
        description="People set up service accounts, and give them what they hold, in these projects and environments. All except prod keeps prod's to Admins."
      >
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            run(() => client.settings.set({ serviceAccounts: draft }), {
              affects: affects.settings(),
              onSuccess: () => {
                toast.success('Saved where people set up service accounts');
                setOpen(false);
                setError(null);
              },
            });
          }}
        >
          <ScopeField legend="Where" scope={draft} onChange={setDraft} />
          <ErrorLine error={error} />
          <div className="dialog-actions">
            <button className="btn" type="button" onClick={close}>
              Cancel
            </button>
            <button className="btn btn-primary" type="submit" disabled={pending}>
              {pending && <Spinner />}
              Save
            </button>
          </div>
        </form>
      </Modal>
    </Card>
  );
}

/**
 * What the keys you keep are checked against: no secret, so shown. The keys
 * themselves are checked by `coffre verify keys`, on your machine: a vault
 * key typed into a web page would be within reach of everything running in it.
 */
function Keys({ keys }: { keys: RouteOutput<'GET /audit/keys'> }) {
  const { current, checks } = keys.vault;
  const replaced = new Set(checks.map((check) => check.vaultId).filter((id) => id !== current.vaultId)).size;
  return (
    <Card
      labelledBy="keys"
      title="Keys"
      description={
        <>
          To check your vault key and app key against these, run <code>coffre verify keys</code>.
          It reads them on your machine and sends neither.
        </>
      }
    >
      <dl className="facts">
        <Fact label="Vault ID">
          <span className="mono">{current.vaultId}</span>
        </Fact>
        <Fact label="Vault key">
          <span>
            Held by <span className="mono">{current.provider}</span>
            {replaced > 0 && `; ${replaced} earlier vault key${replaced === 1 ? '' : 's'} still checkable`}
          </span>
        </Fact>
        <Fact label="App key">
          <span className="mono">{keys.app.keyId}</span>
        </Fact>
      </dl>
    </Card>
  );
}


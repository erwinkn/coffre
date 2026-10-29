import { useState } from 'react';
import type { RouteOutput } from '@coffre/client';
import { scopeInWords, unscoped, type Scope } from '@coffre/core/access';
import { useSuspenseQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { toast } from 'sonner';
import { useCoffre } from '../lib/coffre';
import { pageRoute } from '../lib/page-route';
import { affects, queries } from '../lib/queries';
import { useAction } from '../lib/use-action';
import { useShell } from '../lib/use-shell';
import { Card, Fact, PageHeader } from '../components/page';
import { ScopeField } from '../components/role-field';
import { RolesSettings } from '../components/role-editor';
import { PageTabs } from '../components/tabs';
import { ErrorLine, Modal, Spinner, Toggletip } from '../components/ui';
import { Info, Key, Pencil, Settings, ShieldCheck, UserCog } from '../components/icons';
import type { settings as settingsRoute } from '../options';

const Route = pageRoute<typeof settingsRoute>();

/**
 * The instance's settings, a tab each: General, the instance and who
 * creates service accounts; Roles; Instance roles; Keys, for whoever runs
 * the instance. Your own settings are under Account, at the sidebar's foot.
 */
export function SettingsPage() {
  const { tab } = Route.useSearch();
  const { capabilities } = useShell();
  // One route, its tab in the search: a tab's link is current only for its own.
  const current = { exact: true, includeSearch: true } as const;
  return (
    <>
      <PageHeader title="Settings" />
      <PageTabs label="Settings sections">
        {[
          <Link key="general" to="/settings" search={{}} activeOptions={current}>
            <Settings size={15} />
            General
          </Link>,
          <Link key="roles" to="/settings" search={{ tab: 'roles' }} activeOptions={current}>
            <ShieldCheck size={15} />
            Roles
          </Link>,
          <Link key="instance-roles" to="/settings" search={{ tab: 'instance-roles' }} activeOptions={current}>
            <UserCog size={15} />
            Instance roles
          </Link>,
          capabilities.runsInstance && (
            <Link key="keys" to="/settings" search={{ tab: 'keys' }} activeOptions={current}>
              <Key size={15} />
              Keys
            </Link>
          ),
        ]}
      </PageTabs>
      {tab === undefined ? (
        <General />
      ) : tab === 'keys' ? (
        <KeysTab />
      ) : (
        <RolesSettings kind={tab === 'roles' ? 'role' : 'instance-role'} />
      )}
    </>
  );
}

/** The instance, as its deployment set it up, and who creates service accounts. */
function General() {
  const { auth, capabilities } = useShell();
  const client = useCoffre();
  const { data: directory } = useSuspenseQuery(queries.directory(client, capabilities.canManageGrants));
  const { data: settings } = useSuspenseQuery(queries.settings(client, capabilities.runsInstance));
  const providers = auth?.signin?.providers.map((provider) => provider.label) ?? [];

  const principals = directory?.ok === true ? directory.principals : null;
  const users = principals?.filter((entry) => entry.principalType === 'user').length ?? 0;
  const tokens = principals?.filter((entry) => entry.principalType === 'service').length ?? 0;

  return (
    <>
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
          )}
        </dl>
      </Card>
      {settings?.ok === true && <ServiceSetup scope={settings.serviceAccounts} />}
    </>
  );
}

/**
 * Who creates service accounts without running the instance, and where:
 * anyone who holds access, inside this scope, giving one at most what they
 * hold there. Narrowed, the rest takes an Admin whose own scope reaches it.
 */
function serviceSetupInWords(scope: Scope): string {
  if (unscoped(scope)) return 'Anyone with access, in every project and environment';
  const { projects, environments } = scope;
  if ((projects !== 'all' && 'only' in projects && projects.only.length === 0) || (environments !== 'all' && 'only' in environments && environments.only.length === 0)) {
    return 'Admins only';
  }
  const where = scopeInWords(scope);
  return `Anyone with access, in ${where.charAt(0).toLowerCase()}${where.slice(1)}; elsewhere, Admins`;
}

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
    <Card labelledBy="service-setup" title="Service accounts">
      <dl className="facts">
        <Fact
          label="Who creates them"
          action={
            <button className="btn btn-sm" type="button" onClick={() => setOpen(true)} aria-label="Edit who creates service accounts">
              <Pencil size={14} />
              Edit
            </button>
          }
        >
          <span>{serviceSetupInWords(scope)}</span>
        </Fact>
      </dl>
      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title="Who creates service accounts"
        description="Anyone with access creates service accounts in these projects and environments, giving them at most what they hold there; elsewhere, Admins do. All except prod keeps prod's to Admins."
      >
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            run(() => client.settings.set({ serviceAccounts: draft }), {
              affects: affects.settings(),
              onSuccess: () => {
                toast.success('Saved who creates service accounts');
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

function KeysTab() {
  const { capabilities } = useShell();
  const { data: keys } = useSuspenseQuery(queries.auditKeys(useCoffre(), capabilities.runsInstance));
  if (keys === null) return null;
  return keys.ok ? <Keys keys={keys} /> : <ErrorLine error={`The keys could not be read. ${keys.error}`} />;
}

/** Where a vault key is kept, in words: the deployment's own, or a key service's. */
function keptIn(provider: string): string {
  if (provider === 'local') return "kept in the deployment's configuration";
  if (provider === 'aws-kms') return 'kept in AWS KMS';
  return `kept in ${provider}`;
}

/** A key's identifier by its end, `…3f9a2c`, enough to tell it from another; the whole of it a hover away. */
function KeyId({ id }: { id: string }) {
  return (
    <span className="mono" title={id}>
      {id.length <= 8 ? id : `…${id.slice(-6)}`}
    </span>
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
        </>
      }
    >
      <dl className="facts">
        <Fact label="Vault key">
          <span>
            <KeyId id={current.vaultId} /> <span className="muted">· {keptIn(current.provider)}</span>
          </span>
          {replaced > 0 && (
            <span className="muted">
              {replaced} earlier vault key{replaced === 1 ? '' : 's'} still checkable
            </span>
          )}
        </Fact>
        <Fact label="App key">
          <KeyId id={keys.app.keyId} />
        </Fact>
      </dl>
    </Card>
  );
}

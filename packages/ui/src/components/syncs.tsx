import { Fragment, useEffect, useState, type ReactNode } from 'react';
import { useRouter } from '@tanstack/react-router';
import { DropdownMenu } from 'radix-ui';
import { toast } from 'sonner';
import { useCoffre } from '../lib/coffre';
import { useAction } from '../lib/use-action';
import {
  DESTINATIONS,
  destination,
  destinationConfig,
  firstMissing,
  initialValues,
  isAsked,
  type DestinationKind,
  type FormValues,
} from '../../../client/src/index.ts';
import type { RunOutcome, SyncView } from '../shared/models';
import { Card } from './page';
import { ConfirmDialog, EmptyState, ErrorLine, Modal, Notice, Spinner, Timestamp, Toggletip } from './ui';
import { AlertTriangle, DestinationMark, MoreHorizontal, Pause, Play, Plus, Sync, X } from './icons';

/** How often the card refreshes while a run is in flight. */
const RUNNING_POLL_MS = 2000;

type SyncsResult = { ok: true; syncs: SyncView[]; canManage: boolean } | { ok: false; error: string };

/**
 * Where this environment's secrets are pushed.
 *
 * Hidden from people who can neither see a sync nor add one; everyone who can
 * write a secret sees them, since saving one sends it on.
 */
export function Syncs({
  project,
  environment,
  result,
  canRun,
}: {
  project: string;
  environment: string;
  result: SyncsResult;
  canRun: boolean;
}) {
  const router = useRouter();
  const running = result.ok && result.syncs.some((sync) => sync.running);

  // A save starts a run in the background; watch it land.
  useEffect(() => {
    if (!running) return;
    const timer = setInterval(() => void router.invalidate(), RUNNING_POLL_MS);
    return () => clearInterval(timer);
  }, [running, router]);

  if (result.ok && result.syncs.length === 0 && !result.canManage) return null;
  const canManage = result.ok && result.canManage;

  return (
    <Card
      labelledBy="syncs"
      title="Syncs"
      description="Destinations these secrets are pushed to. A change goes out when it is saved, and every hour coffre checks each destination and repairs what drifted."
      actions={canManage ? <AddSync project={project} environment={environment} /> : undefined}
    >
      {!result.ok ? (
        <div className="card-body">
          <ErrorLine error={result.error} />
        </div>
      ) : result.syncs.length === 0 ? (
        <EmptyState title="Not synced anywhere">
          Push these secrets to GitHub Actions, Vercel, Railway or Cloudflare Workers, and keep
          them current there. Anything else can read them with <code>coffre run</code>.
        </EmptyState>
      ) : (
        <div className="dt-wrap">
          <table className="dt syncs">
            <thead>
              <tr>
                <th>Destination</th>
                <th className="col-shrink">Status</th>
                <th className="col-shrink col-hide-narrow">Token</th>
                <th className="col-actions">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {result.syncs.map((sync) => (
                <SyncRow key={sync.id} sync={sync} canRun={canRun} canManage={canManage} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function SyncRow({ sync, canRun, canManage }: { sync: SyncView; canRun: boolean; canManage: boolean }) {
  const [removing, setRemoving] = useState(false);
  const coffre = useCoffre();
  // Apart, so pausing does not spin the Run now button.
  const pushing = useAction();
  const managing = useAction();
  const pending = pushing.pending || managing.pending;
  const error = pushing.error ?? managing.error;

  function runNow() {
    pushing.run(
      () => coffre.syncs.run(sync.id),
      (result) => announce(sync, result.outcome),
    );
  }

  function setPaused(paused: boolean) {
    managing.run(
      () => coffre.syncs.update(sync.id, { paused }),
      () =>
        toast.success(paused ? `Paused ${sync.destination}` : `Resumed ${sync.destination}`, {
          action: { label: 'Undo', onClick: () => setPaused(!paused) },
        }),
    );
  }

  return (
    <>
      <tr>
        <td>
          <span className="cell-account">
            <DestinationMark provider={sync.provider} size={15} />
            <span className="cell-stack">
              <span>{sync.providerLabel}</span>
              <small className="mono">{sync.destination}</small>
            </span>
          </span>
        </td>
        <td className="nowrap">
          <span className="cell-stack">
            <SyncState sync={sync} />
            <small>
              <Counts sync={sync} />
            </small>
          </span>
        </td>
        <td className="col-shrink col-hide-narrow cell-mono cell-muted">{sync.credential}</td>
        <td className="col-actions">
          <div className="acts">
            {canRun && !sync.paused && (
              <button className="act" onClick={runNow} disabled={pending || sync.running}>
                {pushing.pending ? <Spinner size={13} /> : <Sync size={13} />}
                Run now
              </button>
            )}
            {canManage && (
              <DropdownMenu.Root>
                <DropdownMenu.Trigger asChild>
                  <button
                    className="act act-icon act-quiet"
                    aria-label={`More for ${sync.destination}`}
                    disabled={pending}
                  >
                    <MoreHorizontal size={16} />
                  </button>
                </DropdownMenu.Trigger>
                <DropdownMenu.Portal>
                  <DropdownMenu.Content className="menu" sideOffset={6} align="end">
                    <DropdownMenu.Item className="menu-item" onSelect={() => setPaused(!sync.paused)}>
                      {sync.paused ? <Play size={14} /> : <Pause size={14} />}
                      {sync.paused ? 'Resume' : 'Pause'}
                    </DropdownMenu.Item>
                    <DropdownMenu.Separator className="menu-sep" />
                    <DropdownMenu.Item
                      className="menu-item menu-item-danger"
                      onSelect={() => setRemoving(true)}
                    >
                      <X size={14} />
                      Remove
                    </DropdownMenu.Item>
                  </DropdownMenu.Content>
                </DropdownMenu.Portal>
              </DropdownMenu.Root>
            )}
          </div>
          <ConfirmDialog
            open={removing}
            onOpenChange={setRemoving}
            title={
              <>
                Stop syncing to <span className="mono">{sync.destination}</span>?
              </>
            }
            body={`Nothing more is pushed to ${sync.providerLabel}. Keys coffre already pushed stay there; remove them at ${sync.providerLabel} if they should go too.`}
            confirmLabel="Remove sync"
            onConfirm={() =>
              managing.run(
                () => coffre.syncs.remove(sync.id),
                () => toast.success(`No longer syncing to ${sync.destination}`),
              )
            }
          />
        </td>
      </tr>
      {(sync.lastError !== null || error !== null) && !sync.running && (
        <tr className="row-error">
          <td colSpan={4}>
            <ErrorLine error={error ?? sync.lastError} />
          </td>
        </tr>
      )}
    </>
  );
}

/** One tag for the state that matters most right now. */
function SyncState({ sync }: { sync: SyncView }) {
  if (sync.running) {
    return (
      <span className="tag tag-blue">
        <Spinner size={11} />
        Pushing
      </span>
    );
  }
  if (sync.paused) return <span className="tag tag-outline">Paused</span>;
  if (sync.lastStatus === 'failed') return <span className="tag tag-red">Failed</span>;
  if (sync.pending > 0) return <span className="tag tag-amber">{sync.pending} pending</span>;
  if (sync.lastStatus === 'partial') return <span className="tag tag-amber">Partial</span>;
  if (sync.lastRunAt === null) return <span className="tag">Not run yet</span>;
  return <span className="tag tag-green">In sync</span>;
}

function Counts({ sync }: { sync: SyncView }) {
  const skipped = sync.skipped.length;
  const parts: ReactNode[] = [];
  if (sync.synced > 0 || sync.pending === 0) parts.push(`${sync.synced} synced`);
  if (sync.pending > 0) parts.push(`${sync.pending} pending`);
  if (skipped > 0) {
    parts.push(
      <Toggletip
        label={
          <ul style={{ margin: 0, paddingLeft: '1rem' }}>
            {sync.skipped.map((entry) => (
              <li key={entry.key}>
                <span className="mono">{entry.key}</span>: {entry.reason}
              </li>
            ))}
          </ul>
        }
      >
        <button type="button" className="tag tag-amber tag-button">
          <AlertTriangle size={11} />
          {skipped} skipped
        </button>
      </Toggletip>,
    );
  }
  if (sync.lastRunAt !== null) parts.push(<Timestamp iso={sync.lastRunAt} display="relative" />);
  return (
    <>
      {parts.map((part, index) => (
        <Fragment key={index}>
          {index > 0 && ' · '}
          {part}
        </Fragment>
      ))}
    </>
  );
}

function announce(sync: SyncView, outcome: RunOutcome) {
  if (outcome.status === 'busy') {
    toast('A run is already under way', { description: 'Its result appears here when it ends.' });
    return;
  }
  const changed = outcome.upserted.length + outcome.deleted.length;
  if (outcome.status === 'failed') {
    toast.error(`Could not sync to ${sync.destination}`, { description: outcome.error ?? undefined });
  } else if (outcome.status === 'partial') {
    toast.warning(`${outcome.failed.length} of ${changed + outcome.failed.length} changes failed`, {
      description: outcome.failed[0]?.message,
    });
  } else if (changed === 0) {
    toast.success(`${sync.destination} was already current`);
  } else {
    const parts = [
      outcome.upserted.length > 0 && `pushed ${outcome.upserted.length}`,
      outcome.deleted.length > 0 && `removed ${outcome.deleted.length}`,
    ].filter(Boolean);
    toast.success(`${capitalize(parts.join(', '))} to ${sync.destination}`);
  }
}

function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function AddSync({ project, environment }: { project: string; environment: string }) {
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<DestinationKind>('github-actions');
  const [values, setValues] = useState<FormValues>(() => initialValues(destination(kind)));
  const [credential, setCredential] = useState('');
  const coffre = useCoffre();
  const { pending, error, setError, run } = useAction();

  const entry = destination(kind);
  const missing = firstMissing(entry, values);

  function pick(next: DestinationKind) {
    setKind(next);
    setValues(initialValues(destination(next)));
    setError(null);
  }

  function close() {
    setOpen(false);
    pick('github-actions');
    setCredential('');
  }

  function set(name: string, value: string | string[]) {
    setValues((current) => ({ ...current, [name]: value }));
  }

  return (
    <>
      <button className="btn btn-sm" onClick={() => setOpen(true)}>
        <Plus size={14} />
        Add sync
      </button>
      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title={
          <>
            Sync <span className="mono">{project}/{environment}</span>
          </>
        }
        description="Every key in this environment is pushed to the destination and kept current. coffre only ever removes keys it pushed itself."
        wide
      >
        <form
          className="form"
          style={{ marginTop: '1.25rem' }}
          onSubmit={(event) => {
            event.preventDefault();
            run(
              () =>
                coffre.syncs.add(`${project}/${environment}`, {
                  provider: kind,
                  config: destinationConfig(entry, values),
                  credential: credential.trim(),
                }),
              (sync) => {
                toast.success(`Syncing to ${sync.destination}`, {
                  description: 'The first push has started.',
                });
                close();
              },
            );
          }}
        >
          <div className="choice-grid destinations" role="group" aria-label="Destination">
            {DESTINATIONS.map((option) => (
              <button
                key={option.kind}
                type="button"
                className="choice"
                aria-pressed={option.kind === kind}
                onClick={() => pick(option.kind)}
              >
                <DestinationMark provider={option.kind} />
                {option.label}
              </button>
            ))}
          </div>

          <div className="form-row">
            {entry.fields.map((field) => {
              if (!isAsked(field, values)) return null;
              if (field.type === 'text') {
                return (
                  <label key={`${kind}.${field.name}`} className="field">
                    <span className="label">
                      {field.label}
                      {field.optional === true && <span className="hint"> (optional)</span>}
                    </span>
                    <input
                      className="input input-mono"
                      value={values[field.name] as string}
                      placeholder={field.placeholder}
                      spellCheck={false}
                      autoComplete="off"
                      onChange={(event) => set(field.name, event.target.value)}
                    />
                    {field.hint !== undefined && <span className="hint">{field.hint}</span>}
                  </label>
                );
              }
              const picked = values[field.name] as string[];
              return (
                <div key={`${kind}.${field.name}`} className="field" role="group" aria-label={field.label}>
                  <span className="label">{field.label}</span>
                  <div className="segmented">
                    {field.options.map((option) => (
                      <button
                        key={option.value}
                        type="button"
                        aria-pressed={picked.includes(option.value)}
                        onClick={() =>
                          set(
                            field.name,
                            !field.multiple
                              ? [option.value]
                              : picked.includes(option.value)
                                ? picked.filter((value) => value !== option.value)
                                : [...picked, option.value],
                          )
                        }
                      >
                        {option.label}
                      </button>
                    ))}
                  </div>
                  {field.hint !== undefined && <span className="hint">{field.hint}</span>}
                </div>
              );
            })}
          </div>

          <label className="field">
            <span className="label">Token</span>
            <input
              className="input input-mono"
              value={credential}
              placeholder={entry.credentialExample}
              spellCheck={false}
              autoComplete="off"
              onChange={(event) => setCredential(event.target.value)}
            />
            <span className="hint">
              The secret that holds it, as <code>project/environment/KEY</code>. An environment of
              its own, such as <code>ops/sync</code>, keeps it from everyone who reads these
              secrets. You need read access to it.
            </span>
          </label>

          <Notice tone="info">{entry.token}</Notice>

          <ErrorLine error={error} />

          <div className="dialog-actions">
            <button className="btn" type="button" onClick={close}>
              Cancel
            </button>
            <button
              className="btn btn-primary"
              type="submit"
              disabled={pending || missing !== null || credential.trim() === ''}
              title={missing !== null ? `${missing} is required` : undefined}
            >
              {pending && <Spinner />}
              Start syncing
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
}

import type { ServiceTokenRow } from '@coffre/client';
import { Fragment, useState } from 'react';
import { revokeCredential } from '../lib/changes';
import { memberRef, useCoffre } from '../lib/coffre';
import { affects } from '../lib/queries';
import { useAction } from '../lib/use-action';
import { useChange, useChangeStatus } from '../lib/use-change';
import { RowFailure, RowPending, rowClass } from './row-state';
import { Card } from './page';
import { ConfirmButton, CopyButton, EmptyState, ErrorLine, Modal, Notice, Spinner, Timestamp } from './ui';
import { Key, Plus, X } from './icons';

const LIFETIMES = [30, 90, 180, 365] as const;

/**
 * The bearer tokens a service presents to the API. A value exists in exactly
 * one place, this dialog, for as long as it stays open: coffre keeps a hash.
 */
export function ServiceTokens({ serviceId, tokens }: { serviceId: string; tokens: ServiceTokenRow[] }) {
  const change = revokeCredential(useCoffre(), serviceId);
  const revoke = useChange(change);
  const { status, dismiss } = useChangeStatus(change.list.queryKey);

  return (
    <Card
      labelledBy="service-tokens"
      title="Credentials"
      description="Bearer tokens this service presents to the API. Each is shown once, when it is issued; coffre keeps only a hash."
      actions={<IssueToken serviceId={serviceId} />}
    >
      {tokens.length === 0 ? (
        <EmptyState title="No live credentials">
          Nothing can act as this service until a token is issued.
        </EmptyState>
      ) : (
        <div className="dt-wrap">
          <table className="dt">
            <thead>
              <tr>
                <th>Token</th>
                <th className="col-shrink">Issued (UTC)</th>
                <th className="col-shrink">Last used</th>
                <th className="col-shrink">Expires</th>
                <th className="col-actions">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {tokens.map((token) => {
                const state = status(token.id);
                return (
                  <Fragment key={token.id}>
                    <tr className={rowClass(state)}>
                      <td>
                        <span className="cell-account">
                          <Key size={15} />
                          <span className="cell-stack">
                            <span>{token.label ?? 'Unlabelled'}</span>
                            <small className="mono">{token.hint}</small>
                          </span>
                        </span>
                      </td>
                      <td className="nowrap">
                        <span className="cell-stack">
                          <Timestamp iso={token.createdAt} />
                          <small>by {token.createdBy}</small>
                        </span>
                      </td>
                      <td className="nowrap cell-muted">
                        {token.lastUsedAt === null ? (
                          'Never'
                        ) : (
                          <span className="cell-stack">
                            <Timestamp iso={token.lastUsedAt} display="relative" />
                            {token.lastUsedIp !== null && <small className="mono">{token.lastUsedIp}</small>}
                          </span>
                        )}
                      </td>
                      <td className="nowrap cell-muted">
                        <Timestamp iso={token.expiresAt} display="relative" />
                      </td>
                      <td className="col-actions">
                        {state.state === 'pending' ? (
                          <RowPending status={state} />
                        ) : (
                          <ConfirmButton
                            trigger={
                              <button className="act">
                                <X size={13} />
                                Revoke
                              </button>
                            }
                            title={
                              <>
                                Revoke <span className="mono">{token.hint}</span>?
                              </>
                            }
                            body="Whatever uses it is refused from its next request. Issue a new token first if the service should keep working."
                            confirmLabel="Revoke token"
                            onConfirm={() => revoke(token)}
                          />
                        )}
                      </td>
                    </tr>
                    <RowFailure
                      status={state}
                      columns={5}
                      onDismiss={() => state.state === 'failed' && dismiss(state.mutationId)}
                    />
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function IssueToken({ serviceId }: { serviceId: string }) {
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState('');
  const [days, setDays] = useState<number>(90);
  const [issued, setIssued] = useState<{ token: string; expiresAt: string } | null>(null);
  const coffre = useCoffre();
  const { pending, error, setError, run } = useAction();

  function close() {
    setOpen(false);
    setIssued(null);
    setLabel('');
    setError(null);
  }

  return (
    <>
      <button className="btn btn-sm" onClick={() => setOpen(true)}>
        <Plus size={14} />
        Issue token
      </button>
      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title={issued === null ? 'Issue a token' : 'Copy the token now'}
      >
        {issued === null ? (
          <form
            className="form"
            onSubmit={(event) => {
              event.preventDefault();
              run(
                () =>
                  coffre.tokens.issue(memberRef('service', serviceId), {
                    label: label.trim() === '' ? null : label.trim(),
                    expiresInDays: days,
                  }),
                {
                  affects: affects.credentials(memberRef('service', serviceId)),
                  onSuccess: (credential) => setIssued(credential),
                },
              );
            }}
          >
            <div className="form-row">
              <label className="field">
                <span className="label">Label</span>
                <input
                  className="input"
                  value={label}
                  maxLength={120}
                  placeholder="GitHub Actions deploy"
                  onChange={(event) => setLabel(event.target.value)}
                />
              </label>
              <label className="field" style={{ flex: '0 0 9rem' }}>
                <span className="label">Expires after</span>
                <select className="select" value={days} onChange={(event) => setDays(Number(event.target.value))}>
                  {LIFETIMES.map((lifetime) => (
                    <option key={lifetime} value={lifetime}>
                      {lifetime} days
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <ErrorLine error={error} />
            <div className="dialog-actions">
              <button className="btn" type="button" onClick={close}>
                Cancel
              </button>
              <button className="btn btn-primary" type="submit" disabled={pending}>
                {pending && <Spinner />}
                Issue token
              </button>
            </div>
          </form>
        ) : (
          <div className="form">
            <Notice tone="info">
              This is the only time the value is shown. Store it where the service keeps its
              secrets; the CLI reads it from a file, or stdin, with{' '}
              <span className="mono">coffre --token-file &lt;path|-&gt;</span>.
            </Notice>
            <div className="token-once">
              <code className="mono">{issued.token}</code>
              <CopyButton value={issued.token} label="Copy token" />
            </div>
            <p className="hint">
              Expires <Timestamp iso={issued.expiresAt} />. Send it as{' '}
              <span className="mono">Authorization: Bearer …</span>
            </p>
            <div className="dialog-actions">
              <button className="btn btn-primary" type="button" onClick={close}>
                Done
              </button>
            </div>
          </div>
        )}
      </Modal>
    </>
  );
}

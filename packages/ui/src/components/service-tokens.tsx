import type { TokenRow } from '@coffre/client';
import { credentialScopeInWords } from '@coffre/core/access';
import { useQuery } from '@tanstack/react-query';
import { Fragment, useState } from 'react';
import { revokeCredential } from '../lib/changes';
import { memberRef, useCoffre } from '../lib/coffre';
import { affects, queries } from '../lib/queries';
import { withheldInWords } from '../lib/service-setup';
import { useAction } from '../lib/use-action';
import { useChange, useChangeStatus } from '../lib/use-change';
import { RowFailure, RowPending, rowClass } from './row-state';
import { Card } from './page';
import { ScopePicker, wholeScope, type HeldGrant } from './scope-picker';
import { ConfirmButton, CopyButton, EmptyState, ErrorLine, Modal, Notice, Spinner, Timestamp } from './ui';
import { Key, Plus, X } from './icons';

const LIFETIMES = [30, 90, 180, 365] as const;

/**
 * The bearer tokens a service account presents to the API, for CI without
 * OIDC. A value exists in exactly
 * one place, this dialog, for as long as it stays open: coffre keeps a hash.
 */
export function ServiceTokens({ serviceId, tokens, grants }: { serviceId: string; tokens: TokenRow[]; grants: HeldGrant[] }) {
  const change = revokeCredential(useCoffre(), memberRef('service', serviceId));
  const revoke = useChange(change);
  const { status, dismiss } = useChangeStatus(change.list.queryKey);

  return (
    <>
      <Card labelledBy="service-tokens" title="Bearer tokens">
        {tokens.length === 0 ? (
          <EmptyState title="No bearer tokens" />
        ) : (
          <div className="dt-wrap">
            <table className="dt">
              <thead>
                <tr>
                  <th>Token</th>
                  <th>Reaches</th>
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
                        <td>{token.scope === null ? 'All its account holds' : credentialScopeInWords(token.scope)}</td>
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
                              body={
                                <>
                                  {token.label ?? 'Unlabelled'},{' '}
                                  {token.lastUsedAt === null ? (
                                    'never used'
                                  ) : (
                                    <>
                                      last used <Timestamp iso={token.lastUsedAt} display="relative" />
                                    </>
                                  )}
                                  .{' '}
                                  Whatever uses it is refused at once. Issue a new token first if the
                                  service account should keep working.
                                </>
                              }
                              confirmLabel="Revoke token"
                              onConfirm={() => revoke(token)}
                            />
                          )}
                        </td>
                      </tr>
                      <RowFailure
                        status={state}
                        columns={6}
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
      <div className="table-actions">
        <IssueToken serviceId={serviceId} grants={grants} />
      </div>
    </>
  );
}

function IssueToken({ serviceId, grants }: { serviceId: string; grants: HeldGrant[] }) {
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState('');
  const [days, setDays] = useState<number>(90);
  const [scope, setScope] = useState(() => wholeScope(grants));
  const [issued, setIssued] = useState<{ token: string; expiresAt: string } | null>(null);
  const coffre = useCoffre();
  const { pending, error, setError, run } = useAction();
  const member = memberRef('service', serviceId);
  // Told before it is issued: the sensitive values it would not read, as the server decides (R32).
  const plan = useQuery({ ...queries.tokenPlan(coffre, member, scope), enabled: open && issued === null && Object.keys(scope).length > 0 });
  const unread = withheldInWords(plan.data?.withheld, 'token');

  function close() {
    setOpen(false);
    setIssued(null);
    setLabel('');
    setScope(wholeScope(grants));
    setError(null);
  }

  return (
    <>
      <button className="btn" onClick={() => setOpen(true)}>
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
                    scope,
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
            <ScopePicker grants={grants} value={scope} onChange={setScope} />
            {unread !== null && <Notice tone="warn">{unread}</Notice>}
            {plan.isError && <Notice tone="warn">Coffre could not check which sensitive values this token would read.</Notice>}
            <ErrorLine error={error} />
            <div className="dialog-actions">
              <button className="btn" type="button" onClick={close}>
                Cancel
              </button>
              <button className="btn btn-primary" type="submit" disabled={pending || Object.keys(scope).length === 0}>
                {pending && <Spinner />}
                Issue token
              </button>
            </div>
          </form>
        ) : (
          <div className="form">
            <Notice tone="info">
              This is the only time the value is shown. Store it where the service keeps its
              secrets; a CI run signs the CLI in with it, piped to{' '}
              <span className="mono">coffre login &lt;url&gt; --token</span>.
            </Notice>
            <div className="copy-line">
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

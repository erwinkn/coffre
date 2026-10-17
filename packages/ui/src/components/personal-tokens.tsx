import type { TokenRow } from '@coffre/client';
import { credentialScopeInWords } from '@coffre/core/access';
import { Fragment, type ReactNode } from 'react';

import type { Change } from '../lib/optimistic';
import { useChange, useChangeStatus } from '../lib/use-change';
import { Key, X } from './icons';
import { Card } from './page';
import { RowFailure, RowPending, rowClass } from './row-state';
import { ConfirmButton, EmptyState, ErrorLine, Timestamp } from './ui';

/**
 * Personal tokens, which act as their person within what each reaches:
 * your own on your account page, or a person's on theirs, for whoever runs
 * the instance. Each row says what it is called, what it reaches and when
 * it ends; Revoke stops it at its next request.
 */
export function PersonalTokensCard<TData>({
  tokens,
  change,
  description,
  empty,
  emptyActions,
}: {
  tokens: TokenRow[] | { error: string };
  change: Change<TData, TokenRow, TokenRow, unknown>;
  description: ReactNode;
  /** Said when there is none: phrasing, inside the empty state's paragraph. */
  empty?: ReactNode;
  /** Beneath it, what to do about it. */
  emptyActions?: ReactNode;
}) {
  const revoke = useChange(change);
  const { status, dismiss } = useChangeStatus(change.list.queryKey);
  return (
    <Card labelledBy="personal-tokens" title="Personal tokens" description={description}>
      {'error' in tokens ? (
        <div className="card-body">
          <ErrorLine error={tokens.error} />
        </div>
      ) : tokens.length === 0 ? (
        <EmptyState title="No personal tokens" actions={emptyActions}>
          {empty}
        </EmptyState>
      ) : (
        <div className="dt-wrap">
          <table className="dt stacks stacks-inline">
            <thead>
              <tr>
                <th>Token</th>
                <th>Reaches</th>
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
                            <span>{token.label}</span>
                            <small>
                              <span className="mono">{token.hint}</span>
                              {' · made '}
                              <Timestamp iso={token.createdAt} display="relative" />
                            </small>
                          </span>
                        </span>
                      </td>
                      <td data-label="Reaches">{credentialScopeInWords(token.scope ?? {})}</td>
                      <td className="nowrap cell-muted" data-label="Last used">
                        {token.lastUsedAt === null ? (
                          'Never'
                        ) : (
                          <span className="cell-stack">
                            <Timestamp iso={token.lastUsedAt} display="relative" />
                            {token.lastUsedIp !== null && <small className="mono">{token.lastUsedIp}</small>}
                          </span>
                        )}
                      </td>
                      <td className="nowrap cell-muted" data-label="Expires">
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
                            title={`Revoke “${token.label}”?`}
                            body={
                              <>
                                <span className="mono">{token.hint}</span>, last used{' '}
                                {token.lastUsedAt === null ? 'never' : <Timestamp iso={token.lastUsedAt} display="relative" />}.
                                Whatever uses it is refused at once.
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

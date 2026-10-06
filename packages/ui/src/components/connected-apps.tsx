import type { ConnectedApp } from '@coffre/client';
import { MCP_SCOPE_INFO } from '@coffre/core/mcp';
import { Fragment, type ReactNode } from 'react';

import type { Change } from '../lib/optimistic';
import { useChange, useChangeStatus } from '../lib/use-change';
import { Link as LinkIcon, X } from './icons';
import { Card } from './page';
import { RowFailure, RowPending, rowClass } from './row-state';
import { ConfirmButton, EmptyState, ErrorLine, Timestamp } from './ui';

/**
 * MCP clients connected as someone: your own on your account page, or a
 * person's on theirs, for an owner. Each row says what the app is, what it
 * may do, and when it was last used; Disconnect stops it at its next request.
 */
export function ConnectedAppsCard<TData>({
  apps,
  change,
  description,
  empty,
}: {
  apps: ConnectedApp[] | { error: string };
  change: Change<TData, ConnectedApp, ConnectedApp, unknown>;
  description: ReactNode;
  empty: ReactNode;
}) {
  const disconnect = useChange(change);
  const { status, dismiss } = useChangeStatus(change.list.queryKey);
  return (
    <Card
      labelledBy="apps"
      title="Connected apps"
      description={description}
    >
      {'error' in apps ? (
        <div className="card-body">
          <ErrorLine error={apps.error} />
        </div>
      ) : apps.length === 0 ? (
        <EmptyState title="No connected apps">{empty}</EmptyState>
      ) : (
        <div className="dt-wrap">
          <table className="dt stacks stacks-inline">
            <thead>
              <tr>
                <th>App</th>
                <th>May</th>
                <th className="col-shrink">Last used</th>
                <th className="col-shrink">Expires</th>
                <th className="col-actions">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {apps.map((app) => {
                const state = status(app.id);
                return (
                  <Fragment key={app.id}>
                    <tr className={rowClass(state)}>
                      <td>
                        <span className="cell-account">
                          <LinkIcon size={15} />
                          <span className="cell-stack">
                            <span>
                              {app.name}{' '}
                              {app.registration === 'dcr' && (
                                <span className="tag tag-amber" title="It registered itself: its name is its own claim">
                                  Unverified
                                </span>
                              )}
                            </span>
                            <small>
                              {app.host === null ? 'no website' : <span className="mono">{app.host}</span>}
                              {' · connected '}
                              <Timestamp iso={app.createdAt} display="relative" />
                            </small>
                          </span>
                        </span>
                      </td>
                      <td data-label="May">{scopeLabels(app)}</td>
                      <td className="nowrap cell-muted" data-label="Last used">
                        {app.lastUsedAt === null ? 'Never' : <Timestamp iso={app.lastUsedAt} display="relative" />}
                      </td>
                      <td className="nowrap cell-muted" data-label="Expires">
                        <Timestamp iso={app.expiresAt} display="relative" />
                      </td>
                      <td className="col-actions">
                        {state.state === 'pending' ? (
                          <RowPending status={state} />
                        ) : (
                          <ConfirmButton
                            trigger={
                              <button className="act">
                                <X size={13} />
                                Disconnect
                              </button>
                            }
                            title={`Disconnect ${app.name}?`}
                            body={
                              <>
                                {app.name}
                                {app.host !== null && (
                                  <>
                                    {' '}at <span className="mono">{app.host}</span>
                                  </>
                                )}
                                , last used{' '}
                                {app.lastUsedAt === null ? 'never' : <Timestamp iso={app.lastUsedAt} display="relative" />},
                                stops at its next request. To use it again, connect it again.
                              </>
                            }
                            confirmLabel="Disconnect"
                            onConfirm={() => disconnect(app)}
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

function scopeLabels(app: ConnectedApp): string {
  return app.scopes.map((scope) => MCP_SCOPE_INFO[scope].label).join(', ');
}

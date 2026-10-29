// The Proxy tab as a ledger (variant A of the W260 prototype): one line per
// `/use` route, as the Secrets table has one per key. A row opens in place,
// each cell its own field; what is wrong shows under the line once a save
// is tried, and the bar saves or discards the whole table.
import { Menu } from '@base-ui/react/menu';

import type { ProxyConfig } from '../lib/proxy-prototype';
import type { SecretKey } from '../shared/models';
import { ArrowRight, Key, MoreHorizontal, Pencil, Relay, RotateBack, Trash, Activity } from './icons';
import { EmptyState, MenuPopup } from './ui';
import {
  AllowsField,
  InjectText,
  LimitField,
  limitShort,
  methodsShort,
  NameField,
  RowNotes,
  SendsField,
  SourceMark,
  UpstreamField,
  type Edits,
  type Row,
} from './proxy-parts';

const COLUMNS = 7;

export function ProxyLedger({ edits, config, keys }: { edits: Edits; config: ProxyConfig; keys: readonly SecretKey[] }) {
  if (edits.rows.length === 0) {
    return (
      <section className="card card-wide" aria-label="Proxy credentials">
        <EmptyState title="No credentials yet" />
      </section>
    );
  }
  return (
    <section className="card card-wide" aria-label="Proxy credentials">
      <div className="dt-wrap">
        <table className="dt proxy-ledger">
          <thead>
            <tr>
              <th className="n">#</th>
              <th className="col-route">
                <span className="th">
                  <Relay size={14} />
                  Route
                </span>
              </th>
              <th className="col-upstream">
                <span className="th">
                  <ArrowRight size={14} />
                  Upstream
                </span>
              </th>
              <th>
                <span className="th">
                  <Key size={14} />
                  Sends
                </span>
              </th>
              <th className="col-allows">Allows</th>
              <th className="col-limit">
                <span className="th">
                  <Activity size={14} />
                  Limit
                </span>
              </th>
              <th className="col-actions">
                <span className="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {edits.rows.map((row, index) => (
              <LedgerRow key={row.id} number={index + 1} row={row} edits={edits} config={config} keys={keys} />
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function LedgerRow({ number, row, edits, config, keys }: { number: number; row: Row; edits: Edits; config: ProxyConfig; keys: readonly SecretKey[] }) {
  const { credential, definition } = row;
  const shadowed = credential?.shadowedSince != null;
  const state = row.state === 'same' ? '' : row.state === 'deleted' ? ' is-leaving' : ' is-changed';
  const editing = row.open;
  const notes = <RowNotes row={row} />;
  const hasNotes = Object.keys(row.problems).length > 0 || (editing && row.locked.length > 0);
  return (
    <>
      <tr className={`proxy-line${state}${shadowed && !editing ? ' proxy-shadowed' : ''}${editing ? ' is-editing' : ''}${hasNotes ? ' has-notes' : ''}`} onDoubleClick={() => edits.open(row)}>
        <td className="n">{number}</td>
        <td className="col-route">
          {editing ? (
            <NameField row={row} edits={edits} />
          ) : (
            <span className="proxy-cell">
              <span className="mono proxy-route">/use/{definition.name}</span>
              <SourceMark credential={credential} />
            </span>
          )}
        </td>
        <td className="col-upstream">
          {editing ? (
            <UpstreamField row={row} edits={edits} egresses={config.egresses} />
          ) : (
            <span className="proxy-cell">
              {definition.egress !== null && <span className="tag tag-outline mono">{definition.egress}</span>}
              <span className="mono">{definition.upstream.replace(/^https:\/\//, '')}</span>
            </span>
          )}
        </td>
        <td className="col-sends">
          {editing ? (
            <SendsField row={row} edits={edits} keys={keys} compact />
          ) : (
            <span className="proxy-cell">
              <InjectText inject={definition.inject} keys={keys} />
              {definition.placeholder?.kind === 'prefix' && <span className="proxy-how mono">{definition.placeholder.prefix}…</span>}
            </span>
          )}
        </td>
        <td className="col-allows">
          {editing ? (
            <AllowsField row={row} edits={edits} />
          ) : (
            <span className="proxy-cell proxy-ellipsis">
              <span className="mono">{methodsShort(definition.methods)}</span>
              <span className="proxy-how mono">{definition.paths.length === 0 ? '/*' : definition.paths.join(' ')}</span>
            </span>
          )}
        </td>
        <td className="col-limit">{editing ? <LimitField row={row} edits={edits} /> : <span>{limitShort(definition.limit, credential?.limitPerService)}</span>}</td>
        <td className="col-actions">
          <Menu.Root>
            <Menu.Trigger className="act act-icon act-quiet" aria-label={`Actions for ${definition.name}`}>
              <MoreHorizontal size={16} />
            </Menu.Trigger>
            <MenuPopup align="end">
              {row.state === 'deleted' ? (
                <Menu.Item className="menu-item" onClick={() => edits.restore(row)}>
                  <RotateBack size={14} />
                  Keep
                </Menu.Item>
              ) : (
                <>
                  <Menu.Item className="menu-item" onClick={() => edits.open(row)} disabled={!row.editable || editing}>
                    <Pencil size={14} />
                    Edit
                    {!row.editable && <span className="menu-hint">{credential?.source === 'code' ? 'in code' : 'proxy.edit'}</span>}
                  </Menu.Item>
                  <Menu.Item className="menu-item menu-item-danger" onClick={() => edits.remove(row)} disabled={!row.editable}>
                    <Trash size={14} />
                    Delete
                  </Menu.Item>
                </>
              )}
            </MenuPopup>
          </Menu.Root>
        </td>
      </tr>
      {hasNotes && (
        <tr className={`proxy-notes-row${state}`}>
          <td className="n" />
          <td colSpan={COLUMNS - 1}>{notes}</td>
        </tr>
      )}
    </>
  );
}

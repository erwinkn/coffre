// The Proxy tab as a list and a sheet (variant B of the W260 prototype): the
// routes, one short line each, and beside them the one picked, its whole
// form, and what a sample call through it becomes. Edits still wait for the
// page's one Save.
import { useState, type ReactNode } from 'react';

import { sampleCall, METHODS, type ProxyConfig, type ProxyInject } from '../lib/proxy-prototype';
import type { SecretKey } from '../shared/models';
import { ArrowRight, Lock, RotateBack, Trash } from './icons';
import { EmptyState } from './ui';
import {
  AllowsField,
  Fold,
  KeyChip,
  LimitField,
  NameField,
  PlaceholderField,
  RowNotes,
  SendsField,
  SourceMark,
  UpstreamField,
  type Edits,
  type Row,
} from './proxy-parts';

export function ProxySheet({
  edits,
  config,
  keys,
  selected,
  onSelect,
}: {
  edits: Edits;
  config: ProxyConfig;
  keys: readonly SecretKey[];
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  const rows = edits.rows;
  const row = rows.find((one) => one.id === selected) ?? rows[0];
  if (row === undefined) {
    return (
      <section className="card card-wide" aria-label="Proxy credentials">
        <EmptyState title="No credentials yet" />
      </section>
    );
  }
  return (
    <div className="proxy-split">
      <section className="card proxy-list" aria-label="Proxy credentials">
        <ul>
          {rows.map((one) => (
            <li key={one.id}>
              <button
                type="button"
                className={`proxy-list-row${one.id === row.id ? ' is-current' : ''}${one.state === 'deleted' ? ' is-leaving' : one.state !== 'same' ? ' is-changed' : ''}${one.credential?.shadowedSince != null ? ' proxy-shadowed' : ''}`}
                aria-current={one.id === row.id}
                onClick={() => onSelect(one.id)}
              >
                <span className="mono proxy-list-name">{one.definition.name || 'new'}</span>
                <span className="mono proxy-list-host">{hostOf(one.definition.upstream)}</span>
                <span className="proxy-list-marks">
                  {Object.keys(one.problems).length > 0 && <span className="dot dot-red" aria-label="Needs fixing" />}
                  {one.state !== 'same' && Object.keys(one.problems).length === 0 && <span className="dot" aria-label="Changed" />}
                  {one.credential?.source === 'code' && <Lock size={12} />}
                </span>
              </button>
            </li>
          ))}
        </ul>
      </section>
      <Sheet key={row.id} row={row} edits={edits} config={config} keys={keys} />
    </div>
  );
}

const hostOf = (upstream: string) => {
  try {
    return new URL(upstream).host;
  } catch {
    return upstream;
  }
};

function Sheet({ row, edits, config, keys }: { row: Row; edits: Edits; config: ProxyConfig; keys: readonly SecretKey[] }) {
  // Every field takes edits at once where the row does: the first edit opens it.
  const editable = row.editable && row.state !== 'deleted';
  const field = (label: string, control: ReactNode) => (
    <div className="proxy-sheet-line">
      <span className="proxy-sheet-label">{label}</span>
      <div className="proxy-sheet-field">
        {control}
      </div>
    </div>
  );
  return (
    <section className={`card proxy-sheet${row.state === 'deleted' ? ' is-leaving' : ''}`} aria-label={row.definition.name}>
      <header className="proxy-sheet-head">
        <h2 className="mono proxy-sheet-title">/use/{row.definition.name || '…'}</h2>
        <SourceMark credential={row.credential} />
        <span className="proxy-sheet-actions">
          {row.state === 'deleted' ? (
            <button className="btn btn-sm" type="button" onClick={() => edits.restore(row)}>
              <RotateBack size={14} />
              Keep
            </button>
          ) : (
            row.editable && (
              <button className="btn btn-sm btn-quiet" type="button" onClick={() => edits.remove(row)}>
                <Trash size={14} />
                Delete
              </button>
            )
          )}
        </span>
      </header>
      <fieldset className="proxy-sheet-grid" disabled={!editable}>
        {field('Route', <NameField row={row} edits={edits} />)}
        {field('Upstream', <UpstreamField row={row} edits={edits} egresses={config.egresses} />)}
        {field('Sends', <SendsField row={row} edits={edits} keys={keys} />)}
        {['header', 'query', 'form', 'json'].includes(row.form.inject.kind) && field('Placeholder', <PlaceholderField row={row} edits={edits} />)}
        {field('Allows', <AllowsField row={row} edits={edits} />)}
        {field('Limit', <LimitField row={row} edits={edits} />)}
      </fieldset>
      <RowNotes row={row} />
      <Preview row={row} keys={keys} useUrl={config.useUrl} />
    </section>
  );
}

/** A sample call through the credential, as the proxy would send it on: the path it goes to, and where its keys go. */
function Preview({ row, keys, useUrl }: { row: Row; keys: readonly SecretKey[]; useUrl: string }) {
  const definition = row.definition;
  const [method, setMethod] = useState(definition.methods[0] ?? 'GET');
  const [path, setPath] = useState(definition.paths[0] ?? '/');
  const call = sampleCall(definition, method, path);
  const inject = definition.inject;
  const url = inject.kind === 'query' ? `${call.url}${call.url.includes('?') ? '&' : '?'}${inject.name}=${inject.template}` : call.url;
  return (
    <div className="proxy-preview">
      <Fold className="proxy-preview-ask">
        <select className="fold-select fold-lead mono" aria-label="Method" value={method} onChange={(event) => setMethod(event.target.value)}>
          {METHODS.map((one) => (
            <option key={one}>{one}</option>
          ))}
        </select>
        <span className="fold-text mono">{useUrl.replace(/^https?:\/\//, '')}/{definition.name}</span>
        <input className="fold-input mono" aria-label="Path" value={path} spellCheck={false} onChange={(event) => setPath(event.target.value)} />
      </Fold>
      <div className="proxy-preview-out mono">
        {call.refusal !== null ? (
          <p className="proxy-preview-refused">{call.refusal}</p>
        ) : (
          <>
            <p>
              <ArrowRight size={13} />
              <span>
                {method} <Filled text={url} keys={keys} />
              </span>
              {definition.egress !== null && <span className="proxy-how">via {definition.egress}</span>}
            </p>
            <InjectedLine inject={inject} keys={keys} />
          </>
        )}
      </div>
    </div>
  );
}

function InjectedLine({ inject, keys }: { inject: ProxyInject; keys: readonly SecretKey[] }) {
  switch (inject.kind) {
    case 'header':
      return (
        <p className="proxy-preview-header">
          {inject.name}: <Filled text={inject.template} keys={keys} />
        </p>
      );
    case 'basic':
      return (
        <p className="proxy-preview-header">
          authorization: Basic base64(<Filled text={`${inject.user}:${inject.password}`} keys={keys} />)
        </p>
      );
    case 'sigv4':
      return (
        <p className="proxy-preview-header">
          authorization: AWS4-HMAC-SHA256 Credential=<Filled text={inject.accessKeyId} keys={keys} />/…/{inject.region}/{inject.service}, signed with <Filled text={inject.secretAccessKey} keys={keys} />
        </p>
      );
    case 'form':
    case 'json':
      return (
        <p className="proxy-preview-header">
          body {inject.name}: <Filled text={inject.template} keys={keys} />
        </p>
      );
    case 'query':
      return null;
  }
}

/** A template with each `{KEY}` its value's stand-in, ‹KEY›. */
function Filled({ text, keys }: { text: string; keys: readonly SecretKey[] }) {
  return (
    <>
      {text.split(/(\{[A-Za-z_][A-Za-z0-9_]*\})/).map((part, index) =>
        /^\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(part) ? <KeyChip key={index} name={part.slice(1, -1)} keys={keys} /> : <span key={index}>{part}</span>,
      )}
    </>
  );
}

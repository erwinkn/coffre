// The Proxy tab's list and panel (W260, a prototype, DO NOT MERGE): every
// item one short line, routes, signers, verifiers and databases alike, and
// beside them the one picked, its fields as its kind has them, what a
// sample call through a route becomes, and the item as code. Edits wait for
// the page's one Save.
import { useState, type ReactNode } from 'react';

import {
  allowsToday,
  blankInject,
  codeOf,
  ENCODINGS,
  INJECT_LABELS,
  isGlob,
  lockedInWords,
  METHODS,
  routedInWords,
  sampleCall,
  soleKey,
  targetOf,
  type Encoding,
  type Hmac,
  type InjectKind,
  type Limit,
  type ProxyConfig,
  type ProxyInject,
  type RouteDefinition,
  type SignerDefinition,
  type TunnelDefinition,
  type VerifierDefinition,
} from '../lib/proxy-prototype';
import type { SecretKey } from '../shared/models';
import { ArrowRight, Lock, Plus, RotateBack, Trash, X } from './icons';
import { CopyButton, EmptyState, Toggletip } from './ui';
import { Fold, KeySelect, KindTag, lockedByCodeInWords, MethodsMenu, Needs016, Note, NumberInput, scopeInWords, TemplateInput, TransportSelect, type Edits, type Row } from './proxy-parts';

export function ProxySheet({
  edits,
  config,
  keys,
  selected,
  onSelect,
  footer,
}: {
  edits: Edits;
  config: ProxyConfig;
  keys: readonly SecretKey[];
  selected: string | null;
  onSelect: (id: string) => void;
  /** What sits at the foot of the list, however tall the panel beside it grows: adding an item. */
  footer: ReactNode;
}) {
  const rows = edits.rows;
  const row = rows.find((one) => one.id === selected) ?? rows[0];
  if (row === undefined) {
    return (
      <section className="card card-wide" aria-label="Proxy">
        <EmptyState title="Nothing here yet" />
        <div className="proxy-list-foot">{footer}</div>
      </section>
    );
  }
  return (
    <div className="proxy-split">
      <section className="card proxy-list" aria-label="Proxy items">
        <ul>
          {rows.map((one) => {
            const faulty = Object.keys(one.problems).length > 0;
            return (
              <li key={one.id}>
                <button
                  type="button"
                  className={`proxy-list-row${one.id === row.id ? ' is-current' : ''}${one.state === 'deleted' ? ' is-leaving' : ''}`}
                  aria-current={one.id === row.id}
                  onClick={() => onSelect(one.id)}
                >
                  <KindTag kind={one.definition.kind} />
                  <span className="mono proxy-list-name">{one.definition.name || 'new'}</span>
                  <span className="mono proxy-list-target">{targetOf(one.definition)}</span>
                  <span className="proxy-list-marks">
                    {faulty ? <span className="dot dot-red" aria-label="Needs fixing" /> : one.state !== 'same' && <span className="dot" aria-label="Changed" />}
                    {one.credential?.source === 'code' && <Lock size={12} label={scopeInWords(one.credential)} />}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
        <div className="proxy-list-foot">{footer}</div>
      </section>
      <Panel key={row.id} row={row} edits={edits} config={config} keys={keys} />
    </div>
  );
}

type PanelProps = { row: Row; edits: Edits; config: ProxyConfig; keys: readonly SecretKey[] };

/** A label, its field, and what is wrong with it, one line each. */
function Line({ label, children, notes, aside }: { label: string; children: ReactNode; notes?: ReactNode; aside?: ReactNode }) {
  return (
    <div className="proxy-line">
      <span className="proxy-line-label">
        {label}
        {aside}
      </span>
      <div className="proxy-line-field">
        {children}
        {notes}
      </div>
    </div>
  );
}

const problemOf = (row: Row, ...fields: string[]) => {
  const found = fields.map((field) => row.problems[field]).filter((one) => one !== undefined);
  return found.length === 0 ? null : <Note>{found[0]}</Note>;
};

function Panel({ row, edits, config, keys }: PanelProps) {
  const disabled = !row.editable || row.state === 'deleted';
  const credential = row.credential;
  const definition = row.definition;
  const routed = definition.kind === 'route' || definition.kind === 'tunnel';
  return (
    <section className={`card proxy-sheet${row.state === 'deleted' ? ' is-leaving' : ''}`} aria-label={definition.name}>
      <header className="proxy-sheet-head">
        <KindTag kind={definition.kind} />
        <h2 className="mono proxy-sheet-title">
          {routed ? '/use/' : ''}
          {definition.name || '…'}
        </h2>
        {credential?.source === 'code' && (
          <Toggletip label={lockedByCodeInWords(credential)}>
            <button type="button" className="btn btn-quiet btn-sm btn-icon" aria-label={scopeInWords(credential)}>
              <Lock size={14} />
            </button>
          </Toggletip>
        )}
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
      <fieldset className="proxy-sheet-grid" disabled={disabled}>
        {definition.kind === 'route' ? (
          <RouteFields row={row} route={definition} edits={edits} config={config} keys={keys} disabled={disabled} />
        ) : definition.kind === 'signer' ? (
          <SignerFields row={row} signer={definition} edits={edits} keys={keys} disabled={disabled} />
        ) : definition.kind === 'verifier' ? (
          <VerifierFields row={row} verifier={definition} edits={edits} keys={keys} disabled={disabled} />
        ) : (
          <TunnelFields row={row} tunnel={definition} edits={edits} config={config} keys={keys} disabled={disabled} />
        )}
      </fieldset>
      {definition.kind === 'route' && <Preview route={definition} keys={keys} useUrl={config.useUrl} />}
      <details className="proxy-as-code">
        <summary>As code</summary>
        <div className="proxy-code">
          <pre className="mono">{codeOf(definition)}</pre>
          <span className="proxy-code-copy">
            <CopyButton value={codeOf(definition)} label="Copy as code" />
          </span>
        </div>
      </details>
    </section>
  );
}

/** The name, as the URL or the app says it. */
function NameLine({ row, edits, disabled, prefix }: { row: Row; edits: Edits; disabled: boolean; prefix: boolean }) {
  return (
    <Line label="Name" notes={problemOf(row, 'name')}>
      <Fold invalid={row.problems.name !== undefined}>
        {prefix && <span className="fold-text">/use/</span>}
        <input className="fold-input mono" aria-label="Name" value={row.definition.name} disabled={disabled} spellCheck={false} autoComplete="off" placeholder="name" onChange={(event) => edits.patch(row, (one) => ({ ...one, name: event.target.value }))} />
      </Fold>
    </Line>
  );
}

/** Why where it sends its keys stays, or that an Owner routes a sensitive one, audited. */
function KeyNotes({ row }: { row: Row }) {
  return (
    <>
      {problemOf(row, 'keys')}
      {row.editable && row.locked.length > 0 && <Note tone="warn">{lockedInWords(row.locked.map((key) => ({ key })))}</Note>}
      {row.routed.length > 0 && <Note tone="warn">{routedInWords(row.routed)}</Note>}
    </>
  );
}

function LimitLine({ row, limit, disabled, onChange }: { row: Row; limit: Limit; disabled: boolean; onChange: (limit: Limit) => void }) {
  if (row.credential?.limitPerService) {
    return (
      <Line label="Limit">
        <span className="proxy-static">Per service, in code</span>
      </Line>
    );
  }
  return (
    <Line label="Limit" notes={problemOf(row, 'perMinute', 'perDay')}>
      <div className="proxy-limits">
        <label className="proxy-limit">
          <NumberInput value={limit.perMinute} label="Per minute" disabled={disabled} onChange={(perMinute) => onChange({ ...limit, perMinute })} />
          <span>per minute</span>
        </label>
        <label className="proxy-limit">
          <NumberInput value={limit.perDay} label="Per day" disabled={disabled} onChange={(perDay) => onChange({ ...limit, perDay })} />
          <span>per day</span>
        </label>
      </div>
    </Line>
  );
}

function RemoveButton({ label, disabled, onClick }: { label: string; disabled: boolean; onClick: () => void }) {
  if (disabled) return null;
  return (
    <button type="button" className="btn btn-quiet btn-sm btn-icon proxy-remove" aria-label={label} onClick={onClick}>
      <X size={14} />
    </button>
  );
}

function AddButton({ children, disabled, onClick }: { children: ReactNode; disabled: boolean; onClick: () => void }) {
  if (disabled) return null;
  return (
    <button type="button" className="btn btn-quiet btn-sm proxy-add" onClick={onClick}>
      <Plus size={13} />
      {children}
    </button>
  );
}

// --- a route ----------------------------------------------------------------------------------------

function RouteFields({ row, route, edits, config, keys, disabled }: { row: Row; route: RouteDefinition; edits: Edits; config: ProxyConfig; keys: readonly SecretKey[]; disabled: boolean }) {
  const locked = disabled || row.locked.length > 0;
  const set = (change: (route: RouteDefinition) => RouteDefinition) => edits.patch(row, (one) => change(one as RouteDefinition));
  const setRule = (index: number, rule: ProxyInject) => set((one) => ({ ...one, inject: one.inject.map((each, at) => (at === index ? rule : each)) }));
  const shaped = route.inject.some((rule) => rule.kind !== 'basic' && rule.kind !== 'sigv4');
  return (
    <>
      <NameLine row={row} edits={edits} disabled={disabled} prefix />
      <Line label="Upstream" notes={problemOf(row, 'upstream', 'egress')}>
        <Fold invalid={row.problems.upstream !== undefined || row.problems.egress !== undefined}>
          <input className="fold-input mono" aria-label="Upstream" value={route.upstream} disabled={locked} spellCheck={false} autoComplete="off" placeholder="https://api.example.com" onChange={(event) => set((one) => ({ ...one, upstream: event.target.value }))} />
          <TransportSelect value={route.egress} transports={config.egresses} address={route.upstream} label="Egress" disabled={locked} onChange={(egress) => set((one) => ({ ...one, egress }))} />
        </Fold>
      </Line>
      <Line label="Sends" aside={route.inject.length > 1 && <Needs016 what="Several inject rules per route" />} notes={<>{problemOf(row, 'inject')}<KeyNotes row={row} /></>}>
        <div className="proxy-rows">
          {route.inject.map((rule, index) => (
            <div key={index} className="proxy-row">
              <InjectRule rule={rule} keys={keys} disabled={locked} invalid={row.problems[`inject.${index}`] !== undefined} onChange={(next) => setRule(index, next)} />
              <RemoveButton label="Remove rule" disabled={locked} onClick={() => set((one) => ({ ...one, inject: one.inject.filter((_, at) => at !== index) }))} />
              {problemOf(row, `inject.${index}`)}
            </div>
          ))}
          <AddButton disabled={locked} onClick={() => set((one) => ({ ...one, inject: [...one.inject, blankInject('header')] }))}>
            Add rule
          </AddButton>
        </div>
      </Line>
      {shaped && (
        <Line label="Placeholder" notes={problemOf(row, 'placeholder')}>
          <Fold invalid={row.problems.placeholder !== undefined} className={route.placeholder === null ? 'is-short' : undefined}>
            <select
              className={`fold-select${route.placeholder === null ? '' : ' fold-lead'}`}
              aria-label="Placeholder"
              value={route.placeholder?.kind ?? 'none'}
              disabled={disabled}
              onChange={(event) =>
                set((one) => ({ ...one, placeholder: event.target.value === 'prefix' ? { kind: 'prefix', prefix: '' } : event.target.value === 'jwt' ? { kind: 'jwt', claims: [''] } : null }))
              }
            >
              <option value="none">The handle</option>
              <option value="prefix">Prefix</option>
              <option value="jwt">JWT</option>
            </select>
            {route.placeholder?.kind === 'prefix' && (
              <input className="fold-input mono" aria-label="Prefix" value={route.placeholder.prefix} disabled={disabled} placeholder="sk_test_" onChange={(event) => set((one) => ({ ...one, placeholder: { kind: 'prefix', prefix: event.target.value } }))} />
            )}
            {route.placeholder?.kind === 'jwt' && (
              <input className="fold-input mono" aria-label="Claims" value={route.placeholder.claims.join(' ')} disabled={disabled} placeholder="claims" onChange={(event) => set((one) => ({ ...one, placeholder: { kind: 'jwt', claims: event.target.value.split(' ') } }))} />
            )}
          </Fold>
        </Line>
      )}
      <Line label="Allows" aside={route.allow.length > 0 && !allowsToday(route.allow) && <Needs016 what={route.allow.some((entry) => isGlob(entry.path)) ? 'Glob paths (* and **)' : 'Methods that differ by path'} />}>
        <div className="proxy-rows">
          {route.allow.length === 0 && <span className="proxy-static">Any method, any path</span>}
          {route.allow.map((entry, index) => (
            <div key={index} className="proxy-row">
              <Fold invalid={row.problems[`allow.${index}`] !== undefined}>
                <MethodsMenu methods={entry.methods} disabled={disabled} onChange={(methods) => set((one) => ({ ...one, allow: one.allow.map((each, at) => (at === index ? { ...each, methods } : each)) }))} />
                <input
                  className="fold-input mono"
                  aria-label="Path"
                  value={entry.path}
                  disabled={disabled}
                  spellCheck={false}
                  placeholder="/companies/*/documents/**"
                  onChange={(event) => set((one) => ({ ...one, allow: one.allow.map((each, at) => (at === index ? { ...each, path: event.target.value } : each)) }))}
                />
              </Fold>
              <RemoveButton label="Remove entry" disabled={disabled} onClick={() => set((one) => ({ ...one, allow: one.allow.filter((_, at) => at !== index) }))} />
              {problemOf(row, `allow.${index}`)}
            </div>
          ))}
          <AddButton disabled={disabled} onClick={() => set((one) => ({ ...one, allow: [...one.allow, { methods: ['GET'], path: '/' }] }))}>
            Add entry
          </AddButton>
        </div>
      </Line>
      <LimitLine row={row} limit={route.limit} disabled={disabled} onChange={(limit) => set((one) => ({ ...one, limit }))} />
    </>
  );
}

const KINDS: InjectKind[] = ['header', 'query', 'form', 'json', 'basic', 'sigv4'];

function InjectRule({ rule, keys, disabled, invalid, onChange }: { rule: ProxyInject; keys: readonly SecretKey[]; disabled: boolean; invalid: boolean; onChange: (rule: ProxyInject) => void }) {
  const kind = (
    <select className="fold-select fold-lead fold-kind" aria-label="Sends as" value={rule.kind} disabled={disabled} onChange={(event) => onChange(blankInject(event.target.value as InjectKind))}>
      {KINDS.map((one) => (
        <option key={one} value={one}>
          {INJECT_LABELS[one]}
        </option>
      ))}
    </select>
  );
  if (rule.kind === 'sigv4') {
    const pick = (field: 'accessKeyId' | 'secretAccessKey' | 'sessionToken', label: string) => (
      <KeySelect value={soleKey(rule[field])} keys={keys} label={label} optional={field === 'sessionToken'} disabled={disabled} onChange={(key) => onChange({ ...rule, [field]: key === '' ? '' : `{${key}}` })} />
    );
    return (
      <Fold invalid={invalid}>
        {kind}
        {pick('accessKeyId', 'Access key ID')}
        {pick('secretAccessKey', 'Secret access key')}
        <input className="fold-input fold-short mono" aria-label="Region" value={rule.region} disabled={disabled} placeholder="eu-west-3" onChange={(event) => onChange({ ...rule, region: event.target.value.trim() })} />
        <input className="fold-input fold-short mono" aria-label="Service" value={rule.service} disabled={disabled} placeholder="s3" onChange={(event) => onChange({ ...rule, service: event.target.value.trim() })} />
      </Fold>
    );
  }
  if (rule.kind === 'basic') {
    return (
      <Fold invalid={invalid}>
        {kind}
        <TemplateInput value={rule.user} keys={keys} label="User" placeholder="{USER}" disabled={disabled} onChange={(user) => onChange({ ...rule, user })} />
        <span className="fold-text">:</span>
        <TemplateInput value={rule.password} keys={keys} label="Password" placeholder="empty" disabled={disabled} onChange={(password) => onChange({ ...rule, password })} />
      </Fold>
    );
  }
  return (
    <Fold invalid={invalid}>
      {kind}
      <input className="fold-input fold-name mono" aria-label={rule.kind === 'header' ? 'Header' : 'Field'} value={rule.name} disabled={disabled} spellCheck={false} placeholder={rule.kind === 'header' ? 'authorization' : 'key'} onChange={(event) => onChange({ ...rule, name: event.target.value })} />
      <span className="fold-text">{rule.kind === 'header' ? ':' : '='}</span>
      <TemplateInput value={rule.template} keys={keys} label="Value" placeholder="Bearer {KEY}" disabled={disabled} onChange={(template) => onChange({ ...rule, template })} />
    </Fold>
  );
}

// --- a signer, a verifier ---------------------------------------------------------------------------

function HmacLines({ row, hmac, keys, disabled, locked, onChange }: { row: Row; hmac: Hmac; keys: readonly SecretKey[]; disabled: boolean; locked: boolean; onChange: (hmac: Hmac) => void }) {
  return (
    <>
      <Line label="Key" notes={<>{problemOf(row, 'key')}<KeyNotes row={row} /></>}>
        <KeySelect value={hmac.key} keys={keys} label="Key" disabled={locked} className="select mono proxy-select" onChange={(key) => onChange({ ...hmac, key })} />
      </Line>
      <Line label="Signature" notes={problemOf(row, 'prefix', 'maxBytes')}>
        <div className="proxy-limits">
          <Fold invalid={row.problems.prefix !== undefined}>
            <select className="fold-select fold-lead" aria-label="Encoding" value={hmac.encoding} disabled={disabled} onChange={(event) => onChange({ ...hmac, encoding: event.target.value as Encoding })}>
              {ENCODINGS.map((one) => (
                <option key={one}>{one}</option>
              ))}
            </select>
            <input className="fold-input mono" aria-label="Prefix" value={hmac.prefix} disabled={disabled} spellCheck={false} placeholder="prefix" onChange={(event) => onChange({ ...hmac, prefix: event.target.value })} />
          </Fold>
          <label className="proxy-limit">
            <NumberInput value={hmac.maxBytes} label="Max bytes" disabled={disabled} onChange={(maxBytes) => onChange({ ...hmac, maxBytes })} />
            <span>bytes at most</span>
          </label>
        </div>
      </Line>
    </>
  );
}

function SignerFields({ row, signer, edits, keys, disabled }: { row: Row; signer: SignerDefinition; edits: Edits; keys: readonly SecretKey[]; disabled: boolean }) {
  const locked = disabled || row.locked.length > 0;
  const set = (change: (signer: SignerDefinition) => SignerDefinition) => edits.patch(row, (one) => change(one as SignerDefinition));
  return (
    <>
      <NameLine row={row} edits={edits} disabled={disabled} prefix={false} />
      <Line label="Signs with">
        <select
          className="select proxy-select"
          aria-label="Signs with"
          value={signer.signer.kind}
          disabled={disabled}
          onChange={(event) =>
            set((one) => ({
              ...one,
              signer: event.target.value === 'hmac' ? { kind: 'hmac', key: one.signer.key, encoding: 'hex', prefix: '', maxBytes: null } : { kind: 'private-key', key: one.signer.key },
            }))
          }
        >
          <option value="private-key">A private key (Ed25519, P-256, RSA)</option>
          <option value="hmac">HMAC-SHA256</option>
        </select>
      </Line>
      {signer.signer.kind === 'hmac' ? (
        <HmacLines row={row} hmac={signer.signer} keys={keys} disabled={disabled} locked={locked} onChange={(hmac) => set((one) => ({ ...one, signer: { kind: 'hmac', ...hmac } }))} />
      ) : (
        <Line label="Key" notes={<>{problemOf(row, 'key')}<KeyNotes row={row} /></>}>
          <KeySelect value={signer.signer.key} keys={keys} label="Key" disabled={locked} className="select mono proxy-select" onChange={(key) => set((one) => ({ ...one, signer: { kind: 'private-key', key } }))} />
        </Line>
      )}
      <LimitLine row={row} limit={signer.limit} disabled={disabled} onChange={(limit) => set((one) => ({ ...one, limit }))} />
    </>
  );
}

function VerifierFields({ row, verifier, edits, keys, disabled }: { row: Row; verifier: VerifierDefinition; edits: Edits; keys: readonly SecretKey[]; disabled: boolean }) {
  const set = (change: (verifier: VerifierDefinition) => VerifierDefinition) => edits.patch(row, (one) => change(one as VerifierDefinition));
  return (
    <>
      <NameLine row={row} edits={edits} disabled={disabled} prefix={false} />
      <HmacLines row={row} hmac={verifier.hmac} keys={keys} disabled={disabled} locked={disabled || row.locked.length > 0} onChange={(hmac) => set((one) => ({ ...one, hmac }))} />
      <LimitLine row={row} limit={verifier.limit} disabled={disabled} onChange={(limit) => set((one) => ({ ...one, limit }))} />
    </>
  );
}

// --- a database ---------------------------------------------------------------------------------------

function TunnelFields({ row, tunnel, edits, config, keys, disabled }: { row: Row; tunnel: TunnelDefinition; edits: Edits; config: ProxyConfig; keys: readonly SecretKey[]; disabled: boolean }) {
  const locked = disabled || row.locked.length > 0;
  const set = (change: (tunnel: TunnelDefinition) => TunnelDefinition) => edits.patch(row, (one) => change(one as TunnelDefinition));
  return (
    <>
      <NameLine row={row} edits={edits} disabled={disabled} prefix />
      <Line label="URL key" notes={<>{problemOf(row, 'key')}<KeyNotes row={row} /></>}>
        <KeySelect value={tunnel.key} keys={keys} label="URL key" disabled={locked} className="select mono proxy-select" onChange={(key) => set((one) => ({ ...one, key }))} />
      </Line>
      <Line label="Hosts" notes={problemOf(row, 'hosts')}>
        <div className="proxy-rows">
          {tunnel.hosts.length === 0 && <span className="proxy-static">Any, named by address</span>}
          {tunnel.hosts.map((host, index) => (
            <div key={index} className="proxy-row">
              <input
                className="input mono"
                aria-label="Host"
                value={host}
                disabled={locked}
                spellCheck={false}
                placeholder="db.acme.example"
                onChange={(event) => set((one) => ({ ...one, hosts: one.hosts.map((each, at) => (at === index ? event.target.value : each)) }))}
              />
              <RemoveButton label="Remove host" disabled={locked} onClick={() => set((one) => ({ ...one, hosts: one.hosts.filter((_, at) => at !== index) }))} />
            </div>
          ))}
          <AddButton disabled={locked} onClick={() => set((one) => ({ ...one, hosts: [...one.hosts, ''] }))}>
            Add host
          </AddButton>
        </div>
      </Line>
      <Line label="Network" notes={problemOf(row, 'network')}>
        <Fold className="is-short" invalid={row.problems.network !== undefined}>
          <TransportSelect value={tunnel.network} transports={config.networks} address={null} label="Network" disabled={locked} onChange={(network) => set((one) => ({ ...one, network }))} />
        </Fold>
      </Line>
    </>
  );
}

// --- a sample call -----------------------------------------------------------------------------------

/** A sample call through a route, as the proxy would send it on: the path it goes to, and where each rule puts its keys. */
function Preview({ route, keys, useUrl }: { route: RouteDefinition; keys: readonly SecretKey[]; useUrl: string }) {
  const [method, setMethod] = useState(route.allow[0]?.methods[0] ?? 'GET');
  const [path, setPath] = useState(route.allow[0]?.path.replace(/\/\*\*$/, '/x').replace(/\*/g, 'id') ?? '/');
  const call = sampleCall(route, method, path);
  const query = route.inject.flatMap((rule) => (rule.kind === 'query' ? [`${rule.name}=${rule.template}`] : []));
  const url = query.length === 0 ? call.url : `${call.url}${call.url.includes('?') ? '&' : '?'}${query.join('&')}`;
  return (
    <div className="proxy-preview">
      <Fold className="proxy-preview-ask">
        <select className="fold-select fold-lead mono" aria-label="Method" value={method} onChange={(event) => setMethod(event.target.value)}>
          {METHODS.map((one) => (
            <option key={one}>{one}</option>
          ))}
        </select>
        <span className="fold-text mono">
          {useUrl.replace(/^https?:\/\//, '')}/{route.name}
        </span>
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
              {route.egress !== null && <span className="proxy-how">via {route.egress}</span>}
            </p>
            {route.inject.map((rule, index) => (
              <InjectedLine key={index} rule={rule} keys={keys} />
            ))}
          </>
        )}
      </div>
    </div>
  );
}

function InjectedLine({ rule, keys }: { rule: ProxyInject; keys: readonly SecretKey[] }) {
  switch (rule.kind) {
    case 'header':
      return (
        <p className="proxy-preview-header">
          {rule.name}: <Filled text={rule.template} keys={keys} />
        </p>
      );
    case 'basic':
      return (
        <p className="proxy-preview-header">
          authorization: Basic base64(<Filled text={`${rule.user}:${rule.password}`} keys={keys} />)
        </p>
      );
    case 'sigv4':
      return (
        <p className="proxy-preview-header">
          authorization: AWS4-HMAC-SHA256 Credential=<Filled text={rule.accessKeyId} keys={keys} />/…/{rule.region}/{rule.service}, signed last with <Filled text={rule.secretAccessKey} keys={keys} />
        </p>
      );
    case 'form':
    case 'json':
      return (
        <p className="proxy-preview-header">
          body {rule.name}: <Filled text={rule.template} keys={keys} />
        </p>
      );
    case 'query':
      return null;
  }
}

/** A template with each `{KEY}` its value's stand-in. */
function Filled({ text, keys }: { text: string; keys: readonly SecretKey[] }) {
  return (
    <>
      {text.split(/(\{[A-Za-z_][A-Za-z0-9_]*\})/).map((part, index) => {
        const name = /^\{([A-Za-z_][A-Za-z0-9_]*)\}$/.exec(part)?.[1];
        if (name === undefined) return <span key={index}>{part}</span>;
        const entry = keys.find((one) => one.key === name);
        return (
          <span key={index} className={`proxy-key${entry === undefined ? ' proxy-key-missing' : entry.readable ? '' : ' proxy-key-sensitive'}`}>
            {name}
          </span>
        );
      })}
    </>
  );
}


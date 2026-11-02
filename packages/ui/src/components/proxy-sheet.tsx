// The Proxy tab's list and panel (0.16, T186): every item one short line,
// routes, databases, signers and verifiers alike, and beside them the one
// picked, its fields as its kind has them, what a sample call through a route
// becomes, and the item as code. Edits wait for the page's one Save.
import { useState, type ReactNode } from 'react';
import type { SecretKey } from '@coffre/client';

import {
  blankInject,
  blockedInWords,
  codeOf,
  ENCODINGS,
  INJECT_KINDS,
  INJECT_LABELS,
  missingInWords,
  notClearedInWords,
  routedInWords,
  methodChoices,
  sampleCall,
  savedByInWords,
  soleKey,
  targetOf,
  type AllowAs,
  type InjectKind,
  type ProxyHmac,
  type ProxyInject,
  type ProxyLimit,
  type ProxyRoute,
  type ProxySigner,
  type ProxyTunnel,
  type ProxyVerifier,
} from '../lib/proxy';
import { ArrowRight, Lock, Plus, RotateBack, Trash, X } from './icons';
import { CopyButton, EmptyState, Timestamp, Toggletip } from './ui';
import { Fold, KeySelect, KindTag, lockedByCodeInWords, MethodsMenu, Note, NumberInput, scopeInWords, TemplateInput, type Edits, type Row } from './proxy-parts';

export function ProxySheet({ edits, selected, onSelect, footer }: { edits: Edits; selected: string | null; onSelect: (id: string) => void; footer: ReactNode }) {
  const rows = edits.rows;
  const row = rows.find((one) => one.id === selected) ?? rows[0];
  if (row === undefined) {
    return (
      <section className="card card-wide proxy-empty" aria-label="Proxy">
        <EmptyState title="Nothing here yet">
          {edits.editor.editable
            ? `Add a route, a signer, a verifier or a database, and apps run with ${edits.place.project}/${edits.place.environment} reach it through /use, with its keys filled in.`
            : `Neither this deployment's code nor ${edits.place.project}/${edits.place.environment} defines anything for the credential proxy.`}
        </EmptyState>
        <div className="proxy-list-foot">{footer}</div>
      </section>
    );
  }
  return (
    <div className="proxy-frame">
      <div className="proxy-split">
        <section className="card proxy-list" aria-label="Proxy items">
          <ul>
            {rows.map((one) => {
              const faulty = Object.keys(edits.problems(one)).length > 0;
              return (
                <li key={one.id}>
                  <button
                    type="button"
                    className={`proxy-list-row${one.id === row.id ? ' is-current' : ''}${one.state === 'deleted' ? ' is-leaving' : ''}${one.item?.source === 'code' && !one.item.serves ? ' is-elsewhere' : ''}`}
                    aria-current={one.id === row.id}
                    onClick={() => onSelect(one.id)}
                  >
                    <KindTag kind={one.definition.kind} />
                    <span className="mono proxy-list-name">{one.definition.name || 'new'}</span>
                    <span className="mono proxy-list-target">{targetOf(one.definition)}</span>
                    <span className="proxy-list-marks">
                      {faulty ? (
                        <span className="dot dot-red" aria-label="Needs fixing" />
                      ) : one.state !== 'same' ? (
                        <span className="dot" aria-label="Changed" />
                      ) : (
                        one.item?.notCleared != null && <span className="dot dot-amber" aria-label="Does not route now" title="Does not route now" />
                      )}
                      {one.item?.source === 'code' && <Lock size={12} label={scopeInWords(one.item)} />}
                      {one.item?.source === 'inherited' && <span className="proxy-from">{one.item.from!.split('/')[1]}</span>}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
          <div className="proxy-list-foot">{footer}</div>
        </section>
        <Panel key={row.id} row={row} edits={edits} keys={edits.editor.keys} />
      </div>
    </div>
  );
}

type PanelProps = { row: Row; edits: Edits; keys: readonly SecretKey[] };

/** A label, its field, and what is wrong with it, one line each. */
function Line({ label, children, notes }: { label: string; children: ReactNode; notes?: ReactNode }) {
  return (
    <div className="proxy-line">
      <span className="proxy-line-label">{label}</span>
      <div className="proxy-line-field">
        {children}
        {notes}
      </div>
    </div>
  );
}

function problemOf(edits: Edits, row: Row, ...fields: string[]) {
  const problems = edits.problems(row);
  const found = fields.map((field) => problems[field]).filter((one) => one !== undefined);
  return found.length === 0 ? null : <Note>{found[0]}</Note>;
}

function Panel({ row, edits, keys }: PanelProps) {
  const disabled = !row.editable;
  const item = row.item;
  const definition = row.definition;
  const routed = definition.kind === 'route' || definition.kind === 'tunnel';
  const parent = item?.from?.split('/')[1] ?? null;
  // Moved into code, it serves where it serves now; code's own is in code already.
  const asCode = item?.source === 'code' ? null : codeOf(definition, [`${edits.place.project}/${edits.place.environment}`]);
  return (
    <section className={`card proxy-sheet${row.state === 'deleted' ? ' is-leaving' : ''}`} aria-label={definition.name || 'New item'}>
      <header className="proxy-sheet-head">
        <KindTag kind={definition.kind} />
        <h2 className="mono proxy-sheet-title">
          {routed ? '/use/' : ''}
          {definition.name || '…'}
        </h2>
        {item?.source === 'code' && (
          <Toggletip label={lockedByCodeInWords(item)}>
            <button type="button" className="btn btn-quiet btn-sm btn-icon" aria-label={scopeInWords(item)}>
              <Lock size={14} />
            </button>
          </Toggletip>
        )}
        <span className="proxy-sheet-actions">
          {row.state === 'deleted' || row.state === 'resaved' || row.overtaken ? (
            <button className="btn btn-sm" type="button" onClick={() => edits.restore(row)}>
              <RotateBack size={14} />
              {row.state === 'deleted' ? 'Keep' : 'Undo'}
            </button>
          ) : (
            row.removable && (
              <button className="btn btn-sm btn-quiet" type="button" onClick={() => edits.remove(row)}>
                {parent === null ? <Trash size={14} /> : <RotateBack size={14} />}
                {parent === null ? 'Delete' : `Revert to ${parent}'s`}
              </button>
            )
          )}
        </span>
      </header>
      <Provenance row={row} edits={edits} />
      {item?.notCleared != null && row.state !== 'resaved' && row.state !== 'deleted' && (
        <div className="proxy-uncleared">
          <Note tone="warn">{notClearedInWords(item, edits.place)}</Note>
          {row.editable && row.keys.blocked.length === 0 && item.source !== 'code' && row.state === 'same' && (
            <button className="btn btn-sm" type="button" onClick={() => edits.resave(row)}>
              Save again as you
            </button>
          )}
        </div>
      )}
      <fieldset className="proxy-sheet-grid" disabled={disabled}>
        {definition.kind === 'route' ? (
          <RouteFields row={row} route={definition} edits={edits} keys={keys} disabled={disabled} />
        ) : definition.kind === 'signer' ? (
          <SignerFields row={row} signer={definition} edits={edits} keys={keys} disabled={disabled} />
        ) : definition.kind === 'verifier' ? (
          <VerifierFields row={row} verifier={definition} edits={edits} keys={keys} disabled={disabled} />
        ) : (
          <TunnelFields row={row} tunnel={definition} edits={edits} keys={keys} disabled={disabled} />
        )}
      </fieldset>
      {definition.kind === 'route' && <Preview route={definition} allowAs={item?.allowAs ?? null} keys={keys} useUrl={edits.page.useUrl} />}
      {/* Code's own item is in code already, some of it (a binding, a limit per service) beyond what the page can write out. */}
      {asCode !== null && (
        <details className="proxy-as-code">
          <summary>As code</summary>
          <div className="proxy-code">
            <pre className="mono">{asCode}</pre>
            <span className="proxy-code-copy">
              <CopyButton value={asCode} label="Copy as code" />
            </span>
          </div>
        </details>
      )}
    </section>
  );
}

/** Where an item comes from, under its title: who saved it and when, the parent it is inherited from or overrides, and what code scopes. */
function Provenance({ row, edits }: { row: Row; edits: Edits }) {
  const item = row.item;
  if (item === null) return row.copiedFrom === null ? null : <p className="proxy-provenance">Copied from {row.copiedFrom}, not saved yet.</p>;
  if (row.overtaken) return <p className="proxy-provenance">Changed by another save since you began editing it: saving keeps it as you saw it, with your edits. The review shows each field that sets back.</p>;
  if (row.gone) return <p className="proxy-provenance">Removed by another save since you began editing it: saving makes it again, {row.state === 'resaved' ? 'as it was' : 'as you edited it'}.</p>;
  // Code's item shows locked with code's values, its lock saying where it serves (R66); only one that serves elsewhere says so here.
  if (item.source === 'code') {
    return item.serves ? null : <p className="proxy-provenance">{scopeInWords(item)}: {edits.place.project}/{edits.place.environment} has no {item.definition.name}, and none of its own takes the name.</p>;
  }
  const saved = (lead: string) =>
    item.savedAt === null ? null : (
      <>
        {lead} by {savedByInWords(item.savedBy)} <Timestamp iso={new Date(item.savedAt).toISOString()} display="relative" />
      </>
    );
  if (item.source === 'inherited') {
    return (
      <p className="proxy-provenance">
        Inherited from {item.from}, {saved('saved')}.{row.editable && ` A change here overrides it for ${edits.place.environment}.`}
      </p>
    );
  }
  return (
    <p className="proxy-provenance">
      {saved('Saved')}
      {item.from !== null && <>, over {item.from}&apos;s</>}.
    </p>
  );
}

/** The name, as the URL or the app says it. An inherited item, or one that overrides a parent's, keeps its name. */
function NameLine({ row, edits, disabled, prefix }: { row: Row; edits: Edits; disabled: boolean; prefix: boolean }) {
  const fixed = row.item?.source === 'inherited' || (row.item?.source === 'own' && row.item.from !== null);
  return (
    <Line label="Name" notes={problemOf(edits, row, 'name', 'item')}>
      <Fold invalid={edits.problems(row).name !== undefined}>
        {prefix && <span className="fold-text">/use/</span>}
        <input
          className="fold-input mono"
          aria-label="Name"
          value={row.definition.name}
          disabled={disabled || fixed}
          spellCheck={false}
          autoComplete="off"
          placeholder="name"
          onChange={(event) => edits.patch(row, (one) => ({ ...one, name: event.target.value }))}
        />
      </Fold>
    </Line>
  );
}

/** How its keys stand for this editor: those they may not route, those an Owner routes (audited), those the place lacks yet. */
function KeyNotes({ row, edits }: { row: Row; edits: Edits }) {
  const editing = edits.editor.editable && row.item?.source !== 'code';
  return (
    <>
      {problemOf(edits, row, 'keys')}
      {editing && !row.editable && row.state !== 'deleted' && row.keys.blocked.length > 0 && edits.problems(row).keys === undefined && (
        <Note tone="warn">
          {blockedInWords(row.keys.blocked, edits.place, edits.editor.keys)} Its fields stay as they are{row.removable ? '; you may delete it' : ''}.
        </Note>
      )}
      {editing && row.state !== 'same' && row.state !== 'deleted' && row.keys.routed.length > 0 && <Note tone="warn">{routedInWords(row.keys.routed, edits.place, edits.editor.keys)}</Note>}
      {editing && row.state !== 'deleted' && row.keys.missing.length > 0 && <Note tone="warn">{missingInWords(row.keys.missing, edits.place)}</Note>}
    </>
  );
}

function LimitLine({ row, edits, limit, disabled, onChange }: { row: Row; edits: Edits; limit: ProxyLimit; disabled: boolean; onChange: (limit: ProxyLimit) => void }) {
  if (row.item?.limitPerService) {
    return (
      <Line label="Limit">
        <span className="proxy-static">Per service, in code</span>
      </Line>
    );
  }
  return (
    <Line label="Limit" notes={problemOf(edits, row, 'limit')}>
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

function RouteFields({ row, route, edits, keys, disabled }: { row: Row; route: ProxyRoute; edits: Edits; keys: readonly SecretKey[]; disabled: boolean }) {
  const set = (change: (route: ProxyRoute) => ProxyRoute) => edits.patch(row, (one) => change(one as ProxyRoute));
  const setRule = (index: number, rule: ProxyInject) => set((one) => ({ ...one, inject: one.inject.map((each, at) => (at === index ? rule : each)) }));
  const setAllow = (allow: ProxyRoute['allow']) => set((one) => ({ ...one, allow: allow !== null && allow.length === 0 ? null : allow }));
  const shaped = route.inject.some((rule) => rule.kind !== 'basic' && rule.kind !== 'sigv4');
  const allowAs = row.item?.allowAs ?? null;
  const via = route.egress ?? (row.item?.bound ? "code's egress" : null);
  return (
    <>
      <NameLine row={row} edits={edits} disabled={disabled} prefix />
      <Line label="Upstream" notes={problemOf(edits, row, 'upstream')}>
        <Fold invalid={edits.problems(row).upstream !== undefined}>
          <input className="fold-input mono" aria-label="Upstream" value={route.upstream} disabled={disabled} spellCheck={false} autoComplete="off" placeholder="https://api.example.com" onChange={(event) => set((one) => ({ ...one, upstream: event.target.value }))} />
          <span className="fold-text fold-end" title={via === null ? 'Its requests leave from coffre itself' : `Its requests leave through ${via}`}>
            {via === null ? 'Direct' : `via ${via}`}
          </span>
        </Fold>
      </Line>
      <Line label="Sends" notes={<>{problemOf(edits, row, 'inject')}<KeyNotes row={row} edits={edits} /></>}>
        <div className="proxy-rows">
          {route.inject.map((rule, index) => (
            <div key={index} className="proxy-row">
              <InjectRule rule={rule} keys={keys} disabled={disabled} invalid={edits.problems(row)[`inject.${index}`] !== undefined} onChange={(next) => setRule(index, next)} />
              <RemoveButton label="Remove rule" disabled={disabled || route.inject.length === 1} onClick={() => set((one) => ({ ...one, inject: one.inject.filter((_, at) => at !== index) }))} />
              {problemOf(edits, row, `inject.${index}`)}
            </div>
          ))}
          <AddButton disabled={disabled} onClick={() => set((one) => ({ ...one, inject: [...one.inject, blankInject('header')] }))}>
            Add rule
          </AddButton>
        </div>
      </Line>
      {shaped && (
        <Line label="Placeholder" notes={problemOf(edits, row, 'placeholder')}>
          <Fold invalid={edits.problems(row).placeholder !== undefined} className={route.placeholder === null ? 'is-short' : undefined}>
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
      <Line
        label="Allows"
        notes={
          <>
            {problemOf(edits, row, 'allow')}
            {allowAs?.from === 'legacy' && (
              <p className="hint">
                Code&apos;s <span className="mono">methods</span> and <span className="mono">paths</span>, matched as before 0.16: each path as written, <span className="mono">*</span> itself, never a glob
                {allowAs.methods?.length === 0 && <>; its <span className="mono">methods: []</span> takes no method, so every call is refused</>}
                {route.allow?.length === 0 && (allowAs.methods?.length ?? 0) > 0 && (
                  <>
                    ; its <span className="mono">paths: []</span> takes no path, so every call is refused: a 405 to a method other than {allowAs.methods!.join(', ')}
                  </>
                )}
                .
              </p>
            )}
          </>
        }
      >
        <div className="proxy-rows">
          {route.allow === null && <span className="proxy-static">Any method, any path</span>}
          {route.allow?.length === 0 && <span className="proxy-static">No request</span>}
          {(route.allow ?? []).map((entry, index) => (
            <div key={index} className="proxy-row">
              <Fold invalid={edits.problems(row)[`allow.${index}`] !== undefined}>
                {allowAs?.methods?.length === 0 ? (
                  <span className="fold-text mono">No method</span>
                ) : (
                  <MethodsMenu methods={entry.methods} disabled={disabled} onChange={(methods) => setAllow((route.allow ?? []).map((each, at) => (at === index ? { ...each, methods } : each)))} />
                )}
                <input
                  className="fold-input mono"
                  aria-label="Path"
                  value={entry.path}
                  disabled={disabled}
                  spellCheck={false}
                  placeholder="/companies/*/documents/**"
                  onChange={(event) => setAllow((route.allow ?? []).map((each, at) => (at === index ? { ...each, path: event.target.value } : each)))}
                />
              </Fold>
              <RemoveButton label="Remove entry" disabled={disabled} onClick={() => setAllow((route.allow ?? []).filter((_, at) => at !== index))} />
              {problemOf(edits, row, `allow.${index}`)}
            </div>
          ))}
          <AddButton disabled={disabled} onClick={() => setAllow([...(route.allow ?? []), { methods: ['GET'], path: '/' }])}>
            Add entry
          </AddButton>
        </div>
      </Line>
      <LimitLine row={row} edits={edits} limit={route.limit} disabled={disabled} onChange={(limit) => set((one) => ({ ...one, limit }))} />
    </>
  );
}

function InjectRule({ rule, keys, disabled, invalid, onChange }: { rule: ProxyInject; keys: readonly SecretKey[]; disabled: boolean; invalid: boolean; onChange: (rule: ProxyInject) => void }) {
  const kind = (
    <select className="fold-select fold-lead fold-kind" aria-label="Sends as" value={rule.kind} disabled={disabled} onChange={(event) => onChange(blankInject(event.target.value as InjectKind))}>
      {INJECT_KINDS.map((one) => (
        <option key={one} value={one}>
          {INJECT_LABELS[one]}
        </option>
      ))}
    </select>
  );
  if (rule.kind === 'sigv4') {
    // A field the API took as a template, `{PREFIX}{AWS_SECRET_ACCESS_KEY}`, is no one key to pick: it shows, and edits, as written.
    const pick = (field: 'accessKeyId' | 'secretAccessKey' | 'sessionToken', label: string) => (rule[field] ?? '') !== '' && soleKey(rule[field]) === '' ? (
      <TemplateInput value={rule[field] ?? ''} keys={keys} label={label} placeholder={`{${label.toUpperCase().replace(/ /g, '_')}}`} disabled={disabled} onChange={(template) => onChange({ ...rule, [field]: template === '' && field === 'sessionToken' ? null : template })} />
    ) : (
      <KeySelect
        value={soleKey(rule[field])}
        keys={keys}
        label={label}
        optional={field === 'sessionToken'}
        disabled={disabled}
        onChange={(key) => onChange({ ...rule, [field]: key === '' ? (field === 'sessionToken' ? null : '') : `{${key}}` })}
      />
    );
    // Two lines: what it signs for, then the keys it signs with, a session token's optional.
    return (
      <div className="proxy-fold-stack">
        <Fold invalid={invalid}>
          {kind}
          <span className="fold-text">region</span>
          <input className="fold-input fold-short mono" aria-label="Region" value={rule.region} disabled={disabled} placeholder="eu-west-3" onChange={(event) => onChange({ ...rule, region: event.target.value.trim() })} />
          <span className="fold-text">service</span>
          <input className="fold-input fold-short mono" aria-label="Service" value={rule.service} disabled={disabled} placeholder="s3" onChange={(event) => onChange({ ...rule, service: event.target.value.trim() })} />
        </Fold>
        <Fold invalid={invalid}>
          {pick('accessKeyId', 'Access key ID')}
          {pick('secretAccessKey', 'Secret access key')}
          {pick('sessionToken', 'Session token')}
        </Fold>
      </div>
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
      <input
        className="fold-input fold-name mono"
        aria-label={rule.kind === 'header' ? 'Header' : 'Field'}
        value={rule.name}
        disabled={disabled}
        spellCheck={false}
        placeholder={rule.kind === 'header' ? 'authorization' : 'key'}
        onChange={(event) => onChange({ ...rule, name: event.target.value })}
      />
      <span className="fold-text">{rule.kind === 'header' ? ':' : '='}</span>
      <TemplateInput value={rule.template} keys={keys} label="Value" placeholder="Bearer {KEY}" disabled={disabled} onChange={(template) => onChange({ ...rule, template })} />
    </Fold>
  );
}

// --- a signer, a verifier ---------------------------------------------------------------------------

function HmacLines({ row, edits, hmac, keys, disabled, onChange }: { row: Row; edits: Edits; hmac: ProxyHmac; keys: readonly SecretKey[]; disabled: boolean; onChange: (hmac: ProxyHmac) => void }) {
  return (
    <>
      <Line label="Key" notes={<>{problemOf(edits, row, 'key')}<KeyNotes row={row} edits={edits} /></>}>
        <KeySelect value={hmac.key} keys={keys} label="Key" disabled={disabled} className="select mono proxy-select" onChange={(key) => onChange({ ...hmac, key })} />
      </Line>
      <Line label="Signature" notes={problemOf(edits, row, 'signature')}>
        <div className="proxy-limits">
          <Fold invalid={edits.problems(row).signature !== undefined}>
            <select className="fold-select fold-lead" aria-label="Encoding" value={hmac.encoding} disabled={disabled} onChange={(event) => onChange({ ...hmac, encoding: event.target.value as ProxyHmac['encoding'] })}>
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

function SignerFields({ row, signer, edits, keys, disabled }: { row: Row; signer: ProxySigner; edits: Edits; keys: readonly SecretKey[]; disabled: boolean }) {
  const set = (change: (signer: ProxySigner) => ProxySigner) => edits.patch(row, (one) => change(one as ProxySigner));
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
        <HmacLines row={row} edits={edits} hmac={signer.signer} keys={keys} disabled={disabled} onChange={(hmac) => set((one) => ({ ...one, signer: { kind: 'hmac', ...hmac } }))} />
      ) : (
        <Line label="Key" notes={<>{problemOf(edits, row, 'key')}<KeyNotes row={row} edits={edits} /></>}>
          <KeySelect value={signer.signer.key} keys={keys} label="Key" disabled={disabled} className="select mono proxy-select" onChange={(key) => set((one) => ({ ...one, signer: { kind: 'private-key', key } }))} />
        </Line>
      )}
      <LimitLine row={row} edits={edits} limit={signer.limit} disabled={disabled} onChange={(limit) => set((one) => ({ ...one, limit }))} />
    </>
  );
}

function VerifierFields({ row, verifier, edits, keys, disabled }: { row: Row; verifier: ProxyVerifier; edits: Edits; keys: readonly SecretKey[]; disabled: boolean }) {
  const set = (change: (verifier: ProxyVerifier) => ProxyVerifier) => edits.patch(row, (one) => change(one as ProxyVerifier));
  return (
    <>
      <NameLine row={row} edits={edits} disabled={disabled} prefix={false} />
      <HmacLines row={row} edits={edits} hmac={verifier.hmac} keys={keys} disabled={disabled} onChange={(hmac) => set((one) => ({ ...one, hmac }))} />
      <LimitLine row={row} edits={edits} limit={verifier.limit} disabled={disabled} onChange={(limit) => set((one) => ({ ...one, limit }))} />
    </>
  );
}

// --- a database ---------------------------------------------------------------------------------------

function TunnelFields({ row, tunnel, edits, keys, disabled }: { row: Row; tunnel: ProxyTunnel; edits: Edits; keys: readonly SecretKey[]; disabled: boolean }) {
  const set = (change: (tunnel: ProxyTunnel) => ProxyTunnel) => edits.patch(row, (one) => change(one as ProxyTunnel));
  const via = tunnel.network ?? (row.item?.bound ? "code's network" : null);
  return (
    <>
      <NameLine row={row} edits={edits} disabled={disabled} prefix />
      <Line label="URL key" notes={<>{problemOf(edits, row, 'key')}<KeyNotes row={row} edits={edits} /></>}>
        <KeySelect value={tunnel.key} keys={keys} label="URL key" disabled={disabled} className="select mono proxy-select" onChange={(key) => set((one) => ({ ...one, key }))} />
      </Line>
      <Line label="Hosts" notes={problemOf(edits, row, 'hosts')}>
        <div className="proxy-rows">
          {tunnel.hosts.length === 0 && <span className="proxy-static">Any, named by address</span>}
          {tunnel.hosts.map((host, index) => (
            <div key={index} className="proxy-row">
              <input
                className="input mono"
                aria-label="Host"
                value={host}
                disabled={disabled}
                spellCheck={false}
                placeholder="db.acme.example"
                onChange={(event) => set((one) => ({ ...one, hosts: one.hosts.map((each, at) => (at === index ? event.target.value : each)) }))}
              />
              <RemoveButton label="Remove host" disabled={disabled || tunnel.hosts.length === 1} onClick={() => set((one) => ({ ...one, hosts: one.hosts.filter((_, at) => at !== index) }))} />
            </div>
          ))}
          <AddButton disabled={disabled} onClick={() => set((one) => ({ ...one, hosts: [...one.hosts, ''] }))}>
            Add host
          </AddButton>
        </div>
      </Line>
      <Line label="Network">
        <span className="proxy-static">{via === null ? 'Direct' : `Through ${via}`}</span>
      </Line>
    </>
  );
}

// --- a sample call -----------------------------------------------------------------------------------

/** A sample call through a route, as the proxy would send it on: the path it goes to, and where each rule puts its keys. */
function Preview({ route, allowAs, keys, useUrl }: { route: ProxyRoute; allowAs: AllowAs | null; keys: readonly SecretKey[]; useUrl: string }) {
  const first = route.allow?.[0];
  const [method, setMethod] = useState<string>(first?.methods[0] ?? 'GET');
  const [path, setPath] = useState(first?.path.replace(/\/\*\*$/, '/x').replace(/\*/g, 'id') ?? '/');
  const call = sampleCall(route, method, path, allowAs);
  const query = route.inject.flatMap((rule) => (rule.kind === 'query' ? [`${rule.name}=${rule.template}`] : []));
  const url = query.length === 0 ? call.url : `${call.url}${call.url.includes('?') ? '&' : '?'}${query.join('&')}`;
  return (
    <div className="proxy-preview">
      <Fold className="proxy-preview-ask">
        <select className="fold-select fold-lead mono" aria-label="Method" value={method} onChange={(event) => setMethod(event.target.value)}>
          {methodChoices(route, allowAs).map((one) => (
            <option key={one}>{one}</option>
          ))}
        </select>
        <span className="fold-text mono" title={`${useUrl}/${route.name}`}>
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
        const entry = keys.find((one) => one.key === name && !one.archived);
        return (
          <span key={index} className={`proxy-key${entry === undefined ? ' proxy-key-missing' : entry.readable ? '' : ' proxy-key-sensitive'}`}>
            {name}
          </span>
        );
      })}
    </>
  );
}

// The Proxy tab as a document (variant C of the W260 prototype): each route
// reads as the code would define it, `credentialProxy({ credentials })`, and
// its values are edited where they stand. The code's own entries read the
// same, locked. Edits wait for the page's one Save.
import type { ReactNode } from 'react';
import { Menu } from '@base-ui/react/menu';

import { blankInject, egressRefusal, soleKey, unreadableInWords, type Form, type InjectKind, type ProxyConfig, type ProxyInject } from '../lib/proxy-prototype';
import type { SecretKey } from '../shared/models';
import { Lock, MoreHorizontal, RotateBack, Trash } from './icons';
import { EmptyState, MenuPopup, Tip } from './ui';
import { KeyMenu, MethodsMenu, RowNotes, type Edits, type Row } from './proxy-parts';

export function ProxyDocument({ edits, config, keys }: { edits: Edits; config: ProxyConfig; keys: readonly SecretKey[] }) {
  if (edits.rows.length === 0) {
    return (
      <section className="card card-wide" aria-label="Proxy credentials">
        <EmptyState title="No credentials yet" />
      </section>
    );
  }
  return (
    <div className="proxy-doc-list">
      {edits.rows.map((row) => (
        <Entry key={row.id} row={row} edits={edits} config={config} keys={keys} />
      ))}
    </div>
  );
}

/** A value as code holds it, an input as wide as what it holds. */
function Code({
  value,
  placeholder,
  invalid,
  readOnly,
  label,
  kind = 'str',
  onChange,
}: {
  value: string;
  placeholder: string;
  invalid: boolean;
  readOnly: boolean;
  label: string;
  kind?: 'str' | 'num' | 'name';
  onChange: (value: string) => void;
}) {
  return (
    <input
      className={`code-input code-${kind}${invalid ? ' is-invalid' : ''}`}
      aria-label={label}
      value={value}
      placeholder={placeholder}
      readOnly={readOnly}
      spellCheck={false}
      autoComplete="off"
      inputMode={kind === 'num' ? 'numeric' : undefined}
      onChange={(event) => onChange(event.target.value)}
    />
  );
}

const P = ({ children }: { children: ReactNode }) => <span className="code-punct">{children}</span>;
const K = ({ children }: { children: ReactNode }) => <span className="code-key">{children}</span>;
const Q = ({ children }: { children: ReactNode }) => (
  <>
    <P>&apos;</P>
    {children}
    <P>&apos;</P>
  </>
);

function Entry({ row, edits, config, keys }: { row: Row; edits: Edits; config: ProxyConfig; keys: readonly SecretKey[] }) {
  const { credential, form, problems } = row;
  const code = credential?.source === 'code';
  const shadowed = credential?.shadowedSince != null;
  const readOnly = !row.editable || row.state === 'deleted';
  const redirectLocked = readOnly || row.locked.length > 0;
  const patch = (next: Partial<Form>) => edits.patch(row.id, next);
  const has = (...fields: (keyof typeof problems)[]) => fields.some((field) => problems[field] !== undefined);
  const line = (children: ReactNode, depth = 1) => <div className={`code-line depth-${depth}`}>{children}</div>;
  const shapes = ['header', 'query', 'form', 'json'].includes(form.inject.kind);

  return (
    <article className={`card proxy-doc${row.state === 'deleted' ? ' is-leaving' : row.state !== 'same' ? ' is-changed' : ''}${shadowed ? ' proxy-shadowed' : ''}`} aria-label={row.definition.name}>
      <div className="proxy-doc-gutter">
        {code && <Lock size={13} label="Defined in code" />}
        {row.editable && (
          <Menu.Root>
            <Menu.Trigger className="act act-icon act-quiet" aria-label={`Actions for ${row.definition.name}`}>
              <MoreHorizontal size={16} />
            </Menu.Trigger>
            <MenuPopup align="end">
              {row.state === 'deleted' ? (
                <Menu.Item className="menu-item" onClick={() => edits.restore(row)}>
                  <RotateBack size={14} />
                  Keep
                </Menu.Item>
              ) : (
                <Menu.Item className="menu-item menu-item-danger" onClick={() => edits.remove(row)}>
                  <Trash size={14} />
                  Delete
                </Menu.Item>
              )}
            </MenuPopup>
          </Menu.Root>
        )}
      </div>
      <div className="proxy-code">
        <div className="code-line code-comment">
          {`// /use/${form.name || '…'}`}
          {code ? ', in code, for every environment' : shadowed ? ', shadowed by code: not served' : row.credential?.changedBy ? `, ${row.credential.changedBy.split('@')[0]}` : ''}
        </div>
        {line(
          <>
            <Code kind="name" value={form.name} placeholder="name" label="Name" invalid={has('name')} readOnly={readOnly} onChange={(name) => patch({ name })} />
            <P>: {'{'}</P>
          </>,
          0,
        )}
        {line(
          <>
            <K>upstream</K>
            <P>: </P>
            <Q>
              <Code value={form.upstream} placeholder="https://" label="Upstream" invalid={has('upstream')} readOnly={redirectLocked} onChange={(upstream) => patch({ upstream })} />
            </Q>
            <P>,</P>
            {row.editable && row.locked.length > 0 && (
              <Tip label={unreadableInWords(row.locked)}>
                <span className="code-lock" tabIndex={0}>
                  <Lock size={12} label="Where it sends its keys is locked" />
                </span>
              </Tip>
            )}
          </>,
        )}
        {!(code && form.egress === null) && line(
          <>
            <K>egress</K>
            <P>: </P>
            <select className={`code-select${has('egress') ? ' is-invalid' : ''}`} aria-label="Egress" value={form.egress ?? ''} disabled={redirectLocked} onChange={(event) => patch({ egress: event.target.value === '' ? null : event.target.value })}>
              <option value="">direct</option>
              {config.egresses.map((egress) => (
                <option key={egress.name} value={egress.name} disabled={egressRefusal(egress, form.upstream) !== null && egress.name !== form.egress}>
                  {`'${egress.name}'`}
                </option>
              ))}
            </select>
            <P>,</P>
          </>,
        )}
        <Inject row={row} keys={keys} readOnly={redirectLocked} has={has} onChange={(inject) => patch({ inject })} line={line} />
        {shapes && !(code && form.placeholder === 'none') &&
          line(
            <>
              <K>placeholder</K>
              <P>: </P>
              <select className={`code-select code-fn${has('placeholder') ? ' is-invalid' : ''}`} aria-label="Placeholder" value={form.placeholder} disabled={readOnly} onChange={(event) => patch({ placeholder: event.target.value as Form['placeholder'] })}>
                <option value="none">handle</option>
                <option value="prefix">prefix</option>
                <option value="jwt">jwt</option>
              </select>
              {form.placeholder !== 'none' && (
                <>
                  <P>(</P>
                  <Q>
                    <Code value={form.shape} placeholder={form.placeholder === 'prefix' ? 'sk_test_' : 'claims'} label="Placeholder shape" invalid={has('placeholder')} readOnly={readOnly} onChange={(shape) => patch({ shape })} />
                  </Q>
                  <P>)</P>
                </>
              )}
              <P>,</P>
            </>,
          )}
        {line(
          <>
            <K>methods</K>
            <P>: </P>
            {readOnly ? (
              <span className="code-str">{form.methods.length === 0 ? 'any' : `[${form.methods.map((one) => `'${one}'`).join(', ')}]`}</span>
            ) : (
              <MethodsMenu row={row} edits={edits} className="code-select code-menu" asCode />
            )}
            <P>,</P>
          </>,
        )}
        {line(
          <>
            <K>paths</K>
            <P>: [</P>
            <Code value={form.paths} placeholder="any" label="Paths" invalid={has('paths')} readOnly={readOnly} onChange={(paths) => patch({ paths })} />
            <P>],</P>
          </>,
        )}
        {line(
          credential?.limitPerService ? (
            <>
              <K>limit</K>
              <P>: </P>
              <span className="code-fn">(service) =&gt; …</span>
              <P>,</P>
            </>
          ) : (
            <>
              <K>limit</K>
              <P>: {'{ '}</P>
              <K>perMinute</K>
              <P>: </P>
              <Code kind="num" value={form.perMinute} placeholder="none" label="A minute" invalid={has('perMinute')} readOnly={readOnly} onChange={(perMinute) => patch({ perMinute })} />
              <P>, </P>
              <K>perDay</K>
              <P>: </P>
              <Code kind="num" value={form.perDay} placeholder="none" label="A day" invalid={has('perDay')} readOnly={readOnly} onChange={(perDay) => patch({ perDay })} />
              <P>{' },'}</P>
            </>
          ),
        )}
        {line(<P>{'},'}</P>, 0)}
      </div>
      <RowNotes row={row} />
    </article>
  );
}

const KINDS: InjectKind[] = ['header', 'query', 'form', 'json', 'basic', 'sigv4'];

function Inject({
  row,
  keys,
  readOnly,
  has,
  onChange,
  line,
}: {
  row: Row;
  keys: readonly SecretKey[];
  readOnly: boolean;
  has: (...fields: ('injectName' | 'template' | 'user' | 'password' | 'accessKeyId' | 'secretAccessKey' | 'region' | 'service' | 'keys')[]) => boolean;
  onChange: (inject: ProxyInject) => void;
  line: (children: ReactNode, depth?: number) => ReactNode;
}) {
  const inject = row.form.inject;
  const fn = (
    <select className={`code-select code-fn${has('keys') ? ' is-invalid' : ''}`} aria-label="Sends as" value={inject.kind} disabled={readOnly} onChange={(event) => onChange(blankInject(event.target.value as InjectKind))}>
      {KINDS.map((kind) => (
        <option key={kind} value={kind}>
          {kind}
        </option>
      ))}
    </select>
  );
  const keyMenu = (put: (key: string) => void) => !readOnly && <KeyMenu keys={keys} disabled={readOnly} onPick={put} className="code-keys" />;

  if (inject.kind === 'sigv4') {
    const pick = (field: 'accessKeyId' | 'secretAccessKey', label: string) => (
      <select className={`code-select code-str${has(field) ? ' is-invalid' : ''}`} aria-label={label} value={soleKey(inject[field])} disabled={readOnly} onChange={(event) => onChange({ ...inject, [field]: event.target.value === '' ? '' : `{${event.target.value}}` })}>
        <option value="">pick a key</option>
        {keys.map((entry) => (
          <option key={entry.key} value={entry.key}>
            {`'{${entry.key}}'`}
          </option>
        ))}
      </select>
    );
    return (
      <>
        {line(
          <>
            <K>inject</K>
            <P>: </P>
            {fn}
            <P>({'{'}</P>
          </>,
        )}
        {line(<><K>accessKeyId</K><P>: </P>{pick('accessKeyId', 'Access key ID')}<P>,</P></>, 2)}
        {line(<><K>secretAccessKey</K><P>: </P>{pick('secretAccessKey', 'Secret access key')}<P>,</P></>, 2)}
        {line(
          <>
            <K>region</K>
            <P>: </P>
            <Q>
              <Code value={inject.region} placeholder="eu-west-3" label="Region" invalid={has('region')} readOnly={readOnly} onChange={(region) => onChange({ ...inject, region: region.trim() })} />
            </Q>
            <P>, </P>
            <K>service</K>
            <P>: </P>
            <Q>
              <Code value={inject.service} placeholder="s3" label="Service" invalid={has('service')} readOnly={readOnly} onChange={(service) => onChange({ ...inject, service: service.trim() })} />
            </Q>
            <P>,</P>
          </>,
          2,
        )}
        {line(<P>{'}),'}</P>)}
      </>
    );
  }
  if (inject.kind === 'basic') {
    return line(
      <>
        <K>inject</K>
        <P>: </P>
        {fn}
        <P>(</P>
        <Q>
          <Code value={inject.user} placeholder="user" label="User" invalid={has('user')} readOnly={readOnly} onChange={(user) => onChange({ ...inject, user })} />
        </Q>
        <P>, </P>
        <Q>
          <Code value={inject.password} placeholder="" label="Password" invalid={has('password')} readOnly={readOnly} onChange={(password) => onChange({ ...inject, password })} />
        </Q>
        <P>),</P>
        {keyMenu((key) => onChange({ ...inject, user: `${inject.user}{${key}}` }))}
      </>,
    );
  }
  return line(
    <>
      <K>inject</K>
      <P>: </P>
      {fn}
      <P>(</P>
      <Q>
        <Code value={inject.name} placeholder="name" label="Name" invalid={has('injectName')} readOnly={readOnly} onChange={(name) => onChange({ ...inject, name })} />
      </Q>
      <P>, </P>
      <Q>
        <Code value={inject.template} placeholder="{KEY}" label="Value" invalid={has('template')} readOnly={readOnly} onChange={(template) => onChange({ ...inject, template })} />
      </Q>
      <P>),</P>
      {keyMenu((key) => onChange({ ...inject, template: `${inject.template}{${key}}` }))}
    </>,
  );
}

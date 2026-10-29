import { useState, type ReactNode } from 'react';
import { useQuery, useQueryClient, useSuspenseQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { Menu } from '@base-ui/react/menu';
import { toast } from 'sonner';

import { useCoffre } from '../lib/coffre';
import { queries } from '../lib/queries';
import { useShell } from '../lib/use-shell';
import { isActiveAccessibleEnvironment } from '../lib/project-environments';
import {
  blankDefinition,
  blankInject,
  definitionOf,
  definitionProblems,
  diffOf,
  egressRefusal,
  INJECT_KINDS,
  injectInWords,
  injectLabel,
  keysOf,
  limitInWords,
  METHODS,
  methodsInWords,
  pathsInWords,
  placeholderInWords,
  proxyKey,
  proxyQuery,
  soleKey,
  templateParts,
  unreadable,
  unreadableInWords,
  type Field,
  type ProxyChange,
  type ProxyConfig,
  type ProxyCredential,
  type ProxyDefinition,
  type ProxyInject,
  type ProxyPlace,
  type ProxyStore,
} from '../lib/proxy-prototype';
import type { SecretKey } from '../shared/models';
import { ClosedDoor, PageHeader } from '../components/page';
import { EnvironmentTabs } from '../components/environment-tabs';
import { Protection } from '../components/protected';
import { ConfirmDialog, CopyButton, EmptyState, ErrorLine, MenuPopup, Modal, Spinner, Timestamp, Tip, Toggletip } from '../components/ui';
import { Activity, AlertTriangle, ArrowRight, Clock, CopyFrom, Eye, Key, Lock, MoreHorizontal, Pencil, Plus, Relay, ChevronDown, Trash, Copy } from '../components/icons';
import { pageRoute } from '../lib/page-route';
import type { environmentProxy } from '../options';

const Route = pageRoute<ReturnType<typeof environmentProxy>>();

/**
 * An environment's Proxy tab, a prototype (W260, DO NOT MERGE): the
 * credentials `/use/<name>` serves here, the code's and the environment's
 * own, and an editor for the latter. The deployment passes the store its
 * route reads (`lib/proxy-prototype.ts` says what it mocks).
 */
export function EnvironmentProxyPage({ store }: { store: ProxyStore }) {
  const { project, environment } = Route.useParams();
  const place = { project, environment };
  const { data: secrets } = useSuspenseQuery(queries.secrets(useCoffre(), place));
  const { data: config } = useSuspenseQuery(proxyQuery(store, place));

  if (!secrets.ok) {
    return (
      <ClosedDoor
        icon={<Lock size={18} />}
        label={<span className="mono">{project}/{environment}</span>}
        title="This environment is closed to you"
        actions={
          <Link className="btn" to="/projects/$project" params={{ project }}>
            Back to {project}
          </Link>
        }
      >
        {secrets.error}
      </ClosedDoor>
    );
  }
  return (
    <ProxyLedger
      key={`${project}/${environment}`}
      store={store}
      place={place}
      config={config}
      keys={secrets.keys.filter((entry) => !entry.archived)}
      // `proxy.edit`, mocked: an Owner covering the place, whom the API tells apart as one who loosens a sensitive value.
      canEdit={secrets.loosenable === true}
    />
  );
}

type Opened = { kind: 'add' } | { kind: 'edit'; credential: ProxyCredential } | { kind: 'view'; credential: ProxyCredential } | { kind: 'copy' };

function ProxyLedger({
  store,
  place,
  config,
  keys,
  canEdit,
}: {
  store: ProxyStore;
  place: ProxyPlace;
  config: ProxyConfig;
  keys: SecretKey[];
  canEdit: boolean;
}) {
  const { project, environment } = place;
  const queryClient = useQueryClient();
  const { projects } = useShell();
  const inProject = projects.find((entry) => entry.slug === project)?.environments.find((entry) => entry.slug === environment);
  const [opened, setOpened] = useState<Opened | null>(null);
  const [deleting, setDeleting] = useState<ProxyCredential | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function write(changes: ProxyChange[], done: string): Promise<boolean> {
    setPending(true);
    setError(null);
    try {
      queryClient.setQueryData(proxyKey(place), await store.write(place, changes));
      toast.success(done);
      return true;
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'The change could not be saved.');
      return false;
    } finally {
      setPending(false);
    }
  }

  const credentials = config.credentials;
  const code = credentials.filter((one) => one.source === 'code').map((one) => one.name);
  const editor = opened?.kind === 'add' || opened?.kind === 'edit' ? opened : null;

  return (
    <>
      <PageHeader tile={project} title={environment} aside={inProject !== undefined && <Protection project={project} environment={inProject} />} />
      <EnvironmentTabs project={project} environment={environment} />

      <section className="card card-wide" aria-label="Proxy credentials">
        {credentials.length === 0 ? (
          <EmptyState title="No credentials yet">Add one, or copy them from another environment.</EmptyState>
        ) : (
          <div className="dt-wrap">
            <table className="dt proxy stacks">
              <thead>
                <tr>
                  <th className="n">#</th>
                  <th className="col-proxy-name">
                    <span className="th">
                      <Relay size={14} />
                      Credential
                    </span>
                  </th>
                  <th>
                    <span className="th">
                      <ArrowRight size={14} />
                      Forwards to
                    </span>
                  </th>
                  <th>
                    <span className="th">
                      <Key size={14} />
                      Sends
                    </span>
                  </th>
                  <th className="col-proxy-limit">
                    <span className="th">
                      <Activity size={14} />
                      Limit
                    </span>
                  </th>
                  <th className="col-written">
                    <span className="th">
                      <Clock size={14} />
                      Last changed
                    </span>
                  </th>
                  <th className="col-actions">
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {credentials.map((credential, index) => (
                  <CredentialRow
                    key={`${credential.source}:${credential.name}`}
                    number={index + 1}
                    credential={credential}
                    keys={keys}
                    useUrl={config.useUrl}
                    canEdit={canEdit}
                    onOpen={() => setOpened(canEdit && credential.source === 'environment' ? { kind: 'edit', credential } : { kind: 'view', credential })}
                    onView={() => setOpened({ kind: 'view', credential })}
                    onDelete={() => setDeleting(credential)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <div className="table-actions">
        <AddCredential canEdit={canEdit} project={project} onAdd={() => setOpened({ kind: 'add' })} onCopy={() => setOpened({ kind: 'copy' })} />
      </div>
      {opened === null && <ErrorLine error={error} />}

      {editor !== null && (
        <DefinitionEditor
          key={editor.kind === 'edit' ? editor.credential.name : 'new'}
          place={place}
          before={editor.kind === 'edit' ? editor.credential : null}
          config={config}
          keys={keys}
          code={code}
          pending={pending}
          error={error}
          onClose={() => {
            setOpened(null);
            setError(null);
          }}
          onSave={async (change, words) => {
            if (await write([change], words)) setOpened(null);
          }}
        />
      )}

      {opened?.kind === 'view' && (
        <CredentialView
          credential={opened.credential}
          config={config}
          keys={keys}
          place={place}
          onClose={() => setOpened(null)}
          onEdit={canEdit && opened.credential.source === 'environment' ? () => setOpened({ kind: 'edit', credential: opened.credential }) : undefined}
        />
      )}

      {opened?.kind === 'copy' && (
        <CopyFromEnvironment
          store={store}
          place={place}
          config={config}
          keys={keys}
          pending={pending}
          error={error}
          onClose={() => {
            setOpened(null);
            setError(null);
          }}
          onCopy={async (definitions, from) => {
            const words = `Copied ${definitions.map((one) => one.name).join(', ')} from ${from}`;
            if (await write(definitions.map((definition) => ({ was: null, definition })), words)) setOpened(null);
          }}
        />
      )}

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete ${deleting?.name ?? ''}?`}
        body={
          deleting?.shadowedSince != null
            ? `The code's ${deleting.name} goes on serving ${project}/${environment}; this one was not served.`
            : `Apps calling /use/${deleting?.name ?? ''} in ${project}/${environment} get 404 from now on.`
        }
        confirmLabel="Delete"
        onConfirm={() => {
          if (deleting !== null) void write([{ was: deleting.name, definition: null }], `Deleted ${deleting.name}`);
          setDeleting(null);
        }}
      />
    </>
  );
}

/** Add credential, and the way to copy some from another environment in its chevron's menu; for those who hold `proxy.edit`. */
function AddCredential({ canEdit, project, onAdd, onCopy }: { canEdit: boolean; project: string; onAdd: () => void; onCopy: () => void }) {
  if (!canEdit) {
    return (
      <Toggletip label={`Needs proxy.edit, which Owners of ${project} and of the instance hold.`}>
        <button type="button" className="btn btn-primary" aria-disabled="true">
          <Plus size={14} />
          Add credential
        </button>
      </Toggletip>
    );
  }
  return (
    <div className="split-button">
      <button className="btn btn-primary" type="button" onClick={onAdd}>
        <Plus size={14} />
        Add credential
      </button>
      <Menu.Root>
        <Menu.Trigger className="btn btn-primary btn-icon" aria-label="More to add">
          <ChevronDown size={14} />
        </Menu.Trigger>
        <MenuPopup align="start">
          <Menu.Item className="menu-item" onClick={onCopy}>
            <CopyFrom size={14} />
            Copy from environment…
          </Menu.Item>
        </MenuPopup>
      </Menu.Root>
    </div>
  );
}

function CredentialRow({
  number,
  credential,
  keys,
  useUrl,
  canEdit,
  onOpen,
  onView,
  onDelete,
}: {
  number: number;
  credential: ProxyCredential;
  keys: readonly SecretKey[];
  useUrl: string;
  canEdit: boolean;
  onOpen: () => void;
  onView: () => void;
  onDelete: () => void;
}) {
  const own = credential.source === 'environment';
  const shadowed = credential.shadowedSince !== null;
  return (
    <tr className={shadowed ? 'proxy-shadowed' : undefined}>
      <td className="n">{number}</td>
      <td className="col-proxy-name">
        <div className="proxy-name">
          <button type="button" className="proxy-open mono" onClick={onOpen}>
            {credential.name}
          </button>
          {!own && (
            <Toggletip label="Defined in the deployment's code, for every environment: change it there.">
              <button type="button" className="tag tag-outline tag-button">
                <Lock size={11} />
                Defined in code
              </button>
            </Toggletip>
          )}
          {shadowed && (
            <Toggletip label={`The code defines ${credential.name} too, since ${credential.shadowedSince!.slice(0, 10)}: code's is served here, not this one. Rename this one, or delete it.`}>
              <button type="button" className="tag tag-amber tag-button">
                <AlertTriangle size={11} />
                Shadowed by code
              </button>
            </Toggletip>
          )}
        </div>
        <div className="proxy-sub proxy-use mono">
          /use/{credential.name}
          <CopyButton value={`${useUrl}/${credential.name}`} label={`Copy ${credential.name}'s URL`} />
        </div>
      </td>
      <td>
        <div className="mono proxy-upstream">{credential.upstream.replace(/^https:\/\//, '')}</div>
        <div className="proxy-sub">
          {methodsInWords(credential.methods)} on {pathsInWords(credential.paths)}
          {credential.egress !== null && (
            <>
              {' · via '}
              <span className="mono nowrap">{credential.egress}</span>
            </>
          )}
        </div>
      </td>
      <td>
        <Inject inject={credential.inject} keys={keys} />
        <div className="proxy-sub">
          {injectLabel(credential.inject)}
          {credential.inject.kind === 'sigv4' && `, ${credential.inject.service} in ${credential.inject.region}`}
          {credential.placeholder !== null && (
            <>
              {' · placeholder '}
              {credential.placeholder.kind === 'prefix' ? <span className="mono">{credential.placeholder.prefix}…</span> : 'a JWT'}
            </>
          )}
        </div>
      </td>
      <td className="col-proxy-limit">
        <span>{limitInWords(credential.limit, credential.limitPerService)}</span>
      </td>
      <td className="col-written">
        {credential.changedAt === null ? (
          <span className="cell-muted">In code</span>
        ) : (
          <span className="written">
            <span className="written-by" title={credential.changedBy ?? undefined}>
              {credential.changedBy?.split('@')[0]}
            </span>
            <span className="cell-muted" aria-hidden>
              ·
            </span>
            <Timestamp iso={credential.changedAt} display="relative" />
          </span>
        )}
      </td>
      <td className="col-actions">
        <Menu.Root>
          <Menu.Trigger className="act act-icon act-quiet" aria-label={`Actions for ${credential.name}`}>
            <MoreHorizontal size={16} />
          </Menu.Trigger>
          <MenuPopup align="end">
            {own && canEdit ? (
              <Menu.Item className="menu-item" onClick={onOpen}>
                <Pencil size={14} />
                Edit…
              </Menu.Item>
            ) : (
              <Menu.Item className="menu-item" onClick={onView}>
                <Eye size={14} />
                View
              </Menu.Item>
            )}
            <Menu.Item className="menu-item" onClick={() => void navigator.clipboard.writeText(`${useUrl}/${credential.name}`).then(() => toast.success('Copied'))}>
              <Copy size={14} />
              Copy URL
            </Menu.Item>
            {own && (
              <Menu.Item className="menu-item menu-item-danger" onClick={onDelete} disabled={!canEdit}>
                <Trash size={14} />
                Delete…
                {!canEdit && <span className="menu-hint">needs proxy.edit</span>}
              </Menu.Item>
            )}
          </MenuPopup>
        </Menu.Root>
      </td>
    </tr>
  );
}

/** How a credential sends its keys, each `{KEY}` a chip: locked where it is sensitive, struck out where the environment lacks it. */
function Inject({ inject, keys }: { inject: ProxyInject; keys: readonly SecretKey[] }) {
  if (inject.kind === 'sigv4') {
    return (
      <span className="proxy-template">
        {[inject.accessKeyId, inject.secretAccessKey, inject.sessionToken].filter((one) => one !== '').map((template, index) => (
          <Template key={index} template={template} keys={keys} />
        ))}
      </span>
    );
  }
  return (
    <span className="proxy-template">
      <Template template={injectInWords(inject)} keys={keys} />
    </span>
  );
}

function Template({ template, keys }: { template: string; keys: readonly SecretKey[] }) {
  return (
    <span className="mono">
      {templateParts(template).map((part, index) => ('key' in part ? <KeyChip key={index} name={part.key} keys={keys} /> : <span key={index}>{part.text}</span>))}
    </span>
  );
}

function KeyChip({ name, keys }: { name: string; keys: readonly SecretKey[] }) {
  const entry = keys.find((one) => one.key === name);
  if (entry === undefined) {
    return (
      <Tip label="Not in this environment: the proxy answers 502 until it is set.">
        <span className="proxy-key proxy-key-missing">{name}</span>
      </Tip>
    );
  }
  if (entry.sensitivity === 'sensitive') {
    return (
      <Tip label="Sensitive: no one reads it, so no one changes where it goes.">
        <span className="proxy-key proxy-key-sensitive">
          <Lock size={10} />
          {name}
        </span>
      </Tip>
    );
  }
  return <span className="proxy-key">{name}</span>;
}

// --- the editor ------------------------------------------------------------------------

/** What the form holds, as typed: the definition is read from it on each render. */
type Form = {
  name: string;
  upstream: string;
  inject: ProxyInject;
  methods: string[];
  paths: string;
  perMinute: string;
  perDay: string;
  placeholder: 'none' | 'prefix' | 'jwt';
  prefix: string;
  claims: string;
  egress: string | null;
};

function formOf(definition: ProxyDefinition): Form {
  const placeholder = definition.placeholder;
  return {
    name: definition.name,
    upstream: definition.upstream,
    inject: definition.inject,
    methods: definition.methods,
    paths: definition.paths.join('\n'),
    perMinute: definition.limit.perMinute === null ? '' : String(definition.limit.perMinute),
    perDay: definition.limit.perDay === null ? '' : String(definition.limit.perDay),
    placeholder: placeholder === null ? 'none' : placeholder.kind,
    prefix: placeholder?.kind === 'prefix' ? placeholder.prefix : '',
    claims: placeholder?.kind === 'jwt' ? placeholder.claims.join('\n') : '',
    egress: definition.egress,
  };
}

const number = (text: string) => (text.trim() === '' ? null : Number(text.trim()));

function definitionFrom(form: Form): ProxyDefinition {
  const lines = (text: string) => text.split('\n').map((line) => line.trim()).filter((line) => line !== '');
  return {
    name: form.name.trim(),
    upstream: form.upstream.trim().replace(/\/+$/, ''),
    inject: form.inject,
    methods: METHODS.filter((method) => form.methods.includes(method)),
    paths: lines(form.paths),
    limit: { perMinute: number(form.perMinute), perDay: number(form.perDay) },
    placeholder: form.placeholder === 'none' ? null : form.placeholder === 'prefix' ? { kind: 'prefix', prefix: form.prefix.trim() } : { kind: 'jwt', claims: lines(form.claims) },
    egress: form.egress,
  };
}

function DefinitionEditor({
  place,
  before,
  config,
  keys,
  code,
  pending,
  error,
  onClose,
  onSave,
}: {
  place: ProxyPlace;
  before: ProxyCredential | null;
  config: ProxyConfig;
  keys: readonly SecretKey[];
  code: readonly string[];
  pending: boolean;
  error: string | null;
  onClose: () => void;
  onSave: (change: ProxyChange, words: string) => void;
}) {
  const was = before === null ? null : definitionOf(before);
  const [form, setForm] = useState<Form>(() => formOf(was ?? blankDefinition()));
  const [step, setStep] = useState<'edit' | 'review'>('edit');
  const [tried, setTried] = useState(false);
  const [touched, setTouched] = useState<ReadonlySet<Field>>(() => new Set());
  const touch = (field: Field) => setTouched((current) => new Set(current).add(field));
  const patch = (next: Partial<Form>) => setForm((current) => ({ ...current, ...next }));
  const setInject = (inject: ProxyInject) => {
    patch({ inject });
    touch('keys');
  };

  const definition = definitionFrom(form);
  const others = config.credentials.filter((one) => one.source === 'environment' && one.name !== before?.name).map((one) => one.name);
  const problems = definitionProblems(definition, { place, keys, code, others, egresses: config.egresses, before: was });
  const shown = (field: Field) => (tried || touched.has(field) ? (problems[field] ?? null) : null);
  // Where it sends its keys stays as it is for whoever cannot read one of them: sending a key elsewhere is reading it.
  const locked = was === null ? [] : unreadable(keysOf(was.inject), keys);
  const diff = diffOf(was, definition);
  const where = `${place.project}/${place.environment}`;

  const field = (name: Field, label: ReactNode, control: ReactNode, hint?: ReactNode) => (
    <label className="field">
      <span className="label">{label}</span>
      {control}
      {shown(name) !== null ? <span className="hint proxy-error">{shown(name)}</span> : hint !== undefined && <span className="hint">{hint}</span>}
    </label>
  );

  return (
    <Modal open onOpenChange={(open) => !open && onClose()} wide title={step === 'review' ? `Review ${definition.name}` : before === null ? 'Add credential' : `Edit ${before.name}`}>
      {step === 'edit' ? (
        <form
          className="form proxy-form"
          onSubmit={(event) => {
            event.preventDefault();
            setTried(true);
            if (Object.keys(problems).length === 0 && diff.length > 0) setStep('review');
          }}
        >
          {before?.shadowedSince != null && (
            <p className="proxy-warn">
              <AlertTriangle size={14} />
              The code defines {before.name} too: rename this one to serve it.
            </p>
          )}
          <div className="form-row">
            {field(
              'name',
              'Name',
              <input className="input mono" value={form.name} spellCheck={false} autoComplete="off" placeholder="openai" onChange={(event) => patch({ name: event.target.value })} onBlur={() => touch('name')} />,
              <>
                Apps call <span className="mono">/use/{form.name.trim() === '' ? '<name>' : form.name.trim()}/…</span>
              </>,
            )}
          </div>

          <fieldset className="proxy-group" disabled={locked.length > 0}>
            <legend className="proxy-legend">Where it sends {keysOf(form.inject).length === 1 ? 'its key' : 'its keys'}</legend>
            {locked.length > 0 && (
              <p className="proxy-locked">
                <Lock size={13} />
                {unreadableInWords(locked)}
              </p>
            )}
            <div className="form-row">
              {field(
                'upstream',
                'Upstream',
                <input className="input mono" value={form.upstream} spellCheck={false} autoComplete="off" placeholder="https://api.openai.com/v1" onChange={(event) => patch({ upstream: event.target.value })} onBlur={() => touch('upstream')} />,
                <>
                  <span className="mono">/use/{definition.name || '<name>'}/x</span> goes to <span className="mono">{problems.upstream === undefined ? definition.upstream : '<upstream>'}/x</span>
                </>,
              )}
              <EgressField form={form} config={config} problem={tried || touched.has('upstream') || touched.has('egress') ? (problems.egress ?? null) : null} onChange={(egress) => {
                patch({ egress });
                touch('egress');
              }} />
            </div>
            <InjectEditor inject={form.inject} keys={keys} locked={locked.length > 0} shown={shown} touch={touch} onChange={setInject} />
            {(tried || touched.has('keys')) && problems.keys !== undefined && <ErrorLine error={problems.keys} />}
          </fieldset>

          <fieldset className="proxy-group">
            <legend className="proxy-legend">What an app may ask</legend>
            <div className="field">
              <span className="label">Methods</span>
              <div className="segmented segmented-sm" role="group" aria-label="Methods">
                {METHODS.map((method) => (
                  <button
                    key={method}
                    type="button"
                    aria-pressed={form.methods.includes(method)}
                    onClick={() => patch({ methods: form.methods.includes(method) ? form.methods.filter((one) => one !== method) : [...form.methods, method] })}
                  >
                    {method}
                  </button>
                ))}
              </div>
              {form.methods.length === 0 && <span className="hint">None picked: any method.</span>}
            </div>
            <div className="form-row">
              {field(
                'paths',
                'Paths',
                <textarea className="input mono proxy-lines" rows={3} value={form.paths} spellCheck={false} placeholder={'/chat/completions\n/responses'} onChange={(event) => patch({ paths: event.target.value })} onBlur={() => touch('paths')} />,
                'One prefix a line; none: any path.',
              )}
              <div className="proxy-limits">
                {field('perMinute', 'A minute', <input className="input" inputMode="numeric" value={form.perMinute} placeholder="No limit" onChange={(event) => patch({ perMinute: event.target.value })} onBlur={() => touch('perMinute')} />)}
                {field('perDay', 'A day', <input className="input" inputMode="numeric" value={form.perDay} placeholder="No limit" onChange={(event) => patch({ perDay: event.target.value })} onBlur={() => touch('perDay')} />)}
              </div>
            </div>
            {['header', 'query', 'form', 'json'].includes(form.inject.kind) && (
              <div className="form-row">
                <div className="field">
                  <span className="label">Placeholder</span>
                  <div className="segmented segmented-sm" role="group" aria-label="Placeholder">
                    {(['none', 'prefix', 'jwt'] as const).map((kind) => (
                      <button key={kind} type="button" aria-pressed={form.placeholder === kind} onClick={() => patch({ placeholder: kind })}>
                        {kind === 'none' ? 'The handle' : kind === 'prefix' ? 'With a prefix' : 'A JWT'}
                      </button>
                    ))}
                  </div>
                  {shown('placeholder') !== null ? <span className="hint proxy-error">{shown('placeholder')}</span> : <span className="hint">What the app holds where the key was.</span>}
                </div>
                {form.placeholder === 'prefix' && (
                  <label className="field">
                    <span className="label">Prefix</span>
                    <input className="input mono" value={form.prefix} placeholder="sk_test_" onChange={(event) => patch({ prefix: event.target.value })} onBlur={() => touch('placeholder')} />
                  </label>
                )}
                {form.placeholder === 'jwt' && (
                  <label className="field">
                    <span className="label">Claims</span>
                    <textarea className="input mono proxy-lines" rows={2} value={form.claims} placeholder="https://custom/app_metadata" onChange={(event) => patch({ claims: event.target.value })} onBlur={() => touch('placeholder')} />
                  </label>
                )}
              </div>
            )}
          </fieldset>

          <ErrorLine error={error} />
          <div className="dialog-actions">
            <span className="proxy-who">
              <ShieldNote />
            </span>
            <button className="btn" type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="btn btn-primary" type="submit" disabled={tried && (Object.keys(problems).length > 0 || diff.length === 0)}>
              Review
              <ArrowRight size={14} />
            </button>
          </div>
        </form>
      ) : (
        <div className="form">
          <Diff rows={diff} adding={was === null} />
          <p className="hint">
            {was === null ? `Served at /use/${definition.name} in ${where} once added.` : `Apps calling /use/${definition.name} in ${where} get it at once.`} The change goes in the audit log.
          </p>
          <ErrorLine error={error} />
          <div className="dialog-actions">
            <button className="btn" type="button" onClick={() => setStep('edit')} disabled={pending}>
              Back
            </button>
            <button
              className="btn btn-primary"
              type="button"
              disabled={pending}
              onClick={() => onSave({ was: before?.name ?? null, definition }, was === null ? `Added ${definition.name}` : `Saved ${definition.name}`)}
            >
              {pending && <Spinner />}
              {was === null ? 'Add credential' : 'Save changes'}
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}

/** Who may change a definition, as the proposal has it, said once at the foot of the editor. */
function ShieldNote() {
  return (
    <Toggletip label="proxy.edit, which Owners of the project and of the instance hold. Changing where it sends its keys also takes reading every key it sends.">
      <button type="button" className="tag tag-outline tag-button">
        <Lock size={11} />
        proxy.edit
      </button>
    </Toggletip>
  );
}

function EgressField({ form, config, problem, onChange }: { form: Form; config: ProxyConfig; problem: string | null; onChange: (egress: string | null) => void }) {
  const chosen = config.egresses.find((one) => one.name === form.egress);
  return (
    <label className="field proxy-egress">
      <span className="label">Egress</span>
      <select className="select" value={form.egress ?? ''} onChange={(event) => onChange(event.target.value === '' ? null : event.target.value)}>
        <option value="">Direct</option>
        {config.egresses.map((egress) => {
          const refusal = egressRefusal(egress, form.upstream);
          return (
            <option key={egress.name} value={egress.name} disabled={refusal !== null && egress.name !== form.egress}>
              {egress.name}
              {refusal !== null && ` (${egress.hosts!.join(', ')} only)`}
            </option>
          );
        })}
      </select>
      {problem !== null ? (
        <span className="hint proxy-error">{problem}</span>
      ) : chosen === undefined ? (
        <span className="hint">{config.egresses.length === 0 ? 'The code declares no egress.' : 'Or one the code declares.'}</span>
      ) : (
        <span className="hint">
          {chosen.description === null ? 'Declared in code.' : `${chosen.description.replace(/\.$/, '')}.`}
          {chosen.hosts === null && ' One fixed host: another upstream fails its TLS check, a 502, before any key is sent.'}
        </span>
      )}
    </label>
  );
}

function InjectEditor({
  inject,
  keys,
  locked,
  shown,
  touch,
  onChange,
}: {
  inject: ProxyInject;
  keys: readonly SecretKey[];
  /** Whether where it sends its keys stays as it is: no keys to pick then. */
  locked: boolean;
  shown: (field: Field) => string | null;
  touch: (field: Field) => void;
  onChange: (inject: ProxyInject) => void;
}) {
  const [focused, setFocused] = useState<Field>('template');
  const template = (field: Field, label: string, value: string, placeholder: string, put: (value: string) => void) => (
    <label className="field">
      <span className="label">{label}</span>
      <input
        className="input mono"
        value={value}
        spellCheck={false}
        autoComplete="off"
        placeholder={placeholder}
        aria-invalid={shown(field) !== null}
        onFocus={() => setFocused(field)}
        onChange={(event) => put(event.target.value)}
        onBlur={() => touch(field)}
      />
      {shown(field) !== null && <span className="hint proxy-error">{shown(field)}</span>}
    </label>
  );
  const kindPicker = (
    <label className="field proxy-kind">
      <span className="label">Sends it as</span>
      <select className="select" value={inject.kind} onChange={(event) => onChange(blankInject(event.target.value as ProxyInject['kind']))}>
        {INJECT_KINDS.map((one) => (
          <option key={one.kind} value={one.kind}>
            {one.label}
          </option>
        ))}
      </select>
    </label>
  );
  const error = (field: Field) => shown(field) !== null && <span className="hint proxy-error">{shown(field)}</span>;

  if (inject.kind === 'sigv4') {
    const pick = (field: 'accessKeyId' | 'secretAccessKey' | 'sessionToken', label: string, optional = false) => (
      <label className="field">
        <span className="label">{label}</span>
        <KeySelect value={soleKey(inject[field])} keys={keys} optional={optional} onChange={(key) => onChange({ ...inject, [field]: key === '' ? '' : `{${key}}` })} />
        {error(field)}
      </label>
    );
    return (
      <>
        <div className="form-row">
          {kindPicker}
          <label className="field">
            <span className="label">Region</span>
            <input className="input mono" value={inject.region} placeholder="eu-west-3" onChange={(event) => onChange({ ...inject, region: event.target.value.trim() })} onBlur={() => touch('region')} />
            {error('region')}
          </label>
          <label className="field">
            <span className="label">Service</span>
            <input className="input mono" value={inject.service} placeholder="s3" onChange={(event) => onChange({ ...inject, service: event.target.value.trim() })} onBlur={() => touch('service')} />
            {error('service')}
          </label>
        </div>
        <div className="form-row">
          {pick('accessKeyId', 'Access key ID')}
          {pick('secretAccessKey', 'Secret access key')}
          {pick('sessionToken', 'Session token', true)}
        </div>
      </>
    );
  }

  // One row of keys under the templates, which puts `{KEY}` in the one last typed in.
  const picks = (value: string, put: (value: string) => void, into: string) =>
    !locked && <KeyPicks value={value} keys={keys} into={into} onChange={put} />;

  if (inject.kind === 'basic') {
    const target = focused === 'password' ? 'password' : 'user';
    return (
      <>
        <div className="form-row">{kindPicker}</div>
        <div className="form-row">
          {template('user', 'User', inject.user, '{TWILIO_SID}', (user) => onChange({ ...inject, user }))}
          {template('password', 'Password', inject.password, 'Empty', (password) => onChange({ ...inject, password }))}
        </div>
        {picks(inject[target], (value) => onChange({ ...inject, [target]: value }), target === 'user' ? 'User' : 'Password')}
      </>
    );
  }

  const nameLabel = inject.kind === 'header' ? 'Header' : inject.kind === 'query' ? 'Parameter' : 'Field';
  return (
    <>
      <div className="form-row">
        {kindPicker}
        <label className="field">
          <span className="label">{nameLabel}</span>
          <input className="input mono" value={inject.name} spellCheck={false} placeholder={inject.kind === 'header' ? 'authorization' : 'key'} onChange={(event) => onChange({ ...inject, name: event.target.value })} onBlur={() => touch('injectName')} />
          {error('injectName')}
        </label>
      </div>
      {template('template', 'Value', inject.template, inject.kind === 'header' ? 'Bearer {OPENAI_API_KEY}' : '{MAPS_API_KEY}', (value) => onChange({ ...inject, template: value }))}
      {picks(inject.template, (value) => onChange({ ...inject, template: value }), 'Value')}
    </>
  );
}

/** The environment's keys, as chips: a click puts `{KEY}` at the end of a template, or takes it out. Only the keys it holds are offered. */
function KeyPicks({ value, keys, into, onChange }: { value: string; keys: readonly SecretKey[]; into: string; onChange: (value: string) => void }) {
  return (
    <div className="proxy-picks" role="group" aria-label={`Put a key in ${into}`}>
      {keys.map((entry) => {
        const used = value.includes(`{${entry.key}}`);
        return (
          <button
            key={entry.key}
            type="button"
            className={`proxy-key proxy-key-pick${used ? ' proxy-key-used' : ''}${entry.readable ? '' : ' proxy-key-sensitive'}`}
            aria-pressed={used}
            title={entry.readable ? undefined : entry.sensitivity === 'sensitive' ? 'Sensitive: no one may send it somewhere new' : "You can't read it"}
            onClick={() => onChange(used ? value.replace(`{${entry.key}}`, '') : `${value}{${entry.key}}`)}
          >
            {!entry.readable && <Lock size={10} />}
            {entry.key}
          </button>
        );
      })}
    </div>
  );
}

function KeySelect({ value, keys, optional, onChange }: { value: string; keys: readonly SecretKey[]; optional: boolean; onChange: (key: string) => void }) {
  return (
    <select className="select mono" value={value} onChange={(event) => onChange(event.target.value)}>
      <option value="">{optional ? 'None' : 'Pick a key…'}</option>
      {keys.map((entry) => (
        <option key={entry.key} value={entry.key}>
          {entry.key}
          {entry.sensitivity === 'sensitive' ? ' (sensitive)' : !entry.readable ? " (you can't read it)" : ''}
        </option>
      ))}
    </select>
  );
}

/** A change, field by field: what was, struck through, and what will be. */
function Diff({ rows, adding }: { rows: ReturnType<typeof diffOf>; adding: boolean }) {
  // Words stay in the page's face; addresses, templates and paths are code.
  const code = (label: string) => ['Name', 'Upstream', 'Egress', 'Sends', 'Paths'].includes(label) ? ' mono' : '';
  return (
    <table className="proxy-diff">
      {!adding && (
        <thead>
          <tr>
            <th />
            <th scope="col">Before</th>
            <th scope="col">After</th>
          </tr>
        </thead>
      )}
      <tbody>
        {rows.map((row) => (
          <tr key={row.label}>
            <th scope="row">{row.label}</th>
            {!adding && <td className={`proxy-diff-before${code(row.label)}`}>{row.before ?? '–'}</td>}
            <td className={`${row.after === null ? 'proxy-diff-before' : adding ? '' : 'proxy-diff-after'}${code(row.label)}`}>{row.after ?? 'Deleted'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// --- read only ------------------------------------------------------------------------

function CredentialView({
  credential,
  config,
  keys,
  place,
  onClose,
  onEdit,
}: {
  credential: ProxyCredential;
  config: ProxyConfig;
  keys: readonly SecretKey[];
  place: ProxyPlace;
  onClose: () => void;
  onEdit?: () => void;
}) {
  const egress = config.egresses.find((one) => one.name === credential.egress);
  const fact = (label: string, value: ReactNode) => (
    <div className="fact">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
  return (
    <Modal
      open
      onOpenChange={(open) => !open && onClose()}
      wide
      title={
        <span className="proxy-name">
          <span className="mono">{credential.name}</span>
          {credential.source === 'code' && (
            <span className="tag tag-outline">
              <Lock size={11} />
              Defined in code
            </span>
          )}
        </span>
      }
      description={
        credential.source === 'code'
          ? `The deployment's code defines it, for every environment, ${place.project}/${place.environment} included: change it there.`
          : credential.shadowedSince !== null
            ? `The code defines ${credential.name} too: code's is served here, not this one.`
            : onEdit === undefined
              ? `Changing it needs proxy.edit, which Owners of ${place.project} and of the instance hold.`
              : undefined
      }
    >
      <dl className="facts proxy-facts">
        {fact('Use at', <span className="mono">{config.useUrl}/{credential.name}/…</span>)}
        {fact('Upstream', <span className="mono">{credential.upstream}</span>)}
        {fact('Egress', egress === undefined ? 'Direct' : <><span className="mono">{egress.name}</span>{egress.description !== null && <span className="cell-muted">, {egress.description}</span>}</>)}
        {fact('Sends', <><Inject inject={credential.inject} keys={keys} /><span className="cell-muted">{injectLabel(credential.inject)}{credential.inject.kind === 'sigv4' && `, ${credential.inject.service} in ${credential.inject.region}`}</span></>)}
        {fact('Placeholder', placeholderInWords(credential.placeholder))}
        {fact('Allows', `${methodsInWords(credential.methods)} on ${pathsInWords(credential.paths)}`)}
        {fact('Limit', limitInWords(credential.limit, credential.limitPerService))}
      </dl>
      <div className="dialog-actions">
        <button className="btn" type="button" onClick={onClose}>
          Close
        </button>
        {onEdit !== undefined && (
          <button className="btn btn-primary" type="button" onClick={onEdit}>
            <Pencil size={14} />
            Edit
          </button>
        )}
      </div>
    </Modal>
  );
}

// --- copying ------------------------------------------------------------------------------

/**
 * Definitions from another environment of the project, copied as they are:
 * prod set up from staging, then its upstreams edited. Each is checked here
 * as a new one, so a key it sends must be here, and readable.
 */
function CopyFromEnvironment({
  store,
  place,
  config,
  keys,
  pending,
  error,
  onClose,
  onCopy,
}: {
  store: ProxyStore;
  place: ProxyPlace;
  config: ProxyConfig;
  keys: readonly SecretKey[];
  pending: boolean;
  error: string | null;
  onClose: () => void;
  onCopy: (definitions: ProxyDefinition[], from: string) => void;
}) {
  const { projects } = useShell();
  const siblings = (projects.find((entry) => entry.slug === place.project)?.environments ?? []).filter(
    (one) => isActiveAccessibleEnvironment(one) && !one.personal && one.slug !== place.environment,
  );
  const [source, setSource] = useState(siblings[0]?.slug ?? '');
  const [picked, setPicked] = useState<ReadonlySet<string>>(() => new Set());
  const [step, setStep] = useState<'pick' | 'review'>('pick');
  const from = useQuery({ ...proxyQuery(store, { project: place.project, environment: source }), enabled: source !== '' });

  const code = config.credentials.filter((one) => one.source === 'code').map((one) => one.name);
  const here = config.credentials.filter((one) => one.source === 'environment').map((one) => one.name);
  const candidates = (from.data?.credentials ?? []).filter((one) => one.source === 'environment' && one.shadowedSince === null);
  const checked = candidates.map((credential) => {
    const definition = definitionOf(credential);
    const problems = definitionProblems(definition, { place, keys, code, others: here, egresses: config.egresses, before: null });
    // A name held here already is no fault of the copy: said quietly, apart from what would refuse it.
    const held = here.includes(definition.name) ? 'Defined here already.' : code.includes(definition.name) ? 'The code defines it, for every environment.' : null;
    const first = problems.keys ?? problems.template ?? problems.user ?? problems.password ?? problems.accessKeyId ?? problems.secretAccessKey ?? problems.egress ?? problems.name ?? Object.values(problems)[0] ?? null;
    return { definition, held, problem: held ?? first };
  });
  const chosen = checked.filter((one) => one.problem === null && picked.has(one.definition.name)).map((one) => one.definition);

  return (
    <Modal open onOpenChange={(open) => !open && onClose()} wide title={step === 'pick' ? 'Copy from environment' : `Review ${chosen.length === 1 ? chosen[0]!.name : `${chosen.length} credentials`}`}>
      {step === 'pick' ? (
        <div className="form">
          <div className="form-row">
            <label className="field" style={{ flex: '0 0 14rem' }}>
              <span className="label">From</span>
              <select
                className="select"
                value={source}
                onChange={(event) => {
                  setSource(event.target.value);
                  setPicked(new Set());
                }}
              >
                {siblings.map((one) => (
                  <option key={one.slug} value={one.slug}>
                    {place.project}/{one.slug}
                  </option>
                ))}
              </select>
            </label>
          </div>
          {siblings.length === 0 ? (
            <EmptyState title="No other environment">You can open no other environment of {place.project}.</EmptyState>
          ) : from.isPending ? (
            <Spinner />
          ) : checked.length === 0 ? (
            <EmptyState title="Nothing to copy">{place.project}/{source} defines no credentials of its own.</EmptyState>
          ) : (
            <ul className="proxy-copy-list">
              {checked.map(({ definition, held, problem }) => (
                <li key={definition.name}>
                  <label className={`proxy-copy${problem === null ? '' : ' proxy-copy-blocked'}`}>
                    <input
                      type="checkbox"
                      disabled={problem !== null}
                      checked={problem === null && picked.has(definition.name)}
                      onChange={(event) =>
                        setPicked((current) => {
                          const next = new Set(current);
                          if (event.target.checked) next.add(definition.name);
                          else next.delete(definition.name);
                          return next;
                        })
                      }
                    />
                    <span className="mono proxy-copy-name">{definition.name}</span>
                    <span className="mono cell-muted proxy-copy-upstream">{definition.upstream.replace(/^https:\/\//, '')}</span>
                    {problem !== null && <span className={`hint proxy-copy-problem${held === null ? ' proxy-error' : ''}`}>{problem}</span>}
                  </label>
                </li>
              ))}
            </ul>
          )}
          <p className="hint">Each is copied as it is, upstream included: edit those that differ here after.</p>
          <div className="dialog-actions">
            <button className="btn" type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="btn btn-primary" type="button" disabled={chosen.length === 0} onClick={() => setStep('review')}>
              Review
              <ArrowRight size={14} />
            </button>
          </div>
        </div>
      ) : (
        <div className="form">
          {chosen.map((definition) => (
            <section key={definition.name} className="proxy-copy-review" aria-label={definition.name}>
              {chosen.length > 1 && <h3 className="proxy-copy-title mono">{definition.name}</h3>}
              <Diff rows={diffOf(null, definition).filter((row) => row.label !== 'Name')} adding />
            </section>
          ))}
          <p className="hint">Served in {place.project}/{place.environment} once copied. Each copy goes in the audit log.</p>
          <ErrorLine error={error} />
          <div className="dialog-actions">
            <button className="btn" type="button" onClick={() => setStep('pick')} disabled={pending}>
              Back
            </button>
            <button className="btn btn-primary" type="button" disabled={pending} onClick={() => onCopy(chosen, `${place.project}/${source}`)}>
              {pending && <Spinner />}
              Copy {chosen.length === 1 ? chosen[0]!.name : `${chosen.length} credentials`}
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}

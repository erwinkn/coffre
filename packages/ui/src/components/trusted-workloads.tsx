import type { BindingPlan, BindingView, CoffreClient, KeysPlan } from '@coffre/client';
import { credentialScopeInWords } from '@coffre/core/access';
import { claimValues, EVENT_EXPOSURE, githubEventsAt, GITLAB_PIPELINE_SOURCES } from '@coffre/core/workloads';
import { useQuery } from '@tanstack/react-query';
import { Fragment, useEffect, useState } from 'react';
import {
  askedScope,
  bindingOf,
  EMPTY_FORM,
  githubTarget,
  keySetOf,
  keysOf,
  listedIds,
  listingGap,
  planned,
  summary,
  type Form,
  type GitHubLookup,
  type KeySet,
  type RefKind,
  type ScopeChoice,
} from '../lib/bindings';
import { removeBinding } from '../lib/changes';
import { memberRef, statusOf, useCoffre } from '../lib/coffre';
import { affects, queries } from '../lib/queries';
import { withheldInWords } from '../lib/service-setup';
import { useAction } from '../lib/use-action';
import { useChange, useChangeStatus } from '../lib/use-change';
import { useGitHubLookup } from '../lib/use-github-lookup';
import { GitHubPicker, type Listed } from './github-picker';
import { MultiCombobox } from './multi-combobox';
import { RowFailure, RowPending, rowClass } from './row-state';
import { Card } from './page';
import { ScopePicker, wholeScope, type HeldGrant } from './scope-picker';
import { ConfirmButton, EmptyState, ErrorLine, Modal, Notice, Spinner, Timestamp } from './ui';
import { CheckCircle, GitHub, Key, Link, Plus, X } from './icons';

/**
 * The CI runs that may sign in as a service, by the ID token their platform
 * signs for each run (docs/design/oidc.md). A run is trusted only when
 * every claim of a binding matches, so the claims are what the page shows,
 * in full, before anything is saved.
 */
export function TrustedWorkloads({ serviceId, bindings, grants }: { serviceId: string; bindings: BindingView[]; grants: HeldGrant[] }) {
  const change = removeBinding(useCoffre(), serviceId);
  const remove = useChange(change);
  const { status, dismiss } = useChangeStatus(change.list.queryKey);

  return (
    <>
      <Card labelledBy="trusted-workloads" title="Sign in with OIDC">
        {bindings.length === 0 ? (
          <EmptyState title="No trust bindings" />
        ) : (
          <div className="dt-wrap">
            <table className="dt">
              <thead>
                <tr>
                  <th>Workload</th>
                  <th>Reaches</th>
                  <th className="col-shrink">Added (UTC)</th>
                  <th className="col-shrink">Last used</th>
                  <th className="col-actions">
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {bindings.map((binding) => {
                  const state = status(binding.id);
                  const { title, detail } = summary(binding);
                  return (
                    <Fragment key={binding.id}>
                      <tr className={rowClass(state)}>
                        <td>
                          <span className="cell-account">
                            {binding.profile.startsWith('github') ? <GitHub size={15} /> : <Link size={15} />}
                            <span className="cell-stack">
                              <span>{binding.label ?? title}</span>
                              <small>{binding.label === null ? detail : `${title} · ${detail}`}</small>
                              <details className="claims">
                                <summary>Claims</summary>
                                <Claims binding={binding} />
                                {binding.keys !== null && <ReplaceKeys serviceId={serviceId} issuer={binding.issuer} bindings={bindings} />}
                              </details>
                            </span>
                          </span>
                        </td>
                        <td>{binding.scope === null ? 'All its account holds' : credentialScopeInWords(binding.scope)}</td>
                        <td className="nowrap">
                          <span className="cell-stack">
                            <Timestamp iso={binding.createdAt} />
                            <small>by {binding.createdBy}</small>
                          </span>
                        </td>
                        <td className="nowrap cell-muted">
                          {binding.lastUsedAt === null ? 'Never' : <Timestamp iso={binding.lastUsedAt} display="relative" />}
                        </td>
                        <td className="col-actions">
                          {state.state === 'pending' ? (
                            <RowPending status={state} />
                          ) : (
                            <ConfirmButton
                              trigger={
                                <button className="act">
                                  <X size={13} />
                                  Remove
                                </button>
                              }
                              title={<>Stop trusting {binding.label ?? title}?</>}
                              body={
                                <>
                                  Runs of <strong>{title}</strong> ({detail}) can no longer sign in as{' '}
                                  <span className="mono">service:{serviceId}</span>, and credentials they hold stop
                                  working at once.{' '}
                                  {binding.lastUsedAt === null ? (
                                    'It was never used.'
                                  ) : (
                                    <>
                                      It was last used <Timestamp iso={binding.lastUsedAt} display="relative" />.
                                    </>
                                  )}{' '}
                                  To trust these runs again, add a new binding.
                                </>
                              }
                              confirmLabel="Remove binding"
                              onConfirm={() => remove(binding)}
                            />
                          )}
                        </td>
                      </tr>
                      <RowFailure status={state} columns={5} onDismiss={() => state.state === 'failed' && dismiss(state.mutationId)} />
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <div className="table-actions">
        <TrustWorkload serviceId={serviceId} grants={grants} bindings={bindings} />
      </div>
    </>
  );
}

function Claims({ binding }: { binding: Pick<BindingPlan, 'issuer' | 'jwksUri' | 'keys' | 'claims'> }) {
  return (
    <table className="claims-table">
      <tbody>
        <tr>
          <th>iss</th>
          <td className="mono">{binding.issuer}</td>
        </tr>
        {Object.entries(binding.claims).map(([name, value]) => (
          <tr key={name}>
            <th className="mono">{name}</th>
            <td className="mono">{claimValues(value).join(', ')}</td>
          </tr>
        ))}
        <tr>
          <th>keys</th>
          <td className="mono">{keysOf(binding)}</td>
        </tr>
      </tbody>
    </table>
  );
}

/**
 * New keys, pasted, for the service's bindings on an issuer whose keys they
 * carry: when the issuer rotates its keys. Each binding is replaced by one
 * the same but for them, as the review says before anything is saved.
 */
function ReplaceKeys({ serviceId, issuer, bindings }: { serviceId: string; issuer: string; bindings: BindingView[] }) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState('');
  // The plan, with the keys it was made for: Save sends those, whatever the field says by then.
  const [preview, setPreview] = useState<{ plan: KeysPlan; jwks: KeySet } | null>(null);
  const plan = preview?.plan ?? null;
  const unread = withheldInWords(plan?.withheld, 'binding');
  const coffre = useCoffre();
  const member = memberRef('service', serviceId);
  const { pending, error, setError, run } = useAction();
  const on = bindings.filter((binding) => binding.issuer === issuer).length;

  function close() {
    setOpen(false);
    setText('');
    setPreview(null);
    setError(null);
  }

  function review() {
    let jwks: KeySet;
    try {
      const pasted = keySetOf(text);
      if (pasted === undefined) throw new Error("Paste the issuer's key set");
      jwks = pasted;
    } catch (problem) {
      setError((problem as Error).message);
      return;
    }
    void run(() => coffre.bindings.previewKeys(member, { issuer, jwks }), { affects: [], onSuccess: (next) => setPreview({ plan: next, jwks }) });
  }

  return (
    <>
      <button className="act" type="button" onClick={() => setOpen(true)}>
        <Key size={13} />
        Replace keys
      </button>
      <Modal open={open} onOpenChange={(next) => (next ? setOpen(true) : close())} title={preview === null ? 'Replace keys' : 'Review the keys'}>
        {preview === null || plan === null ? (
          <form
            className="form"
            onSubmit={(event) => {
              event.preventDefault();
              review();
            }}
          >
            <p>
              The {on === 1 ? 'binding' : `${on} bindings`} of <span className="mono">service:{serviceId}</span> on{' '}
              <span className="mono">{issuer}</span> will verify tokens with these keys alone. While the issuer rotates, paste a set that
              holds the old key and the new, and tokens signed with either sign in.
            </p>
            <label className="field">
              <span className="label">Keys</span>
              <textarea
                className="input mono"
                rows={6}
                value={text}
                spellCheck={false}
                placeholder='{ "keys": [ … ] }'
                onChange={(event) => {
                  setText(event.target.value);
                  setError(null);
                }}
              />
              <span className="hint">
                From a Kubernetes cluster: <span className="mono">kubectl get --raw /openid/v1/jwks</span>
              </span>
            </label>
            <ErrorLine error={error} />
            <div className="dialog-actions">
              <button className="btn" type="button" onClick={close}>
                Cancel
              </button>
              <button className="btn btn-primary" type="submit" disabled={pending}>
                {pending && <Spinner />}
                Review
              </button>
            </div>
          </form>
        ) : (
          <div className="form">
            <p>
              {plan.replaces.length === 1 ? 'Its binding' : `Its ${plan.replaces.length} bindings`} on <span className="mono">{issuer}</span>{' '}
              {plan.replaces.length === 1 ? 'is' : 'are'} replaced by {plan.replaces.length === 1 ? 'one' : 'ones'} the same but for these keys.
              Credentials {plan.replaces.length === 1 ? 'it' : 'they'} issued, five minutes each at most, end at once.
            </p>
            <table className="claims-table">
              <tbody>
                {plan.keys.map((key) => (
                  <tr key={key.thumbprint}>
                    <th className="mono">{key.alg}</th>
                    <td className="mono">{key.kid ?? key.thumbprint}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {unread !== null && <Notice tone="warn">{unread}</Notice>}
            <ErrorLine error={error} />
            <div className="dialog-actions">
              <button className="btn" type="button" onClick={() => setPreview(null)}>
                Back
              </button>
              <button
                className="btn btn-primary"
                type="button"
                disabled={pending}
                onClick={() => void run(() => coffre.bindings.replaceKeys(member, { issuer, jwks: preview.jwks }), { affects: affects.bindings(member), onSuccess: close })}
              >
                {pending && <Spinner />}
                Save keys
              </button>
            </div>
          </div>
        )}
      </Modal>
    </>
  );
}

/** Beside `pull_request` and `workflow_run` in the events' list: they run code nobody reviewed, said in full once chosen. */
function exposureNote(event: string) {
  return EVENT_EXPOSURE[event] === undefined ? null : <span className="tag tag-amber">unreviewed code</span>;
}

/**
 * What GitHub said of the repository or owner the form names: who it is,
 * as confirmation, or why it could not say, with the way to type its IDs.
 */
function GitHubFound({ lookup, kind }: { lookup: GitHubLookup | null; kind: 'repository' | 'owner' }) {
  if (lookup === null) return null;
  if (lookup.state === 'looking') {
    return (
      <p className="lookup" role="status">
        <Spinner size={13} />
        Looking it up on GitHub…
      </p>
    );
  }
  if (lookup.state === 'found') {
    const { github, repositoryId, ownerId } = lookup.ids;
    return (
      <p className="lookup lookup-found" role="status">
        <CheckCircle size={14} />
        <span>
          <span className="mono lookup-name">{github}</span>
          {kind === 'repository' ? ` · ID ${repositoryId}, owned by ${github.split('/')[0]} (ID ${ownerId})` : ` · ID ${ownerId}`}
        </span>
      </p>
    );
  }
  return (
    <p className="lookup lookup-failed" role="status">
      {lookup.message}
    </p>
  );
}

/**
 * What the deployment's GitHub App could not list, said under the field (`listingGap`): it
 * is installed nowhere yet, or reaches no repository, with where to change
 * that, or GitHub did not answer. Nothing without an app, or while it lists.
 */
function Listing({ listing, owner }: { listing: { data?: Awaited<ReturnType<CoffreClient['bindings']['repositories']>>; error: unknown }; owner: boolean }) {
  if (listing.error !== null && listing.error !== undefined) {
    // A 503 says what GitHub answered, for the person; anything else is no more use to them than that it failed.
    const why = statusOf(listing.error) === 503 ? `: ${(listing.error as Error).message}` : '. Type the name: it is still looked up.';
    return <p className="hint">The GitHub App's repositories could not be listed{why}</p>;
  }
  const listed = listing.data;
  if (listed === undefined || !('repositories' in listed)) return null;
  const install = (words: string) => (
    <a href={listed.app.installUrl} target="_blank" rel="noreferrer">
      {words}
    </a>
  );
  switch (listingGap(listed, owner)) {
    case 'partial':
      return <p className="hint">Only some of {listed.app.name}'s repositories are listed: type any other by name.</p>;
    case 'not_installed':
      return <p className="hint">{listed.app.name} is installed on no account yet: {install('install it')} on yours to pick its repositories here.</p>;
    case 'no_repositories':
      return <p className="hint">{listed.app.name} reaches no repository yet: {install('choose some')} to pick them here.</p>;
    case null:
      return null;
  }
}

/** What trusting `pull_request` or `workflow_run` exposes, said where the owner chooses it and again before saving. */
function Exposure({ events }: { events: string[] }) {
  const exposed = events.filter((event) => EVENT_EXPOSURE[event] !== undefined);
  if (exposed.length === 0) return null;
  return (
    <Notice tone="warn">
      {exposed.map((event) => (
        <p key={event}>
          <span className="mono">{event}</span>: {EVENT_EXPOSURE[event]}
        </p>
      ))}
      <p>Give this service account only the secrets CI needs.</p>
    </Notice>
  );
}

/** What the bindings a plan replaces reached, beside what the new one reaches: the same, unless the person chose again. */
function Reached({ plan, bindings }: { plan: BindingPlan; bindings: BindingView[] }) {
  const reached = [...new Set(plan.replaces.flatMap((replaced) => {
    const scope = bindings.find((binding) => binding.id === replaced.id)?.scope;
    return scope === undefined ? [] : [scope === null ? 'all its account holds' : credentialScopeInWords(scope)];
  }))];
  if (reached.every((words) => words === credentialScopeInWords(plan.scope))) return <> This one reaches what {plan.replaces.length === 1 ? 'it' : 'they'} did.</>;
  return <> {plan.replaces.length === 1 ? 'It' : 'They'} reached {reached.join('; ')}: this one reaches what it says above.</>;
}

function TrustWorkload({ serviceId, grants, bindings }: { serviceId: string; grants: HeldGrant[]; bindings: BindingView[] }) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<Form>(EMPTY_FORM);
  const whole = (): ScopeChoice => ({ scope: wholeScope(grants), chosen: false });
  const [choice, setChoice] = useState(whole);
  const [plan, setPlan] = useState<BindingPlan | null>(null);
  // The sensitive values its credentials would not read, as the server planned it (R32).
  const unread = withheldInWords(plan?.withheld, 'binding');
  // What the plan was made from: Save sends it, whatever the form says by then.
  const [reviewed, setReviewed] = useState<ReturnType<typeof input> | null>(null);
  const coffre = useCoffre();
  const member = memberRef('service', serviceId);
  const { pending, error, setError, run } = useAction();
  const lookup = useAction();
  const target = githubTarget(form);
  // Not asked while IDs are typed in: the name is then a private repository's, which GitHub would not show.
  const github = useGitHubLookup(form.typedIds ? { ...target, name: '' } : target);
  const found = github.lookup?.state === 'found' ? github.lookup.ids : null;
  // What the deployment's GitHub App is installed on, asked once the dialog shows a GitHub binding: names the field offers, their IDs known.
  const listing = useQuery({ ...queries.githubRepositories(coffre), enabled: open && form.platform === 'github' });
  const listed = listing.data !== undefined && 'repositories' in listing.data ? listing.data : null;
  useEffect(() => {
    if (listed !== null) github.remember(...listedIds(listed.repositories));
    // Once per listing: `remember` is new each render.
  }, [listed]);
  const set = (changes: Partial<Form>) => {
    setForm((current) => ({ ...current, ...changes }));
    setPlan(null);
  };
  const input = () => ({ ...bindingOf(form, found), ...askedScope(choice), label: form.label.trim() === '' ? null : form.label.trim(), replaces: [] });

  function close() {
    setOpen(false);
    setForm(EMPTY_FORM);
    setChoice(whole());
    setPlan(null);
    setError(null);
    lookup.setError(null);
  }

  function review() {
    let request: ReturnType<typeof input>;
    try {
      request = input();
    } catch (problem) {
      setError((problem as Error).message);
      return;
    }
    void run(() => coffre.bindings.preview(member, request), {
      affects: [],
      // One that replaces bindings reaches what they did unless told: the picker says so, should the person go back.
      onSuccess: (next) => {
        setPlan(next);
        setReviewed(request);
        setChoice((current) => planned(current, next));
      },
    });
  }

  const field = (label: string, key: keyof Form, props: { placeholder?: string; mono?: boolean; hint?: string; onBlur?: () => void } = {}) => (
    <label className="field">
      <span className="label">{label}</span>
      <input
        className={`input${props.mono ? ' mono' : ''}`}
        value={form[key] as string}
        placeholder={props.placeholder}
        spellCheck={props.mono ? false : undefined}
        onChange={(event) => set({ [key]: event.target.value } as Partial<Form>)}
        onBlur={props.onBlur}
      />
      {props.hint !== undefined && <span className="hint">{props.hint}</span>}
    </label>
  );

  // The repository, or the organization, its IDs looked up as it settles; typed in only where GitHub shows nothing.
  const owner = target.kind === 'owner';
  const lookedUp = github.lookup;
  const named = owner
    ? { label: 'Organization', key: 'owner' as const, placeholder: 'acme' }
    : { label: 'Repository', key: 'repository' as const, placeholder: 'acme/api' };
  const githubIds = (
    <div className="lookup-group">
      <GitHubPicker
        label={named.label}
        value={form[named.key]}
        onChange={(name) => set({ [named.key]: name })}
        // Its IDs are the list's, never IDs typed for another name.
        onPick={(name) => set({ [named.key]: name, typedIds: false, repositoryId: '', ownerId: '' })}
        onBlur={github.settle}
        options={
          listed === null
            ? null
            : owner
              ? listed.installations.map((name): Listed => ({ name }))
              : listed.repositories.map((each): Listed => ({ name: each.github, private: each.private }))
        }
        placeholder={named.placeholder}
        empty={listed === null ? '' : `None of ${listed.app.name}'s ${owner ? 'accounts' : 'repositories'} match: type the whole name.`}
      />
      <Listing listing={listing} owner={owner} />
      {!form.typedIds && <GitHubFound lookup={lookedUp} kind={target.kind} />}
      {(form.typedIds || lookedUp?.state === 'missing' || lookedUp?.state === 'failed') && (
        <details className="disclosure" open={form.typedIds} onToggle={(event) => set({ typedIds: event.currentTarget.open })}>
          <summary>{owner ? 'Enter its ID' : 'Private repository? Enter IDs'}</summary>
          <div className="disclosure-body">
            <div className="form-row">
              {!owner && field('Repository ID', 'repositoryId', { mono: true })}
              {field('Owner ID', 'ownerId', { mono: true })}
            </div>
            <p className="hint">
              Bindings use IDs, since a name can pass to someone else. Get them with{' '}
              <span className="mono">
                {owner ? `gh api users/${target.name || 'acme'} --jq .id` : `gh api repos/${target.name || 'acme/api'} --jq '.id, .owner.id'`}
              </span>
            </p>
          </div>
        </details>
      )}
    </div>
  );

  const ref = (
    <div className="form-row">
      <label className="field" style={{ flex: '0 0 8rem' }}>
        <span className="label">At</span>
        <select
          className="select"
          value={form.refKind}
          onChange={(event) => {
            const refKind = event.target.value as RefKind;
            // A release runs at a tag; a schedule, a pull request or a workflow_run on a branch.
            set({ refKind, events: form.events.filter((each) => githubEventsAt(refKind).includes(each)) });
          }}
        >
          <option value="branch">Branch</option>
          <option value="tag">Tag</option>
        </select>
      </label>
      {field(form.refKind === 'branch' ? 'Branch' : 'Tag', 'refName', { mono: true })}
    </div>
  );

  return (
    <>
      <button className="btn" onClick={() => setOpen(true)}>
        <Plus size={14} />
        Trust a workload
      </button>
      <Modal open={open} onOpenChange={(next) => (next ? setOpen(true) : close())} title={plan === null ? 'Trust a workload' : 'Review the binding'}>
        {plan === null ? (
          <form
            className="form"
            onSubmit={(event) => {
              event.preventDefault();
              review();
            }}
          >
            <nav className="segmented" aria-label="Platform">
              {(['github', 'gitlab', 'other'] as const).map((platform) => (
                <button key={platform} type="button" aria-pressed={form.platform === platform} onClick={() => set({ platform })}>
                  {platform === 'github' ? 'GitHub Actions' : platform === 'gitlab' ? 'GitLab' : 'Other issuer'}
                </button>
              ))}
            </nav>

            {form.platform === 'github' && (
              <>
                <nav className="segmented" aria-label="Workflow">
                  <button type="button" aria-pressed={!form.reusable} onClick={() => set({ reusable: false })}>
                    A workflow of the repository
                  </button>
                  <button type="button" aria-pressed={form.reusable} onClick={() => set({ reusable: true })}>
                    A reusable workflow
                  </button>
                </nav>
                {form.reusable ? (
                  <>
                    {field('Called workflow', 'called', { placeholder: 'acme/deploy/.github/workflows/release.yml@refs/heads/main', mono: true })}
                    {field("Its commit", 'sha', { placeholder: 'the full SHA it is trusted at', mono: true, hint: 'A new version of the workflow needs a new binding.' })}
                    <label className="check">
                      <input type="checkbox" checked={form.anyRepository} onChange={(event) => set({ anyRepository: event.target.checked })} />
                      Called from any repository of the organization
                    </label>
                    {githubIds}
                    {!form.anyRepository &&
                      field('Calling workflow (optional)', 'workflow', { placeholder: 'deploy.yml', mono: true, hint: 'Left out, every workflow of the repository at the ref below may call it.' })}
                  </>
                ) : (
                  <>
                    {githubIds}
                    {field('Workflow file', 'workflow', { placeholder: 'deploy.yml', mono: true })}
                  </>
                )}
                {ref}
                <MultiCombobox
                  label="Events"
                  options={githubEventsAt(form.refKind)}
                  value={form.events}
                  onChange={(events) => set({ events })}
                  placeholder="push, workflow_dispatch…"
                  note={exposureNote}
                  mono
                  hint={form.events.includes('pull_request') ? `A pull request matches by the branch it merges into: ${form.refName.trim() || 'main'}.` : undefined}
                />
                {field('GitHub environment (optional)', 'environment', {
                  placeholder: 'production',
                  mono: true,
                  hint: 'Only jobs that run in this environment sign in, once its protection rules, such as required reviewers, let them.',
                })}
                <Exposure events={form.events} />
              </>
            )}

            {form.platform === 'gitlab' && (
              <>
                {field('GitLab', 'gitlabUrl', { placeholder: 'https://gitlab.com', hint: 'Left empty, gitlab.com.' })}
                <div className="form-row">
                  {field('Project', 'project', { placeholder: 'acme/api', mono: true })}
                  <div className="field" style={{ flex: '0 0 auto', alignSelf: 'end' }}>
                    <button
                      className="btn"
                      type="button"
                      disabled={lookup.pending || form.project.trim() === ''}
                      onClick={() =>
                        void lookup.run(
                          () => coffre.bindings.lookup({ gitlab: form.project.trim(), ...(form.gitlabUrl.trim() === '' ? {} : { gitlabUrl: form.gitlabUrl.trim() }) }),
                          { affects: [], onSuccess: (ids) => 'projectId' in ids && set({ projectId: ids.projectId, namespaceId: ids.namespaceId }) },
                        )
                      }
                    >
                      {lookup.pending && <Spinner />}
                      Look up IDs
                    </button>
                  </div>
                </div>
                <div className="form-row">
                  {field('Project ID', 'projectId', { mono: true })}
                  {field('Namespace ID', 'namespaceId', { mono: true })}
                </div>
                <ErrorLine error={lookup.error} />
                {ref}
                <MultiCombobox
                  label="Pipeline sources"
                  options={GITLAB_PIPELINE_SOURCES}
                  value={form.sources}
                  onChange={(sources) => set({ sources })}
                  placeholder="push, web, schedule"
                  mono
                  hint="Merge-request pipelines are never trusted: they name another project."
                />
              </>
            )}

            {form.platform === 'other' && (
              <>
                {field('Issuer', 'issuer', {
                  placeholder: 'https://accounts.google.com',
                  hint: form.jwks.trim() === '' ? undefined : 'Exactly as its tokens name it in iss: with its keys pasted below, coffre asks it nothing.',
                })}
                {field('Subject (sub)', 'sub', { mono: true, hint: "You vouch for what this issuer's subject means: a Google service account's unique ID, say." })}
                <label className="field">
                  <span className="label">Other claims, one <span className="mono">name=value</span> a line</span>
                  <textarea
                    className="input mono"
                    rows={3}
                    value={form.extra}
                    spellCheck={false}
                    placeholder="kubernetes.io.serviceaccount.uid=…"
                    onChange={(event) => set({ extra: event.target.value })}
                  />
                  <span className="hint">A nested claim goes by its path, its names joined by dots.</span>
                </label>
                <label className="field">
                  <span className="label">Keys (optional)</span>
                  <textarea
                    className="input mono"
                    rows={3}
                    value={form.jwks}
                    spellCheck={false}
                    placeholder='{ "keys": [ … ] }'
                    onChange={(event) => set({ jwks: event.target.value })}
                  />
                  <span className="hint">
                    Left empty, coffre fetches the issuer's keys. Paste them for one it cannot reach, such as a private Kubernetes cluster:{' '}
                    <span className="mono">kubectl get --raw /openid/v1/jwks</span>
                  </span>
                </label>
              </>
            )}

            <ScopePicker
              grants={grants}
              value={choice.scope}
              onChange={(next) => {
                setChoice({ scope: next, chosen: true });
                setPlan(null);
              }}
            />
            {field('Label (optional)', 'label', { placeholder: 'Deploys to production' })}
            <ErrorLine error={error} />
            <div className="dialog-actions">
              <button className="btn" type="button" onClick={close}>
                Cancel
              </button>
              <button className="btn btn-primary" type="submit" disabled={pending || Object.keys(choice.scope).length === 0}>
                {pending && <Spinner />}
                Review
              </button>
            </div>
          </form>
        ) : (
          <div className="form">
            <p>
              Runs whose ID token matches these claims sign in as <span className="mono">service:{serviceId}</span> and reach{' '}
              {credentialScopeInWords(plan.scope)}, as long as the account holds it.
            </p>
            <Claims binding={plan} />
            <Exposure events={claimValues(plan.claims.event_name)} />
            {unread !== null && <Notice tone="warn">{unread}</Notice>}
            {plan.replaces.length > 0 && (
              <Notice tone="info">
                This replaces {plan.replaces.length === 1 ? 'a binding' : `${plan.replaces.length} bindings`}
                {plan.replaces.some((replaced) => replaced.why === 'keys_moved') ? ', since the issuer moved its keys' : ''}.
                <Reached plan={plan} bindings={bindings} />
              </Notice>
            )}
            <ErrorLine error={error} />
            <div className="dialog-actions">
              <button className="btn" type="button" onClick={() => setPlan(null)}>
                Back
              </button>
              <button
                className="btn btn-primary"
                type="button"
                disabled={pending}
                // What the review said it reaches, whatever the account holds by now.
                onClick={() => void run(() => coffre.bindings.create(member, { ...reviewed!, scope: plan.scope }), { affects: affects.bindings(member), onSuccess: close })}
              >
                {pending && <Spinner />}
                Save binding
              </button>
            </div>
          </div>
        )}
      </Modal>
    </>
  );
}

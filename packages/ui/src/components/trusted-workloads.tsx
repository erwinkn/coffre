import type { BindingPlan, BindingView } from '@coffre/client';
import { claimValues, EVENT_EXPOSURE, githubEventsAt, GITLAB_PIPELINE_SOURCES } from '@coffre/core/workloads';
import { Fragment, useState } from 'react';
import { bindingOf, EMPTY_FORM, summary, type Form, type RefKind } from '../lib/bindings';
import { removeBinding } from '../lib/changes';
import { memberRef, useCoffre } from '../lib/coffre';
import { affects } from '../lib/queries';
import { useAction } from '../lib/use-action';
import { useChange, useChangeStatus } from '../lib/use-change';
import { RowFailure, RowPending, rowClass } from './row-state';
import { Card } from './page';
import { ConfirmButton, EmptyState, ErrorLine, Modal, Notice, Spinner, Timestamp } from './ui';
import { GitHub, Link, Plus, X } from './icons';

/**
 * The CI runs that may sign in as a service, by the ID token their platform
 * signs for each run (docs/design/oidc.md). A run is trusted only when
 * every claim of a binding matches, so the claims are what the page shows,
 * in full, before anything is saved.
 */
export function TrustedWorkloads({ serviceId, bindings }: { serviceId: string; bindings: BindingView[] }) {
  const change = removeBinding(useCoffre(), serviceId);
  const remove = useChange(change);
  const { status, dismiss } = useChangeStatus(change.list.queryKey);

  return (
    <>
      <Card
        labelledBy="trusted-workloads"
        title="Sign in with OIDC"
        description={
          <>
            A CI run signs in with the ID token GitHub Actions or GitLab gives it, so there is no secret to store. For example,{' '}
            <span className="mono">deploy.yml</span> in <span className="mono">acme/api</span>, on pushes to <span className="mono">main</span>.
          </>
        }
      >
        {bindings.length === 0 ? (
          <EmptyState title="No trust bindings">Trust a workflow to let its runs sign in.</EmptyState>
        ) : (
          <div className="dt-wrap">
            <table className="dt">
              <thead>
                <tr>
                  <th>Workload</th>
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
                              </details>
                            </span>
                          </span>
                        </td>
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
                      <RowFailure status={state} columns={4} onDismiss={() => state.state === 'failed' && dismiss(state.mutationId)} />
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <div className="table-actions">
        <TrustWorkload serviceId={serviceId} />
      </div>
    </>
  );
}

function Claims({ binding }: { binding: Pick<BindingPlan, 'issuer' | 'jwksUri' | 'claims'> }) {
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
          <td className="mono">{binding.jwksUri}</td>
        </tr>
      </tbody>
    </table>
  );
}

/** Checkboxes for what may start a run: GitHub's events, or GitLab's pipeline sources. */
function Choices(props: { label: string; options: readonly string[]; chosen: string[]; onChange: (chosen: string[]) => void; hint?: string }) {
  const { options, chosen } = props;
  return (
    <fieldset className="field checks">
      <legend className="label">{props.label}</legend>
      <div className="checks-row">
        {options.map((option) => (
          <label key={option} className="check mono">
            <input
              type="checkbox"
              checked={chosen.includes(option)}
              // Kept in the options' order, as the server stores them.
              onChange={(event) => props.onChange(options.filter((each) => (each === option ? event.target.checked : chosen.includes(each))))}
            />
            {option}
          </label>
        ))}
      </div>
      {props.hint !== undefined && <span className="hint">{props.hint}</span>}
    </fieldset>
  );
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

function TrustWorkload({ serviceId }: { serviceId: string }) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<Form>(EMPTY_FORM);
  const [plan, setPlan] = useState<BindingPlan | null>(null);
  const coffre = useCoffre();
  const member = memberRef('service', serviceId);
  const { pending, error, setError, run } = useAction();
  const lookup = useAction();
  const set = (changes: Partial<Form>) => {
    setForm((current) => ({ ...current, ...changes }));
    setPlan(null);
  };
  const input = () => ({ ...bindingOf(form), label: form.label.trim() === '' ? null : form.label.trim(), replaces: [] });

  function close() {
    setOpen(false);
    setForm(EMPTY_FORM);
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
    void run(() => coffre.bindings.preview(member, request), { affects: [], onSuccess: setPlan });
  }

  const field = (label: string, key: keyof Form, props: { placeholder?: string; mono?: boolean; hint?: string } = {}) => (
    <label className="field">
      <span className="label">{label}</span>
      <input
        className={`input${props.mono ? ' mono' : ''}`}
        value={form[key] as string}
        placeholder={props.placeholder}
        onChange={(event) => set({ [key]: event.target.value } as Partial<Form>)}
      />
      {props.hint !== undefined && <span className="hint">{props.hint}</span>}
    </label>
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
                <div className="form-row">
                  {field('Repository', 'repository', { placeholder: 'acme/api', mono: true })}
                  <div className="field" style={{ flex: '0 0 auto', alignSelf: 'end' }}>
                    <button
                      className="btn"
                      type="button"
                      disabled={lookup.pending || form.repository.trim() === ''}
                      onClick={() =>
                        void lookup.run(() => coffre.bindings.lookup({ github: form.repository.trim() }), {
                          affects: [],
                          onSuccess: (ids) => 'repositoryId' in ids && set({ repositoryId: ids.repositoryId, ownerId: ids.ownerId }),
                        })
                      }
                    >
                      {lookup.pending && <Spinner />}
                      Look up IDs
                    </button>
                  </div>
                </div>
                <div className="form-row">
                  {!(form.reusable && form.anyRepository) && field('Repository ID', 'repositoryId', { mono: true })}
                  {field('Owner ID', 'ownerId', { mono: true })}
                </div>
                <p className="hint">
                  Bindings use IDs, since a name can pass to someone else. For a private repository:{' '}
                  <span className="mono">gh api repos/{form.repository.trim() || 'acme/api'} --jq '.id, .owner.id'</span>
                </p>
                <ErrorLine error={lookup.error} />
                {form.reusable ? (
                  <>
                    {field('Called workflow', 'called', { placeholder: 'acme/deploy/.github/workflows/release.yml@refs/heads/main', mono: true })}
                    {field("Its commit", 'sha', { placeholder: 'the full SHA it is trusted at', mono: true, hint: 'A new version of the workflow needs a new binding.' })}
                    {field('Calling workflow (optional)', 'workflow', { placeholder: 'deploy.yml', mono: true, hint: 'Left out, every workflow of the repository at the ref below may call it.' })}
                    <label className="check">
                      <input type="checkbox" checked={form.anyRepository} onChange={(event) => set({ anyRepository: event.target.checked })} />
                      Called from any repository of the organization
                    </label>
                  </>
                ) : (
                  field('Workflow file', 'workflow', { placeholder: 'deploy.yml', mono: true })
                )}
                {ref}
                <Choices
                  label="Events"
                  options={githubEventsAt(form.refKind)}
                  chosen={form.events}
                  onChange={(events) => set({ events })}
                  hint={form.events.includes('pull_request') ? `A pull request matches by the branch it merges into: ${form.refName.trim() || 'main'}.` : undefined}
                />
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
                <Choices
                  label="Pipeline sources"
                  options={GITLAB_PIPELINE_SOURCES}
                  chosen={form.sources}
                  onChange={(sources) => set({ sources })}
                  hint="Merge-request pipelines are never trusted: they name another project."
                />
              </>
            )}

            {form.platform === 'other' && (
              <>
                {field('Issuer', 'issuer', { placeholder: 'https://accounts.google.com' })}
                {field('Subject (sub)', 'sub', { mono: true, hint: "You vouch for what this issuer's subject means: a Google service account's unique ID, say." })}
                <label className="field">
                  <span className="label">Other claims, one <span className="mono">name=value</span> a line</span>
                  <textarea className="input mono" rows={3} value={form.extra} onChange={(event) => set({ extra: event.target.value })} />
                </label>
              </>
            )}

            {field('Label (optional)', 'label', { placeholder: 'Deploys to production' })}
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
              Runs whose ID token matches these claims sign in as <span className="mono">service:{serviceId}</span> and read what it can
              read.
            </p>
            <Claims binding={plan} />
            <Exposure events={claimValues(plan.claims.event_name)} />
            {plan.replaces.length > 0 && (
              <Notice tone="info">
                This replaces {plan.replaces.length === 1 ? 'a binding' : `${plan.replaces.length} bindings`}
                {plan.replaces.some((replaced) => replaced.why === 'keys_moved') ? ', since the issuer moved its keys' : ''}.
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
                onClick={() => void run(() => coffre.bindings.create(member, input()), { affects: affects.bindings(member), onSuccess: close })}
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

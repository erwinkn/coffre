import { useState } from 'react';
import { useSuspenseQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import type { InheritedGrant } from '@coffre/client';
import { assignableToEnvironment, EVERY_PROJECT, ROLE_NAMES, ROLES, type Role } from '@coffre/core/access';
import { memberRef, useCoffre } from '../lib/coffre';
import { affects, queries } from '../lib/queries';
import { useAction } from '../lib/use-action';
import { useShell } from '../lib/use-shell';
import { slugProblem } from '../lib/validation';
import { ExpiryField } from './expiry-field';
import { GrantsTable } from './grants';
import { Layers, Plus } from './icons';
import { ConfirmButton, ErrorLine, Modal, Notice, Spinner } from './ui';

/**
 * Grants on every project (`*`, the projects made later too) and on one
 * environment slug in every project (`*` and the slug): only owners give
 * and take them, here, from the CLI or the API; the pages show who holds
 * them to whoever sees the grants of a project they reach.
 */

/** Where a grant on every project is, as people read it: "All projects", or "dev in every project". */
export function everyProjectPlace(environmentSlug: string | null): string {
  return environmentSlug === null ? 'All projects' : `${environmentSlug} in every project`;
}

/** The slug a grant on every project covers, from its path: null for `*`. */
function slugOf(place: string): string | null {
  return place === '*' ? null : place.slice('*/'.length);
}

/** The grants on every project, for those shown them: who makes places, and who manages access. */
export function useEveryProject(): InheritedGrant[] {
  const { data } = useSuspenseQuery(queries.projects(useCoffre()));
  return data.ok ? data.everyProject : [];
}

/** Those grants that reach a place: a project (`environment` null), or an environment of that slug. */
export function reaching(grants: InheritedGrant[], environment: string | null): InheritedGrant[] {
  return grants.filter((grant) => grant.place === '*' || (environment !== null && slugOf(grant.place) === environment));
}

/** A member as a line names them: `ada@acme.example`, or a token's name. */
function who(member: string): string {
  return member.slice(member.indexOf(':') + 1);
}

/**
 * Who reaches a place through grants on every project, said in its dialog
 * before it is made or renamed: making a place there gives them access at once.
 */
export function ReachedBy({ grants, lead }: { grants: InheritedGrant[]; lead: string }) {
  if (grants.length === 0) return null;
  return (
    <Notice tone="info">
      {lead}{' '}
      {grants.map((grant, index) => (
        <span key={`${grant.member} ${grant.place}`}>
          {index > 0 && ', '}
          <strong className="mono">{who(grant.member)}</strong> ({grant.roleName.toLowerCase()},{' '}
          {everyProjectPlace(slugOf(grant.place)).toLowerCase()})
        </span>
      ))}
      .
    </Notice>
  );
}

/**
 * One member's grants on every project, on their Access tab: "All projects ·
 * Developer". Owners grant and revoke them here; whoever else sees them, as
 * on a project they reach, sees them only.
 */
export function EveryProjectGrants({ principalType, principalId }: { principalType: 'user' | 'service'; principalId: string }) {
  const member = memberRef(principalType, principalId);
  const { capabilities } = useShell();
  const owner = capabilities.canManageGrants;
  const grants = useEveryProject().filter((grant) => grant.member === member);
  if (grants.length === 0 && !owner) return null;
  return (
    <section className="every-project" aria-label="Access to every project">
      <h2 className="section-title">Every project</h2>
      {grants.length > 0 && (
        <section className="card">
          <GrantsTable
            lead={
              <span className="th">
                <Layers size={14} />
                Where
              </span>
            }
          >
            {grants.map((grant, index) => (
              <EveryProjectRow key={grant.place} number={index + 1} grant={grant} principalId={principalId} owner={owner} />
            ))}
          </GrantsTable>
        </section>
      )}
      {owner ? (
        <div className="table-actions">
          <GrantEveryProject principalType={principalType} principalId={principalId} />
        </div>
      ) : (
        <p className="hint section-foot">Only owners grant or revoke on every project.</p>
      )}
    </section>
  );
}

function EveryProjectRow({ number, grant, principalId, owner }: { number: number; grant: InheritedGrant; principalId: string; owner: boolean }) {
  const coffre = useCoffre();
  const { pending, error, run } = useAction();
  const where = everyProjectPlace(slugOf(grant.place));
  return (
    <>
      <tr>
        <td className="n">{number}</td>
        <td className="col-lead" data-label="Where">
          {where}
        </td>
        <td className="col-access" data-label="Permissions">
          <span className={`tag${grant.role === 'owner' ? ' tag-violet' : ''}`}>{grant.roleName}</span>
        </td>
        <td className={`col-expires cell-mono cell-muted${grant.expiresAt === null ? ' is-never' : ''}`} data-label="Expires">
          {grant.expiresAt === null ? 'Never' : grant.expiresAt.slice(0, 10)}
        </td>
        <td className="col-actions">
          {owner && (
            <ConfirmButton
              trigger={
                <button className="act act-danger" disabled={pending}>
                  Revoke
                </button>
              }
              title={
                <>
                  Revoke {grant.roleName.toLowerCase()} on {where.toLowerCase()} from <span className="mono">{principalId}</span>?
                </>
              }
              body={
                <>
                  They lose it at once, wherever it reaches, including any process using it right now.
                  Grants they hold on projects themselves still apply.
                </>
              }
              confirmLabel="Revoke access"
              onConfirm={() =>
                run(() => coffre.access.set(grant.member, { [grant.place]: null }), {
                  affects: affects.everyProject(grant.member),
                  onSuccess: () => toast.success(`Revoked ${grant.roleName.toLowerCase()} on ${where.toLowerCase()}`),
                })
              }
            />
          )}
        </td>
      </tr>
      {error !== null && (
        <tr>
          <td colSpan={5}>
            <ErrorLine error={error} />
          </td>
        </tr>
      )}
    </>
  );
}

/** The roles a grant on every project takes: all of them, or, on one environment name, those an environment can hold. */
const ROLE_CHOICES: { role: Role; name: string; environment: boolean }[] = ROLE_NAMES.map((role) => ({
  role,
  name: ROLES[role].name,
  environment: assignableToEnvironment(role),
}));

/**
 * Give a member a role on every project, the ones created later too, or on
 * one environment name in every project. Owners only, as the API.
 */
function GrantEveryProject({ principalType, principalId }: { principalType: 'user' | 'service'; principalId: string }) {
  const coffre = useCoffre();
  const member = memberRef(principalType, principalId);
  const [open, setOpen] = useState(false);
  const [environment, setEnvironment] = useState('');
  const [role, setRole] = useState<Role>('viewer');
  const [expiresAt, setExpiresAt] = useState<string | null>(null);
  const { pending, error, setError, run } = useAction();
  const slug = environment.trim();
  const slugError = slug === '' ? null : slugProblem(slug);
  const roles = ROLE_CHOICES.filter((choice) => slug === '' || choice.environment);
  const chosen = roles.some((choice) => choice.role === role) ? role : 'viewer';
  const where = everyProjectPlace(slug === '' ? null : slug);

  function close() {
    setOpen(false);
    setEnvironment('');
    setRole('viewer');
    setExpiresAt(null);
    setError(null);
  }

  return (
    <>
      <button className="btn" onClick={() => setOpen(true)}>
        <Plus size={14} />
        Grant on every project
      </button>

      <Modal
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : close())}
        title={
          <>
            Grant <span className="mono">{principalId}</span> on every project
          </>
        }
        description="A role on every project, including ones created later. With an environment name, only the environment of that name in each project."
      >
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            const place = slug === '' ? EVERY_PROJECT : `${EVERY_PROJECT}/${slug}`;
            run(() => coffre.access.set(member, { [place]: expiresAt === null ? chosen : { role: chosen, until: expiresAt } }), {
              affects: affects.everyProject(member),
              onSuccess: () => {
                toast.success(`Granted ${ROLES[chosen].name.toLowerCase()} on ${where.toLowerCase()}`);
                close();
              },
            });
          }}
        >
          <label className="field">
            <span className="label">Environment name</span>
            <input
              className="input input-mono"
              spellCheck={false}
              autoComplete="off"
              placeholder="Every environment"
              value={environment}
              aria-invalid={slugError !== null}
              aria-describedby="every-project-environment-hint"
              onChange={(event) => setEnvironment(event.target.value)}
            />
            <span className={`hint${slugError !== null ? ' edit-note-error' : ''}`} id="every-project-environment-hint">
              {slugError ??
                (slug === ''
                  ? 'Every environment of every project.'
                  : `Only the environment named ${slug} in each project, including projects created later.`)}
            </span>
          </label>

          <div className="form-row">
            <label className="field" style={{ flexGrow: 2 }}>
              <span className="label">Role</span>
              <select className="select" value={chosen} onChange={(event) => setRole(event.target.value as Role)}>
                {roles.map((choice) => (
                  <option key={choice.role} value={choice.role}>
                    {choice.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span className="label">Expires</span>
              <ExpiryField label="Expires" expiresAt={expiresAt} onChange={setExpiresAt} />
            </label>
          </div>

          <p className="hint">
            {where} · {ROLES[chosen].name}: {ROLES[chosen].description}
          </p>
          <ErrorLine error={error} />

          <div className="dialog-actions">
            <button className="btn" type="button" onClick={close}>
              Cancel
            </button>
            <button className="btn btn-primary" type="submit" disabled={pending || slugError !== null}>
              {pending ? <Spinner /> : 'Grant'}
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
}

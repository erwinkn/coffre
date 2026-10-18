import { useId, useState } from 'react';
import type { RoleImpact, RoleView } from '@coffre/client';
import { definitionProblem, type Permission, type RoleDefinition } from '@coffre/core/access';
import { useSuspenseQuery } from '@tanstack/react-query';
import { toast } from 'sonner';

import { useCoffre } from '../lib/coffre';
import { affects, queries } from '../lib/queries';
import {
  columnInWords,
  GRID_PERMISSIONS,
  impactExamples,
  impactInWords,
  ordered,
  PERMISSION_WORDS,
  projectWide,
  roleIdFrom,
  roleIdProblem,
  sameDefinition,
  toggle,
  type Column,
  type Columns,
} from '../lib/roles';
import { useAction } from '../lib/use-action';
import { Card } from './page';
import { Check, Lock, Pencil, Plus, RotateBack, Trash } from './icons';
import { ConfirmDialog, ErrorLine, Modal, Notice, Spinner } from './ui';

// Settings › Roles (docs/design/roles.md): what each role holds, in two
// columns, an environment's and a protected one's, which a person holds
// there; a service account holds the first everywhere. Any member reads
// them; an Owner of the whole instance edits them, each change weighed
// first (`?dryRun=1`) and said in words before it is confirmed.

type Kind = 'role' | 'instance-role';

/** The instance's roles and instance roles, each a card of rows that open its editor. */
export function RolesSettings() {
  const { data } = useSuspenseQuery(queries.roles(useCoffre()));
  if (!data.ok) {
    return (
      <Card labelledBy="roles" title="Roles">
        <div className="card-row">
          <ErrorLine error={`The roles could not be read. ${data.error}`} />
        </div>
      </Card>
    );
  }
  return (
    <>
      <RoleList kind="role" roles={data.roles} editable={data.editable} />
      <RoleList kind="instance-role" roles={data.instanceRoles} editable={data.editable} />
    </>
  );
}

function RoleList({ kind, roles, editable }: { kind: Kind; roles: RoleView[]; editable: boolean }) {
  // The role open in the editor, by id, or one being made: never a role's id, which `new` may be.
  const [open, setOpen] = useState<{ role: string } | { making: true } | null>(null);
  const project = kind === 'role';
  const opened = open === null || 'making' in open ? null : roles.find((role) => role.id === open.role);
  return (
    <Card
      labelledBy={project ? 'roles' : 'instance-roles'}
      title={project ? 'Roles' : 'Instance roles'}
      description={
        <>
          {project
            ? 'What a grant gives, on a project or one of its environments. In a protected environment a person holds the second column; a service account always holds the first.'
            : 'What a person holds, by their instance role, in every project its scope takes in, before any grant adds to it.'}
          {!editable && ' Only an Owner of the whole instance edits them.'}
        </>
      }
      actions={
        project && editable && (
          <button className="btn" type="button" onClick={() => setOpen({ making: true })}>
            <Plus size={14} />
            New role
          </button>
        )
      }
    >
      <ul className="role-list" aria-label={project ? 'Roles' : 'Instance roles'}>
        {roles.map((role) => (
          <li key={role.id} className="card-row role-row">
            <div className="role-row-text">
              <p className="card-row-title role-row-title">
                {role.name}
                <RoleBadges role={role} />
              </p>
              {role.description !== '' && <p className="card-row-desc">{role.description}</p>}
              <dl className="role-columns">
                <div>
                  <dt>Holds</dt>
                  <dd>{columnInWords(role.permissions)}</dd>
                </div>
                <div>
                  <dt>
                    <Lock size={12} />
                    In protected environments
                  </dt>
                  <dd>{columnInWords(role.protected)}</dd>
                </div>
              </dl>
            </div>
            <div className="role-row-side">
              <span className="role-row-count">{held(kind, role.grants)}</span>
              <button
                className="btn btn-sm"
                type="button"
                aria-label={`${editable && !role.fixed ? 'Edit' : 'View'} ${role.name}`}
                onClick={() => setOpen({ role: role.id })}
              >
                {editable && !role.fixed && <Pencil size={14} />}
                {editable && !role.fixed ? 'Edit…' : 'View'}
              </button>
            </div>
          </li>
        ))}
      </ul>
      {open !== null && opened !== undefined && (
        <RoleEditor
          // Each opening starts from the role as it is.
          key={'making' in open ? '' : `role:${open.role}`}
          kind={kind}
          role={opened}
          roles={roles}
          editable={editable && (opened === null || !opened.fixed)}
          onClose={() => setOpen(null)}
        />
      )}
    </Card>
  );
}

/** "3 grants", "1 person": who a role reaches now. */
function held(kind: Kind, count: number): string {
  if (kind === 'instance-role') return count === 0 ? 'Nobody' : count === 1 ? '1 person' : `${count} people`;
  return count === 0 ? 'No grants' : count === 1 ? '1 grant' : `${count} grants`;
}

/** Where a role comes from, and whether it is as it shipped. */
function RoleBadges({ role }: { role: RoleView }) {
  return (
    <>
      {role.builtin ? <span className="tag tag-outline">Built-in</span> : <span className="tag tag-blue">Custom</span>}
      {role.edited && <span className="tag tag-amber">Edited</span>}
      {role.fixed && (
        <span className="tag">
          <Lock size={11} />
          Fixed
        </span>
      )}
    </>
  );
}

type Draft = RoleDefinition & Columns & { id: string };

/** A change asked for, weighed, waiting for its confirmation. */
type Pending = { action: 'save' | 'reset' | 'delete'; impact: RoleImpact };

/**
 * One role's editor, or a new one's: its name, description and grid, and
 * Save, Reset to default for a built-in one edited, Delete for one an Owner
 * made. Each asks the server what it would do first and says it, then does
 * it once confirmed. Read-only to anyone who does not edit roles, and for
 * Owner and Member, which hold everything and nothing, always.
 */
function RoleEditor({
  kind,
  role,
  roles,
  editable,
  onClose,
}: {
  kind: Kind;
  /** Null for a new role. */
  role: RoleView | null;
  roles: RoleView[];
  editable: boolean;
  onClose: () => void;
}) {
  const coffre = useCoffre();
  const instance = kind === 'instance-role';
  const [draft, setDraft] = useState<Draft>(() =>
    role === null
      ? { id: '', name: '', description: '', permissions: [], protected: [] }
      : { id: role.id, name: role.name, description: role.description, ...ordered(role) },
  );
  // A new role's id follows its name until it is typed itself.
  const [idTyped, setIdTyped] = useState(false);
  // The change weighed, kept after its confirmation closes, so that its words stay while it fades.
  const [pending, setPending] = useState<Pending | null>(null);
  const [asking, setAsking] = useState(false);
  const weigh = useAction();
  const apply = useAction();
  const ids = { name: useId(), id: useId(), description: useId(), start: useId() };

  const made = role === null;
  const label = role?.name ?? (draft.name.trim() || 'New role');
  const idError = made ? roleIdProblem(draft.id, roles.map((each) => each.id)) : null;
  const definitionError = draft.name.trim() === '' ? 'A role needs a name.' : definitionProblem(draft);
  const changed = role === null || !sameDefinition(draft, role);
  const definition = { name: draft.name.trim(), description: draft.description, permissions: draft.permissions, protected: draft.protected };
  const busy = weigh.pending || apply.pending;

  const set = (permission: Permission, column: Column, on: boolean) => setDraft((current) => ({ ...current, ...toggle(current, permission, column, on) }));
  const startFrom = (id: string) => {
    const source = roles.find((each) => each.id === id);
    setDraft((current) => ({ ...current, ...(source === undefined ? { permissions: [], protected: [] } : ordered(source)) }));
  };

  /** Ask what an action would do; the confirmation shows it. */
  function ask(action: Pending['action']) {
    void weigh.run(
      () => (action === 'save' ? coffre.roles.preview(draft.id, definition, { instance }) : coffre.roles.previewReset(draft.id, { instance })),
      {
        affects: [],
        onSuccess: (impact) => {
          setPending({ action, impact });
          setAsking(true);
        },
      },
    );
  }

  function confirm({ action }: Pending) {
    const name = action === 'save' ? definition.name : label;
    void apply.run(
      () => (action === 'save' ? coffre.roles.set(draft.id, definition, { instance }) : coffre.roles.reset(draft.id, { instance })),
      {
        affects: affects.roles(),
        onSuccess: () => {
          toast.success(
            action === 'delete'
              ? `Deleted the ${name} role`
              : action === 'reset'
                ? `${name} is as it ships again`
                : made
                  ? `Made the ${name} role`
                  : `Saved the ${name} role`,
          );
          onClose();
        },
      },
    );
  }

  const granted = role !== null && !role.builtin && role.grants > 0;
  const error = weigh.error ?? apply.error;

  return (
    <Modal
      open
      onOpenChange={(next) => !next && !busy && onClose()}
      wide
      title={made ? 'New role' : editable ? <>Edit {role.name}</> : role.name}
      description={
        !editable && role !== null
          ? role.fixed
            ? `${role.name} holds ${role.id === 'member' ? 'nothing' : 'everything'}, always: nobody edits it.`
            : 'Only an Owner of the whole instance edits roles.'
          : made
            ? 'A project role, granted as any is. You can delete it while no grant names it.'
            : undefined
      }
    >
      <form
        className="form"
        onSubmit={(event) => {
          event.preventDefault();
          ask('save');
        }}
      >
        {editable && (
          <div className="form-row">
            <label className="field" htmlFor={ids.name}>
              <span className="label">Name</span>
              <input
                id={ids.name}
                className="input"
                autoFocus={made}
                maxLength={40}
                autoComplete="off"
                placeholder={made ? 'Release manager' : undefined}
                value={draft.name}
                onChange={(event) => {
                  const name = event.target.value;
                  setDraft((current) => ({ ...current, name, ...(made && !idTyped ? { id: roleIdFrom(name) } : {}) }));
                }}
              />
            </label>
            {made && (
              <label className="field" htmlFor={ids.id}>
                <span className="label">Id</span>
                <input
                  id={ids.id}
                  className="input input-mono"
                  spellCheck={false}
                  autoComplete="off"
                  maxLength={32}
                  placeholder="release-manager"
                  value={draft.id}
                  aria-invalid={draft.id !== '' && idError !== null}
                  aria-describedby={`${ids.id}-hint`}
                  onChange={(event) => {
                    setIdTyped(true);
                    setDraft((current) => ({ ...current, id: event.target.value }));
                  }}
                />
                <span id={`${ids.id}-hint`} className={`hint${draft.id !== '' && idError !== null ? ' edit-note-error' : ''}`}>
                  {draft.id !== '' && idError !== null ? idError : 'What the CLI and grants name it. It never changes.'}
                </span>
              </label>
            )}
          </div>
        )}
        {editable && (
          <label className="field" htmlFor={ids.description}>
            <span className="label">
              Description <span className="hint">(optional)</span>
            </span>
            <input
              id={ids.description}
              className="input"
              maxLength={200}
              autoComplete="off"
              value={draft.description}
              onChange={(event) => setDraft((current) => ({ ...current, description: event.target.value }))}
            />
          </label>
        )}
        {made && (
          <label className="field" htmlFor={ids.start}>
            <span className="label">Start from</span>
            <select id={ids.start} className="select" defaultValue="" onChange={(event) => startFrom(event.target.value)}>
              <option value="">Nothing</option>
              {roles.map((each) => (
                <option key={each.id} value={each.id}>
                  {each.name}
                </option>
              ))}
            </select>
          </label>
        )}
        {!editable && role !== null && role.description !== '' && <p className="dialog-body">{role.description}</p>}

        <RoleGrid name={label} columns={draft} editable={editable} onChange={set} />

        {editable && (
          <p className="hint">
            Reading takes using, and a protected environment holds no more than any other: the boxes keep both true.
            {instance ? ' An instance role reaches every project its holder’s scope takes in.' : ''}
          </p>
        )}
        {role !== null && role.edited && (
          <Notice tone="info">
            Edited. As it ships, it holds {columnInWords(role.default?.permissions ?? [])}; in protected environments,{' '}
            {columnInWords(role.default?.protected ?? [])}.
          </Notice>
        )}
        {editable && changed && definitionError !== null && draft.name.trim() !== '' && <p className="hint edit-note-error">{definitionError}</p>}
        <ErrorLine error={error} />

        <div className="dialog-actions role-editor-actions">
          {editable && role !== null && (role.builtin ? role.edited : true) && (
            <div className="role-editor-aside">
              {role.builtin ? (
                <button className="btn" type="button" disabled={busy} onClick={() => ask('reset')}>
                  <RotateBack size={14} />
                  Reset to default
                </button>
              ) : (
                <button
                  className="btn btn-danger-outline"
                  type="button"
                  disabled={busy || granted}
                  aria-describedby={granted ? `${ids.name}-granted` : undefined}
                  onClick={() => ask('delete')}
                >
                  <Trash size={14} />
                  Delete…
                </button>
              )}
              {granted && (
                <span id={`${ids.name}-granted`} className="hint">
                  {role.grants === 1 ? '1 grant names it' : `${role.grants} grants name it`}: revoke {role.grants === 1 ? 'it' : 'them'} first.
                </span>
              )}
            </div>
          )}
          <button className="btn" type="button" disabled={busy} onClick={onClose}>
            {editable ? 'Cancel' : 'Close'}
          </button>
          {editable && (
            <button className="btn btn-primary" type="submit" disabled={busy || !changed || definitionError !== null || idError !== null}>
              {weigh.pending && <Spinner />}
              {made ? 'Make role…' : 'Save…'}
            </button>
          )}
        </div>
      </form>

      {/* Inside the editor, so that it is a dialog nested in it: Escape closes it alone. */}
      <ConfirmDialog
        open={asking}
        onOpenChange={setAsking}
        title={
          pending?.action === 'delete'
            ? `Delete the ${label} role?`
            : pending?.action === 'reset'
              ? `Reset ${label} to its default?`
              : made
                ? `Make the ${definition.name} role?`
                : `Save the ${label} role?`
        }
        body={pending === null ? '' : impactLead(pending)}
        detail={pending !== null && pending.impact.impact.length > 0 && <ImpactList impact={pending.impact} />}
        confirmLabel={pending?.action === 'delete' ? 'Delete' : pending?.action === 'reset' ? 'Reset' : 'Save'}
        destructive={pending?.action === 'delete'}
        onConfirm={() => pending !== null && confirm(pending)}
      />
    </Modal>
  );
}

/** What a change does, before its lines: whether it reaches anyone now. */
function impactLead({ action, impact }: Pending): string {
  const logged = 'It is logged, with the role as it was.';
  if (impact.impact.length === 0) {
    return action === 'delete'
      ? `No grant names it, so nobody loses anything. ${logged}`
      : `Nobody holds more or less for it today: it applies to whoever holds the role from now on. ${logged}`;
  }
  return `It applies at once to everyone the role reaches; tokens issued before keep at most what they held. These count people: service accounts that hold the role change with it too. ${logged}`;
}

/** A change's impact, line by line, with whom each reaches. */
function ImpactList({ impact }: { impact: RoleImpact }) {
  return (
    <ul className="impact-list">
      {impact.impact.map((line) => {
        const who = impactExamples(line);
        return (
          <li key={`${line.change} ${line.permission} ${line.protected}`} className={`impact-line impact-${line.change}`}>
            <span className={`tag ${line.change === 'widens' ? 'tag-amber' : 'tag-blue'}`}>{line.change === 'widens' ? 'Widens' : 'Narrows'}</span>
            <span>
              {impactInWords(line)}
              {who !== null && <span className="impact-who">{who}</span>}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

/**
 * The grid: a row per permission, a column for environments and one for
 * protected ones, real checkboxes each named in full for a screen reader
 * ("Developer: Read values in protected environments"). Project-wide
 * permissions have the first column alone, under a heading of their own.
 */
function RoleGrid({
  name,
  columns,
  editable,
  onChange,
}: {
  name: string;
  columns: Columns;
  editable: boolean;
  onChange: (permission: Permission, column: Column, on: boolean) => void;
}) {
  const cell = (permission: Permission, column: Column) => {
    const on = (column === 'normal' ? columns.permissions : columns.protected).includes(permission);
    const where = projectWide(permission) ? ', on the whole project' : column === 'normal' ? ' in environments' : ' in protected environments';
    const words = `${name}: ${PERMISSION_WORDS[permission].label}${where}`;
    if (!editable) {
      return on ? (
        <span className="role-grid-yes" title={words}>
          <Check size={15} />
          <span className="visually-hidden">{words}: yes</span>
        </span>
      ) : (
        <span className="role-grid-no">
          <span aria-hidden>–</span>
          <span className="visually-hidden">{words}: no</span>
        </span>
      );
    }
    return <input type="checkbox" className="role-grid-box" aria-label={words} checked={on} onChange={(event) => onChange(permission, column, event.target.checked)} />;
  };
  const values = GRID_PERMISSIONS.filter((permission) => !projectWide(permission));
  const wide = GRID_PERMISSIONS.filter(projectWide);
  const row = (permission: Permission) => {
    const { label, note } = PERMISSION_WORDS[permission];
    return (
      <tr key={permission}>
        <th scope="row">
          {label}
          {note !== undefined && <span className="role-grid-note">{note}</span>}
        </th>
        <td>{cell(permission, 'normal')}</td>
        {projectWide(permission) ? <td /> : <td>{cell(permission, 'protected')}</td>}
      </tr>
    );
  };
  return (
    <div className="role-grid-wrap">
      <table className="role-grid">
        <caption className="visually-hidden">What {name} holds, in environments and in protected ones</caption>
        <thead>
          <tr>
            <th scope="col">Permission</th>
            {/* A phone's narrow columns take the short words; a screen reader always reads the long ones. */}
            <th scope="col">
              <span className="role-grid-long">Environments</span>
              <span className="role-grid-short" aria-hidden>
                Normal
              </span>
            </th>
            <th scope="col">
              <span className="th">
                <Lock size={12} />
                <span className="role-grid-long">Protected environments</span>
                <span className="role-grid-short" aria-hidden>
                  Protected
                </span>
              </span>
            </th>
          </tr>
        </thead>
        <tbody>{values.map(row)}</tbody>
        <tbody>
          <tr className="role-grid-group">
            <th scope="colgroup" colSpan={3}>
              Project-wide <span className="role-grid-note">one column: a project is never protected</span>
            </th>
          </tr>
          {wide.map(row)}
        </tbody>
      </table>
    </div>
  );
}

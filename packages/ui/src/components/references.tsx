import { useEffect, useId, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import type { ListedReference, ReferenceView, SecretKey } from '@coffre/client';

import { useCoffre } from '../lib/coffre';
import { queries } from '../lib/queries';
import { useAction } from '../lib/use-action';
import { secretKeyProblem } from '../lib/validation';
import { ArrowRight } from './icons';
import { Card } from './page';
import { ConfirmDialog, ErrorLine, Modal, Notice, Timestamp } from './ui';

/**
 * References: a secret read live through another (docs/design/environments.md).
 * The vault makes and checks each one; these only show them.
 */

/** Why a reference does not read, in a few words; null while it does. */
export function referenceProblem(state: ReferenceView['state']): string | null {
  switch (state) {
    case 'live':
      return null;
    case 'broken':
      return 'Broken';
    case 'replaced':
      return 'No value';
    case 'source_archived':
      return 'Source archived';
    case 'source_deleted':
      return 'Source deleted';
    case 'source_is_reference':
      return 'Source is a reference';
    case 'source_empty':
      return 'Source has no value';
  }
}

/** A secret's path as a link to it, when you can open it there. */
function SecretPath({ path, open }: { path: string; open: boolean }) {
  const [project, environment, key] = path.split('/') as [string, string, string];
  if (!open) {
    return (
      <span className="mono" title="You can't open the source">
        {path}
      </span>
    );
  }
  return (
    <Link className="mono" to="/projects/$project/$environment" params={{ project, environment }} search={{ filter: key }}>
      {path}
    </Link>
  );
}

/**
 * What a key that is a reference shows where its value would be: what it
 * reads, and, when it does not read, why. Reading it is a reveal like any
 * other, logged as a read of the source.
 */
export function ReferenceValue({ reference }: { reference: NonNullable<SecretKey['reference']> }) {
  const problem = referenceProblem(reference.state);
  return (
    <span className="reference-value">
      <ArrowRight size={13} aria-label="A reference to" />
      <SecretPath path={reference.source} open={reference.canOpenSource} />
      {problem !== null && (
        <span className="tag tag-red" title={reference.endedBy === null ? undefined : `By ${reference.endedBy}`}>
          {problem}
        </span>
      )}
    </span>
  );
}

/**
 * The references that read a secret from elsewhere, under its row: where
 * each is held, who made it, who reads through it, and Break for those who
 * may.
 */
export function LentReferences({ references, onBreak }: { references: ListedReference[]; onBreak: (reference: ListedReference) => void }) {
  return (
    <ul className="lent-references" aria-label="Read through references">
      {references.map((reference) => (
        <li key={reference.id}>
          <span>
            Read through <SecretPath path={reference.holder} open={false} />, made by {reference.createdBy.replace(/^user:/, '')}{' '}
            <Timestamp iso={reference.createdAt} display="relative" />
            {reference.readers !== null && (
              <span className="cell-muted">
                {' '}
                · {reference.readers.length === 0 ? 'no one reads it by a grant' : `${reference.readers.length} ${reference.readers.length === 1 ? 'person reads' : 'people read'} it: ${reference.readers.map((reader) => reader.replace(/^user:/, '').replace(/^token:/, 'service:')).join(', ')}`}
              </span>
            )}
          </span>
          {reference.canBreak && (
            <button type="button" className="btn btn-sm btn-danger-outline" onClick={() => onBreak(reference)}>
              Break
            </button>
          )}
        </li>
      ))}
    </ul>
  );
}

/**
 * Make a key a reference to a secret you read, by path: whoever reads its
 * environment reads that secret through it, as it changes. Paths you can
 * read are offered as you type.
 */
export function MakeReference({
  open,
  onOpenChange,
  holder,
  environments,
  onMake,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** `billing/prod/DATABASE_URL`. */
  holder: string;
  /** `market/prod`, each environment you read. */
  environments: readonly string[];
  onMake: (source: string) => void;
}) {
  const [source, setSource] = useState('');
  const listId = useId();
  useEffect(() => {
    if (open) setSource('');
  }, [open]);
  const [project, environment, key] = source.split('/');
  const problem =
    source === '' ? null
    : source.split('/').length !== 3 || project === '' || environment === '' ? 'A secret, as project/environment/KEY.'
    : secretKeyProblem(key!);
  const holderEnvironment = holder.split('/').slice(0, 2).join('/');

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={`Make ${holder.split('/')[2]} a reference`}
      description={`Whoever can read ${holderEnvironment} will read the secret you name, as it changes, even without access to its project. It takes your own read on that secret.`}
    >
      <form
        className="form"
        onSubmit={(event) => {
          event.preventDefault();
          if (problem !== null || source === '') return;
          onMake(source);
          onOpenChange(false);
        }}
      >
        <label className="field">
          <span className="label">Secret to read</span>
          <input
            className="input input-mono"
            autoFocus
            spellCheck={false}
            autoComplete="off"
            list={listId}
            placeholder="market/prod/DATABASE_URL"
            value={source}
            aria-invalid={problem !== null}
            onChange={(event) => setSource(event.target.value)}
          />
          <datalist id={listId}>
            {environments.map((each) => (
              <option key={each} value={`${each}/`} />
            ))}
          </datalist>
          <span className={`hint${problem !== null ? ' edit-note-error' : ''}`}>
            {problem ?? 'A reference cannot point at a reference: name the secret it reads.'}
          </span>
        </label>
        <div className="dialog-actions">
          <button className="btn" type="button" onClick={() => onOpenChange(false)}>
            Cancel
          </button>
          <button className="btn btn-primary" type="submit" disabled={source === '' || problem !== null}>
            Make reference
          </button>
        </div>
      </form>
    </Modal>
  );
}

/**
 * A project's secrets that others read through references held elsewhere,
 * and who: on its access tab, beside the grants, since "who can read this"
 * includes them. Those who may break one, its source's access managers or
 * whoever writes where it is held, do it here.
 */
export function ReferencesInto({ project }: { project: string }) {
  const coffre = useCoffre();
  const { data } = useQuery(queries.references(coffre, project));
  const { run, error } = useAction();
  const [breaking, setBreaking] = useState<ListedReference | null>(null);
  const into = data?.ok === true ? data.references.filter((reference) => reference.source.startsWith(`${project}/`)) : [];
  if (into.length === 0) return null;
  return (
    <Card
      labelledBy="references-into"
      title="Also readable through references"
      description={`Secrets of ${project} that others read through references held elsewhere. Who reads a reference's environment reads its source, with no grant here.`}
    >
      <div className="dt-wrap">
        <table className="dt stacks">
          <thead>
            <tr>
              <th>Secret</th>
              <th>Read through</th>
              <th>Readers</th>
              <th className="col-actions">
                <span className="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {into.map((reference) => (
              <tr key={reference.id}>
                <td className="mono" data-label="Secret">{reference.source}</td>
                <td data-label="Read through">
                  <span className="cell-stack">
                    <span className="mono">{reference.holder}</span>
                    <small className="cell-muted">
                      Made by {reference.createdBy.replace(/^user:/, '')} <Timestamp iso={reference.createdAt} display="relative" />
                    </small>
                  </span>
                </td>
                <td data-label="Readers">
                  {reference.readers === null
                    ? '—'
                    : reference.readers.length === 0
                      ? <span className="cell-muted">No one, by a grant</span>
                      : reference.readers.map((reader) => reader.replace(/^user:/, '').replace(/^token:/, 'service:')).join(', ')}
                </td>
                <td className="col-actions">
                  {reference.canBreak && (
                    <button type="button" className="btn btn-sm btn-danger-outline" onClick={() => setBreaking(reference)}>
                      Break
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {error !== null && <ErrorLine error={error} />}
      <ConfirmDialog
        open={breaking !== null}
        onOpenChange={(open) => !open && setBreaking(null)}
        title="Break this reference?"
        body={breaking === null ? '' : `Whoever reads ${breaking.holder.split('/').slice(0, 2).join('/')} stops reading ${breaking.source} through it, and a run there refuses until ${breaking.holder.split('/')[2]} gets a value.`}
        confirmLabel="Break"
        onConfirm={() => {
          const path = breaking!.holder;
          void run(() => coffre.references.break(path), { affects: [['references']] });
        }}
      />
    </Card>
  );
}

/**
 * The references that archiving `path` would stop, a project, an
 * environment or a key: those reading a secret in it, held outside it.
 * Archiving is refused while any read (D41); the server decides, and this
 * shows the dialog what it will say.
 */
export function archiveBlockers(path: string, references: readonly ListedReference[]): ListedReference[] {
  const within = (secret: string) => secret === path || secret.startsWith(`${path}/`);
  return references.filter((reference) => reference.state === 'live' && within(reference.source) && !within(reference.holder));
}

/**
 * What an archive dialog shows while references read what it would
 * archive: each, and Break for those who may break it. Archive waits until
 * none is left.
 */
export function ArchiveBlocked({ references }: { references: readonly ListedReference[] }) {
  const coffre = useCoffre();
  const { run, error, pending } = useAction();
  if (references.length === 0) return null;
  const many = references.length > 1;
  return (
    <div className="archive-blocked">
      <Notice tone="bad">
        {many ? `${references.length} references read it` : 'A reference reads it'} from elsewhere. Break{' '}
        {many ? 'them' : 'it'} first: archiving would stop {many ? 'those reads' : 'that read'}.
      </Notice>
      <ul className="archive-blockers" aria-label="References that read it">
        {references.map((reference) => (
          <li key={reference.id}>
            <span className="cell-stack">
              <span className="mono">{reference.holder}</span>
              <small>
                reads <span className="mono">{reference.source}</span>
              </small>
            </span>
            {reference.canBreak ? (
              <button
                type="button"
                className="btn btn-sm btn-danger-outline"
                disabled={pending}
                onClick={() => void run(() => coffre.references.break(reference.holder), { affects: [['references'], ['secrets']] })}
              >
                Break
              </button>
            ) : (
              <small className="cell-muted">{`${reference.source.split('/')[0]}'s access managers, or whoever writes ${reference.holder.split('/').slice(0, 2).join('/')}, can break it`}</small>
            )}
          </li>
        ))}
      </ul>
      <p className="hint">Once broken, a run where it is held refuses until that key gets a value of its own.</p>
      {error !== null && <ErrorLine error={error} />}
    </div>
  );
}

import { useEffect, useId, useState } from 'react';

import { folderProblem } from '../lib/validation';
import { Folder } from './icons';
import { Modal } from './ui';

/**
 * A folder's heading row inside a table: the rows after it, up to the next
 * heading, are filed in it. Folders only arrange a list
 * (docs/design/environments.md).
 */
export function FolderRow({ folder, count, columns }: { folder: string; count: number; columns: number }) {
  return (
    <tr className="folder-row">
      <th colSpan={columns} scope="rowgroup">
        <span className="th">
          <Folder size={14} />
          {folder}
          <span className="count">{count}</span>
        </span>
      </th>
    </tr>
  );
}

/**
 * Where to file something: a folder by name, one already in use or a new
 * one, or none. Asked in a dialog, since it is one field and one decision.
 */
export function MoveToFolder({
  open,
  onOpenChange,
  what,
  current,
  folders,
  onMove,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** What moves, as the title names it: "STRIPE_KEY". */
  what: string;
  current: string | null;
  /** The folders in use beside it, offered as you type. */
  folders: readonly string[];
  onMove: (folder: string | null) => void;
}) {
  const [name, setName] = useState(current ?? '');
  const listId = useId();
  useEffect(() => {
    if (open) setName(current ?? '');
  }, [open, current]);
  const problem = folderProblem(name);
  const folder = name === '' ? null : name;

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={`Move ${what} to a folder`}
      description="A folder arranges the list. It changes nothing else: names, values and access stay as they are."
    >
      <form
        className="form"
        onSubmit={(event) => {
          event.preventDefault();
          if (problem !== null) return;
          if (folder !== current) onMove(folder);
          onOpenChange(false);
        }}
      >
        <label className="field">
          <span className="label">Folder</span>
          <input
            className="input"
            autoFocus
            spellCheck={false}
            autoComplete="off"
            list={listId}
            placeholder="No folder"
            value={name}
            aria-invalid={problem !== null}
            onChange={(event) => setName(event.target.value)}
          />
          <datalist id={listId}>
            {folders.map((each) => (
              <option key={each} value={each} />
            ))}
          </datalist>
          <span className={`hint${problem !== null ? ' edit-note-error' : ''}`}>
            {problem ?? 'Pick one in use, or name a new one. Empty for no folder.'}
          </span>
        </label>
        <div className="dialog-actions">
          <button className="btn" type="button" onClick={() => onOpenChange(false)}>
            Cancel
          </button>
          <button className="btn btn-primary" type="submit" disabled={problem !== null || folder === current}>
            {folder === null && current !== null ? 'Take out of its folder' : 'Move'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

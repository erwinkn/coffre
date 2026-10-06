import { useEffect, useId, useState, type ReactNode } from 'react';
import { Menu } from '@base-ui/react/menu';

import { folderProblem } from '../lib/validation';
import { Folder, MoreHorizontal, Pencil, X } from './icons';
import { ConfirmDialog, MenuPopup, Modal } from './ui';

/**
 * A folder's heading row inside a table: the rows after it, up to the next
 * heading, are filed in it. Folders only arrange a list
 * (docs/design/environments.md).
 */
export function FolderRow({ folder, count, columns, actions }: { folder: string; count: number; columns: number; actions?: ReactNode }) {
  return (
    <tr className="folder-row">
      <th colSpan={columns} scope="rowgroup">
        <span className="folder-row-head">
          <span className="th">
            <Folder size={14} />
            {folder}
            <span className="count">{count}</span>
          </span>
          {actions}
        </span>
      </th>
    </tr>
  );
}

/**
 * A folder heading's menu: rename it, which re-files everything in it, or
 * remove it, which takes everything out. A folder is only a label, so what
 * was in it stays where it is, and a rename onto a folder in use merges the
 * two.
 */
export function FolderMenu({
  folder,
  count,
  what,
  folders,
  onRename,
  onRemove,
}: {
  folder: string;
  count: number;
  /** What it holds, as a sentence counts them: `project`, `key`. */
  what: string;
  /** The other folders in use beside it, offered as you type. */
  folders: readonly string[];
  onRename: (name: string) => void;
  onRemove: () => void;
}) {
  const [renaming, setRenaming] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [name, setName] = useState(folder);
  const listId = useId();
  useEffect(() => {
    if (renaming) setName(folder);
  }, [renaming, folder]);
  const problem = folderProblem(name);
  const merges = name !== folder && folders.includes(name);
  const items = `${count} ${what}${count === 1 ? '' : 's'}`;

  return (
    <>
      <Menu.Root>
        <Menu.Trigger className="act act-icon act-quiet folder-row-menu" aria-label={`Actions for the folder ${folder}`}>
          <MoreHorizontal size={16} />
        </Menu.Trigger>
        <MenuPopup align="end">
          <Menu.Item className="menu-item" onClick={() => setRenaming(true)}>
            <Pencil size={14} />
            Rename folder…
          </Menu.Item>
          <Menu.Item className="menu-item menu-item-danger" onClick={() => setRemoving(true)}>
            <X size={14} />
            Remove folder…
          </Menu.Item>
        </MenuPopup>
      </Menu.Root>

      <Modal
        open={renaming}
        onOpenChange={setRenaming}
        title={`Rename ${folder}`}
        description={`Its ${items} move with it. Nothing else changes.`}
      >
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            if (problem !== null || name === '' || name === folder) return;
            onRename(name);
            setRenaming(false);
          }}
        >
          <label className="field">
            <span className="label">Name</span>
            <input
              className="input"
              autoFocus
              spellCheck={false}
              autoComplete="off"
              list={listId}
              value={name}
              aria-invalid={problem !== null}
              onChange={(event) => setName(event.target.value)}
            />
            <datalist id={listId}>
              {folders.filter((each) => each !== folder).map((each) => (
                <option key={each} value={each} />
              ))}
            </datalist>
            <span className={`hint${problem !== null ? ' edit-note-error' : ''}`}>
              {problem ?? (merges ? `${name} is in use: the two become one folder.` : 'One level: no slash.')}
            </span>
          </label>
          <div className="dialog-actions">
            <button className="btn" type="button" onClick={() => setRenaming(false)}>
              Cancel
            </button>
            <button className="btn btn-primary" type="submit" disabled={problem !== null || name === '' || name === folder}>
              {merges ? 'Merge' : 'Rename'}
            </button>
          </div>
        </form>
      </Modal>

      <ConfirmDialog
        open={removing}
        onOpenChange={setRemoving}
        title={`Remove the folder ${folder}?`}
        body={`Its ${items} stay where they are, in no folder. Nothing else changes.`}
        confirmLabel="Remove folder"
        onConfirm={onRemove}
      />
    </>
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
      description="Folders only arrange the list: names, values and access stay as they are."
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

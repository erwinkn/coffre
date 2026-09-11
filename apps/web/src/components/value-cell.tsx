import { Check, Copy, Eye, EyeOff, LoaderCircle, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import type { Secret } from '../../../../packages/contracts/src/index';
import { invoke } from '../lib/operations';
import { Button } from './ui/button';
import { Dialog } from './ui/dialog';

interface ReadValue { id: string; version: number; value: string }
type Cell = { mode: 'idle' } | { mode: 'revealed'; value: string } | { mode: 'edit'; value: string; original: string; version: number };
export function ValueCell({ secret, editable, readable, protectedEnvironment, editId, claimEdit, finishEdit, changed, report }: { secret: Secret; editable: boolean; readable: boolean; protectedEnvironment: boolean; editId: string | null; claimEdit: (id: string, dirty?: boolean) => boolean; finishEdit: () => void; changed: () => void; report: (text: string) => void }) {
  const [cell, setCell] = useState<Cell>({ mode: 'idle' });
  const [busy, setBusy] = useState(false), [copied, setCopied] = useState(false), [confirm, setConfirm] = useState(false);
  const input = useRef<HTMLTextAreaElement>(null), valueButton = useRef<HTMLButtonElement>(null);
  const sequence = useRef(0), controller = useRef<AbortController | null>(null), timer = useRef<ReturnType<typeof setTimeout> | null>(null), copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const stateRef = useRef(cell); stateRef.current = cell;
  function clear(focus = false) {
    sequence.current++; controller.current?.abort(); if (timer.current) clearTimeout(timer.current);
    setCell({ mode: 'idle' }); setBusy(false); setConfirm(false);
    if (stateRef.current.mode === 'edit' || editId === secret.id) finishEdit();
    if (focus) queueMicrotask(() => valueButton.current?.focus());
  }
  function scheduleMask() {
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => { clear(); report('Value masked. Any unsaved draft was discarded.'); }, 45000);
  }
  useEffect(() => {
    const hide = () => { if (document.hidden) clear(); };
    document.addEventListener('visibilitychange', hide);
    return () => { sequence.current++; controller.current?.abort(); if (timer.current) clearTimeout(timer.current); if (copyTimer.current) clearTimeout(copyTimer.current); document.removeEventListener('visibilitychange', hide); };
  }, []);
  useEffect(() => { if (cell.mode === 'edit' && editId !== secret.id) clear(); }, [editId]);
  useEffect(() => { if (cell.mode === 'edit') input.current?.focus({ preventScroll: true }); }, [cell.mode]);
  async function read(purpose: 'edit' | 'reveal' | 'copy') {
    if (busy || !readable) return;
    if (purpose === 'edit' && !claimEdit(secret.id)) return;
    if (purpose === 'reveal' && cell.mode === 'revealed') { clear(true); return; }
    const current = ++sequence.current;
    controller.current?.abort(); controller.current = new AbortController(); setBusy(true);
    try {
      const data = await invoke<ReadValue>({ type: 'secret.read', id: secret.id, purpose }, controller.current.signal);
      if (current !== sequence.current || document.hidden) return;
      if (purpose === 'copy') {
        await navigator.clipboard.writeText(data.value);
        if (current !== sequence.current) return;
        setCopied(true); if (copyTimer.current) clearTimeout(copyTimer.current); copyTimer.current = setTimeout(() => setCopied(false), 1500);
      } else {
        setCell(purpose === 'edit' ? { mode: 'edit', value: data.value, original: data.value, version: data.version } : { mode: 'revealed', value: data.value });
        scheduleMask();
      }
    } catch (error) {
      if (current === sequence.current) { if (purpose === 'edit') finishEdit(); report(error instanceof Error ? error.message : 'Could not read the value'); }
    } finally { if (current === sequence.current) setBusy(false); }
  }
  async function save(confirmed = false) {
    if (cell.mode !== 'edit' || busy) return;
    if (cell.value === cell.original) { clear(true); return; }
    if (protectedEnvironment && !confirmed) { setConfirm(true); return; }
    const current = ++sequence.current; setBusy(true);
    try {
      await invoke({ type: 'secret.write', id: secret.id, expectedVersion: cell.version, value: cell.value, confirmed });
      if (current !== sequence.current) { changed(); return; }
      clear(true); changed(); report('Value saved. A new version was recorded.');
    } catch (error) { if (current === sequence.current) { setConfirm(false); report(error instanceof Error ? error.message : 'Could not save the value'); } }
    finally { if (current === sequence.current) setBusy(false); }
  }
  return <>
    {cell.mode === 'edit' ? <div className="value-editor" data-testid="value-editor">
      <textarea ref={input} className="value-input" aria-label={`Value for ${secret.key}`} aria-describedby="cell-edit-help" value={cell.value} rows={1} wrap="off" spellCheck={false} autoComplete="off" autoCorrect="off" autoCapitalize="off" disabled={busy}
        onChange={event => { setCell({ ...cell, value: event.target.value }); claimEdit(secret.id, event.target.value !== cell.original); scheduleMask(); }}
        onKeyDown={event => { if (event.nativeEvent.isComposing) return; if (event.key === 'Escape') { event.preventDefault(); clear(true); } else if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); void save(); } }} />
      <span className="cell-controls"><Button size="icon" variant="ghost" aria-label={`Cancel editing ${secret.key}`} disabled={busy} onClick={() => clear(true)}><X size={14} /></Button><Button size="icon" variant="ghost" className="accept" aria-label={`Save ${secret.key}`} disabled={busy} onClick={() => void save()}>{busy ? <LoaderCircle className="spin" size={14} /> : <Check size={14} />}</Button></span>
    </div> : <div className="value-display">
      <button ref={valueButton} className={`value-trigger ${cell.mode === 'idle' ? 'mask' : ''}`} aria-label={`${editable ? 'Edit' : 'Reveal'} value for ${secret.key}`} disabled={!readable || busy} onClick={() => void read(editable ? 'edit' : 'reveal')}>{busy ? 'Loading…' : cell.mode === 'idle' ? '••••••••••••' : cell.value}</button>
      <span className="cell-controls"><Button size="icon" variant="ghost" aria-label={`${cell.mode === 'revealed' ? 'Hide' : 'Reveal'} ${secret.key}`} disabled={!readable || busy} onClick={() => void read('reveal')}>{cell.mode === 'revealed' ? <EyeOff size={14} /> : <Eye size={14} />}</Button><Button size="icon" variant="ghost" aria-label={`Copy ${secret.key}`} disabled={!readable || busy} onClick={() => void read('copy')}>{copied ? <Check size={14} /> : <Copy size={14} />}</Button></span>
    </div>}
    <Dialog open={confirm} onClose={() => !busy && setConfirm(false)} title="Confirm protected change" description={`Update ${secret.key} in this protected environment? The change creates a new version and an audit event.`}><div className="form-actions"><Button onClick={() => setConfirm(false)} disabled={busy}>Back to editing</Button><Button variant="default" onClick={() => void save(true)} disabled={busy}>{busy ? 'Saving…' : 'Confirm change'}</Button></div></Dialog>
  </>;
}

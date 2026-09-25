import { useEffect, useRef, useState, type ReactNode } from 'react';
import { AlertDialog, Dialog, Tooltip } from 'radix-ui';
import { AlertCircle, AlertTriangle, Check, Copy, Info, Loader, X } from './icons';

/* -------------------------------------------------------------------------- */
/* Tooltip                                                                     */
/* -------------------------------------------------------------------------- */

export function TooltipProvider({ children }: { children: ReactNode }) {
  // 400ms before the first tip; afterwards adjacent tips open instantly, which
  // makes a row of controls feel immediate without the delay losing its
  // purpose (preventing accidental activation on a passing cursor).
  return (
    <Tooltip.Provider delayDuration={400} skipDelayDuration={300}>
      {children}
    </Tooltip.Provider>
  );
}

export function Tip({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <Tooltip.Root>
      <Tooltip.Trigger asChild>{children}</Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content className="tooltip" sideOffset={6} collisionPadding={8}>
          {label}
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}

/* -------------------------------------------------------------------------- */
/* Feedback primitives                                                         */
/* -------------------------------------------------------------------------- */

export function Spinner({ size = 14 }: { size?: number }) {
  return <Loader size={size} className="spinner" />;
}

export function ErrorLine({ error }: { error: string | null }) {
  if (error === null) return null;
  return (
    <p className="error-line" role="alert">
      <AlertCircle size={14} />
      <span>{error}</span>
    </p>
  );
}

const NOTICE_ICON = {
  info: Info,
  good: Check,
  bad: AlertTriangle,
  neutral: Info,
} as const;

export function Notice({
  tone = 'neutral',
  children,
}: {
  tone?: keyof typeof NOTICE_ICON;
  children: ReactNode;
}) {
  const Icon = NOTICE_ICON[tone];
  return (
    <div
      className={`notice${tone === 'neutral' ? '' : ` notice-${tone}`}`}
      role={tone === 'bad' ? 'alert' : undefined}
    >
      <Icon size={16} />
      <div>{children}</div>
    </div>
  );
}

/**
 * Nothing here yet, said in a sentence.
 *
 * It sits where the table would have been, left-aligned like the rows it
 * stands in for, rather than as a centred illustration.
 */
export function EmptyState({
  title,
  children,
  actions,
}: {
  title: string;
  children?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="empty">
      <p className="empty-title">{title}</p>
      {children !== undefined && <p className="empty-body">{children}</p>}
      {actions !== undefined && <div className="empty-actions">{actions}</div>}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Copy                                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Copy to clipboard with a settled confirmation.
 *
 * The label swap is the whole feedback mechanism, so it holds for 1.4s -- long
 * enough to be noticed after the eye has moved on, short enough not to look
 * stuck. `text` renders as a row action ("Copy" / "Copied"); `icon` as a
 * glyph with a tooltip, for tight spots.
 */
export function CopyButton({
  value,
  label = 'Copy',
  variant = 'icon',
}: {
  value: string;
  label?: string;
  variant?: 'icon' | 'text';
}) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (timer.current !== null) clearTimeout(timer.current);
  }, []);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      return; // Clipboard denied; say nothing rather than claim success.
    }
    setCopied(true);
    if (timer.current !== null) clearTimeout(timer.current);
    timer.current = setTimeout(() => setCopied(false), 1400);
  }

  if (variant === 'text') {
    return (
      <button type="button" className="act" aria-label={label} onClick={copy}>
        {copied ? <Check size={13} /> : <Copy size={13} />}
        <span className="act-label" aria-live="polite">
          {copied ? 'Copied' : 'Copy'}
        </span>
      </button>
    );
  }

  return (
    <Tip label={copied ? 'Copied' : label}>
      <button type="button" className="btn btn-quiet btn-sm btn-icon" aria-label={label} onClick={copy}>
        {copied ? <Check size={14} /> : <Copy size={14} />}
      </button>
    </Tip>
  );
}

/* -------------------------------------------------------------------------- */
/* Confirmation                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Confirmation for actions with reach.
 *
 * Reserved for changes that affect other people or other screens (archiving a
 * project, revoking a grant). Restoring one secret is reversible and gets an
 * undo toast instead -- a dialog on every action trains people to dismiss them.
 */
type ConfirmProps = {
  title: ReactNode;
  body: ReactNode;
  confirmLabel: string;
  destructive?: boolean;
  onConfirm: () => void;
};

function ConfirmContent({ title, body, confirmLabel, destructive, onConfirm }: ConfirmProps) {
  return (
    <AlertDialog.Portal>
      <AlertDialog.Overlay className="overlay" />
      <AlertDialog.Content className="dialog dialog-confirm">
        <AlertDialog.Title className="dialog-title">{title}</AlertDialog.Title>
        <AlertDialog.Description className="dialog-body">{body}</AlertDialog.Description>
        <div className="dialog-actions">
          <AlertDialog.Cancel asChild>
            <button className="btn">Cancel</button>
          </AlertDialog.Cancel>
          <AlertDialog.Action asChild>
            <button
              className={`btn ${destructive === false ? 'btn-primary' : 'btn-danger'}`}
              onClick={onConfirm}
            >
              {confirmLabel}
            </button>
          </AlertDialog.Action>
        </div>
      </AlertDialog.Content>
    </AlertDialog.Portal>
  );
}

export function ConfirmButton({
  trigger,
  disabled,
  ...confirm
}: ConfirmProps & { trigger: ReactNode; disabled?: boolean }) {
  return (
    <AlertDialog.Root>
      <AlertDialog.Trigger asChild disabled={disabled}>
        {trigger}
      </AlertDialog.Trigger>
      <ConfirmContent {...confirm} />
    </AlertDialog.Root>
  );
}

/**
 * The same confirmation, opened from something that is not a trigger.
 *
 * A menu item cannot be one: it unmounts as the menu closes, taking the dialog
 * with it. So the caller keeps the open state and the dialog lives outside the
 * menu entirely.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  ...confirm
}: ConfirmProps & { open: boolean; onOpenChange: (open: boolean) => void }) {
  return (
    <AlertDialog.Root open={open} onOpenChange={onOpenChange}>
      <ConfirmContent {...confirm} />
    </AlertDialog.Root>
  );
}

/**
 * A plain modal, for a task you chose to begin.
 *
 * Distinct from ConfirmButton: that one interrupts to ask about something you
 * already started, this one holds a form.
 */
export function Modal({
  open,
  onOpenChange,
  title,
  description,
  wide = false,
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  wide?: boolean;
  children: ReactNode;
}) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content
          className={`dialog${wide ? ' dialog-wide' : ''}`}
          // Radix warns when a dialog has no description. Most of these forms
          // are their own explanation, so opt out rather than write a
          // paragraph of preamble for each one.
          {...(description === undefined ? { 'aria-describedby': undefined } : {})}
        >
          <div className="dialog-head">
            <Dialog.Title className="dialog-title">{title}</Dialog.Title>
            <Dialog.Close asChild>
              <button className="btn btn-quiet btn-sm btn-icon" aria-label="Close">
                <X size={15} />
              </button>
            </Dialog.Close>
          </div>
          {description !== undefined && (
            <Dialog.Description className="dialog-body">{description}</Dialog.Description>
          )}
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/* -------------------------------------------------------------------------- */
/* Time                                                                        */
/* -------------------------------------------------------------------------- */

const RELATIVE_STEPS: [limit: number, divisor: number, unit: Intl.RelativeTimeFormatUnit][] = [
  [60, 1, 'second'],
  [3600, 60, 'minute'],
  [86400, 3600, 'hour'],
  [2592000, 86400, 'day'],
  [31536000, 2592000, 'month'],
  [Infinity, 31536000, 'year'],
];

function relative(iso: string, now: number, style: 'long' | 'narrow' = 'long'): string {
  const delta = (new Date(iso).getTime() - now) / 1000;
  const magnitude = Math.abs(delta);
  const [, divisor, unit] = RELATIVE_STEPS.find(([limit]) => magnitude < limit)!;
  const formatter = new Intl.RelativeTimeFormat('en', { numeric: 'auto', style });
  return formatter.format(Math.round(delta / divisor), unit);
}

function absolute(iso: string, precise: boolean): string {
  return iso.replace('T', ' ').replace('Z', '').slice(0, precise ? 23 : 19);
}

/**
 * A timestamp. Absolute UTC by default, "3 hours ago" on hover.
 *
 * Absolute is the default on purpose: in the audit log this is evidence, and
 * someone reading it is often transcribing it into a finding. `relative` flips
 * the two, in the short form ("5h ago"), for glanceable metadata like "last
 * written". The relative form can
 * differ between server and client by a rounding step, so that one text node
 * opts out of the hydration check rather than render a placeholder first.
 */
export function Timestamp({
  iso,
  precise = false,
  display = 'absolute',
}: {
  iso: string;
  precise?: boolean;
  display?: 'absolute' | 'relative';
}) {
  const [now, setNow] = useState<number | null>(null);
  useEffect(() => setNow(Date.now()), [iso]);

  if (display === 'relative') {
    return (
      <Tip label={`${absolute(iso, precise)} UTC`}>
        <time dateTime={iso} suppressHydrationWarning>
          {relative(iso, now ?? Date.now(), 'narrow')}
        </time>
      </Tip>
    );
  }

  const body = (
    <time className="mono" dateTime={iso}>
      {absolute(iso, precise)}
    </time>
  );
  if (now === null) return body;
  return <Tip label={relative(iso, now)}>{body}</Tip>;
}

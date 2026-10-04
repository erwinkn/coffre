import { useEffect, useRef, useState, type ReactElement, type ReactNode } from 'react';
import { AlertDialog } from '@base-ui/react/alert-dialog';
import { Dialog } from '@base-ui/react/dialog';
import { Menu } from '@base-ui/react/menu';
import { Popover } from '@base-ui/react/popover';
import { Tooltip } from '@base-ui/react/tooltip';
import { AlertCircle, AlertTriangle, Check, Copy, Info, Loader, X } from './icons';

/* -------------------------------------------------------------------------- */
/* Tooltip                                                                     */
/* -------------------------------------------------------------------------- */

export function TooltipProvider({ children }: { children: ReactNode }) {
  // 400ms before the first tip; afterwards adjacent tips open instantly, which
  // makes a row of controls feel immediate without the delay losing its
  // purpose (preventing accidental activation on a passing cursor).
  return (
    <Tooltip.Provider delay={400} timeout={300}>
      {children}
    </Tooltip.Provider>
  );
}

export function Tip({
  label,
  side,
  children,
}: {
  label: ReactNode;
  side?: 'top' | 'right' | 'bottom' | 'left';
  children: ReactElement;
}) {
  return (
    <Tooltip.Root>
      <Tooltip.Trigger render={children} />
      <Tooltip.Portal>
        <Tooltip.Positioner
          className="tooltip-positioner"
          side={side}
          sideOffset={6}
          collisionPadding={8}
        >
          <Tooltip.Popup className="tooltip">{label}</Tooltip.Popup>
        </Tooltip.Positioner>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}

/**
 * The same bubble as Tip, for a note a touch screen must reach too.
 *
 * A tooltip opens on hover and focus only, so on a phone it never opens. This
 * one also opens on a tap, which means its trigger has to be a real button.
 * With a mouse, hover alone drives it: a click would otherwise close the note
 * the hover just opened.
 */
export function Toggletip({
  label,
  side,
  align,
  children,
}: {
  label: ReactNode;
  side?: 'top' | 'right' | 'bottom' | 'left';
  /** `end` for a trigger at the right edge, so the tip opens leftwards. */
  align?: 'start' | 'center' | 'end';
  children: ReactElement;
}) {
  const [open, setOpen] = useState(false);
  const mouse = useRef(false);
  const hover = (next: boolean) => (event: { pointerType: string }) => {
    if (event.pointerType === 'mouse') setOpen(next);
  };

  return (
    <Popover.Root
      open={open}
      onOpenChange={(next, { reason }) => {
        const clicked = reason === 'trigger-press' && mouse.current;
        mouse.current = false;
        if (!clicked) setOpen(next);
      }}
    >
      <Popover.Trigger
        render={children}
        onPointerEnter={hover(true)}
        onPointerLeave={hover(false)}
        onPointerDown={(event) => {
          mouse.current = event.pointerType === 'mouse';
        }}
      />
      <Popover.Portal>
        <Popover.Positioner
          className="tooltip-positioner"
          side={side}
          align={align}
          sideOffset={6}
          collisionPadding={16}
        >
          {/* Focus stays on the trigger, so there is nothing to return it to. */}
          <Popover.Popup className="tooltip" initialFocus={false} finalFocus={false}>
            {label}
          </Popover.Popup>
        </Popover.Positioner>
      </Popover.Portal>
    </Popover.Root>
  );
}

/* -------------------------------------------------------------------------- */
/* Menu                                                                        */
/* -------------------------------------------------------------------------- */

/**
 * A menu's floating panel, placed against its `Menu.Trigger`.
 *
 * The callers keep the rest of Base UI's menu parts: the trigger, the items
 * and their separators read better at the call site than behind props.
 */
export function MenuPopup({
  side,
  align,
  className,
  children,
}: {
  side?: 'top' | 'bottom';
  align: 'start' | 'end';
  className?: string;
  children: ReactNode;
}) {
  return (
    <Menu.Portal>
      <Menu.Positioner className="menu-positioner" side={side} align={align} sideOffset={6}>
        <Menu.Popup className={className === undefined ? 'menu' : `menu ${className}`}>
          {children}
        </Menu.Popup>
      </Menu.Positioner>
    </Menu.Portal>
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
/* Text                                                                        */
/* -------------------------------------------------------------------------- */

/**
 * An identifier that wraps after its underscores rather than mid-word.
 *
 * To the line breaker `DOCUSIGN_INTEGRATION_KEY` is one word, so a narrow
 * column cuts it wherever room runs out (`…_KE` / `Y`). A <wbr> after each
 * underscore offers the natural places instead. Copied text is unchanged, and
 * `overflow-wrap: anywhere` still catches a segment too long for any line.
 */
export function breakAfterUnderscores(text: string): ReactNode {
  return text
    .split('_')
    .flatMap((part, index) => (index === 0 ? [part] : ['_', <wbr key={index} />, part]));
}

/* -------------------------------------------------------------------------- */
/* Copy                                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Copy to clipboard with a settled confirmation.
 *
 * The glyph turns into a check, and screen readers hear "Copied", for 1.4s --
 * long enough to be noticed after the eye has moved on, short enough not to
 * look stuck.
 */
export function CopyButton({
  value,
  label = 'Copy',
  variant = 'icon',
}: {
  value: string;
  label?: string;
  /** `act` sits among a table row's actions; `icon` anywhere else. */
  variant?: 'icon' | 'act';
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

  return (
    <Tip label={copied ? 'Copied' : label}>
      <button
        type="button"
        className={variant === 'act' ? 'act act-icon' : 'btn btn-quiet btn-sm btn-icon'}
        aria-label={label}
        onClick={copy}
      >
        {copied ? <Check size={14} className="copied" /> : <Copy size={14} />}
        <span className="visually-hidden" aria-live="polite">
          {copied ? 'Copied' : ''}
        </span>
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
      <AlertDialog.Backdrop className="overlay" />
      <AlertDialog.Popup className="dialog dialog-confirm">
        <AlertDialog.Title className="dialog-title">{title}</AlertDialog.Title>
        <AlertDialog.Description className="dialog-body">{body}</AlertDialog.Description>
        <div className="dialog-actions">
          <AlertDialog.Close className="btn">Cancel</AlertDialog.Close>
          <AlertDialog.Close
            className={`btn ${destructive === false ? 'btn-primary' : 'btn-danger'}`}
            onClick={onConfirm}
          >
            {confirmLabel}
          </AlertDialog.Close>
        </div>
      </AlertDialog.Popup>
    </AlertDialog.Portal>
  );
}

export function ConfirmButton({
  trigger,
  disabled,
  ...confirm
}: ConfirmProps & { trigger: ReactElement; disabled?: boolean }) {
  return (
    <AlertDialog.Root>
      <AlertDialog.Trigger render={trigger} disabled={disabled} />
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
        <Dialog.Backdrop className="overlay" />
        <Dialog.Popup className={`dialog${wide ? ' dialog-wide' : ''}`}>
          <div className="dialog-head">
            <Dialog.Title className="dialog-title">{title}</Dialog.Title>
            <Dialog.Close className="btn btn-quiet btn-sm btn-icon" aria-label="Close">
              <X size={15} />
            </Dialog.Close>
          </div>
          {description !== undefined && (
            <Dialog.Description className="dialog-body">{description}</Dialog.Description>
          )}
          {children}
        </Dialog.Popup>
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

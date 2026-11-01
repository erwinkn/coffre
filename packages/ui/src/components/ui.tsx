import { cloneElement, useEffect, useRef, useState, useSyncExternalStore, type ButtonHTMLAttributes, type ReactElement, type ReactNode } from 'react';
import { AlertDialog } from '@base-ui/react/alert-dialog';
import { Dialog } from '@base-ui/react/dialog';
import { Menu } from '@base-ui/react/menu';
import { Popover } from '@base-ui/react/popover';
import { Tooltip } from '@base-ui/react/tooltip';
import { AlertCircle, AlertTriangle, Check, Copy, Info, Loader, X } from './icons';
import { createCopier, type Copier } from '../lib/copy-attempts';
import { usePreferences } from '../lib/preferences';

const hydrated = () => true;
const serverRender = () => false;
const unchanging = () => () => {};

/**
 * Whether the page is the browser's: false on the server and while
 * hydrating, which draws what the server drew, then true.
 *
 * What draws nothing while closed (a dialog, a menu's popup, a tooltip)
 * mounts only then, so the server skips its Root: a few in each row of an
 * environment's table, each costing more to render than the row. A dialog,
 * whose trigger is elsewhere, mounts with nothing else; a tooltip or a menu
 * draws its trigger anew, the same button, as it mounts.
 */
function useHydrated(): boolean {
  return useSyncExternalStore(unchanging, hydrated, serverRender);
}

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

/**
 * A tooltip on `children`, an element that takes a ref, as a button does.
 *
 * On the server and while hydrating it draws `children` alone: a closed
 * tooltip adds nothing to the page, and its Root and Trigger cost more to
 * render than the button they wrap, four times in each row of an
 * environment's table. Once the page is the browser's, the tooltip mounts
 * around it (`useHydrated`), its trigger drawn anew.
 */
export function Tip({
  label,
  side,
  children,
}: {
  label: ReactNode;
  side?: 'top' | 'right' | 'bottom' | 'left';
  children: ReactElement;
}) {
  if (!useHydrated()) return children;
  return <TipRoot label={label} side={side}>{children}</TipRoot>;
}

function TipRoot({
  label,
  side,
  children,
}: {
  label: ReactNode;
  side?: 'top' | 'right' | 'bottom' | 'left';
  children: ReactElement;
}) {
  const { portal } = usePreferences();
  return (
    <Tooltip.Root>
      <Tooltip.Trigger render={children} />
      <Tooltip.Portal container={portal}>
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
  const { portal } = usePreferences();
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
      <Popover.Portal container={portal}>
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
  const { portal } = usePreferences();
  return (
    <Menu.Portal container={portal}>
      <Menu.Positioner className="menu-positioner" side={side} align={align} sideOffset={6}>
        <Menu.Popup className={className === undefined ? 'menu' : `menu ${className}`}>
          {children}
        </Menu.Popup>
      </Menu.Positioner>
    </Menu.Portal>
  );
}

/**
 * A button that opens a menu: `trigger`, the button as drawn closed, and
 * `children`, the menu's items.
 *
 * On the server and while hydrating it draws the button alone, as a closed
 * menu's trigger reads to assistive technology, and mounts the menu once
 * the page is the browser's (`useHydrated`): a table draws one in each row,
 * and a menu's Root costs more to render than the row around it.
 */
export function MenuButton({
  trigger,
  disabled,
  align,
  children,
}: {
  trigger: ReactElement<ButtonHTMLAttributes<HTMLButtonElement>>;
  disabled?: boolean;
  align: 'start' | 'end';
  children: ReactNode;
}) {
  if (!useHydrated()) return cloneElement(trigger, { 'aria-haspopup': 'menu', 'aria-expanded': false, disabled });
  return (
    <Menu.Root>
      <Menu.Trigger render={trigger} disabled={disabled} />
      <MenuPopup align={align}>{children}</MenuPopup>
    </Menu.Root>
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
  warn: AlertTriangle,
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
 * look stuck. A copy that fails says so the same way, in red, rather than
 * leaving the click looking ignored.
 *
 * `value` is the text. A caller that must read it first (Copy on a hidden
 * secret) passes the `copier` it owns instead, and `onCopy`, called inside the
 * click so the clipboard write keeps its user gesture, which starts a copy on
 * that copier. Copies do not lock the button: a click while one is out starts
 * the next, and the latest one's ending is the one that shows. The copier's
 * owner outlives the button, so a remount keeps the feedback of a copy in flight.
 */
export function CopyButton({
  label = 'Copy',
  variant = 'icon',
  ...source
}: {
  label?: string;
  /** `act` sits among a table row's actions; `icon` anywhere else. */
  variant?: 'icon' | 'act';
} & ({ value: string; copier?: undefined; onCopy?: undefined } | { value?: undefined; copier: Copier; onCopy: () => void })) {
  const [own] = useState(() => createCopier());
  const copier = source.copier ?? own;
  const state = useSyncExternalStore(copier.subscribe, copier.feedback, copier.feedback);

  function copy() {
    if (source.copier !== undefined) source.onCopy();
    else void own.run(source.value);
  }

  const text = state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : label;
  return (
    <Tip label={text}>
      <button
        type="button"
        className={variant === 'act' ? 'act act-icon' : 'btn btn-quiet btn-sm btn-icon'}
        aria-label={label}
        aria-busy={state === 'pending' || undefined}
        onClick={copy}
      >
        {state === 'pending' ? (
          <Spinner size={13} />
        ) : state === 'copied' ? (
          <Check size={14} className="copied" />
        ) : state === 'failed' ? (
          <AlertCircle size={14} className="copy-failed" />
        ) : (
          <Copy size={14} />
        )}
        <span className="visually-hidden" aria-live="polite">
          {state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : ''}
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
  /** What the body's sentence cannot hold, such as a list: after it, outside its paragraph. */
  detail?: ReactNode;
  confirmLabel: string;
  destructive?: boolean;
  /** While something must happen first, which `detail` says. */
  confirmDisabled?: boolean;
  onConfirm: () => void;
};

function ConfirmContent({ title, body, detail, confirmLabel, destructive, confirmDisabled, onConfirm }: ConfirmProps) {
  const { portal } = usePreferences();
  return (
    <AlertDialog.Portal container={portal}>
      <AlertDialog.Backdrop className="overlay" />
      <AlertDialog.Popup className="dialog dialog-confirm">
        <AlertDialog.Title className="dialog-title">{title}</AlertDialog.Title>
        <AlertDialog.Description className="dialog-body">{body}</AlertDialog.Description>
        {detail}
        <div className="dialog-actions">
          <AlertDialog.Close className="btn">Cancel</AlertDialog.Close>
          <AlertDialog.Close
            className={`btn ${destructive === false ? 'btn-primary' : 'btn-danger'}`}
            onClick={onConfirm}
            disabled={confirmDisabled}
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
  // Drawn while hydrating only if open; after, always, so that it closes with its animation.
  if (!useHydrated() && !open) return null;
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
  const { portal } = usePreferences();
  if (!useHydrated() && !open) return null;
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal container={portal}>
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

/** One formatter per style, made once: making one costs more than a row of a page renders around it. */
const RELATIVE = {
  long: new Intl.RelativeTimeFormat('en', { numeric: 'auto', style: 'long' }),
  narrow: new Intl.RelativeTimeFormat('en', { numeric: 'auto', style: 'narrow' }),
};

function relative(iso: string, now: number, style: 'long' | 'narrow' = 'long'): string {
  const delta = (new Date(iso).getTime() - now) / 1000;
  const magnitude = Math.abs(delta);
  const [, divisor, unit] = RELATIVE_STEPS.find(([limit]) => magnitude < limit)!;
  return RELATIVE[style].format(Math.round(delta / divisor), unit);
}

/** A UTC time as the log writes it: `2026-10-17 08:45:13`, to the millisecond when `precise`. */
export function absolute(iso: string, precise: boolean): string {
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

/**
 * One icon vocabulary for the whole app.
 *
 * Every glyph is a 24-unit viewBox, 1.6 stroke, round caps and joins, drawn in
 * `currentColor`. Mixing icon families is the fastest way to make a product UI
 * feel assembled rather than designed, so there is exactly one source here and
 * no icon dependency.
 */

type IconProps = {
  size?: number;
  className?: string;
  style?: React.CSSProperties;
  /** Icons are decorative by default; pass a label when one carries meaning. */
  label?: string;
};

function Svg({
  size = 16,
  className,
  style,
  label,
  children,
}: IconProps & { children: React.ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      style={style}
      aria-hidden={label === undefined}
      aria-label={label}
      role={label === undefined ? undefined : 'img'}
    >
      {children}
    </svg>
  );
}

/**
 * The mark: a keyhole, drawn solid so it holds up white-on-ink inside the
 * brand tile at 16px. `MARK_SVG` below is the tile and keyhole together, for
 * the favicon.
 */
export function Mark(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="9.5" r="3.4" fill="currentColor" stroke="none" />
      <path d="M10.35 11.2h3.3l1.15 7.3h-5.6Z" fill="currentColor" stroke="none" />
    </Svg>
  );
}

export const MARK_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#171717"/><circle cx="16" cy="13" r="4.3" fill="#fafafa"/><path d="M13.9 15.2h4.2l1.45 9.2h-7.1Z" fill="#fafafa"/></svg>`;

export function Settings(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 2.75h0a1.6 1.6 0 0 1 1.6 1.6v.35a1.6 1.6 0 0 0 2.42 1.4l.3-.18a1.6 1.6 0 0 1 2.19.59l.4.7a1.6 1.6 0 0 1-.59 2.18l-.3.18a1.6 1.6 0 0 0 0 2.76l.3.18a1.6 1.6 0 0 1 .59 2.18l-.4.7a1.6 1.6 0 0 1-2.19.59l-.3-.18a1.6 1.6 0 0 0-2.42 1.4v.35a1.6 1.6 0 0 1-1.6 1.6h-.8a1.6 1.6 0 0 1-1.6-1.6v-.35a1.6 1.6 0 0 0-2.42-1.4l-.3.18a1.6 1.6 0 0 1-2.19-.59l-.4-.7a1.6 1.6 0 0 1 .59-2.18l.3-.18a1.6 1.6 0 0 0 0-2.76l-.3-.18a1.6 1.6 0 0 1-.59-2.18l.4-.7a1.6 1.6 0 0 1 2.19-.59l.3.18a1.6 1.6 0 0 0 2.42-1.4v-.35a1.6 1.6 0 0 1 1.6-1.6Z" />
    </Svg>
  );
}

export function Folder(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M3 7.5A1.5 1.5 0 0 1 4.5 6h4l2 2.5h7A1.5 1.5 0 0 1 19 10v7.5a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 3 17.5Z" />
    </Svg>
  );
}

export function Layers(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="m12 3 8 4.5-8 4.5-8-4.5Z" />
      <path d="m4 12 8 4.5 8-4.5" />
      <path d="m4 16.5 8 4.5 8-4.5" />
    </Svg>
  );
}

export function Key(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="7.5" cy="12" r="3.5" />
      <path d="M11 12h9.5M17 12v3M20 12v2.5" />
    </Svg>
  );
}

export function Users(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="9" cy="8" r="3.25" />
      <path d="M3.5 19.5a5.5 5.5 0 0 1 11 0" />
      <path d="M16 5.5a3.25 3.25 0 0 1 0 6.2M17.5 15a5.5 5.5 0 0 1 3 4.5" />
    </Svg>
  );
}

export function Ledger(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M5 4.5A1.5 1.5 0 0 1 6.5 3h11A1.5 1.5 0 0 1 19 4.5v15a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 19.5Z" />
      <path d="M8.5 8h7M8.5 12h7M8.5 16h4" />
    </Svg>
  );
}

export function Eye(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" />
      <circle cx="12" cy="12" r="3" />
    </Svg>
  );
}

export function EyeOff(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M9.9 5.8A9.6 9.6 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a17 17 0 0 1-2.7 3.5M6.2 7.5A16.6 16.6 0 0 0 2.5 12S6 18.5 12 18.5a9.3 9.3 0 0 0 3.6-.7" />
      <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" />
      <path d="m3.5 3.5 17 17" />
    </Svg>
  );
}

export function Copy(props: IconProps) {
  return (
    <Svg {...props}>
      <rect x="9" y="9" width="11" height="11" rx="1.75" />
      <path d="M5.5 15A1.5 1.5 0 0 1 4 13.5v-8A1.5 1.5 0 0 1 5.5 4h8A1.5 1.5 0 0 1 15 5.5" />
    </Svg>
  );
}

export function Check(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="m4.5 12.5 5 5 10-11" />
    </Svg>
  );
}

/** Audit "allow". Paired with the text label; never the only signal. */
export function CheckCircle(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="m8.5 12 2.5 2.5 4.5-5" />
    </Svg>
  );
}

/** Audit "deny". A slashed circle reads as refusal without relying on red. */
export function SlashCircle(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="m6.5 6.5 11 11" />
    </Svg>
  );
}

export function X(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="m6 6 12 12M18 6 6 18" />
    </Svg>
  );
}

export function AlertTriangle(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M10.7 4.2 2.9 17.5A1.5 1.5 0 0 0 4.2 19.8h15.6a1.5 1.5 0 0 0 1.3-2.3L13.3 4.2a1.5 1.5 0 0 0-2.6 0Z" />
      <path d="M12 9.5v4M12 16.8v.01" />
    </Svg>
  );
}

export function AlertCircle(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.75v4.75M12 16.2v.01" />
    </Svg>
  );
}

export function Info(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 11.25v5M12 7.9v.01" />
    </Svg>
  );
}

export function ChevronRight(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="m9 5.5 6.5 6.5L9 18.5" />
    </Svg>
  );
}

export function ChevronDown(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M5.5 9 12 15.5 18.5 9" />
    </Svg>
  );
}

export function Plus(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M12 5v14M5 12h14" />
    </Svg>
  );
}

export function Pencil(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M4 20h4l10.5-10.5a2.1 2.1 0 0 0-3-3L5 17v3Z" />
      <path d="m14.5 6 3 3" />
    </Svg>
  );
}

export function Archive(props: IconProps) {
  return (
    <Svg {...props}>
      <rect x="3" y="4.5" width="18" height="4" rx="1.25" />
      <path d="M4.75 8.5v9.75A1.75 1.75 0 0 0 6.5 20h11a1.75 1.75 0 0 0 1.75-1.75V8.5" />
      <path d="M10 12.5h4" />
    </Svg>
  );
}

export function History(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M3.5 12a8.5 8.5 0 1 0 2.6-6.1" />
      <path d="M3.5 4.5V10h5.5" />
      <path d="M12 8v4.3l3 1.7" />
    </Svg>
  );
}

export function Upload(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M12 15.5V4M8 7.5 12 3.5l4 4" />
      <path d="M4.5 14.5v4A1.5 1.5 0 0 0 6 20h12a1.5 1.5 0 0 0 1.5-1.5v-4" />
    </Svg>
  );
}

export function ShieldCheck(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M12 3.5 5 6v5.5c0 4.2 2.9 7.6 7 9 4.1-1.4 7-4.8 7-9V6Z" />
      <path d="m9 12 2.25 2.25L15.5 10" />
    </Svg>
  );
}

export function Search(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="11" cy="11" r="6.5" />
      <path d="m16 16 4.5 4.5" />
    </Svg>
  );
}

export function Sun(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2.5v2M12 19.5v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M2.5 12h2M19.5 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4" />
    </Svg>
  );
}

export function Moon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M20 13.5A8.5 8.5 0 0 1 10.5 4a8.5 8.5 0 1 0 9.5 9.5Z" />
    </Svg>
  );
}

export function Monitor(props: IconProps) {
  return (
    <Svg {...props}>
      <rect x="3" y="4.5" width="18" height="12" rx="1.75" />
      <path d="M8.5 20h7M12 16.5V20" />
    </Svg>
  );
}

export function Loader(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M12 3.5v3.75" opacity="1" />
      <path d="M12 16.75v3.75" opacity="0.35" />
      <path d="M20.5 12h-3.75" opacity="0.7" />
      <path d="M7.25 12H3.5" opacity="0.5" />
      <path d="m18.01 5.99-2.65 2.65" opacity="0.85" />
      <path d="m8.64 15.36-2.65 2.65" opacity="0.4" />
      <path d="m18.01 18.01-2.65-2.65" opacity="0.6" />
      <path d="M8.64 8.64 5.99 5.99" opacity="0.25" />
    </Svg>
  );
}

export function Link(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M10 13.5a3.5 3.5 0 0 0 5 0l3-3a3.54 3.54 0 0 0-5-5l-1.5 1.5" />
      <path d="M14 10.5a3.5 3.5 0 0 0-5 0l-3 3a3.54 3.54 0 0 0 5 5l1.5-1.5" />
    </Svg>
  );
}

export function MoreHorizontal(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="5.5" cy="12" r="1.1" fill="currentColor" />
      <circle cx="12" cy="12" r="1.1" fill="currentColor" />
      <circle cx="18.5" cy="12" r="1.1" fill="currentColor" />
    </Svg>
  );
}

export function RotateBack(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M3.5 12a8.5 8.5 0 1 0 2.6-6.1" />
      <path d="M3.5 4.5V10h5.5" />
    </Svg>
  );
}

export function Inbox(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M3.5 13.5h4l1.5 2.5h6l1.5-2.5h4" />
      <path d="M5.6 5.2 3.5 13.5v4A1.5 1.5 0 0 0 5 19h14a1.5 1.5 0 0 0 1.5-1.5v-4l-2.1-8.3A1.5 1.5 0 0 0 16.9 4H7.1a1.5 1.5 0 0 0-1.5 1.2Z" />
    </Svg>
  );
}

export function Menu(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M4 7h16M4 12h16M4 17h10" />
    </Svg>
  );
}

export function ArrowRight(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M4.5 12h15M14 6.5l5.5 5.5-5.5 5.5" />
    </Svg>
  );
}

export function ChevronsUpDown(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="m7.5 9.5 4.5-4.5 4.5 4.5M7.5 14.5l4.5 4.5 4.5-4.5" />
    </Svg>
  );
}

export function Hash(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M9.5 3.5 7.5 20.5M16.5 3.5l-2 17M4.5 8.5h16M3.5 15.5h16" />
    </Svg>
  );
}

export function Clock(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3 2" />
    </Svg>
  );
}

export function User(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="8" r="3.5" />
      <path d="M5 20a7 7 0 0 1 14 0" />
    </Svg>
  );
}

export function Lock(props: IconProps) {
  return (
    <Svg {...props}>
      <rect x="4.5" y="10.5" width="15" height="10" rx="2" />
      <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
    </Svg>
  );
}

export function Terminal(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="m5 7.5 4.5 4.5L5 16.5M12 17h7" />
    </Svg>
  );
}

export function Activity(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M3.5 12h4l2.5-6.5 4 13 2.5-6.5h4" />
    </Svg>
  );
}

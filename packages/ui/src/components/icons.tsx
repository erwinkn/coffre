import type { LucideIcon } from 'lucide-react';
import {
  Activity as ActivityGlyph,
  ArrowRight as ArrowRightGlyph,
  Archive as ArchiveGlyph,
  Ban,
  Check as CheckGlyph,
  ChevronDown as ChevronDownGlyph,
  ChevronRight as ChevronRightGlyph,
  ChevronsUpDown as ChevronsUpDownGlyph,
  CircleAlert,
  CircleCheck,
  Clock as ClockGlyph,
  Cloud as CloudGlyph,
  Copy as CopyGlyph,
  Ellipsis,
  Eye as EyeGlyph,
  EyeOff as EyeOffGlyph,
  Folder as FolderGlyph,
  Hash as HashGlyph,
  History as HistoryGlyph,
  Inbox as InboxGlyph,
  Info as InfoGlyph,
  KeyRound,
  Layers as LayersGlyph,
  Link as LinkGlyph,
  LoaderCircle,
  Lock as LockGlyph,
  LogOut,
  Menu as MenuGlyph,
  Monitor as MonitorGlyph,
  Moon as MoonGlyph,
  PanelLeft as PanelLeftGlyph,
  Pause as PauseGlyph,
  Pencil as PencilGlyph,
  Play as PlayGlyph,
  Plus as PlusGlyph,
  RefreshCw,
  RotateCcw,
  ScrollText,
  Search as SearchGlyph,
  Settings as SettingsGlyph,
  ShieldCheck as ShieldCheckGlyph,
  Sun as SunGlyph,
  Terminal as TerminalGlyph,
  TrainFront,
  TriangleAlert,
  Upload as UploadGlyph,
  User as UserGlyph,
  UserRoundCog,
  Users as UsersGlyph,
  X as XGlyph,
} from 'lucide-react';

/**
 * One icon vocabulary for the whole app: Lucide, at one stroke weight.
 *
 * Mixing icon families is the fastest way to make a product UI feel assembled
 * rather than designed, so every glyph comes through here and call sites never
 * import Lucide themselves: changing one is a line in this file. The
 * exceptions are marks that are not ours to redraw: coffre's keyhole and the
 * sign-in providers' logos.
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

/**
 * Lucide draws on a 24-unit grid with a 2-unit stroke. At the 14-16px these
 * are shown, 1.75 sits closer to Inter's weight beside them.
 */
const STROKE = 1.75;

function lucide(Glyph: LucideIcon) {
  // Lucide hides a glyph from assistive technology unless it is labelled.
  return function Icon({ size = 16, className, style, label }: IconProps) {
    return (
      <Glyph
        size={size}
        strokeWidth={STROKE}
        className={className}
        style={style}
        {...(label === undefined ? {} : { 'aria-label': label, role: 'img' })}
      />
    );
  };
}

// Places
export const Folder = lucide(FolderGlyph);
export const Layers = lucide(LayersGlyph);
export const Users = lucide(UsersGlyph);
export const User = lucide(UserGlyph);
/** Your own settings, so they never share the workspace's gear. */
export const UserCog = lucide(UserRoundCog);
export const Key = lucide(KeyRound);
export const Ledger = lucide(ScrollText);
export const Settings = lucide(SettingsGlyph);

// Secrets
export const Eye = lucide(EyeGlyph);
export const EyeOff = lucide(EyeOffGlyph);
export const Copy = lucide(CopyGlyph);
export const Pencil = lucide(PencilGlyph);
export const Archive = lucide(ArchiveGlyph);
export const History = lucide(HistoryGlyph);
export const RotateBack = lucide(RotateCcw);
export const Upload = lucide(UploadGlyph);
export const Sync = lucide(RefreshCw);
export const Pause = lucide(PauseGlyph);
export const Play = lucide(PlayGlyph);
export const Lock = lucide(LockGlyph);
export const Terminal = lucide(TerminalGlyph);
export const Hash = lucide(HashGlyph);
export const Clock = lucide(ClockGlyph);

// Outcomes
export const Check = lucide(CheckGlyph);
export const CheckCircle = lucide(CircleCheck);
export const SlashCircle = lucide(Ban);
export const ShieldCheck = lucide(ShieldCheckGlyph);
export const AlertTriangle = lucide(TriangleAlert);
export const AlertCircle = lucide(CircleAlert);
export const Info = lucide(InfoGlyph);
export const Activity = lucide(ActivityGlyph);
export const Inbox = lucide(InboxGlyph);
export const Loader = lucide(LoaderCircle);

// Controls
export const X = lucide(XGlyph);
export const Plus = lucide(PlusGlyph);
export const Search = lucide(SearchGlyph);
export const Menu = lucide(MenuGlyph);
export const PanelLeft = lucide(PanelLeftGlyph);
export const MoreHorizontal = lucide(Ellipsis);
export const ChevronRight = lucide(ChevronRightGlyph);
export const ChevronDown = lucide(ChevronDownGlyph);
export const ChevronsUpDown = lucide(ChevronsUpDownGlyph);
export const ArrowRight = lucide(ArrowRightGlyph);
export const Link = lucide(LinkGlyph);
export const SignOut = lucide(LogOut);

// Theme
export const Sun = lucide(SunGlyph);
export const Moon = lucide(MoonGlyph);
export const Monitor = lucide(MonitorGlyph);

/**
 * GitHub's mark, drawn as GitHub publishes it: a filled shape on its own
 * 16-unit grid, since a brand is not ours to redraw in the stroke style.
 */
export function GitHub({ size = 16, className, style }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="currentColor"
      className={className}
      style={style}
      aria-hidden
    >
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
    </svg>
  );
}

/** Google's "G", in its four colours, as Google's sign-in guidelines require. */
export function Google({ size = 16, className, style }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" className={className} style={style} aria-hidden>
      <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" />
      <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" />
      <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" />
      <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" />
    </svg>
  );
}

/** Microsoft's four squares. */
export function Microsoft({ size = 16, className, style }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 21 21" className={className} style={style} aria-hidden>
      <rect x="0" y="0" width="10" height="10" fill="#F25022" />
      <rect x="11" y="0" width="10" height="10" fill="#7FBA00" />
      <rect x="0" y="11" width="10" height="10" fill="#00A4EF" />
      <rect x="11" y="11" width="10" height="10" fill="#FFB900" />
    </svg>
  );
}

/** Vercel's triangle. */
export function Vercel({ size = 16, className, style }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" className={className} style={style} aria-hidden>
      <path d="M12 2.5 23 21.5H1Z" />
    </svg>
  );
}

// Railway and Cloudflare marks are detailed enough that a redraw would be a
// guess; a plain glyph stands in for them.
const Cloud = lucide(CloudGlyph);
const Train = lucide(TrainFront);

/** The mark beside a sync provider; any other brand gets the sync glyph. */
export function SyncMark({ brand, size = 16 }: { brand: string; size?: number }) {
  switch (brand) {
    case 'github':
      return <GitHub size={size} />;
    case 'vercel':
      return <Vercel size={size} />;
    case 'railway':
      return <Train size={size} />;
    case 'cloudflare':
      return <Cloud size={size} />;
    default:
      return <Sync size={size} />;
  }
}

/** The mark on a provider's button; any other OpenID Connect issuer gets a key. */
export function ProviderMark({ brand, size = 16 }: { brand: string; size?: number }) {
  switch (brand) {
    case 'github':
      return <GitHub size={size} />;
    case 'google':
      return <Google size={size} />;
    case 'microsoft':
      return <Microsoft size={size} />;
    default:
      return <Key size={size} />;
  }
}

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
  Menu as MenuGlyph,
  Monitor as MonitorGlyph,
  Moon as MoonGlyph,
  Pencil as PencilGlyph,
  Plus as PlusGlyph,
  RotateCcw,
  ScrollText,
  Search as SearchGlyph,
  Settings as SettingsGlyph,
  ShieldCheck as ShieldCheckGlyph,
  Sun as SunGlyph,
  Terminal as TerminalGlyph,
  TriangleAlert,
  Upload as UploadGlyph,
  User as UserGlyph,
  Users as UsersGlyph,
  X as XGlyph,
} from 'lucide-react';

/**
 * One icon vocabulary for the whole app: Lucide, at one stroke weight.
 *
 * Mixing icon families is the fastest way to make a product UI feel assembled
 * rather than designed, so every glyph comes through here and call sites never
 * import Lucide themselves: changing one is a line in this file. The two
 * exceptions are marks that are not ours to redraw, coffre's keyhole and
 * GitHub's logo.
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
export const MoreHorizontal = lucide(Ellipsis);
export const ChevronRight = lucide(ChevronRightGlyph);
export const ChevronDown = lucide(ChevronDownGlyph);
export const ChevronsUpDown = lucide(ChevronsUpDownGlyph);
export const ArrowRight = lucide(ArrowRightGlyph);
export const Link = lucide(LinkGlyph);

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

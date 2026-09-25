const HUES = ['blue', 'green', 'amber', 'violet'] as const;

/** The same name always lands on the same tint, on every screen (FNV-1a). */
export function tileHue(name: string): (typeof HUES)[number] {
  let hash = 0x811c9dc5;
  for (const char of name) hash = Math.imul(hash ^ char.charCodeAt(0), 0x01000193) >>> 0;
  return HUES[hash % HUES.length];
}

/**
 * A letter on a tint, standing in for a project wherever its name appears.
 *
 * It is a recognition aid, not information: the name is always beside it, so
 * the tile is hidden from assistive technology.
 */
export function Tile({ name, size = 'sm' }: { name: string; size?: 'sm' | 'lg' }) {
  return (
    <span className={`tile tile-${tileHue(name)}${size === 'lg' ? ' tile-lg' : ''}`} aria-hidden>
      {name.slice(0, 1)}
    </span>
  );
}

/**
 * coffre's mark: a keyhole cut from a disc, which leaves a lowercase c, its
 * slot tilted up 14°. Drawn on a 32-unit grid, where 2 units are a pixel at
 * 16px.
 *
 * Everything that draws it reads this file: `Mark` in the app, the favicon,
 * and `scripts/icons.ts`, which renders the PNGs and the README's mark from
 * it. The colours stand in until the brand has its own: change them here,
 * then run `pnpm --filter @coffre/ui icons`.
 */

/** 64px and up. */
export const MARK_PATH = 'M24.17 12.23A9 9 0 1 0 24.93 14.91L18.39 16.27A3.6 3.6 0 1 1 17.84 14.07Z';

/** 48px and below: a larger disc, the hole on the pixel grid, a thicker slot, so both stay open at 16px. */
export const MARK_PATH_SMALL = 'M25.77 10.94A11 11 0 1 0 26.95 14.9L17.92 16.81A4 4 0 1 1 17.08 13.45Z';

/** The tile behind the mark wherever it stands alone: the favicon, app icons, the README. */
export const TILE = '#000';

/** The mark on its tile. */
export const INK = '#fff';

/** The tile's corner radius, on the 32-unit grid. */
export const TILE_RADIUS = 7;

export function markPath(size: number): string {
  return size <= 48 ? MARK_PATH_SMALL : MARK_PATH;
}

/**
 * The mark on its tile, as an SVG document, drawn for `size` pixels.
 * `square` leaves the corners for the platform to round (iOS, GitHub);
 * `adaptive` swaps the colours in a dark browser, for the favicon.
 */
export function markSvg(size: number, { square = false, adaptive = false } = {}): string {
  const dark = adaptive ? `<style>@media (prefers-color-scheme:dark){rect{fill:${INK}}path{fill:${TILE}}}</style>` : '';
  const radius = square ? '' : ` rx="${TILE_RADIUS}"`;
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">${dark}` +
    `<rect width="32" height="32"${radius} fill="${TILE}"/>` +
    `<path d="${markPath(size)}" fill="${INK}"/></svg>`
  );
}

/**
 * Writes the mark's files from `src/components/mark.ts`:
 *
 *   src/assets/          what the app links: the iOS icon
 *   docs/brand/          the README's mark, the SVG favicon on its own, and
 *                        16 and 48px PNGs
 *   ../cli/assets/       the 512px logo for the GitHub App setup makes,
 *                        which the CLI ships and names
 *
 *   node scripts/icons.ts
 *
 * It rasterizes the paths itself, antialiased like a browser (16 rows of
 * coverage per pixel, exact across), so it needs nothing but Node.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { crc32, deflateSync } from 'node:zlib';

import { INK, markPath, markSvg, TILE, TILE_RADIUS } from '../src/components/mark.ts';

const assets = new URL('../src/assets/', import.meta.url);
const brand = new URL('../../../docs/brand/', import.meta.url);
const cli = new URL('../../cli/assets/', import.meta.url);

/** Square: GitHub and iOS round the corners themselves. */
const FILES: { dir: URL; name: string; size: number; square?: boolean }[] = [
  { dir: assets, name: 'apple-touch-icon.png', size: 180, square: true },
  { dir: brand, name: 'favicon-16.png', size: 16 },
  { dir: brand, name: 'favicon-48.png', size: 48 },
  { dir: cli, name: 'github-app-logo.png', size: 512, square: true },
];

for (const dir of [assets, brand, cli]) mkdirSync(dir, { recursive: true });
writeFileSync(new URL('mark.svg', brand), markSvg(64));
writeFileSync(new URL('favicon.svg', brand), markSvg(16, { adaptive: true }));
for (const { dir, name, size, square = false } of FILES) {
  const tile = square ? 'M0 0H32V32H0Z' : roundedSquare(TILE_RADIUS);
  writeFileSync(new URL(name, dir), png(size, coverage(tile, size), coverage(markPath(size), size)));
}

function roundedSquare(r: number): string {
  const e = 32 - r;
  return `M${r} 0H${e}A${r} ${r} 0 0 1 32 ${r}V${e}A${r} ${r} 0 0 1 ${e} 32H${r}A${r} ${r} 0 0 1 0 ${e}V${r}A${r} ${r} 0 0 1 ${r} 0Z`;
}

type Point = [number, number];

/** How much of each pixel the path covers, from 0 to 1, filled even-odd. */
function coverage(path: string, size: number): Float64Array {
  const scale = size / 32;
  const edges: [Point, Point][] = [];
  for (const ring of outline(path)) {
    const points = ring.map(([x, y]): Point => [x * scale, y * scale]);
    points.forEach((point, i) => edges.push([point, points[(i + 1) % points.length]!]));
  }
  const ROWS = 16;
  const cover = new Float64Array(size * size);
  for (let row = 0; row < size * ROWS; row++) {
    const y = (row + 0.5) / ROWS;
    const xs = edges
      .filter(([[, y0], [, y1]]) => (y0 <= y) !== (y1 <= y))
      .map(([[x0, y0], [x1, y1]]) => x0 + ((y - y0) / (y1 - y0)) * (x1 - x0))
      .sort((a, b) => a - b);
    const line = Math.floor(row / ROWS) * size;
    for (let i = 0; i + 1 < xs.length; i += 2) {
      const [from, to] = [Math.max(0, xs[i]!), Math.min(size, xs[i + 1]!)];
      for (let x = Math.floor(from); x < to; x++) {
        cover[line + x]! += (Math.min(to, x + 1) - Math.max(from, x)) / ROWS;
      }
    }
  }
  return cover;
}

/** A path of M, H, V, L, A (circular) and Z, as closed polygons. */
function outline(path: string): Point[][] {
  const tokens = path.match(/[A-Za-z]|-?[\d.]+/g)!;
  const rings: Point[][] = [];
  let ring: Point[] = [];
  let at: Point = [0, 0];
  const num = () => Number(tokens.shift());
  while (tokens.length > 0) {
    const command = tokens.shift()!;
    if (command === 'M') ring = [(at = [num(), num()])];
    else if (command === 'H') ring.push((at = [num(), at[1]]));
    else if (command === 'V') ring.push((at = [at[0], num()]));
    else if (command === 'L') ring.push((at = [num(), num()]));
    else if (command === 'A') {
      const [r, , , large, sweep, x, y] = [num(), num(), num(), num(), num(), num(), num()];
      ring.push(...arc(at, [x, y], r, large === 1, sweep === 1));
      at = [x, y];
    } else if (command === 'Z') rings.push(ring);
    else throw new Error(`icons: no ${command} in a mark's path`);
  }
  return rings;
}

/** A circular arc as points, its start excluded (SVG 1.1, F.6.5). */
function arc([x1, y1]: Point, [x2, y2]: Point, radius: number, large: boolean, sweep: boolean): Point[] {
  const [hx, hy] = [(x1 - x2) / 2, (y1 - y2) / 2];
  const half = hx * hx + hy * hy;
  const r = Math.max(radius, Math.sqrt(half));
  const reach = (large === sweep ? -1 : 1) * Math.sqrt(Math.max(0, (r * r - half) / half));
  const [cx, cy] = [reach * hy + (x1 + x2) / 2, -reach * hx + (y1 + y2) / 2];
  const start = Math.atan2(y1 - cy, x1 - cx);
  let turn = Math.atan2(y2 - cy, x2 - cx) - start;
  if (sweep && turn < 0) turn += 2 * Math.PI;
  if (!sweep && turn > 0) turn -= 2 * Math.PI;
  const steps = Math.ceil(Math.abs(turn) * 64);
  return Array.from({ length: steps }, (_, i): Point => {
    const angle = start + (turn * (i + 1)) / steps;
    return i + 1 === steps ? [x2, y2] : [cx + r * Math.cos(angle), cy + r * Math.sin(angle)];
  });
}

/** The mark over its tile, blended as browsers do, in sRGB. */
function png(size: number, tile: Float64Array, mark: Float64Array): Buffer {
  const [under, over] = [rgb(TILE), rgb(INK)];
  const rows = Buffer.alloc(size * (1 + size * 4));
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const [m, t] = [Math.min(1, mark[y * size + x]!), Math.min(1, tile[y * size + x]!)];
      const alpha = m + t * (1 - m);
      const at = y * (1 + size * 4) + 1 + x * 4;
      for (let c = 0; c < 3; c++) {
        rows[at + c] = alpha === 0 ? 0 : Math.round((over[c]! * m + under[c]! * t * (1 - m)) / alpha);
      }
      rows[at + 3] = Math.round(alpha * 255);
    }
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header.set([8, 6, 0, 0, 0], 8); // 8 bits, RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', deflateSync(rows, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

function chunk(type: string, data: Buffer): Buffer {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length, 0);
  head.write(type, 4, 'latin1');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), data])), 0);
  return Buffer.concat([head, data, crc]);
}

function rgb(hex: string): number[] {
  const digits = hex.length === 4 ? [...hex.slice(1)].map((d) => d + d) : hex.slice(1).match(/../g)!;
  return digits.map((pair) => parseInt(pair, 16));
}

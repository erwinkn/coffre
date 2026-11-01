import type { IconNode } from 'lucide';

/**
 * What draws a Lucide glyph inside its `<svg>`, as markup: its strokes, in a
 * group that carries the stroke's attributes, which draw exactly as they
 * would on the `<svg>` itself, since no style sets an icon's fill or stroke.
 * `Icon` hands it to React whole, one write for the server rather than an
 * element and an attribute at a time.
 */
export function glyphMarkup(glyph: IconNode, strokeWidth: number): string {
  const strokes = glyph
    .map(([tag, attributes]) => `<${tag}${Object.entries(attributes).map(([name, value]) => ` ${name}="${escapeAttribute(String(value))}"`).join('')}/>`)
    .join('');
  return `<g fill="none" stroke="currentColor" stroke-width="${strokeWidth}" stroke-linecap="round" stroke-linejoin="round">${strokes}</g>`;
}

function escapeAttribute(value: string): string {
  return value.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;');
}

#!/usr/bin/env node
// Verify every text/background pair in the web UI palette against WCAG 2.1.
//
// The palette is authored in OKLCH, which is perceptually uniform and therefore
// pleasant to build ramps in -- but perceptual lightness is NOT relative
// luminance, so an OKLCH ramp that looks evenly spaced can still fail contrast.
// This converts back to sRGB and checks the real ratio.
//
// Run: node scripts/check-contrast.mjs

// --- OKLCH -> sRGB ----------------------------------------------------------

function oklchToSrgb(L, C, hDeg) {
    const h = (hDeg * Math.PI) / 180;
    const a = C * Math.cos(h);
    const b = C * Math.sin(h);

    const l_ = L + 0.3963377774 * a + 0.2158037573 * b;
    const m_ = L - 0.1055613458 * a - 0.0638541728 * b;
    const s_ = L - 0.0894841775 * a - 1.291485548 * b;

    const l = l_ ** 3;
    const m = m_ ** 3;
    const s = s_ ** 3;

    return [
        +4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
        -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
        -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s,
    ];
}

/** WCAG relative luminance wants linear-light values, which is what we already have. */
function luminance(linear) {
    const [r, g, b] = linear.map((v) => Math.max(0, Math.min(1, v)));
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(fg, bg) {
    const a = luminance(oklchToSrgb(...fg));
    const b = luminance(oklchToSrgb(...bg));
    const [hi, lo] = a > b ? [a, b] : [b, a];
    return (hi + 0.05) / (lo + 0.05);
}

function hex(oklch) {
    const srgb = oklchToSrgb(...oklch);
    const enc = srgb.map((v) => {
        const c = Math.max(0, Math.min(1, v));
        const g = c <= 0.0031308 ? 12.92 * c : 1.055 * c ** (1 / 2.4) - 0.055;
        return Math.round(g * 255)
            .toString(16)
            .padStart(2, '0');
    });
    return `#${enc.join('')}`;
}

/** True when the colour falls outside the sRGB gamut and will be clipped. */
function outOfGamut(oklch) {
    return oklchToSrgb(...oklch).some((v) => v < -0.001 || v > 1.001);
}

// --- The palette ------------------------------------------------------------
// Keep in lockstep with apps/web/src/styles/globals.css, where each token is
// one light-dark() declaration. Surfaces and text are true neutrals; hue is
// kept for meaning: blue for links, focus and edits not yet saved, amber for a
// revealed value, red for archive and denial, green for allow, violet for
// owners.

const LIGHT = {
    canvas: [0.985, 0, 0],
    panel: [1, 0, 0],
    subtle: [0.97, 0, 0],
    border: [0.922, 0, 0],
    edge: [0.64, 0, 0],
    ink: [0.205, 0, 0],
    ink2: [0.44, 0, 0],
    ink3: [0.52, 0, 0],
    accent: [0.52, 0.19, 262],
    accentWash: [0.955, 0.02, 258],
    green: [0.5, 0.13, 152],
    greenWash: [0.955, 0.03, 158],
    red: [0.52, 0.19, 27],
    redWash: [0.955, 0.02, 22],
    amber: [0.5, 0.11, 62],
    amberWash: [0.955, 0.045, 88],
    violet: [0.5, 0.19, 296],
    violetWash: [0.955, 0.022, 300],
    float: [0.235, 0, 0],
    onFloat: [0.985, 0, 0],
    onFloat2: [0.8, 0, 0],
};

const DARK = {
    canvas: [0.155, 0, 0],
    panel: [0.19, 0, 0],
    subtle: [0.225, 0, 0],
    border: [0.29, 0, 0],
    edge: [0.52, 0, 0],
    ink: [0.95, 0, 0],
    ink2: [0.79, 0, 0],
    ink3: [0.7, 0, 0],
    accent: [0.74, 0.13, 255],
    accentWash: [0.28, 0.06, 262],
    green: [0.77, 0.14, 155],
    greenWash: [0.27, 0.045, 158],
    red: [0.74, 0.15, 24],
    redWash: [0.28, 0.06, 24],
    amber: [0.82, 0.12, 82],
    amberWash: [0.29, 0.05, 78],
    violet: [0.76, 0.12, 300],
    violetWash: [0.28, 0.06, 300],
    float: [0.3, 0, 0],
    onFloat: [0.97, 0, 0],
    onFloat2: [0.8, 0, 0],
};

// [foreground, background, minimum ratio, label]
// 4.5 is the AA floor for body text; 3.0 covers UI boundaries and focus rings
// (WCAG 1.4.11). Every pair here is one the stylesheet actually draws.
const PAIRS = [
    ['ink', 'canvas', 4.5, 'body text on the page'],
    ['ink', 'panel', 4.5, 'text in cards, tables, inputs, menus'],
    ['ink', 'subtle', 4.5, 'text in table heads and hovered rows'],
    ['ink2', 'canvas', 4.5, 'secondary text on the page'],
    ['ink2', 'panel', 4.5, 'secondary text in cards'],
    ['ink2', 'subtle', 4.5, 'column heads'],
    ['ink3', 'canvas', 4.5, 'descriptions and meta on the page'],
    ['ink3', 'panel', 4.5, 'placeholders, hints, row numbers'],
    ['ink3', 'subtle', 4.5, 'meta on a hovered row, neutral tag'],
    ['ink3', 'amberWash', 4.5, 'meta on a revealed row'],
    ['ink3', 'accentWash', 4.5, 'meta on an edited row'],
    ['ink3', 'redWash', 4.5, 'meta on a denied or leaving row'],
    ['panel', 'ink', 4.5, 'primary button, tooltip'],
    ['panel', 'red', 4.5, 'destructive button'],
    ['onFloat', 'float', 4.5, 'save bar and toasts'],
    ['onFloat2', 'float', 4.5, 'save bar summary, toast description'],
    ['accent', 'canvas', 4.5, 'links on the page'],
    ['accent', 'panel', 4.5, 'links and row actions in cards'],
    ['accent', 'subtle', 4.5, 'row action on a hovered row'],
    ['accent', 'accentWash', 4.5, 'blue tag, edited row action'],
    ['accent', 'amberWash', 4.5, 'row action on a revealed row'],
    ['green', 'panel', 4.5, 'allow in the audit log'],
    ['green', 'greenWash', 4.5, 'green tag'],
    ['red', 'panel', 4.5, 'revoke, archive, deny'],
    ['red', 'redWash', 4.5, 'red tag, deny on a denied row'],
    ['amber', 'amberWash', 4.5, 'reveal countdown, amber tag'],
    ['violet', 'violetWash', 4.5, 'owner tag'],
    ['ink', 'amberWash', 4.5, 'the revealed value itself'],
    ['ink', 'accentWash', 4.5, 'text on an edited row'],
    ['ink', 'redWash', 4.5, 'text on a denied row'],
    ['edge', 'panel', 3.0, 'input and checkbox boundary'],
    ['edge', 'canvas', 3.0, 'input boundary on the page'],
    ['accent', 'panel', 3.0, 'focus ring'],
    ['accent', 'canvas', 3.0, 'focus ring on the page'],
];

let failures = 0;
let checks = 0;

for (const [themeName, theme] of [
    ['light', LIGHT],
    ['dark', DARK],
]) {
    console.log(`\n${themeName}`);

    for (const [name, value] of Object.entries(theme)) {
        if (outOfGamut(value)) {
            console.error(`  GAMUT  ${name} oklch(${value.join(' ')}) clips in sRGB`);
            failures += 1;
        }
    }

    for (const [fg, bg, min, label] of PAIRS) {
        checks += 1;
        const ratio = contrast(theme[fg], theme[bg]);
        const ok = ratio >= min;
        if (!ok) failures += 1;
        const mark = ok ? 'ok  ' : 'FAIL';
        console.log(
            `  ${mark} ${ratio.toFixed(2).padStart(5)}:1 (min ${min.toFixed(1)})  ` +
                `${fg} on ${bg}  ${hex(theme[fg])}/${hex(theme[bg])}  -- ${label}`,
        );
    }
}

console.log('');
if (failures > 0) {
    console.error(`Contrast check FAILED: ${failures} of ${checks} pairs below target.`);
    process.exit(1);
}
console.log(`Contrast check passed (${checks} pairs, both themes).`);

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
// one light-dark() declaration. Paper and ink are warm neutrals (hue ~85);
// colour is reserved for meaning: blue ink for pending edits and links, ochre
// for a revealed value, red for archive and denial, green for allow.

const LIGHT = {
    paper: [0.965, 0.01, 87],
    sheet: [0.988, 0.005, 95],
    wash: [0.937, 0.014, 89],
    rule: [0.865, 0.022, 86],
    ruleSoft: [0.911, 0.019, 86],
    edge: [0.622, 0.025, 85],
    ink: [0.223, 0.008, 85],
    ink2: [0.392, 0.016, 82],
    ink3: [0.496, 0.021, 81],
    onInk2: [0.83, 0.014, 85],
    accent: [0.393, 0.106, 263],
    accentWash: [0.93, 0.013, 262],
    red: [0.482, 0.149, 32],
    redWash: [0.925, 0.026, 42],
    green: [0.467, 0.102, 148],
    greenWash: [0.931, 0.024, 133],
    ochre: [0.467, 0.095, 72],
    ochreWash: [0.926, 0.053, 91],
};

const DARK = {
    paper: [0.188, 0.009, 85],
    sheet: [0.224, 0.01, 81],
    wash: [0.241, 0.012, 85],
    rule: [0.331, 0.017, 82],
    ruleSoft: [0.271, 0.012, 78],
    edge: [0.538, 0.025, 83],
    ink: [0.935, 0.018, 86],
    ink2: [0.797, 0.025, 86],
    ink3: [0.682, 0.025, 85],
    onInk2: [0.42, 0.016, 83],
    accent: [0.793, 0.072, 266],
    accentWash: [0.29, 0.031, 266],
    red: [0.745, 0.124, 34],
    redWash: [0.282, 0.041, 36],
    green: [0.806, 0.1, 149],
    greenWash: [0.272, 0.03, 146],
    ochre: [0.832, 0.113, 87],
    ochreWash: [0.303, 0.042, 86],
};

// [foreground, background, minimum ratio, label]
// 4.5 is the AA floor for body text; 3.0 covers UI boundaries and focus rings
// (WCAG 1.4.11). Every pair here is one the stylesheet actually draws.
const PAIRS = [
    ['ink', 'paper', 4.5, 'body text on the page'],
    ['ink', 'sheet', 4.5, 'text in inputs, menus and dialogs'],
    ['ink', 'wash', 4.5, 'text on a hovered row'],
    ['ink2', 'paper', 4.5, 'secondary text, nav items'],
    ['ink2', 'sheet', 4.5, 'dialog body text'],
    ['ink2', 'wash', 4.5, 'tag text'],
    ['ink3', 'paper', 4.5, 'column heads, eyebrows, meta'],
    ['ink3', 'sheet', 4.5, 'placeholders and hints in dialogs'],
    ['ink3', 'wash', 4.5, 'meta on a hovered row'],
    ['ink3', 'ochreWash', 4.5, 'meta on a revealed row'],
    ['ink3', 'redWash', 4.5, 'meta on a denied audit row'],
    ['ink3', 'accentWash', 4.5, 'meta on an edited row'],
    ['paper', 'ink', 4.5, 'primary buttons, save bar, toasts, tooltips'],
    ['paper', 'ink2', 4.5, 'primary button, hovered'],
    ['onInk2', 'ink', 4.5, 'save-bar summary, toast description'],
    ['paper', 'red', 4.5, 'destructive confirm button, error toast'],
    ['paper', 'accent', 4.5, 'hovered filter chip'],
    ['accent', 'paper', 4.5, 'links and row actions'],
    ['accent', 'sheet', 4.5, 'links in dialogs and menus'],
    ['accent', 'wash', 4.5, 'row action on a hovered row'],
    ['accent', 'accentWash', 4.5, 'edited tag, hovered row action, filter chip'],
    ['accent', 'ochreWash', 4.5, 'row actions on a revealed row'],
    ['red', 'paper', 4.5, 'revoke, archive, deny'],
    ['red', 'sheet', 4.5, 'destructive menu item'],
    ['red', 'redWash', 4.5, 'archive tag, deny on a denied row'],
    ['green', 'paper', 4.5, 'allow in the audit log'],
    ['green', 'greenWash', 4.5, 'create tag in the import plan'],
    ['ochre', 'ochreWash', 4.5, 'reveal countdown on a revealed row'],
    ['ink', 'ochreWash', 4.5, 'the revealed value itself'],
    ['ink', 'redWash', 4.5, 'text on a denied audit row'],
    ['ink', 'accentWash', 4.5, 'text on an edited row'],
    ['edge', 'sheet', 3.0, 'input boundary'],
    ['edge', 'paper', 3.0, 'input boundary on the page'],
    ['accent', 'sheet', 3.0, 'focus ring on an input'],
    ['accent', 'paper', 3.0, 'focus ring on the page'],
    ['ink', 'paper', 3.0, 'secondary button boundary'],
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

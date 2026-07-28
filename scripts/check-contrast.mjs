#!/usr/bin/env node
// Verify every text/background pair in the admin UI palette against WCAG 2.1.
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
// Keep in lockstep with apps/admin/app/globals.css. Hue 264 is the existing
// coffre accent (#6ea8fe); neutrals carry a trace of it rather than being dead
// grey, and nothing is tinted "warm by default".

const DARK = {
    bg: [0.168, 0.01, 264],
    // Sidebar and top bar. One step *away* from the canvas so chrome recedes
    // and cards rise; the second neutral layer product UI wants.
    panel: [0.142, 0.011, 264],
    surface: [0.212, 0.013, 264],
    surface2: [0.257, 0.016, 264],
    sunken: [0.139, 0.011, 264],
    border: [0.322, 0.019, 264],
    ink: [0.949, 0.005, 264],
    ink2: [0.792, 0.013, 264],
    ink3: [0.686, 0.017, 264],
    // Chroma on every accent is held just under the sRGB gamut boundary for its
    // own lightness -- see the GAMUT check below. Going higher does not produce
    // a more saturated colour, only a clipped one that shifts hue.
    accent: [0.744, 0.128, 264],
    allow: [0.796, 0.155, 152],
    deny: [0.735, 0.156, 25],
    secret: [0.845, 0.145, 85],
};

const LIGHT = {
    bg: [0.977, 0.003, 264],
    panel: [0.958, 0.005, 264],
    surface: [1.0, 0.0, 264],
    surface2: [0.963, 0.005, 264],
    sunken: [0.974, 0.005, 264],
    border: [0.886, 0.009, 264],
    ink: [0.235, 0.016, 264],
    ink2: [0.446, 0.019, 264],
    ink3: [0.532, 0.019, 264],
    accent: [0.523, 0.175, 264],
    allow: [0.481, 0.122, 152],
    deny: [0.523, 0.203, 25],
    secret: [0.475, 0.098, 70],
};

// [foreground, background, minimum ratio, label]
// 4.5 is the AA floor for body text; 3.0 covers large text and UI boundaries.
const PAIRS = (p) => [
    ['ink', 'bg', 4.5, 'body text on canvas'],
    ['ink', 'surface', 4.5, 'body text on card'],
    ['ink', 'surface2', 4.5, 'body text on hovered row'],
    ['ink', 'sunken', 4.5, 'input text'],
    ['ink2', 'bg', 4.5, 'secondary text on canvas'],
    ['ink2', 'surface', 4.5, 'secondary text on card'],
    ['ink2', 'surface2', 4.5, 'secondary text on hovered row'],
    // ink3 is the muted/label tier and the historical failure point: the old
    // --muted (#8b94a6) sat at 4.2:1 on the panel colour.
    ['ink3', 'bg', 4.5, 'muted label on canvas'],
    ['ink3', 'surface', 4.5, 'muted label on card'],
    ['ink3', 'surface2', 4.5, 'muted label on hovered row'],
    ['ink3', 'sunken', 4.5, 'placeholder text'],
    ['ink', 'panel', 4.5, 'active nav item'],
    ['ink2', 'panel', 4.5, 'nav item'],
    ['ink3', 'panel', 4.5, 'nav section label'],
    ['accent', 'panel', 4.5, 'link in sidebar'],
    ['accent', 'bg', 4.5, 'link on canvas'],
    ['accent', 'surface', 4.5, 'link on card'],
    ['accent', 'sunken', 3.0, 'focus ring on input'],
    ['allow', 'bg', 4.5, 'allow text on canvas'],
    ['allow', 'surface', 4.5, 'allow text on card'],
    ['deny', 'bg', 4.5, 'deny text on canvas'],
    ['deny', 'surface', 4.5, 'deny text on card'],
    ['secret', 'sunken', 4.5, 'revealed secret value'],
    ['border', 'surface', 1.4, 'card border against card'],
];

let failures = 0;
let checks = 0;

for (const [themeName, theme] of [
    ['dark', DARK],
    ['light', LIGHT],
]) {
    console.log(`\n${themeName}`);

    for (const [name, value] of Object.entries(theme)) {
        if (outOfGamut(value)) {
            console.error(`  GAMUT  ${name} oklch(${value.join(' ')}) clips in sRGB`);
            failures += 1;
        }
    }

    for (const [fg, bg, min, label] of PAIRS(theme)) {
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

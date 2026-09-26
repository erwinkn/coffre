import { escapeHtml } from './http.ts';
import { PERSONAS } from './people.ts';

const STYLE = `
  :root { color-scheme: light dark; --fg: #1c1c1e; --muted: #6b6b70; --line: #dcdce0;
    --bg: #fafafa; --card: #fff; --accent: #2f5bd3; --danger: #b3261e; }
  @media (prefers-color-scheme: dark) { :root { --fg: #ececee; --muted: #9a9aa2;
    --line: #34343a; --bg: #151517; --card: #1d1d20; --accent: #8aa8ff; --danger: #ff8a80; } }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg);
    color: var(--fg); font: 15px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
  main { width: min(440px, calc(100vw - 32px)); margin: 32px 0; }
  .eyebrow { margin: 0; color: var(--muted); font-size: 13px; }
  h1 { margin: 4px 0 6px; font-size: 20px; font-weight: 600; }
  p { margin: 0 0 16px; color: var(--muted); }
  code { font: 13px ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--fg); word-break: break-all; }
  ul { list-style: none; margin: 0 0 16px; padding: 0; border: 1px solid var(--line);
    border-radius: 8px; background: var(--card); overflow: hidden; }
  li + li { border-top: 1px solid var(--line); }
  button { font: inherit; cursor: pointer; }
  .persona { all: unset; box-sizing: border-box; display: grid; grid-template-columns: 1fr auto;
    width: 100%; padding: 10px 14px; cursor: pointer; }
  .persona:hover, .persona:focus-visible { background: color-mix(in srgb, var(--accent) 8%, transparent); }
  .persona:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
  .persona small { grid-column: 1; color: var(--muted); }
  .persona em { grid-row: 1 / span 2; grid-column: 2; align-self: center; font-style: normal;
    font-size: 12px; color: var(--muted); }
  .other { display: flex; gap: 8px; margin-bottom: 12px; }
  input { flex: 1; min-width: 0; font: inherit; padding: 7px 10px; color: var(--fg);
    background: var(--card); border: 1px solid var(--line); border-radius: 6px; }
  .primary { padding: 7px 14px; border: 0; border-radius: 6px; background: var(--accent); color: var(--bg); }
  .deny { padding: 0; border: 0; background: none; color: var(--muted); text-decoration: underline; }
  .error { color: var(--danger); }
`;

function layout(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>${STYLE}</style>
</head>
<body><main>
${body}
</main></body>
</html>
`;
}

function hiddenInputs(params: URLSearchParams): string {
  return [...params]
    .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`)
    .join('');
}

export function consentPage(opts: {
  label: string;
  action: string;
  clientId: string;
  redirectUri: string;
  scope: readonly string[];
  /** The original request parameters, re-validated when the form comes back. */
  carry: URLSearchParams;
  hint?: string;
  message?: string;
}): string {
  const carry = hiddenInputs(opts.carry);
  const personas = PERSONAS.map(
    (p) => `<li><button class="persona" name="email" value="${escapeHtml(p.email)}">
<span>${escapeHtml(p.name)}</span><small>${escapeHtml(p.email)}</small><em>${escapeHtml(p.note)}</em>
</button></li>`,
  ).join('\n');
  const scope = opts.scope.length > 0 ? opts.scope.join(' ') : '(none)';

  return layout(
    `Sign in to ${opts.clientId}`,
    `<p class="eyebrow">${escapeHtml(opts.label)}</p>
<h1>Sign in to <code>${escapeHtml(opts.clientId)}</code></h1>
<p>Returns to <code>${escapeHtml(opts.redirectUri)}</code><br>with scope <code>${escapeHtml(scope)}</code></p>
${opts.message ? `<p class="error">${escapeHtml(opts.message)}</p>` : ''}
<form method="post" action="${escapeHtml(opts.action)}">${carry}
<ul>
${personas}
</ul>
</form>
<form method="post" action="${escapeHtml(opts.action)}" class="other">${carry}
<input type="email" name="email" required placeholder="someone@example.com" aria-label="Another email" value="${escapeHtml(opts.hint ?? '')}">
<button class="primary">Continue</button>
</form>
<form method="post" action="${escapeHtml(opts.action)}">${carry}
<button class="deny" name="deny" value="1">Deny access</button>
</form>`,
  );
}

/** For requests that cannot safely be sent back to the client. */
export function errorPage(label: string, message: string): string {
  return layout(
    'Sign-in error',
    `<p class="eyebrow">${escapeHtml(label)}</p>
<h1>This sign-in request is invalid</h1>
<p class="error">${escapeHtml(message)}</p>
<p>The client was not redirected back, because it or its redirect URI could not be trusted.</p>`,
  );
}

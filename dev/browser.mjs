// Being a browser at a local stack: signing in through the dev IdP's
// stand-in GitHub, and calling the API as coffre's own pages do. The seed
// and the restore drill both act this way, so what they do is audited like
// anything a person does.

/** The cookie a redirect sets, not one it clears, as a request sends it back; null for none. */
function cookieOf(response) {
    const set = response.headers.getSetCookie().find((cookie) => !/=;|max-age=0/i.test(cookie));
    return response.status === 302 && set !== undefined ? set.split(';')[0] : null;
}

/** A browser at the coffre at `api`, signing in through the dev IdP at `idp`. */
export function browser(api, idp) {
    /**
     * Sign in as a browser would: leave for the stand-in GitHub, answer its
     * persona page with the email, and come back with a session cookie, or
     * null when coffre turns them away.
     */
    async function trySignIn(email) {
        const leave = await fetch(`${api}/auth/signin/github`, { redirect: 'manual' });
        const pending = cookieOf(leave);
        if (pending === null) throw new Error(`leaving for GitHub: expected a redirect with a cookie, got ${leave.status}`);
        const authorize = new URL(leave.headers.get('location'));
        if (authorize.origin !== new URL(idp).origin) throw new Error(`sign-in went to ${authorize.origin}, not the dev IdP`);
        const form = new URLSearchParams(authorize.searchParams);
        form.set('email', email);
        const approve = await fetch(authorize.origin + authorize.pathname, { method: 'POST', body: form, redirect: 'manual' });
        const back = await fetch(approve.headers.get('location') ?? `${api}/`, { headers: { cookie: pending }, redirect: 'manual' });
        return cookieOf(back);
    }

    async function signIn(email) {
        const session = await trySignIn(email);
        if (session === null) throw new Error(`signing in as ${email}: coffre turned them away`);
        return session;
    }

    /** A call as one of coffre's own pages makes it, with the session cookie: the response, whatever it says. */
    function send(session, method, path, body) {
        return fetch(`${api}${path}`, {
            method,
            headers: { cookie: session, origin: api, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
            body: body === undefined ? undefined : JSON.stringify(body),
            redirect: 'manual',
        });
    }

    /** `send`, which must succeed: its JSON. */
    async function call(session, method, path, body) {
        const response = await send(session, method, path, body);
        if (!response.ok) throw new Error(`${method} ${path} -> ${response.status} ${await response.text()}`);
        return response.status === 204 ? null : response.json();
    }

    return { trySignIn, signIn, send, call };
}

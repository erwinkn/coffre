// Being a browser at a local stack: signing in through the dev IdP's
// stand-in GitHub, with a passkey when coffre asks for one, and calling the
// API as coffre's own pages do. The seed and the restore drill both act this
// way, so what they do is audited like anything a person does.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import { SoftAuthenticator } from '@coffre/conformance/authenticator';

/** The cookie a redirect sets, not one it clears, as a request sends it back; null for none. */
function cookieOf(response) {
    const set = response.headers.getSetCookie().find((cookie) => !/=;|max-age=0/i.test(cookie));
    return response.status === 302 && set !== undefined ? set.split(';')[0] : null;
}

/** The cookies a response sets, not those it clears, as a request sends them back. */
function cookiesOf(response) {
    return response.headers.getSetCookie().filter((cookie) => !/=;|max-age=0/i.test(cookie)).map((cookie) => cookie.split(';')[0]);
}

/**
 * The software passkeys of the people this browser signs in, by email (docs/design/passkeys.md, section 7.1): kept in
 * `file` when given, so that another process signs them in again (the restore drill's two halves) and a browser's
 * virtual authenticator can take one (`dev/passkey.mjs`). Each with its counter, which every signature moves and the
 * file keeps, read again before each use: Chrome's virtual authenticator counts up whatever it is given, so a key it
 * also signs with goes on from Chrome's count, never back to an older one, which coffre refuses (section 7.3).
 * Throwaway keys, for a local stack only.
 */
function passkeyStore(file) {
    let saved = {};
    const read = () => {
        if (file !== undefined && existsSync(file)) saved = JSON.parse(readFileSync(file, 'utf8'));
        return saved;
    };
    return {
        async get(email) {
            const key = read()[email];
            return key === undefined ? null : SoftAuthenticator.restore(key);
        },
        async put(email, key) {
            read()[email] = await key.save();
            if (file === undefined) return;
            mkdirSync(dirname(file), { recursive: true });
            writeFileSync(file, `${JSON.stringify(saved, null, 2)}\n`, { mode: 0o600 });
        },
    };
}

/**
 * A browser at the coffre at `api`, signing in through the dev IdP at `idp`.
 *
 * Behind a tunnel, the stack names itself by its public URLs (`tunnel.api`,
 * `tunnel.idp`): the redirects point there, and the app checks the origin of a
 * call against its own. Those answer only a person's browser, so this one sends
 * everything to `api` and `idp` instead, saying it is at the public origin.
 */
export function browser(api, idp, tunnel = {}, { passkeys } = {}) {
    const keys = passkeyStore(passkeys);
    const site = tunnel.api ?? api;
    const home = tunnel.idp ?? idp;
    const toLoopback = (address) => {
        const url = new URL(address);
        const local = url.origin === new URL(site).origin ? api : url.origin === new URL(home).origin ? idp : null;
        return local === null ? address : local + url.pathname + url.search;
    };

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
        if (authorize.origin !== new URL(home).origin) throw new Error(`sign-in went to ${authorize.origin}, not the dev IdP`);
        const form = new URLSearchParams(authorize.searchParams);
        form.set('email', email);
        const approve = await fetch(toLoopback(authorize.origin + authorize.pathname), { method: 'POST', body: form, redirect: 'manual' });
        const back = await fetch(toLoopback(approve.headers.get('location') ?? `${site}/`), { headers: { cookie: pending }, redirect: 'manual' });
        if (back.status === 302 && new URL(back.headers.get('location'), site).pathname === '/auth/passkey') return passkeyStep(email, cookiesOf(back).join('; '));
        return cookieOf(back);
    }

    /**
     * The passkey coffre asks for after the provider (section 3.1): a new one for a person who must add one, kept;
     * else a touch of the one kept for them. The session cookie, or null when coffre turns them away.
     */
    async function passkeyStep(email, cookie) {
        const asked = await fetch(`${api}/api/auth/passkey`, { headers: { cookie } });
        if (!asked.ok) throw new Error(`the passkey step for ${email}: ${asked.status} ${await asked.text()}`);
        const { purpose, options, state } = await asked.json();
        const ceremony = { rpId: new URL(site).hostname, origin: new URL(site).origin, challenge: new Uint8Array(Buffer.from(options.challenge, 'base64url')) };
        let response;
        if (purpose === 'enroll') {
            const key = await SoftAuthenticator.create('ES256');
            response = await key.register({ ...ceremony, userHandle: new Uint8Array(Buffer.from(options.user.id, 'base64url')) });
            await keys.put(email, key);
        } else {
            const key = await keys.get(email);
            if (key === null) throw new Error(`${email} holds a passkey this browser does not: start the stack over, or sign in as someone else`);
            response = await key.assert(ceremony);
            // Its counter moved: kept, for the next signature, here or in a browser.
            await keys.put(email, key);
        }
        const answered = await fetch(`${api}/api/auth/passkey`, {
            method: 'POST',
            headers: { cookie, origin: site, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
            body: JSON.stringify({ response, ...(state === undefined ? {} : { state }) }),
        });
        if (!answered.ok) return null;
        return cookiesOf(answered).find((pair) => /^(__Host-)?coffre_session=/.test(pair)) ?? null;
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
            headers: { cookie: session, origin: site, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
            body: body === undefined ? undefined : JSON.stringify(body),
            redirect: 'manual',
        });
    }

    /** `send`, which must succeed: its JSON. */
    async function call(session, method, path, body) {
        return answered(method, path, await send(session, method, path, body));
    }

    async function answered(method, path, response) {
        if (!response.ok) throw new Error(`${method} ${path} -> ${response.status} ${await response.text()}`);
        return response.status === 204 ? null : response.json();
    }

    /**
     * `call`, for an act that takes a touch of its own (docs/design/passkeys.md, section 4.2), such as approving a
     * terminal: refused `touch_required`, it goes again with a touch of the passkey kept for `email`.
     */
    async function touched(session, email, method, path, body) {
        const first = await send(session, method, path, body);
        const refusal = first.status === 403 ? await first.clone().json().catch(() => null) : null;
        if (refusal?.error !== 'touch_required') return answered(method, path, first);
        const key = await keys.get(email);
        if (key === null) throw new Error(`coffre asked ${email} for a touch of a passkey this browser does not hold`);
        const challenge = new Uint8Array(Buffer.from(refusal.touch.options.challenge, 'base64url'));
        const response = await key.assert({ rpId: new URL(site).hostname, origin: new URL(site).origin, challenge });
        await keys.put(email, key);
        return call(session, method, path, { ...body, touch: { state: refusal.touch.state, response } });
    }

    return { trySignIn, signIn, send, call, touched };
}

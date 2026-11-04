#!/usr/bin/env node
// Give a persona's passkey, the one the seed added (dev/browser.mjs), to a
// Chrome you drive, through the DevTools protocol: a virtual authenticator
// in its current tab, holding that key, which answers coffre's "Confirm it's
// you" with no prompt, for as long as this runs. Under the dev stack's `optional`, Owners sign in with
// a passkey (docs/design/passkeys.md, section 2), and admin@acme.example's is
// the seed's.
//
//   node dev/passkey.mjs <DevTools URL> [email]
//
// The URL is the browser's WebSocket, `ws://127.0.0.1:9222/devtools/browser/…`
// (Chrome started with --remote-debugging-port, or `agent-browser cdp-url`).
// The email is admin@acme.example unless given. The key file is the one
// dev/start.sh names (COFFRE_DEV_PASSKEY_FILE). Throwaway keys, for a local
// stack only.
import { readFileSync } from 'node:fs';

const [url, email = 'admin@acme.example'] = process.argv.slice(2);
const file = process.env.COFFRE_DEV_PASSKEY_FILE ?? new URL('./.wrangler/state/passkeys.json', import.meta.url).pathname;
if (url === undefined) {
    console.error('usage: node dev/passkey.mjs <DevTools WebSocket URL> [email]');
    process.exit(2);
}
const saved = JSON.parse(readFileSync(file, 'utf8'))[email];
if (saved === undefined) {
    console.error(`${file} holds no passkey of ${email}'s: the seed adds one for each persona it signs in with one`);
    process.exit(1);
}
const rpId = new URL(process.env.COFFRE_DEV_PUBLIC_URL ?? 'http://localhost:3000').hostname;

// The DevTools protocol over one WebSocket: each call answered by its id, on the tab's session once attached.
const socket = new WebSocket(url);
await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', () => reject(new Error(`cannot reach ${url}`)), { once: true });
});
let next = 0;
const waiting = new Map();
socket.addEventListener('message', ({ data }) => {
    const message = JSON.parse(data);
    const call = waiting.get(message.id);
    if (call === undefined) return;
    waiting.delete(message.id);
    if (message.error) call.reject(new Error(`${call.method}: ${message.error.message}`));
    else call.resolve(message.result);
});
function send(method, params = {}, sessionId) {
    const id = ++next;
    socket.send(JSON.stringify({ id, method, params, ...(sessionId === undefined ? {} : { sessionId }) }));
    return new Promise((resolve, reject) => waiting.set(id, { method, resolve, reject }));
}

const { targetInfos } = await send('Target.getTargets');
const tab = targetInfos.find((target) => target.type === 'page');
if (tab === undefined) throw new Error('the browser has no tab open');
const { sessionId } = await send('Target.attachToTarget', { targetId: tab.targetId, flatten: true });
await send('WebAuthn.enable', {}, sessionId);
const { authenticatorId } = await send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
}, sessionId);
// The protocol's bytes are base64, not base64url.
const base64 = (text) => Buffer.from(text, 'base64url').toString('base64');
await send('WebAuthn.addCredential', {
    authenticatorId,
    credential: {
        credentialId: base64(saved.credentialId),
        isResidentCredential: true,
        rpId,
        privateKey: base64(saved.privateKey),
        userHandle: base64(saved.userHandle),
        signCount: 0,
    },
}, sessionId);
// The authenticator lasts as long as the session that added it: this process, until Ctrl-C or the browser closes.
console.log(`${email}'s passkey is in "${tab.title || tab.url}": coffre at ${rpId} takes it with no prompt while this runs. Ctrl-C to stop.`);
socket.addEventListener('close', () => process.exit(0));

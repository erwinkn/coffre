/**
 * How far apart two clocks may be where a time is the only thing that makes a request fresh: a minute, a policy Erwin
 * set (2026-11-06, the limits audit, #501, D3), not a measurement. It bounds Coffre's own parts, a Worker's clock
 * against Postgres's (`USE_AHEAD_MS`) and the app's against the vault's (how far past its longest a credential's end may
 * be, `credentials.ts`), and a workload's sign-in proof, which carries no nonce (`EXCHANGE_SKEW_SECONDS`). Where
 * something else makes a request fresh, that check keeps its own bound: a DPoP proof's 300 s (its nonce), an AWS proof's
 * 5 minutes (STS signs it), an ID token's 30 s, an Access token's 0.
 */
export const CLOCK_SKEW_MS = 60_000;

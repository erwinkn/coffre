// What each class of request may cost, stated once: the cost tests hold every route of a class to its budget. `use` and
// `change` are targets: a route over one today is held at exactly what it costs (`OVER`, and the change routes' `over`
// in change-cost.test.ts), so that it may only come down, and is struck off once it fits. The other budgets are
// ceilings, each today's largest, not a target: a route under one may grow up to it unnoticed, the trade for not
// editing a table of counts with every feature.
//
// `statements` counts every database's (the app's, the vault's, its hot path's), `trips` the round trips, each a Sync
// as Hyperdrive sends them, and `vaultCalls` the calls to the vault. A change's trips are every database's; a page's,
// its app connection's alone, each vault call being a connection of its own. A test holds each measure it takes.
//
// And no request grows with the instance: the growth tests hold each to the same statements, rows and pages, within
// slack for pages, on a small instance and a grown one. That check stays exact.
import assert from 'node:assert/strict';

export type Measure = 'statements' | 'trips' | 'vaultCalls';
export type Budget = Readonly<Partial<Record<Measure, number>>>;
/** A route held to a budget of its own, above its class's (`of`). */
export type Over = { budget: Budget; of: Budget };

export const BUDGET = {
  /** A `/use`, or a reveal of one key, warm: one database call, the vault's. */
  use: { statements: 1, vaultCalls: 1 },
  /** A change: two round trips on the request path (docs/design/two-trips.md), none on the hot path. */
  change: { trips: 2 },
  /** A page signed out: it reads nothing. */
  signedOut: { statements: 0, trips: 0, vaultCalls: 0 },
  // Ceilings, each today's largest, not a target.
  /** A call at the proxy, the vault's decision warm in its cache: its session (or binding) and place; the vault is not asked. */
  proxied: { statements: 1, vaultCalls: 0 },
  /** A page's server render, warm: an Owner's page of a service account. */
  page: { statements: 23, trips: 6, vaultCalls: 4 },
  /** A read through the API, a reveal or an export included: a CI run's list. */
  read: { statements: 5, vaultCalls: 1 },
  /** A request's check of its caller (`me`): the app's reads alone; the vault is not asked. */
  caller: { statements: 2, vaultCalls: 0 },
  /** A CI run's sign-in with its ID token. */
  signIn: { statements: 2, vaultCalls: 1 },
} as const satisfies Record<string, Budget>;

/**
 * Uses over their target today, each held to what it costs now until it is brought down. One that fits its class
 * fails, to be struck off. The change routes over theirs are held in change-cost.test.ts, beside each route.
 */
export const OVER = {
  /** A workload's call whose cache lapsed: the credential and the place read first, then the vault's use. */
  coldUse: { budget: { statements: 3, vaultCalls: 1 }, of: BUDGET.use },
  /** A handle's first `/use` in the vault's isolate: its touch of when it was last used, then two uses. */
  coldHandleUse: { budget: { statements: 3, vaultCalls: 1 }, of: BUDGET.use },
  /** A Worker's `/use` through its service binding: the binding and the place read by the app first, then the use. */
  bindingUse: { budget: { statements: 3, vaultCalls: 1 }, of: BUDGET.use },
  /** A reveal of one key through an MCP connection or behind Access: the project and the key read by the app first, then the use. */
  wayInReveal: { budget: { statements: 3, vaultCalls: 1 }, of: BUDGET.use },
} as const satisfies Record<string, Over>;

/** Each measure `spent` takes beyond `budget`, as a line: none if it fits. */
export function overBudget(spent: Budget, budget: Budget): string[] {
  return Object.entries(spent).flatMap(([measure, value]) => {
    const most = budget[measure as Measure];
    if (most === undefined) throw new Error(`no budget of ${measure}`);
    return value! > most ? [`${value} ${measure}, over ${most}`] : [];
  });
}

/** `spent` within `budget`, or a failure naming the route and what it took. */
export function assertWithin(name: string, spent: Budget, budget: Budget, trace = ''): void {
  const over = overBudget(spent, budget);
  assert.deepEqual(over, [], `${name}: ${over.join(', ')}${trace}`);
}

/** A route over its class's budget: at exactly its own, so that it may only come down, and still over its class's. */
export function assertOver(name: string, spent: Budget, { budget, of }: Over, trace = ''): void {
  const moved = Object.entries(spent).flatMap(([measure, value]) => {
    const held = budget[measure as Measure];
    return value === held ? [] : [`${value} ${measure}, held at ${held}`];
  });
  assert.deepEqual(moved, [], `${name}: ${moved.join(', ')}${trace}`);
  assert.notDeepEqual(overBudget(spent, of), [], `${name} fits its class now: drop its own budget`);
}

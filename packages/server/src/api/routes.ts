import type { z } from 'zod';

import { auditRoutes } from './routes/audit.ts';
import { bindingRoutes } from './routes/bindings.ts';
import { freezeRoutes } from './routes/freezes.ts';
import { keyRoutes } from './routes/keys.ts';
import { meRoutes } from './routes/me.ts';
import { memberRoutes } from './routes/members.ts';
import { oauthRoutes } from './routes/oauth.ts';
import { placeRoutes } from './routes/places.ts';
import { roleRoutes } from './routes/roles.ts';
import { secretRoutes } from './routes/secrets.ts';
import { settingsRoutes } from './routes/settings.ts';
import { signinRoutes } from './routes/signin.ts';
import { tokenRoutes } from './routes/tokens.ts';
import { unservedRoutes } from './routes/unserved.ts';

/**
 * The API, as `METHOD /route`: every area's routes. An area adds its list here, and nothing else of the router.
 * Those not served yet come first, so that an area serving one replaces it.
 */
export const routes = { ...unservedRoutes, ...meRoutes, ...placeRoutes, ...secretRoutes, ...keyRoutes, ...memberRoutes, ...bindingRoutes, ...roleRoutes, ...settingsRoutes, ...freezeRoutes, ...signinRoutes, ...tokenRoutes, ...oauthRoutes, ...auditRoutes };

export type Routes = typeof routes;
export type RouteKey = keyof Routes;

type InputSchema<K extends RouteKey> = NonNullable<Routes[K]['input']>;

/** What a caller sends: the body, or the query string for a GET. */
export type RouteInput<K extends RouteKey> = [InputSchema<K>] extends [never]
  ? undefined
  : InputSchema<K> extends z.ZodType
    ? z.input<InputSchema<K>>
    : never;

/** What the handler returns, before it is written as JSON. */
export type RouteOutput<K extends RouteKey> = Awaited<ReturnType<Routes[K]['run']>>;

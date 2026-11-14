import { keyRoutes } from './routes/keys.ts';
import { meRoutes } from './routes/me.ts';
import { memberRoutes } from './routes/members.ts';
import { placeRoutes } from './routes/places.ts';
import { roleRoutes } from './routes/roles.ts';
import { secretRoutes } from './routes/secrets.ts';
import { settingsRoutes } from './routes/settings.ts';
import { signinRoutes } from './routes/signin.ts';
import { unservedRoutes } from './routes/unserved.ts';

/**
 * The API, as `METHOD /route`: every area's routes. An area adds its list here, and nothing else of the router.
 * Those not served yet come first, so that an area serving one replaces it.
 */
export const routes = { ...unservedRoutes, ...meRoutes, ...placeRoutes, ...secretRoutes, ...keyRoutes, ...memberRoutes, ...roleRoutes, ...settingsRoutes, ...signinRoutes };

import { keyRoutes } from './routes/keys.ts';
import { meRoutes } from './routes/me.ts';
import { placeRoutes } from './routes/places.ts';
import { secretRoutes } from './routes/secrets.ts';

/** The API, as `METHOD /route`: every area's routes. An area adds its list here, and nothing else of the router. */
export const routes = { ...meRoutes, ...placeRoutes, ...secretRoutes, ...keyRoutes };

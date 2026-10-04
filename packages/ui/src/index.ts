// `@coffre/ui`: coffre's pages, as a TanStack Start router a deployment's
// own Start app uses (its src/router.tsx re-exports `getRouter`). Its server
// entry hands the pages to `@coffre/server`, which renders them with the
// request's nonce and API client.
export { getRouter } from './router.tsx';

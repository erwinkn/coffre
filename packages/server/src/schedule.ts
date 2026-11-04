/**
 * How often the scheduled run beats (`runScheduled`), in minutes: Workers' cron, `*\/5 * * * *` in the deployment's
 * `wrangler.jsonc`, which `coffre init` writes and a test holds to this; Node's timer (`node.ts`).
 */
export const SCHEDULE_MINUTES = 5;

// What this instance allows, in one place: read by the app (app/src/coffre.ts),
// the vault (vault/src/worker.ts) and the app's build (app/vite.config.ts).
// Each holds its own part. A field left out keeps its default, shown
// commented; nobody changes these at run time (docs/deploy.md, "deployment.ts").
import { defineDeployment } from '@coffre/core/deployment';

export const deployment = defineDeployment({
  people: {
    // browserSessionHours: 12, // above 0, at most 168
    // cliSessionDays: 30, // above 0, at most 365
  },
  services: {
    // tokenMaxDays: 365, // 1 to 365
    // signInsPerAddress: 10_000, // per 10 s, as app/wrangler.jsonc's SIGN_IN_PER_SOURCE says too: the build checks
    // useOnly: false, // true: no service token issued or taken; services sign in with a key
    // noReads: false, // true: no binding lists reads, so key-bound sessions get plain values only
  },
  reads: {
    // bulkLimit: { count: 1_000, windowMinutes: 15 }, // keys one principal opens, the window a day at most
  },
  values: {
    // rotateAfterDays: 365, // null: never flag a value for rotation
  },
  proxy: {
    // revokedWithinSeconds: 60, // 3 to 3,600
    // cacheValues: true, // false: every request asks the vault
    editable: true, // Owners write the credential proxy's routes, signers, verifiers and databases in each environment's Proxy tab
  },
  audit: {
    // keepUsesDays: null, // null: every day's uses kept
    // repeatsWithinSeconds: 60, // 0 to 3,600; 0: every use an entry of its own
  },
});

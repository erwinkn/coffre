ARG NODE_IMAGE=node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d

FROM ${NODE_IMAGE} AS build

ENV CI=true
ENV COREPACK_HOME=/corepack
WORKDIR /app

RUN corepack enable \
    && corepack prepare pnpm@11.8.0 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/db/package.json packages/db/package.json
RUN pnpm --filter @coffre/db install --frozen-lockfile

COPY packages/db packages/db
RUN pnpm --filter @coffre/db deploy --prod --legacy --offline \
        --config.strict-peer-dependencies=false /migration

FROM ${NODE_IMAGE} AS runtime

ENV NODE_ENV=production
WORKDIR /migration

RUN rm -rf /usr/local/lib/node_modules/corepack \
        /usr/local/lib/node_modules/npm \
    && rm -f /usr/local/bin/corepack /usr/local/bin/npm /usr/local/bin/npx

COPY --from=build --chown=node:node /migration ./

USER node

CMD ["node", "src/migrate.ts"]

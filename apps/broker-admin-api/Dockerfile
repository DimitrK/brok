# syntax=docker/dockerfile:1.7

FROM node:20-alpine AS builder

ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"

RUN corepack enable

WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json .npmrc tsconfig.base.json ./
COPY apps ./apps
COPY packages ./packages
COPY scripts ./scripts

RUN find /app -name '*.tsbuildinfo' -delete

RUN --mount=type=cache,id=broker-interceptor-pnpm-store,target=/pnpm/store pnpm install --frozen-lockfile --store-dir=/pnpm/store
RUN --mount=type=cache,id=broker-interceptor-turbo-cache,target=/app/.turbo pnpm turbo run build --filter=@broker-interceptor/broker-admin-api...
RUN pnpm --filter @broker-interceptor/broker-admin-api deploy --prod /out
RUN pnpm --filter @broker-interceptor/db exec prisma generate --schema /out/node_modules/@broker-interceptor/db/prisma/schema.prisma
RUN node ./scripts/fix-esm-specifiers.mjs /out

FROM node:20-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production

RUN addgroup -S broker && adduser -S broker -G broker

COPY --from=builder /out ./

USER broker
EXPOSE 8080

CMD ["node", "dist/index.js"]

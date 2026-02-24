FROM node:20-bookworm-slim

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH

RUN corepack enable

WORKDIR /workspace

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json turbo.json .npmrc ./

COPY packages/interceptor-node ./packages/interceptor-node
COPY packages/schemas ./packages/schemas
COPY packages/eslint-config ./packages/eslint-config
COPY packages/prettier-config ./packages/prettier-config
COPY packages/typescript-config ./packages/typescript-config

# Install only interceptor-node and its local workspace dependencies.
RUN pnpm install --frozen-lockfile --filter @broker-interceptor/interceptor-node...

# interceptor-node imports generated DTOs from @broker-interceptor/schemas/dist/generated.
RUN pnpm --filter @broker-interceptor/schemas build

# Build interceptor-node so preload/test runtime is available if needed.
RUN pnpm --filter @broker-interceptor/interceptor-node build

WORKDIR /workspace/packages/interceptor-node

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["pnpm", "test:service"]

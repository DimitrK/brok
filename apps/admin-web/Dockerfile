FROM node:20-alpine AS builder

WORKDIR /app
RUN corepack enable

COPY pnpm-lock.yaml package.json pnpm-workspace.yaml turbo.json tsconfig.base.json ./
COPY packages ./packages
COPY apps/admin-web ./apps/admin-web

RUN pnpm install --frozen-lockfile
RUN pnpm --filter @broker-interceptor/admin-web run build

FROM nginx:1.27-alpine AS runtime

COPY --from=builder /app/apps/admin-web/dist /usr/share/nginx/html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

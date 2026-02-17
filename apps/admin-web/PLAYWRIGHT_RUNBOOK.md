# Playwright Runbook (`apps/admin-web`)

Use this checklist to open the SPA, inspect UI state, and capture debugging artifacts from a real browser.

## 1) Start the frontend

From repo root:

```bash
pnpm --filter @broker-interceptor/admin-web dev
```

Default URL is usually `http://localhost:4173/` (or next free port).

## 2) Prepare Playwright CLI wrapper

```bash
export CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
export PWCLI="$CODEX_HOME/skills/playwright/scripts/playwright_cli.sh"
```

Note: wrapper is not executable in this workspace, so invoke it with `bash`.

```bash
bash "$PWCLI" --help
```

## 3) Open the app and snapshot

```bash
bash "$PWCLI" open http://localhost:4174/
bash "$PWCLI" snapshot
```

Use snapshot refs (`e19`, `e20`, etc.) for interactions:

```bash
bash "$PWCLI" click e20
bash "$PWCLI" fill e14 "dev-admin-token"
bash "$PWCLI" snapshot
```

## 4) Capture logs and traces

Console errors/warnings:

```bash
bash "$PWCLI" console error
bash "$PWCLI" console warning
```

Network log:

```bash
bash "$PWCLI" network
```

Artifacts are written to `.playwright-cli/*`.

## 5) Take screenshots

Use the standard artifact folder:

```bash
mkdir -p output/playwright
bash "$PWCLI" screenshot --full-page --filename output/playwright/admin-web-state.png
```

## 6) Optional: mock API responses for deterministic UI checks

Add route mocks:

```bash
bash "$PWCLI" route "**/healthz" --status 200 --content-type "application/json" --body '{"status":"ok"}'
bash "$PWCLI" route "**/v1/tenants" --status 200 --content-type "application/json" --body '{"tenants":[]}'
```

List/remove mocks:

```bash
bash "$PWCLI" route-list
bash "$PWCLI" unroute "**/v1/tenants"
```

## 7) Cleanup

Close browser session:

```bash
bash "$PWCLI" close
```

Stop frontend dev server in its terminal (`Ctrl+C`).

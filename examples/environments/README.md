# agent-browser Environments

A playground for running agent-browser in different compute environments. Enter a URL, pick an environment, and take a screenshot or accessibility snapshot.

Currently supported environments:

- **Serverless Function** -- `@sparticuz/chromium` + `puppeteer-core` running directly inside a Vercel serverless function
- **Vercel Sandbox** -- agent-browser + Chrome in an ephemeral Linux microVM

More environments (Docker, GitHub Actions, etc.) are coming.

## Getting Started

```bash
cd examples/environments
pnpm install
pnpm dev
```

## Serverless Function

Runs headless Chrome directly in the serverless function. On Vercel, `@sparticuz/chromium` provides the binary automatically. Locally, the app finds your system Chrome or uses `CHROMIUM_PATH`.

## Vercel Sandbox

Spins up a Linux microVM on demand, installs agent-browser + Chrome, runs the commands, and shuts down. No binary size limits. Create a snapshot to make startup sub-second:

```bash
npx tsx scripts/create-snapshot.ts
# Output: AGENT_BROWSER_SNAPSHOT_ID=snap_xxxxxxxxxxxx
```

Add the snapshot ID to your Vercel environment variables or `.env.local`.

## Environment Variables

| Variable | Environment | Description |
|---|---|---|
| `CHROMIUM_PATH` | Serverless | Path to local Chrome/Chromium binary (auto-detected on Vercel) |
| `AGENT_BROWSER_SNAPSHOT_ID` | Sandbox | Pre-built snapshot ID for fast startup |

## Project Structure

```
examples/environments/
  app/
    page.tsx                  # Demo UI
    actions/browse.ts         # Server actions (all environments)
    api/browse/route.ts       # API route for programmatic access
  lib/
    agent-browser.ts          # Serverless: @sparticuz/chromium + puppeteer-core
    agent-browser-sandbox.ts  # Sandbox: Vercel Sandbox client
  scripts/
    create-snapshot.ts        # Create sandbox snapshot
```

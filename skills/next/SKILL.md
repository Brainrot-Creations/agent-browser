---
name: next
description: Run headless Chrome in Next.js serverless functions using @sparticuz/chromium + puppeteer-core. Use when the user needs browser automation from a Next.js app, wants to take screenshots or snapshots from server actions or API routes, or is building a Next.js app that needs headless Chrome. Triggers include "screenshot from Next.js", "headless Chrome in serverless", "browser automation in Next.js", "puppeteer on Vercel", or any task requiring Chrome in a Next.js server context.
---

# Browser Automation in Next.js Serverless Functions

Run headless Chrome directly inside Next.js server actions and API routes using `@sparticuz/chromium` + `puppeteer-core`. No external server needed -- Chrome runs in the same serverless function.

## Dependencies

```bash
pnpm add @sparticuz/chromium puppeteer-core
```

## Core Pattern

```ts
import puppeteer from "puppeteer-core";
import chromium from "@sparticuz/chromium";
import fs from "node:fs";

const CHROME_PATHS = [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
];

function findLocalChrome(): string {
  for (const p of CHROME_PATHS) {
    if (fs.existsSync(p)) return p;
  }
  throw new Error(
    `Chrome not found. Set CHROMIUM_PATH to your Chrome/Chromium binary.`,
  );
}

async function launchBrowser() {
  const isLambda =
    !!process.env.VERCEL || !!process.env.AWS_LAMBDA_FUNCTION_NAME;

  const executablePath = isLambda
    ? await chromium.executablePath()
    : process.env.CHROMIUM_PATH || findLocalChrome();

  const args = isLambda
    ? chromium.args
    : ["--no-sandbox", "--disable-setuid-sandbox"];

  return puppeteer.launch({
    args,
    executablePath,
    headless: true,
    defaultViewport: { width: 1280, height: 720 },
  });
}
```

On Vercel, `@sparticuz/chromium` bundles a compatible Chromium binary automatically. Locally, the launcher falls back to the system Chrome installation or `CHROMIUM_PATH`.

## Server Actions

### Screenshot

```ts
"use server";

export async function takeScreenshot(url: string) {
  const browser = await launchBrowser();
  try {
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: "networkidle2", timeout: 30_000 });
    const title = await page.title();
    const screenshot = await page.screenshot({
      fullPage: true,
      encoding: "base64",
    });
    return { ok: true, title, screenshot: screenshot as string };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  } finally {
    await browser.close();
  }
}
```

### Accessibility Snapshot

```ts
"use server";

export async function takeSnapshot(url: string) {
  const browser = await launchBrowser();
  try {
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: "networkidle2", timeout: 30_000 });
    const title = await page.title();
    const snapshot = await page.accessibility.snapshot();
    return { ok: true, title, snapshot: JSON.stringify(snapshot, null, 2) };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  } finally {
    await browser.close();
  }
}
```

## API Routes

```ts
// app/api/browse/route.ts
import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  const { url, action } = await req.json();

  if (!url) {
    return NextResponse.json({ error: "Provide a 'url'" }, { status: 400 });
  }

  const browser = await launchBrowser();
  try {
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: "networkidle2", timeout: 30_000 });

    if (action === "screenshot") {
      const screenshot = await page.screenshot({ encoding: "base64" });
      return NextResponse.json({ screenshot });
    }

    if (action === "snapshot") {
      const snapshot = await page.accessibility.snapshot();
      return NextResponse.json({ snapshot });
    }

    return NextResponse.json(
      { error: "action must be 'screenshot' or 'snapshot'" },
      { status: 400 },
    );
  } finally {
    await browser.close();
  }
}
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `CHROMIUM_PATH` | Local dev only | Path to Chrome/Chromium binary. Not needed on Vercel. |

On Vercel, `@sparticuz/chromium` auto-detects the bundled binary. Locally, if Chrome is not in a standard location, set `CHROMIUM_PATH`.

## Vercel Configuration

The `@sparticuz/chromium` binary is large (~50MB). Increase the serverless function's memory and timeout if needed:

```ts
// next.config.ts
const nextConfig = {
  serverExternalPackages: ["@sparticuz/chromium"],
};
export default nextConfig;
```

If the project lives in a monorepo subdirectory, set `outputFileTracingRoot` so the Chromium binary is included in the deployment:

```ts
import path from "node:path";

const nextConfig = {
  outputFileTracingRoot: path.join(import.meta.dirname, "../../"),
  serverExternalPackages: ["@sparticuz/chromium"],
};
export default nextConfig;
```

## Limitations

- Vercel serverless functions have a 50MB compressed size limit. `@sparticuz/chromium` fits within this but leaves limited room for other large dependencies.
- Function execution timeout is 10s on Hobby, 300s on Pro. Complex page loads may need the Pro plan.
- Each invocation launches a fresh browser. There is no session persistence between requests.
- For workflows that need persistent sessions, longer timeouts, or full Chrome (no size limits), use the Vercel Sandbox pattern instead (see the `vercel-sandbox` skill).

## Example

See `examples/environments/` in the agent-browser repo for a working app with a demo UI, both serverless and sandbox patterns, and a deploy-to-Vercel button.

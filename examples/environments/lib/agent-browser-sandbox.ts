/**
 * Run agent-browser inside a Vercel Sandbox.
 *
 * No external server needed -- a Linux microVM spins up on demand,
 * runs agent-browser + headless Chrome, and shuts down when done.
 *
 * For production, create a snapshot with agent-browser and Chromium
 * pre-installed so startup is sub-second instead of ~30s.
 */

import { Sandbox } from "@vercel/sandbox";

export type SandboxResult = {
  exitCode: number;
  stdout: string;
  stderr: string;
};

const SNAPSHOT_ID = process.env.AGENT_BROWSER_SNAPSHOT_ID;

async function createSandbox(): Promise<InstanceType<typeof Sandbox>> {
  if (SNAPSHOT_ID) {
    return Sandbox.create({
      source: { type: "snapshot", snapshotId: SNAPSHOT_ID },
      timeout: 120_000,
    });
  }

  const sandbox = await Sandbox.create({
    runtime: "node24",
    timeout: 120_000,
  });

  await sandbox.runCommand("npm", ["install", "-g", "agent-browser"]);
  await sandbox.runCommand("npx", ["agent-browser", "install"]);

  return sandbox;
}

async function exec(
  sandbox: InstanceType<typeof Sandbox>,
  cmd: string,
  args: string[],
): Promise<SandboxResult> {
  const result = await sandbox.runCommand(cmd, args);
  return {
    exitCode: result.exitCode,
    stdout: await result.stdout(),
    stderr: await result.stderr(),
  };
}

/**
 * Screenshot a URL using agent-browser inside a Vercel Sandbox.
 * Returns base64-encoded PNG.
 */
export async function screenshotUrl(
  url: string,
  opts: { fullPage?: boolean } = {},
): Promise<{ screenshot: string; title: string }> {
  const sandbox = await createSandbox();

  try {
    await exec(sandbox, "agent-browser", ["open", url]);

    const titleResult = await exec(sandbox, "agent-browser", [
      "get",
      "title",
      "--json",
    ]);
    const title = tryParseJson(titleResult.stdout)?.data?.title || url;

    const screenshotArgs = ["screenshot", "--json"];
    if (opts.fullPage) screenshotArgs.push("--full");
    const ssResult = await exec(sandbox, "agent-browser", screenshotArgs);
    const screenshot = tryParseJson(ssResult.stdout)?.data?.base64 || "";

    await exec(sandbox, "agent-browser", ["close"]);

    return { screenshot, title };
  } finally {
    await sandbox.stop();
  }
}

/**
 * Snapshot a URL (accessibility tree) using agent-browser inside a Vercel Sandbox.
 */
export async function snapshotUrl(
  url: string,
  opts: { interactive?: boolean; compact?: boolean } = {},
): Promise<{ snapshot: string; title: string }> {
  const sandbox = await createSandbox();

  try {
    await exec(sandbox, "agent-browser", ["open", url]);

    const titleResult = await exec(sandbox, "agent-browser", [
      "get",
      "title",
      "--json",
    ]);
    const title = tryParseJson(titleResult.stdout)?.data?.title || url;

    const snapshotArgs = ["snapshot"];
    if (opts.interactive) snapshotArgs.push("-i");
    if (opts.compact) snapshotArgs.push("-c");
    const snapResult = await exec(sandbox, "agent-browser", snapshotArgs);

    await exec(sandbox, "agent-browser", ["close"]);

    return { snapshot: snapResult.stdout, title };
  } finally {
    await sandbox.stop();
  }
}

/**
 * Run arbitrary agent-browser commands inside a Vercel Sandbox.
 * Each command is a string array like ["open", "https://example.com"].
 */
export async function runCommands(
  commands: string[][],
): Promise<SandboxResult[]> {
  const sandbox = await createSandbox();

  try {
    const results: SandboxResult[] = [];
    for (const args of commands) {
      const result = await exec(sandbox, "agent-browser", args);
      results.push(result);
      if (result.exitCode !== 0) break;
    }
    return results;
  } finally {
    await sandbox.stop();
  }
}

/**
 * Create a reusable snapshot with agent-browser + Chromium pre-installed.
 * Run this once, then set AGENT_BROWSER_SNAPSHOT_ID for fast startup.
 */
export async function createSnapshot(): Promise<string> {
  const sandbox = await Sandbox.create({
    runtime: "node24",
    timeout: 300_000,
  });

  await sandbox.runCommand("npm", ["install", "-g", "agent-browser"]);
  await sandbox.runCommand("npx", ["agent-browser", "install"]);

  const snapshot = await sandbox.snapshot();
  return snapshot.snapshotId;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function tryParseJson(str: string): any {
  try {
    return JSON.parse(str);
  } catch {
    return null;
  }
}

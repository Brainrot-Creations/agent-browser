/**
 * Node.js Daemon vs Rust Native Daemon benchmark.
 *
 * Compares the published npm version (Node.js daemon, from main) against
 * the Rust-only build from ctate/native-2, running real agent-browser
 * commands inside a Vercel Sandbox.
 *
 * Phase 1 -- Node.js daemon:
 *   npm install -g agent-browser  (published version with Node daemon)
 *
 * Phase 2 -- Rust native daemon:
 *   Clone repo, checkout ctate/native-2, cargo build --release, replace binary
 *
 * Usage:
 *   pnpm bench                        # default: 5 iterations, 1 warmup
 *   pnpm bench -- --iterations 10     # override iterations
 *   pnpm bench -- --warmup 2          # override warmup count
 *   pnpm bench -- --json              # write results.json
 *   pnpm bench -- --branch my-branch  # override native branch (default: ctate/native-2)
 *   pnpm bench -- --vcpus 8           # sandbox vCPUs (default: 4, higher = faster Rust build)
 */

import { Sandbox } from "@vercel/sandbox";
import { readFileSync, writeFileSync } from "fs";
import { scenarios, type Scenario } from "./scenarios.js";

// ---------------------------------------------------------------------------
// Env
// ---------------------------------------------------------------------------

function loadEnv() {
  try {
    const content = readFileSync(".env", "utf-8");
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq === -1) continue;
      const key = trimmed.slice(0, eq);
      let val = trimmed.slice(eq + 1);
      if (
        (val.startsWith('"') && val.endsWith('"')) ||
        (val.startsWith("'") && val.endsWith("'"))
      ) {
        val = val.slice(1, -1);
      }
      process.env[key] = val;
    }
  } catch {}
}
loadEnv();

const credentials = {
  token: process.env.SANDBOX_VERCEL_TOKEN!,
  teamId: process.env.SANDBOX_VERCEL_TEAM_ID!,
  projectId: process.env.SANDBOX_VERCEL_PROJECT_ID!,
};

if (!credentials.token || !credentials.teamId || !credentials.projectId) {
  console.error(
    "Missing credentials. Set SANDBOX_VERCEL_TOKEN, SANDBOX_VERCEL_TEAM_ID, SANDBOX_VERCEL_PROJECT_ID in .env",
  );
  process.exit(1);
}


// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

function parseArgs() {
  const args = process.argv.slice(2);
  let iterations = 5;
  let warmup = 1;
  let json = false;
  let branch = "ctate/native-2";
  let vcpus = 4;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--iterations" && args[i + 1]) {
      iterations = parseInt(args[++i], 10);
    } else if (args[i] === "--warmup" && args[i + 1]) {
      warmup = parseInt(args[++i], 10);
    } else if (args[i] === "--json") {
      json = true;
    } else if (args[i] === "--branch" && args[i + 1]) {
      branch = args[++i];
    } else if (args[i] === "--vcpus" && args[i + 1]) {
      vcpus = parseInt(args[++i], 10);
    }
  }

  return { iterations, warmup, json, branch, vcpus };
}

const config = parseArgs();

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TIMEOUT_MS = 30 * 60 * 1000;
const REPO_URL = "https://github.com/vercel-labs/agent-browser.git";

const CHROMIUM_SYSTEM_DEPS = [
  "nss",
  "nspr",
  "libxkbcommon",
  "atk",
  "at-spi2-atk",
  "at-spi2-core",
  "libXcomposite",
  "libXdamage",
  "libXrandr",
  "libXfixes",
  "libXcursor",
  "libXi",
  "libXtst",
  "libXScrnSaver",
  "libXext",
  "mesa-libgbm",
  "libdrm",
  "mesa-libGL",
  "mesa-libEGL",
  "cups-libs",
  "alsa-lib",
  "pango",
  "cairo",
  "gtk3",
  "dbus-libs",
];

// ---------------------------------------------------------------------------
// Sandbox helpers
// ---------------------------------------------------------------------------

type SandboxInstance = InstanceType<typeof Sandbox>;

async function run(
  sandbox: SandboxInstance,
  cmd: string,
  args: string[],
): Promise<string> {
  const result = await sandbox.runCommand(cmd, args);
  const stdout = await result.stdout();
  const stderr = await result.stderr();
  if (result.exitCode !== 0) {
    throw new Error(
      `Command failed (exit ${result.exitCode}): ${cmd} ${args.join(" ")}\n${stderr || stdout}`,
    );
  }
  return stdout;
}

async function shell(sandbox: SandboxInstance, script: string): Promise<string> {
  return run(sandbox, "sh", ["-c", script]);
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

interface Stats {
  avgMs: number;
  minMs: number;
  maxMs: number;
  p50Ms: number;
  samples: number[];
}

function computeStats(samples: number[]): Stats {
  const sorted = [...samples].sort((a, b) => a - b);
  const sum = sorted.reduce((a, b) => a + b, 0);
  return {
    avgMs: Math.round(sum / sorted.length),
    minMs: sorted[0],
    maxMs: sorted[sorted.length - 1],
    p50Ms: sorted[Math.floor(sorted.length / 2)],
    samples: sorted,
  };
}

// ---------------------------------------------------------------------------
// Scenario runner
// ---------------------------------------------------------------------------

type DaemonMode = "node" | "native";

function daemonEnv(mode: DaemonMode): Record<string, string> {
  return { AGENT_BROWSER_SESSION: `bench-${mode}` };
}

async function agentBrowser(
  sandbox: SandboxInstance,
  args: string[],
  mode: DaemonMode,
): Promise<void> {
  const result = await sandbox.runCommand({
    cmd: "agent-browser",
    args,
    env: daemonEnv(mode),
  });
  if (result.exitCode !== 0) {
    const stderr = await result.stderr();
    const stdout = await result.stdout();
    throw new Error(
      `agent-browser ${args.join(" ")} failed (exit ${result.exitCode}): ${stderr || stdout}`,
    );
  }
}

async function timedAgentBrowser(
  sandbox: SandboxInstance,
  args: string[],
  mode: DaemonMode,
): Promise<number> {
  const start = Date.now();
  const result = await sandbox.runCommand({
    cmd: "agent-browser",
    args,
    env: daemonEnv(mode),
  });
  const elapsed = Date.now() - start;
  if (result.exitCode !== 0) {
    const stderr = await result.stderr();
    const stdout = await result.stdout();
    throw new Error(
      `agent-browser ${args.join(" ")} failed (exit ${result.exitCode}): ${stderr || stdout}`,
    );
  }
  return elapsed;
}

interface ScenarioResult {
  name: string;
  description: string;
  stats: Stats;
  error?: string;
}

async function runScenario(
  sandbox: SandboxInstance,
  scenario: Scenario,
  mode: DaemonMode,
  iterations: number,
  warmup: number,
): Promise<ScenarioResult> {
  try {
    if (scenario.setup) {
      for (const cmd of scenario.setup) {
        await agentBrowser(sandbox, cmd, mode);
      }
    }

    for (let w = 0; w < warmup; w++) {
      for (const cmd of scenario.commands) {
        await agentBrowser(sandbox, cmd, mode);
      }
    }

    const samples: number[] = [];
    for (let i = 0; i < iterations; i++) {
      let totalMs = 0;
      for (const cmd of scenario.commands) {
        totalMs += await timedAgentBrowser(sandbox, cmd, mode);
      }
      samples.push(totalMs);
    }

    if (scenario.teardown) {
      for (const cmd of scenario.teardown) {
        await agentBrowser(sandbox, cmd, mode);
      }
    }

    return {
      name: scenario.name,
      description: scenario.description,
      stats: computeStats(samples),
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      name: scenario.name,
      description: scenario.description,
      stats: { avgMs: -1, minMs: -1, maxMs: -1, p50Ms: -1, samples: [] },
      error: message,
    };
  }
}

// ---------------------------------------------------------------------------
// Benchmark phases
// ---------------------------------------------------------------------------

interface DaemonResults {
  mode: DaemonMode;
  label: string;
  scenarios: ScenarioResult[];
}

async function benchmarkDaemon(
  sandbox: SandboxInstance,
  mode: DaemonMode,
  label: string,
): Promise<DaemonResults> {
  console.log(`\n--- ${label} ---`);

  await agentBrowser(sandbox, ["open", "about:blank"], mode);
  console.log(`  Browser launched (session: bench-${mode})`);

  const results: ScenarioResult[] = [];
  for (const scenario of scenarios) {
    process.stdout.write(`  ${scenario.name} `);
    const result = await runScenario(
      sandbox,
      scenario,
      mode,
      config.iterations,
      config.warmup,
    );
    if (result.error) {
      console.log(`FAILED: ${result.error.slice(0, 120)}`);
    } else {
      const dots = ".".repeat(Math.max(1, 30 - scenario.name.length));
      console.log(
        `${dots} ${result.stats.avgMs}ms avg (p50: ${result.stats.p50Ms}ms, min: ${result.stats.minMs}ms, max: ${result.stats.maxMs}ms)`,
      );
    }
    results.push(result);
  }

  await agentBrowser(sandbox, ["close"], mode);
  console.log(`  Browser closed.`);

  return { mode, label, scenarios: results };
}

// ---------------------------------------------------------------------------
// Install helpers
// ---------------------------------------------------------------------------

async function installChromiumDeps(sandbox: SandboxInstance) {
  console.log("Installing Chromium system dependencies...");
  await shell(
    sandbox,
    `sudo dnf clean all 2>&1 && sudo dnf install -y --skip-broken ${CHROMIUM_SYSTEM_DEPS.join(" ")} 2>&1 && sudo ldconfig 2>&1`,
  );
}

async function installNodeDaemon(sandbox: SandboxInstance) {
  console.log("Installing agent-browser from npm (Node.js daemon)...");
  await run(sandbox, "npm", ["install", "-g", "agent-browser"]);
  await run(sandbox, "npx", ["agent-browser", "install"]);
  const version = await shell(sandbox, "agent-browser --version 2>&1 || true");
  console.log(`  version: ${version.trim()}`);
}

async function installNativeDaemon(sandbox: SandboxInstance, branch: string) {
  console.log(`Building native daemon from ${branch}...`);

  // Install Rust toolchain
  console.log("  Installing Rust toolchain...");
  const rustStart = Date.now();
  await shell(
    sandbox,
    "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y 2>&1",
  );
  console.log(`  Rust installed (${Math.round((Date.now() - rustStart) / 1000)}s)`);

  // Clone and checkout branch
  console.log(`  Cloning repo (branch: ${branch})...`);
  const cloneStart = Date.now();
  await shell(
    sandbox,
    `git clone --depth 1 --branch ${branch} ${REPO_URL} /tmp/agent-browser 2>&1`,
  );
  console.log(`  Cloned (${Math.round((Date.now() - cloneStart) / 1000)}s)`);

  // Build release binary
  console.log("  Building release binary (cargo build --release)...");
  const buildStart = Date.now();
  await shell(
    sandbox,
    "source $HOME/.cargo/env && cd /tmp/agent-browser/cli && cargo build --release 2>&1",
  );
  const buildSec = Math.round((Date.now() - buildStart) / 1000);
  console.log(`  Built (${buildSec}s)`);

  // Replace the npm-installed binary with the freshly built one
  const npmBinPath = (await shell(sandbox, "which agent-browser")).trim();
  console.log(`  Replacing ${npmBinPath} with native build...`);
  await shell(
    sandbox,
    `sudo cp /tmp/agent-browser/cli/target/release/agent-browser ${npmBinPath}`,
  );

  // Chrome is already installed from the Node phase, just verify
  const version = await shell(sandbox, "agent-browser --version 2>&1 || true");
  console.log(`  version: ${version.trim()}`);
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

function printResults(node: DaemonResults, native: DaemonResults) {
  console.log("\n\n========== RESULTS ==========\n");

  const header =
    "Scenario".padEnd(20) + "| Node (ms) | Rust (ms) | Speedup";
  const sep = "-".repeat(20) + "|-----------|-----------|--------";
  console.log(header);
  console.log(sep);

  for (let i = 0; i < node.scenarios.length; i++) {
    const n = node.scenarios[i];
    const r = native.scenarios[i];
    const name = n.name.padEnd(20);

    if (n.error || r.error) {
      const nodeVal = n.error
        ? "FAILED".padStart(9)
        : String(n.stats.avgMs).padStart(9);
      const rustVal = r.error
        ? "FAILED".padStart(9)
        : String(r.stats.avgMs).padStart(9);
      console.log(`${name}| ${nodeVal} | ${rustVal} |    --`);
      continue;
    }

    const nodeMs = String(n.stats.avgMs).padStart(9);
    const rustMs = String(r.stats.avgMs).padStart(9);
    const speedup =
      r.stats.avgMs > 0
        ? (n.stats.avgMs / r.stats.avgMs).toFixed(2) + "x"
        : "--";
    console.log(`${name}| ${nodeMs} | ${rustMs} | ${speedup.padStart(6)}`);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log("agent-browser Daemon Benchmark (Node.js vs Rust Native)");
  console.log(`Branch: ${config.branch}`);
  console.log(`Iterations: ${config.iterations} (+ ${config.warmup} warmup)`);
  console.log(`vCPUs: ${config.vcpus}\n`);

  console.log("Creating sandbox...");
  const sandbox = await Sandbox.create({
    ...credentials,
    timeout: TIMEOUT_MS,
    runtime: "node22",
    networkPolicy: "allow-all" as const,
    resources: { vcpus: config.vcpus },
  });
  console.log(`Sandbox: ${sandbox.sandboxId}`);

  try {
    await installChromiumDeps(sandbox);

    // Phase 1: Node.js daemon (from published npm package)
    await installNodeDaemon(sandbox);
    const nodeResults = await benchmarkDaemon(
      sandbox,
      "node",
      "Node.js Daemon (npm)",
    );

    // Phase 2: Rust native daemon (built from branch)
    await installNativeDaemon(sandbox, config.branch);
    const nativeResults = await benchmarkDaemon(
      sandbox,
      "native",
      `Rust Native Daemon (${config.branch})`,
    );

    printResults(nodeResults, nativeResults);

    if (config.json) {
      const output = {
        timestamp: new Date().toISOString(),
        branch: config.branch,
        vcpus: config.vcpus,
        iterations: config.iterations,
        warmup: config.warmup,
        node: nodeResults.scenarios.map((s) => ({
          name: s.name,
          description: s.description,
          ...s.stats,
          error: s.error,
        })),
        native: nativeResults.scenarios.map((s) => ({
          name: s.name,
          description: s.description,
          ...s.stats,
          error: s.error,
        })),
      };
      writeFileSync("results.json", JSON.stringify(output, null, 2));
      console.log("\nResults written to results.json");
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`\nFatal error: ${message}`);
    process.exit(1);
  } finally {
    try {
      await sandbox.stop();
      console.log("\nSandbox stopped.");
    } catch {
      console.warn("Warning: failed to stop sandbox.");
    }
  }
}

main();

/**
 * Create a Vercel Sandbox snapshot with agent-browser + Chromium pre-installed.
 *
 * Run once:   npx tsx scripts/create-snapshot.ts
 * Then set:   AGENT_BROWSER_SNAPSHOT_ID=<output id>
 *
 * This makes sandbox creation sub-second instead of ~30s.
 */

import { createSnapshot } from "../lib/agent-browser-sandbox";

async function main() {
  console.log("Creating Vercel Sandbox with agent-browser + Chromium...");
  console.log("This takes ~30-60 seconds on first run.\n");

  const snapshotId = await createSnapshot();

  console.log("\nSnapshot created successfully!");
  console.log(`\n  AGENT_BROWSER_SNAPSHOT_ID=${snapshotId}\n`);
  console.log("Add this to your .env.local or Vercel environment variables.");
}

main().catch((err) => {
  console.error("Failed to create snapshot:", err.message || err);
  process.exit(1);
});

---
"agent-browser": minor
---

### New Features
- **`inspect` command** - Opens Chrome DevTools for the active page by launching a local proxy server that forwards the DevTools frontend to the browser's CDP WebSocket. Commands continue to work while DevTools is open. Implemented in both Node.js and native paths. (#736)
- **`get cdp-url` subcommand** - Retrieve the Chrome DevTools Protocol WebSocket URL for the active page, useful for external debugging tools. (#736)
- **Native screenshot annotate** - The `--annotate` flag for screenshots now works in the native Rust daemon, bringing parity with the Node.js path. (#706)

### Improvements
- **KERNEL_API_KEY now optional** - External credential injection no longer requires `KERNEL_API_KEY` to be set, making it easier to use Kernel with pre-configured environments. (#687)
- **Browserbase simplified** - Removed the `BROWSERBASE_PROJECT_ID` requirement, reducing setup friction for Browserbase users. (#625)

### Bug Fixes
- Fixed Browserbase API using incorrect endpoint to release sessions (#707)
- Fixed CDP connect paths using hardcoded 10s timeout instead of `getDefaultTimeout()` (#704)
- Fixed lone Unicode surrogates causing errors by sanitizing with `toWellFormed()` (#720)
- Fixed CDP connection failure on IPv6-first systems (#717)
- Fixed recordings not inheriting the current viewport settings (#718)

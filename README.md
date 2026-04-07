<h1 align="center">Agent Browser</h1>

<p align="center">
  <strong>Give Claude native browser automation intelligence.</strong>
</p>

<p align="center">
  <a href="https://github.com/Brainrot-Creations/claude-plugins"><img src="https://img.shields.io/badge/claude--code-plugin--marketplace-blue" alt="Claude Code Plugin" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License" /></a>
</p>

---

## Install

In Claude Code:

```
/plugin marketplace add Brainrot-Creations/claude-plugins
```

```
/plugin install agent-browser@brainrot-creations
```

```
/reload-plugins
```

Then install the CLI:

```bash
npm install -g agent-browser
agent-browser install
```

Done. Talk to Claude naturally:

- _"Open my app and take a screenshot of the dashboard"_
- _"Fill out the signup form on this page"_
- _"Scrape the pricing table from this website"_

---

## How it works

Agent Browser is a fast native browser automation CLI built on Chrome DevTools Protocol. Claude uses it to navigate pages, interact with elements, capture screenshots, extract data, and automate any browser task — all through your local Chrome instance.

Every browser session runs in the background via a persistent daemon, so chained commands are fast and reliable.

---

## Troubleshooting

- **`agent-browser` not found** — Run `npm install -g agent-browser` then `agent-browser install`
- **Chrome not launching** — Run `agent-browser install` to download Chrome for Testing
- **Session conflicts** — Use named sessions: `agent-browser --session myapp open <url>`

---

## For Developers

This repo is a fork of [vercel-labs/agent-browser](https://github.com/vercel-labs/agent-browser). The Claude plugin definition (skills, commands) lives in [claude-plugins](https://github.com/Brainrot-Creations/claude-plugins/tree/main/plugins/agent-browser).

---

[MIT License](./LICENSE) · [contact@brainrotcreations.com](mailto:contact@brainrotcreations.com)

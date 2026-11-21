# Exa search for Dirgha agents

Dirgha registers Exa's official hosted MCP server in [`.mcp.json`](../.mcp.json), so any MCP client started from this repository gets web search and page fetch without writing a wrapper.

## Why this shape

Exa runs the server at `https://mcp.exa.ai/mcp`. Using the hosted server means there is no API key to embed in the repo, no local process to manage, and no dependency to install. Dirgha's own gate still screens every tool call — Exa is an MCP server like any other.

The configured tools are:

| Tool | What it does |
|---|---|
| `web_search_exa` | Search the web and return relevant, ready-to-use content |
| `web_fetch_exa` | Read clean content from known URLs |

Search and fetch work **keyless** at Exa's free rate limit. See the [Exa MCP docs](https://exa.ai/docs/get-started/exa-mcp.md) for advanced search, OAuth and API-key modes.

## Setup

Nothing to install. With the repository's `.mcp.json` loaded:

1. Start Dirgha (or any MCP client using this config).
2. Ask for something that needs the web, e.g.:
   - "Search for recent Dapr 1.15 release notes and summarize the breaking changes."
   - "Fetch https://exa.ai/docs and list the MCP tools it exposes."

If you hit a 429, connect with your own key instead:

```text
https://mcp.exa.ai/mcp?tools=web_search_exa,web_fetch_exa
```

with an `x-api-key` header, or use `?login` for OAuth. `agent_run` requires one of those; it is deliberately not enabled here.

## Verify the connection

```bash
node scripts/verify-exa-mcp.mjs
```

The script performs an MCP `initialize` and `tools/list` against the configured URL and asserts that `web_search_exa` and `web_fetch_exa` are present. It exits non-zero if the server is unreachable or the tools are missing.

Override the endpoint with `EXA_MCP_URL` when testing an authenticated or advanced-tool variant.

## Files

| Path | Purpose |
|---|---|
| `.mcp.json` | Registers `exa` alongside the Dirgha native kernel |
| `scripts/verify-exa-mcp.mjs` | Dependency-free smoke test |
| `docs/exa-search.md` | This document |

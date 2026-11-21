# Dirgha 2.0 — Architecture

A sovereign coding and physical-AI harness that adapts to your workflow without forcing governance overhead on solo developers. Headless one-shots, an Ink TUI, a readline REPL, parallel sub-agent fleets, DAG-chained sequential agents, remote MCP servers, Open GPU Cloud Market dispatch, and the Rust native kernel all run behind one launcher (`bin/dirgha.mjs`).

## Purpose

Engineers ship working code and reliable autonomous systems. Dirgha pairs a fast TypeScript agent loop (`src/`) with a Rust micro-kernel (`crates/`, 24 MCP tools) and an optional WebAssembly safety gate (`lokahi_gate.wasm`). Solo developers default to `--profile developer` (zero governance friction), while teams and regulated enterprises enable LOKAHI enforcement, Arniko SARIF scanning, Ahimsa impact manifests, and immutable Org Policy Locks (`/etc/dirgha/policy.json`).

It is **free-tier and local-first**: the same machinery runs on local Ollama / llama.cpp models, OpenRouter `:free` tiers, or enterprise BYOK endpoints, with a 4-tier failover cascade that swaps a failed model without losing the partial transcript.

## Core Design Principles

1. **Progressive governance (zero forced friction).** `developer` profile defaults to `lokahi: off`, `arniko: false`, `gpuMarket: true`. Teams opt in via `--profile team|enterprise|robotics` or lock policy fail-closed via `/etc/dirgha/policy.json`.
2. **Fail-closed when enforced.** When LOKAHI is in `enforce` mode, `createToolExecutor` evaluates real tool payloads (shell command, file path, browser URL, git args, GPU jurisdiction/spend) through `lokahi_gate.wasm` and optional LOKAHI/Ahimsa manifests; missing or failing gates refuse execution.
3. **Adapt to workflows; don't fork dirgha.** Skills, themes, hooks, MCP servers, **TypeScript / ESM extensions**, and **third-party GPU cloud providers** (`specs/GPU_PROVIDER_SCHEMA.json`) are loadable artifacts, not patches.
4. **Every model. Every wire. Every transport.** OpenAI chat-completions, Anthropic messages, Gemini generate, MCP stdio, MCP HTTP/SSE — one factory, providers as config blobs.
5. **Failover is multi-tier and lossless.** A 4-tier cascade (user → same-family → registry → free fallback) keeps the agent alive with mid-session transcript resume and stall abort.
6. **Multi-key BYOK with cooldown rotation.** Rate-limited keys cool out automatically while the next-priority key takes over.
7. **Crash-safe persistence & hardened boundaries.** Append-only JSONL sessions, symlink-safe workspace containment, fail-closed IPv6/DNS SSRF guard, OS-CSPRNG cryptographic keys, and strict sandbox fail-closed mode.
8. **Honest execution.** Tools never fabricate passing audits, SAT dossiers, or scanner findings; demo tools explicitly mark `"simulated": true`.

## What Dirgha 2.0 Includes

- **Terminal coding agent:** `dirgha "prompt"` (one-shot), `dirgha` (Ink TUI), `dirgha resume <id>`, `dirgha fleet launch <goal>`, `dirgha fleet dag ...`, `dirgha verify "<goal>" --accept "<cmd>"`.
- **29 built-in tools:** `fs_read`, `fs_write`, `fs_edit`, `fs_ls`, `shell`, `search_grep`, `search_glob`, `git`, `github`, `browser`, `checkpoint`, `cron`, `task`, `gpu_compute`, LSP lookups, media/web tools, and MCP tools.
- **37 CLI subcommands + 20 interactive slash commands** across `act`, `plan`, `verify`, and `ask` modes.
- **Open GPU Cloud Market (`src/gpu/`):** Multi-cloud GPU orchestration (`dirgha gpu providers|certify|register|remove`) with SSRF-safe third-party provider certification, residency filtering, and hourly budget limits.
- **Arniko & Ahimsa Bridges:** Opt-in `dirgha scan --sarif` security scanning (`gitleaks`, `semgrep`, `trivy`) and Ahimsa-to-LOKAHI manifest compilation.
- **Rust Native Kernel (`crates/`):** 24 MCP tools, bearer-authenticated local Cockpit (`data/cockpit.html`), CycloneDX SBOM/OpenVEX (`dtrack-rs`), hash-chained ledger (`arniko-audit`), and MuJoCo robotics evaluation sidecar.

## Directory Layout

```
bin/
└── dirgha.mjs        unified CLI launcher (TS agent + Rust kernel + doctor)
crates/               Rust micro-kernel (lokahi-gate, dirgha-core, native-host, memory-mgp, dtrack-rs, arniko-audit, flywheel-engine, llm-router)
specs/                JSON Schemas & Rust adapter traits (incl. GPU_PROVIDER_SCHEMA.json)
src/
├── kernel/           agent loop, message types, event stream, projection
├── safety/           modules-config, lokahi-runtime, policy (WASM gate), ahimsa-bridge
├── security/         arniko-bridge (SARIF v2.1.0), skill scanner
├── gpu/              Open GPU Cloud Market (RunPod/Modal/Lambda/Vast + third-party provider-spec)
├── providers/        wire transports + provider classes; rate-limit middleware
├── intelligence/     model catalogue, cost tracker, error classifier, models refresh
├── auth/             keystore + keypool (multi-key, cooldown) + providers registry
├── context/          soul, primer, git-state, mode, mode-enforcement, compaction, ledger, session
├── audit/            append-only JSONL writer + reader subcommand
├── extensions/       loadable plugin API (registerTool / registerSlash / registerSubcommand / on)
├── tools/            registry + 29 built-in tools (incl. gpu_compute) + task subagent dispatcher
├── mcp/              client + stdio + HTTP/SSE transports + bearerProvider rotation
├── skills/           agentskills.io frontmatter loader + matcher + runtime
├── subagents/        delegator + pool for the `task` tool
├── fleet/            parallel git-worktree dispatch
├── hooks/            registry + AgentHooks shape + config-bridge
├── cli/              entry points (main, interactive, 37 subcommands, 20 slashes)
└── tui/              Ink TUI with <Static> transcript + StatusBar
```

## How a one-shot turn flows

```
$ dirgha "implement log-histo per SPEC.md" -m hy3
   │
   ▼ cli/main.ts
   ├─ parseFlags + resolveModelAlias        (kimi → moonshotai/kimi-k2-instruct, etc.)
   ├─ hydrateEnvFromPool                     (multi-key BYOK, cooldown-aware)
   ├─ hydrateEnvFromKeyStore                 (legacy single-slot)
   ├─ loadExtensions(~/.dirgha/extensions)   (user plugins register tools / slashes / hooks)
   ├─ loadSoul, loadProjectPrimer, resolveMode, loadSkills + matchSkills
   ├─ providers.forModel  ◀────── construction-time failover
   ├─ createCostTracker, createErrorClassifier
   ├─ buildAgentHooksFromConfig ⊕ enforceMode
   ├─ createCompactionTransform              (75% trigger; prints `[compacted]` banner)
   ├─ SubagentDelegator + register `task` tool
   ▼
runAgentLoop (kernel/agent-loop.ts)
   ├─ for each turn:
   │    ├─ beforeTurn hook (continue / abort)
   │    ├─ contextTransform (compaction + skills injection)
   │    ├─ provider.stream(req) ──── chunks → events
   │    ├─ for each tool_use:
   │    │    ├─ beforeToolCall hook (mode-enforce + user) — can veto
   │    │    ├─ toolExecutor.execute(call, signal)
   │    │    └─ afterToolCall hook (rewrite)
   │    └─ afterTurn hook (usage)
   └─ stopReason: end_turn | tool_use | max_turns | error | aborted
   ▼
runtime failover (mid-session): if stopReason=error and a fallback is registered, swap and resume from result.messages with maxTurns − turnCount remaining
   ▼
persist: session.append(message) for every new message + appendAudit(turn-end)
   ▼
exit
```

## Test floor

`npm run test:cli:offline` — **38 / 38 green in 16 s.** No row in the parity matrix closes without a test that locks it in. 3 network suites (`hooks`, `cancel`, `provider_matrix`) gated on API keys.

## Extending dirgha

Drop an ESM module at `~/.dirgha/extensions/<name>/index.mjs`:

```js
export default async function (api) {
  api.registerTool({
    name: "deploy",
    description: "Deploy to staging",
    inputSchema: { type: "object", properties: { env: { type: "string" } } },
    execute: async (input) => ({
      content: "deployed",
      isError: false,
      durationMs: 0,
    }),
  });
  api.registerSlash({
    name: "stats",
    description: "project stats",
    handler: () => "OK",
  });
  api.on("turn_start", (ev) => {
    /* observe every turn */
  });
}
```

The loader awaits async default exports. Extension errors are isolated — a broken extension is named on stderr but doesn't break the rest of the CLI.

## Authoring a skill

Drop `~/.dirgha/skills/<name>/SKILL.md`:

```markdown
---
name: my-skill
description: Use when the user asks about X
triggers:
  keywords: [foo, bar]
---

# My skill

Step 1. Do this.
Step 2. Then that.
```

Or install from a git repo:

```bash
dirgha skills install https://github.com/user/awesome-pack
dirgha skills list
```

Compatible with the [agentskills.io](https://agentskills.io) frontmatter standard.

## Roadmap

| Sprint | Goal                                                               | Status      |
| ------ | ------------------------------------------------------------------ | ----------- |
| 1      | `dirgha update --check / --self / --packages`                      | ✓ shipped   |
| 2      | `dirgha models refresh`                                            | ✓ shipped   |
| 3      | TS / ESM extensions API                                            | ✓ shipped   |
| 4      | This doc + README + ROADMAP refresh                                | ✓ shipped   |
| 5      | Pi-package npm marketplace (`dirgha install npm:@foo/dirgha-pack`) | spec only   |
| 6      | OAuth flows for Anthropic Pro / ChatGPT Plus                       | spec only   |
| 7      | Web dashboard for audit + cost (live HTML view)                    | not started |

The matrix file and the test sweep are the binding contract for each sprint.

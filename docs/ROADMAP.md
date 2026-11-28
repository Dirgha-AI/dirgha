# Dirgha 2.0 — Roadmap

The shipped state and the binding contract for what comes next.

## Shipped (v2.0.0)

- ✓ Unified TS coding agent (`src/`) + Rust kernel (`crates/`, 24 MCP tools) behind one launcher (`bin/dirgha.mjs`)
- ✓ Modular governance profiles (`developer`, `safe-dev`, `team`, `enterprise`, `robotics`) with per-session CLI toggles (`--lokahi`/`--no-lokahi`, `--arniko`/`--no-arniko`, `--no-gpu`) and fail-closed Enterprise Org Policy Lock (`/etc/dirgha/policy.json` / `DIRGHA_ORG_POLICY`)
- ✓ Full LOKAHI v1.1 conformance & cryptography (`src/safety/lokahi-crypto.ts`, `src/safety/lokahi-conformance.ts`, `dirgha policy keygen|init|sign|verify|approve|evidence`): RFC-8785 JCS + Ed25519 signed manifests, argument-level tool rules, dual-control 45s Ahimsa S2 approval tickets with replay defense, and SSRF-guarded external HTTP gateway adapter
- ✓ Runtime LOKAHI WASM gate wired into `createToolExecutor` (evaluating real tool payloads, LOKAHI manifests, argument rules, GPU residency/spend caps, and OS-CSPRNG cryptographic keys across Rust crates)
- ✓ Hardened security boundaries: fail-closed IPv6/DNS SSRF guard (`url-guard.ts`), symlink-safe workspace containment, strict sandbox fail-closed mode, Windows process-tree termination, and per-call timeout abort propagation
- ✓ Commercial Open GPU Cloud Market (`src/gpu/`): smart cheapest-compliant GPU router (`dirgha gpu find`), open third-party provider onboarding (`specs/GPU_PROVIDER_SCHEMA.json`, `dirgha gpu init-manifest|certify|register`), RFC-4180 finance chargeback CSV export (`dirgha gpu chargeback`), and zero-dependency partner starter server (`examples/gpu-provider-starter/`)
- ✓ Opt-in Arniko security automation (`dirgha scan` + `src/security/arniko-hooks.ts`): zero-dependency `dirgha-builtin-secrets` scanner with credential redaction, `onAgentOutput`/`onPreCommit` runtime hooks (bypassed in `developer` profile), honest external CLI detection (`gitleaks`/`semgrep`/`trivy`), OASIS SARIF v2.1.0 output, and Ahimsa-to-LOKAHI manifest bridge
- ✓ Multi-tab Enterprise Control Plane UI (`data/cockpit.html` + `scripts/dev-server.mjs`): live Governance & Compliance Evidence Pack generator, Open GPU Cloud Market certifier, Arniko SARIF secret scanner, and Physical AI/MuJoCo hardware viewport
- ✓ Production release & deployment engineering: cross-platform Rust kernel + `lokahi_gate.wasm` + SHA-256 GitHub Release workflow (`.github/workflows/publish.yml`), the published Docker Compose private-stack template (`docker-compose.private-stack.example.yml`), and hardened Kubernetes manifests delivered to enterprise customers
- ✓ Multi-provider agent loop: 14+ provider families + any OpenAI-compatible/Ollama endpoint, BYOK pool with priority + LRU + cooldown + 4-tier failover cascade
- ✓ Ink TUI with streaming markdown, tool approvals, paste collapse, and virtualized transcript
- ✓ 29 built-in tools & 38 subcommands across `act`/`plan`/`verify`/`ask` modes
- ✓ Fleet parallel git-worktree agents, DAG chaining, sub-agent pool, session persistence, checkpoints, ledger search, LSP lookups, skills, and ESM extensions
- ✓ Physical AI MuJoCo evaluation harness with honest sidecar failure reporting (zero fabricated SAT passes)

## Next Milestones (v2.1+)

- **Real robotics policy & hardware adapters**: replace remaining `"simulated": true` demo tools with real VLA inference, LeRobot Hub push, and hardware CAD/manufacturing integrations behind S2 approvals.
- **Public GPU Cloud Partner Directory**: automated nightly health/latency certification for third-party providers implementing `specs/GPU_PROVIDER_SCHEMA.json`.
- **Enterprise Terraform modules & Helm chart repo**: signed OCI Helm chart publication complementing the private Kubernetes manifests delivered to customers.

## On deck

- **Pi-package npm marketplace** — `dirgha install npm:@foo/dirgha-pack` and `dirgha install git:github.com/user/repo` for full packages bundling extensions + skills + prompts + themes.
- **OAuth flows for Anthropic Pro / ChatGPT Plus / Copilot** — needs maintained client_ids per provider.
- **Web dashboard** — live HTML view of audit + cost + ledger.
- **Theme token upgrade** — semantic tokens replacing flat Palette; 11 baked-in themes from Gemini CLI's Apache-2.0 source.
- **Provider extensibility skill** — `/provider add <name>` slash command with 6-step recipe.
- **Sub-agent orchestration patterns** — consensus voting, divide-and-conquer beyond current fleet/DAG shapes.

## Constraints

- Every src file ≤ 200 lines.
- Every parity-matrix row closure cites a code path and a test.
- Every sprint ends with `npm test` green (offline unit, gateway, and launcher suites). Live-network and platform-specific checks run separately via `npm run test:e2e`.
- Soul and tone are not changed without explicit user request.
- No competitor names in code comments, file content, or stdout/stderr messages.

## How a fresh contributor picks up the work

1. Read `docs/ARCHITECTURE.md` for the kernel + provider model.
2. Read `docs/cli/index/index.md` for the full feature index.
3. Run `npm test` to confirm the offline green baseline.
4. Write or extend a test before changing code.
5. Open an issue or PR with the proposal.

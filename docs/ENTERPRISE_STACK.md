# Dirgha Enterprise Stack — Commercial & Sovereign Deployment Guide

Dirgha 2.0 is designed around **progressive governance**: solo developers get a fast, zero-friction local coding agent out of the box, while security teams, regulated enterprises, and robotics integrators can turn on **LOKAHI** policy enforcement, **Arniko** supply-chain scanning, **Ahimsa AI** impact manifests, and **Open GPU Cloud Market** data-residency controls using standard profiles or an IT-managed organization lock.

## 1. Unified Stack Architecture

| Layer | Component | Default in `developer` | Purpose |
|---|---|---|---|
| **Run** | **Dirgha 2.0** (`@dirgha/code`) | Always On | Coding CLI/TUI, 29 built-in tools, fleet/DAG worktrees, 24-tool Rust MCP kernel, MuJoCo robotics harness |
| **Compute** | **Open GPU Cloud Market** (`src/gpu/`) | On | Multi-cloud GPU routing (RunPod, Modal, Lambda, Vast.ai + third-party certified providers via `specs/GPU_PROVIDER_SCHEMA.json`) with spend caps & jurisdiction filters |
| **Enforce** | **LOKAHI** (`lokahi_gate.wasm` + manifest policy) | Off (Opt-in) | Fail-closed capability firewall (`off` / `advisory` / `enforce`), S2 Ed25519 human approvals, signed hash-chained evidence |
| **Scan** | **Arniko Bridge** (`dirgha scan`) | Off (Opt-in) | Secret, SAST, and SBOM/CVE scanning (`gitleaks`, `semgrep`, `trivy`) with OASIS SARIF v2.1.0 output |
| **Assess** | **Ahimsa AI Bridge** (`src/safety/ahimsa-bridge.ts`) | Off (Opt-in) | Validates Ahimsa impact/consent manifests and compiles them into LOKAHI tool + GPU residency policies |

## 2. Five Built-In Profiles (Zero Forced Friction)

Select a profile via `--profile <name>`, `DIRGHA_PROFILE=<name>`, or `~/.dirgha/config.json`:

| Profile | LOKAHI Mode | Arniko Scan | Ahimsa Manifest | GPU Market | Intended Audience |
|---|---|---|---|---|---|
| `developer` *(default)* | `off` | `false` | `false` | `true` | Solo builders & OSS contributors — zero governance overhead |
| `safe-dev` | `advisory` | `false` | `false` | `true` | Developers who want non-blocking safety warnings logged |
| `team` | `enforce` | `true` | `false` | `true` | Engineering teams enforcing repo-level security & spend guardrails |
| `enterprise` | `enforce` | `true` | `true` | `true` | Regulated orgs requiring signed policies, SARIF evidence & residency |
| `robotics` | `enforce` | `true` | `true` | `true` | Physical-AI & MuJoCo/SAT pipelines requiring S2 human-in-the-loop |

### Per-Session Module Toggles

When no Organization Policy Lock is installed, developers can toggle any module freely:

```bash
# Default solo experience (no LOKAHI, no Arniko)
dirgha "refactor src/utils/parser.ts"

# Turn on LOKAHI advisory or strict enforcement for one run
dirgha --lokahi "deploy migration script"
dirgha --lokahi-mode=advisory "audit network calls"

# Run with Arniko SARIF scanning
dirgha scan --sarif -o security-report.sarif

# Explicitly disable governance or GPU cloud dispatch
dirgha --no-lokahi --no-arniko "local prototype"
dirgha --no-gpu "offline-only build"
```

## 3. Enterprise Organization Policy Lock (Fail-Closed)

Enterprises can prevent `--no-lokahi`, `--no-arniko`, or profile downgrades by deploying a read-only policy lock file at `/etc/dirgha/policy.json` (or pointing `DIRGHA_ORG_POLICY` to a managed path):

```json
{
  "locked": true,
  "profile": "enterprise",
  "lokahi": {
    "mode": "enforce",
    "failClosed": true,
    "manifestPath": "/etc/dirgha/lokahi-manifest.json"
  },
  "arniko": {
    "enabled": true,
    "blockOnHigh": true
  },
  "ahimsa": {
    "enabled": true,
    "requireSignedManifest": true
  },
  "gpuMarket": {
    "enabled": true,
    "allowedJurisdictions": ["EU", "US"],
    "maxHourlyUsd": 12.0
  }
}
```

Behavior guarantees:
- If `DIRGHA_ORG_POLICY` is set to a missing or malformed file, Dirgha **fails closed** and refuses to start.
- Any attempt to pass `--no-lokahi`, `--no-arniko`, or a weaker profile than the lock requires exits with code `1` and an explicit policy-lock error.
- Tool execution in `src/tools/exec.ts` automatically enforces active org-lock rules across one-shot CLI, interactive TUI, daemon, and ACP server entrypoints.

## 4. Open GPU Cloud Market (Third-Party Provider Onboarding & Smart Routing)

Cloud providers can onboard to Dirgha's GPU market without forking the codebase:

1. Scaffold a compliant manifest or run the zero-dependency reference partner server (`examples/gpu-provider-starter/server.mjs`) implementing `specs/GPU_PROVIDER_SCHEMA.json` (`/catalog`, `/instances`, `/instances/{id}`).
2. Certify and register the provider locally (with automatic schema validation + SSRF/DNS checks).
3. Route workloads to the cheapest compliant GPU across all built-in + third-party providers and export RFC-4180 finance chargeback CSVs:

```bash
dirgha gpu init-manifest --id=my-cloud --name="My Sovereign GPU" --endpoint=https://gpu.mycloud.example/v1
dirgha gpu certify ./my-cloud-provider.json --probe
dirgha gpu register ./my-cloud-provider.json
dirgha gpu find --min-vram=24 --jurisdiction=EU --compliance=soc2,gdpr --max-price=2.50
dirgha gpu chargeback --csv > gpu-chargeback.csv
```

See `docs/gpu-cloud-market.md` for the full provider certification guide.

## 5. LOKAHI Cryptography, Conformance & Arniko Automation

- **Signed Boundary Manifests (`dirgha policy`)**: RFC-8785 JCS canonicalization + Ed25519 signing/verification (`dirgha policy keygen|init|sign|verify|evidence`) and dual-control S2 approval tickets (`dirgha policy approve --ttl=45` honoring the 45-second Ahimsa window with replay nonce defense).
- **LOKAHI v1.1 Conformance & Argument Rules**: Regex, glob, exact, and forbidden (`null`) argument-level policies enforced in `src/safety/lokahi-runtime.ts`, plus an SSRF-guarded external HTTP gateway client (`src/safety/lokahi-conformance.ts`).
- **Opt-in Arniko Runtime Hooks**: Zero-friction in `developer` profile; in `team` and `enterprise` profiles, `onAgentOutput` blocks hardcoded secrets on file writes and `onPreCommit` scans workspaces before `git commit`/`push` via `dirgha-builtin-secrets` (plus optional `gitleaks`/`semgrep`/`trivy` CLIs with OASIS SARIF v2.1.0 output).
- **Enterprise Control Plane UI**: `npm run dev` serves the 4-tab Governance, GPU Market Certifier, Arniko SARIF Scanner, and Physical AI Cockpit on port `3000`.

## 6. Regulatory & Standards Alignment

| Standard / Regulation | Dirgha Stack Capability |
|---|---|
| **EU AI Act (High-Risk & GPAI)** | LOKAHI fail-closed capability gate, human-in-the-loop S2 Ed25519 approvals, Ahimsa risk/consent manifests, Compliance Evidence Packs (`dirgha policy evidence`) |
| **NIST AI RMF 1.0 (Govern / Map / Measure / Manage)** | Profiled governance controls, Arniko SARIF vulnerability measurement, reproducible MuJoCo evaluation |
| **ISO/IEC 42001 (AIMS)** | Org-wide immutable `/etc/dirgha/policy.json`, signed decision ledger, verifiable tool & argument boundaries |
| **EU Cyber Resilience Act (CRA)** | CycloneDX SBOM & OpenVEX (`sbom-vex`), Arniko SARIF v2.1.0 scanning, OS-CSPRNG cryptographic keys |
| **India DPDP / GDPR Data Residency** | Local-first BYOK + Ollama/llama.cpp offline execution, GPU provider jurisdiction & compliance routing (`soc2`, `iso27001`, `dpdp`, `gdpr`) |

## 7. Commercial Packaging Tiers

| Tier | Licensing & Delivery | Included Capabilities |
|---|---|---|
| **Open Core (OSS)** | Apache-2.0 (`@dirgha/code`) | Full coding CLI/TUI, 29 tools, 38 subcommands, 24-tool Rust MCP kernel, local WASM gate, Open GPU Cloud Market SDK |
| **Team** | Commercial Support & Rule Packs | Curated LOKAHI policy packs, Arniko pre-commit hooks & CI SARIF templates, multi-provider GPU budget & chargeback CSVs |
| **Enterprise Sovereign** | Private Stack (delivered to customers; public starter at `docker-compose.private-stack.example.yml`) | Org Policy Lock rollout, Ed25519 manifest signing, air-gapped local LLM + private GPU cluster routing, auditor evidence exports |
| **Robotics Integrator (SAT)** | Enterprise + Physical-AI Pack | MuJoCo CI harnesses, hardware S2 approval workflows, Control Plane mobile approvals, custom actuator/VLA adapters |
| **GPU Cloud Partner Program** | Certified Provider Listing | Reference starter server (`examples/gpu-provider-starter/`), certification against `specs/GPU_PROVIDER_SCHEMA.json`, marketplace listing |

## 8. Quickstart Private Stack Deployment (Docker Compose)

```bash
# Docker Compose (single host / workstation / VM) — the published template is a working starter
cp .env.example .env
docker compose -f docker-compose.private-stack.example.yml up -d
# With optional local Ollama + Arniko scanner worker:
docker compose -f docker-compose.private-stack.example.yml --profile local-llm --profile security up -d
```

The production-configured Compose bundle and the hardened Kubernetes manifests (EKS / GKE / AKS /
air-gapped on-prem), including the Secret and signed-manifest mounting runbook, are delivered to
Enterprise Sovereign customers and are not published in this repository. Request it through the
[enterprise pilot issue](https://github.com/Dirgha-AI/dirgha/issues/new).

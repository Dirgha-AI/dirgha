# Dirgha Cluster — Independent Audit & Next-Steps Prescription (Pillar 1 & 2)

**Auditor:** Independent Principal Systems & Security Auditor
**Date:** Mon 23 November 2026
**Target:** `dirgha cluster` scaffolding (Pillar 1 Inference Engineering + Pillar 2 Model & API Orchestration) and the `model-catalog-sync` skill
**Scope:** Targets A–E per brief
**Git state:** `main` at `60a43f3`, ahead of `origin/main` by 2 commits, **not pushed** — compliant with Salik Shah's GitHub rule (local-only).

---

## 1. Executive Summary

The scaffolding for `dirgha cluster` (Pillar 1 & 2) and the `model-catalog-sync` skill is **complete as skeleton scaffolding and compiles/passes its existing tests**, but it is **not yet a functioning distributed inference system**. The Rust core (`crates/dirgha-cluster`) defines data structures, partitioning math, and a wire-frame format, but contains **zero networking, zero compute-backend integration, and zero actual distributed execution**. The TypeScript CLI (`cluster.ts`) simulates cluster state in JSON files and emits a `mock_sig` join token that is cryptographically incompatible with the Rust `verify_join_token`. The model-catalog sync script runs and produces a canonical catalog, but its canonical-schema translators are defined yet never wired in. LOKAHI (Target E) is solid — 102/102 tests pass.

**Bottom line:** Pillar 1 & 2 are *architected* but not *implemented*. The next phase is to wire up the active TCP loopback server on port 54125, bind GGUF layer slicing via libllama/Candle C-FFI, and integrate SGLang RadixAttention prefix caching — as the strategy blueprints themselves prescribe.

---

## 2. Audit Scorecard

| Target | Area | Verdict | Summary |
|:--|:--|:--|:--|
| **A** | Rust Core Engine (`crates/dirgha-cluster`) | **WARN** | Compiles; 2/2 unit tests pass. But skeleton only: no TCP transport, no mDNS discovery, no compute backend, no actual distributed execution. |
| **B** | TypeScript CLI & Provider Integration | **WARN** | Build/typecheck/tests all pass (4/4 cluster, 30/30 dispatch). But cluster is simulated via JSON files; `mock_sig` join token is incompatible with Rust verifier; provider targets a dead endpoint (`localhost:54125` with no listener). |
| **C** | Model Catalog Synchronizer Skill | **PASS** | Sync runs end-to-end: 4,648 LiteLLM + OpenRouter → 5,105 unique models written to `~/.dirgha/models-catalog.json`. Code smells + unwired canonical-schema translators noted. |
| **D** | Strategy Blueprints (`Dirgha-Internal\strategy\market-and-vision\`) | **PASS** | Coherent, internally consistent strategy docs (Exo/SGLang/LiteLLM harvest, P2P arch, Sovereign CloudOps stack). Correctly identify the missing implementation pieces. |
| **E** | LOKAHI Stability Check | **PASS** | 102/102 tests pass (`test_core.py` + `test_decisions.py`). Deterministic security gate is stable. |

**Overall:** Pillar 3 (LOKAHI) is solid. Pillar 1 & 2 are **scaffolded, not functional**.

---

## 3. Verification Evidence

| # | Command | Result |
|:-|:-|:-|
| A1 | `cargo test -p dirgha-cluster` | **2 passed, 0 failed** (`partition_math_70b_three_heterogeneous_nodes`, `tensor_frame_roundtrip`) |
| B1 | `npm run typecheck` | **exit 0** (no TS errors) |
| B2 | `npm run build` | **exit 0** (build + postbuild succeed) |
| B3 | `vitest cluster.test.ts` | **4 passed** |
| B4 | `vitest dispatch.test.ts` | **30 passed** |
| B5 | `bin/dirgha.mjs cluster --help` | **Works** — all 6 subcommands documented |
| C1 | `python sync_catalogs.py C:\Users\ABC\.dirgha` | **4,648 LiteLLM + OpenRouter → 5,105 unique models written** |
| E1 | `python -m pytest test_core.py test_decisions.py` | **102 passed in 13.12s** |

---

## 4. Identified Gaps / Flaws

### Target A — Rust Core Engine (`crates/dirgha-cluster`)

**A-1. No network transport (critical gap).** `transport.rs` defines a clean 34-byte binary wire frame (`DIRGHA_MAGIC` + Blake3 checksum + length-prefixed payload) and roundtrips it in-memory, but there is **no `tokio` TCP listener, no client, no server on port 54125, and no activation ring**. The architecture doc (Module 3) promises `tokio`-based zero-copy TCP/QUIC forwarding; none exists. The coordinator cannot send or receive a single activation.

**A-2. Weak integrity checksum (protocol weakness).** The frame checksum is Blake3 truncated to **4 bytes** (~1/2³² collision probability per frame). At 16 KB activation traffic across a 3-node ring, silent corruption is a real risk over long inference sessions. No sequence-number replay protection, no frame authentication (no MAC), and no mTLS despite the architecture doc calling for node mutual TLS.

**A-3. Join-token trust model is incomplete.** `ClusterAuth::verify_join_token` cryptographically verifies the signature against the *embedded* public key, but never checks that public key against a **trusted issuer / leader allowlist**. Any entity with an Ed25519 keypair can mint a structurally valid `dirgha-join_...` token. Rogue nodes can present valid-looking tokens.

**A-4. `ClusterTopology::new` sets `created_at_unix_ms: 0`** — never populated with wall-clock time. Minor, but breaks any time-based topology staleness or token-expiry correlation.

**A-5. Partitioner ignores backend heterogeneity and per-node headroom.** `partition_layers` weights purely by `available_memory_bytes`. A CPU node and a CUDA node receive equal layer weight per byte, despite different compute characteristics. Only *total* cluster memory is validated against `1.10 × model_weight_bytes`; a single node can still be assigned a slice larger than its own usable memory (OOM risk). No re-partitioning or CPU-offload fallback on node departure (the architecture doc promises this; it is not implemented).

**A-6. Engine is a pass-through simulation.** `ClusterEngine::step_forward` echoes `input_activation` back unchanged (no actual layer compute, no GGUF/Candle binding). Workers cannot partition (`load_and_partition_model` requires `topology` = leader only). No heartbeat, no leader election, no failover.

**A-7. Missing error boundaries.** No timeout on activation transfers, no backpressure, no circuit breaker for a slow/stale node, no OOM handling for a node whose slice exceeds its memory.

### Target B — TypeScript CLI & Provider Integration

**B-1. `mock_sig` join token is cryptographically incompatible (critical gap).** `cluster.ts` `init` emits `dirgha-join_${clusterId}:${expire}:local:mock_sig`. The Rust `verify_join_token` expects 4 colon-separated parts where part 4 is a hex-encoded 64-byte Ed25519 signature. `mock_sig` (8 ASCII chars) is not valid hex of 64 bytes and would fail `hex::decode` / `Signature::from_bytes`. TS-issued tokens cannot be verified by the Rust engine, and vice versa.

**B-2. Cluster state is simulated, not distributed.** `init`/`join`/`status`/`partition`/`run`/`leave` all operate on `~/.dirgha/cluster-state.json` — a local file. `join` fabricates a `remote_leader` node with hardcoded 24 GB CUDA and a `127.0.0.1:54126` local worker. No socket is opened, no handshake occurs, no peer is contacted. The cluster is a single-node fiction.

**B-3. Dead endpoint.** `ClusterProvider` routes `cluster/*` and `local/*` to `http://localhost:54125/v1/chat/completions`, but **nothing listens on 54125** (no Rust TCP server, no TS HTTP server). Every cluster model request will fail with connection-refused until the loopback server is wired.

**B-4. Port conflation.** `run` reports gateway endpoint `http://localhost:4000/v1/chat/completions`, but `init` defaults the coordinator to port 54125. The architecture separates cluster coordinator (54125) from gateway (4000); the CLI output conflates them.

**B-5. `isKnownProvider` inconsistency.** `dispatch.ts` can route to `"cluster"`, but `isKnownProvider("cluster")` returns `false` (line 176–178 omits `cluster`). Minor but breaks any caller that gates on `isKnownProvider`.

**B-6. No error boundary for unavailable cluster.** `stream()` in `ClusterProvider` blindly POSTs to `localhost:54125`; connection failure surfaces as a raw fetch error with no retry, no fallback, and no graceful degradation to a local/remote model.

### Target C — Model Catalog Synchronizer Skill

**C-1. Fragile annotation ordering (code smell).** `DirghaModelDescriptor.id: string_id = ""` references `string_id` (defined as `string_id = str` on line 42) *before* it is declared. It works only because `from __future__ import annotations` defers evaluation; removing that import breaks the module. Reorder for clarity.

**C-2. Canonical-schema translators are unwired (gap).** `references/canonical_schemas.py` defines the full bidirectional OpenAI↔Anthropic Rosetta Stone (`openai_to_anthropic`, `anthropic_to_openai`, `DirghaCanonicalRequest`), but **`sync_catalogs.py` never imports or uses it**, and nothing in the skill integrates the translators into the sync pipeline or the gateway. The dual-face schema standard is documented but not connected.

**C-3. No offline/air-gapped mode.** The script requires network access to `raw.githubusercontent.com` (LiteLLM) and `openrouter.ai` (OpenRouter). For sovereign on-prem / air-gapped data centers there is no local-mirror or catalog-bundle fallback.

**C-4. No tests.** There are no unit tests for `sync_catalogs.py` or `canonical_schemas.py` (normalization, cost conversion, merge precedence).

### Target D — Strategy Blueprints

No code defects (documentation only). The three blueprints are coherent and correctly identify the missing implementation pieces (libllama C-FFI, SGLang RadixAttention, Exo P2P ring, mDNS discovery). **Action: treat them as the implementation spec, not as shipped code.**

### Target E — LOKAHI

No defects found. 102/102 tests pass, including the v0.1.3 disjoint-quorum fixes, the kinetic-ahimsa physical-envelope interlock, the stopping-distance CBF, and the MCP stdio-proxy JSON-RPC interceptor. The experimental decisions tier (v0.1.4) is off-by-default and fails closed. Stable.

---

## 5. Next Steps for the Lead Engineer

The following is an exact, step-by-step implementation roadmap for the next phase. It follows the prescriptions already written in `DIRGHA_CLUSTER_P2P_ARCHITECTURE.md` and `OPEN_SOURCE_HARVEST_BLUEPRINT.md`.

### Phase 1: Wire the active TCP loopback server (port 54125) — Week 1

**Goal:** A real coordinator process listens on `127.0.0.1:54125` and can send/receive `TensorFrame`s.

1. **Add `tokio` + `tokio-util` to `crates/dirgha-cluster/Cargo.toml`** (workspace dependency), with a `runtime` feature gated behind `--features rt`.
2. **Implement `TcpTransport` in `transport.rs`:**
   - `TcpListener` bound to `0.0.0.0:54125` (configurable; default 54125).
   - Async `send_frame(frame: &TensorFrame)` / `recv_frame()` using length-prefix framing (read 34-byte header, then `payload_len` bytes).
   - Upgrade checksum: full 32-byte Blake3 (or HMAC-Blake3 with a cluster session key) instead of 4-byte truncation. Add a per-frame `nonce`/`sequence` field to the header to prevent replay.
3. **Implement `Coordinator` in `engine.rs`:**
   - Accepts TCP connections from workers, maintains a live `ClusterTopology` with heartbeat timestamps.
   - Simple leader-election placeholder (first binder wins; document the limitation).
   - Broadcasts partition plan to workers after `load_and_partition_model`.
4. **Wire `ClusterProvider` (TS) to the live socket:** Change `ClusterProvider.stream` to open a TCP connection to `localhost:54125` (or a Unix socket) and speak the `TensorFrame` binary protocol instead of `http://localhost:54125/v1`. Keep the HTTP fallback as a documented future option.
5. **Replace `mock_sig`:** `cluster.ts` `init` must generate a real Ed25519 keypair (via `noble-ed25519` or a Rust FFI/N-API call to `dirgha-cluster::ClusterAuth::generate_join_token`) and emit `dirgha-join_{cluster_id}:{expire}:{pubkey_hex}:{sig_hex}` matching the Rust verifier exactly.
6. **Add integration test:** Rust `#[cfg(test)]` spin up a `TcpListener` on localhost, send one `ActivationForward` frame, decode it, assert roundtrip end-to-end. Run under `cargo test`.

**Definition of Done (Phase 1):** `cargo test -p dirgha-cluster` passes (existing + new transport test), and a TS script can open a TCP connection to `localhost:54125`, send a `TensorFrame`, and receive an echoed frame back.

---

### Phase 2: Bind GGUF layer slicing via libllama C-FFI / Candle — Week 2

**Goal:** Each node actually executes its assigned layer slice on real weights.

1. **Vendor/build `libllama` (gguf) shared library** (or add `candle-core` + `candle-transformers` as the pure-Rust fallback engine). Choose one primary; document the other as secondary per the architecture doc (Module 4).
2. **Add `backend/` module to `crates/dirgha-cluster`:**
   - `Backend` trait: `load_layer_slice(model_path, start_layer, end_layer) -> Session`, `forward(activation) -> activation`.
   - `LlamaBackend`: loads GGUF via `llama_load_model_from_file`, restricts to `[start_layer, end_layer]` via `llama_set_layer_range` equivalent (or loads full model and slices KV cache per docs).
   - `CandleBackend`: pure-Rust fallback for CPU-only nodes.
3. **Integrate with `ClusterEngine::step_forward`:** instead of echoing input, run the locally assigned `LayerRange` through the backend session and return the resulting activation tensor as a `TensorFrame::ActivationResult`.
4. **Per-node memory guard:** before assigning a slice, verify `node.available_memory_bytes >= slice_weight_bytes + 10% KV headroom`; reject or re-partition if not.
5. **GGUF header reader:** parse total layer count, layer byte size, and quantization from the GGUF/SafeTensors header so `partition_layers` is called with real `model_weight_bytes` (not a hardcoded 42 GB).

**Definition of Done (Phase 2):** A single process can load a GGUF model, execute layers 0–26, pipe the activation to a second process executing layers 27–79, and produce a sampled token. (Use localhost loopback for the pipe.)

---

### Phase 3: Integrate SGLang RadixAttention prefix caching — Week 3

**Goal:** Cache KV tensors of repeated agent prefixes (system prompt + codebase context) so subsequent tool turns skip prefill.

1. **Port `sglang/srt/mem_cache/radix_cache.py`** into Dirgha's context engine (`src/context/` or `crates/dirgha-cluster`) as `RadixCache`:
   - Radix-tree keyed by token-id prefix.
   - `lookup(prefix_tokens) -> Option<KVCacheBlock>`, `insert(prefix_tokens, kv_block)`, `evict(lru)`.
2. **Wire into the coordinator:** before forwarding a prompt down the ring, check `RadixCache` for a matching system-prompt/context prefix; if hit, skip prefill for that prefix and inject cached KV.
3. **TTL + memory-bound eviction:** bound cache size (e.g., 25% of pooled VRAM) with LRU eviction; document the tradeoff vs. Exo's ring (no recompute on hit).
4. **Measure:** prefill latency with/without cache on a repeated 15k-token agent prompt; target ~15ms hit vs. ~800ms miss (per blueprint claim).

**Definition of Done (Phase 3):** Repeated agent turns sharing a system prefix show ≥5x prefill latency reduction; cache hit returns valid KV that produces identical tokens to a full prefill.

---

### Phase 4: mDNS discovery + Ed25519 cluster tokens — Week 4

**Goal:** Zero-config LAN joining and real cryptographic membership.

1. **Implement mDNS/UDP discovery** (port 54124 per architecture doc) or WireGuard-mesh address advertisement. Nodes broadcast `{node_id, pubkey, available_vram_bytes, backend, lan_address}`.
2. **Trusted issuer for join tokens:** `verify_join_token` checks the embedded pubkey against the leader's advertised/known pubkey (allowlist). Reject tokens signed by unknown keys.
3. **Token expiry enforcement:** `verify_join_token` already checks `current_unix_sec > expire_sec`; ensure `ClusterTopology::created_at_unix_ms` is set to real time so expiry is meaningful.
4. **Heartbeat/liveness:** workers re-announce every N seconds; leader drops silent nodes and triggers re-partition (see A-5).

**Definition of Done (Phase 4):** Two machines on the same LAN can `dirgha cluster init` / `dirgha cluster join` and see each other in `cluster status` with real, verified Ed25519 tokens.

---

### Phase 5: Harden error boundaries & operator observability — Week 5

1. Add per-request timeouts + circuit breaker on activation transfers (slow/dead node → re-partition or fail fast with a clear error).
2. Add backpressure: if a downstream worker's activation queue is full, upstream pauses (prevents memory growth).
3. `ClusterProvider.stream`: on connection failure to 54125, return a structured error and an optional fallback route (local CPU model or OpenRouter) instead of a raw fetch error.
4. Fix `isKnownProvider` to include `"cluster"`.
5. Add `cluster status` liveness column (last heartbeat, backend, per-node memory utilization).

**Definition of Done (Phase 5):** Killing a mid-inference worker node does not hang the coordinator indefinitely; it either re-partitions or returns a deterministic error within the timeout.

---

## 6. Governance Compliance

| Constraint | Status | Evidence |
|:--|:--|:--|
| **GitHub rule** — no push to any remote | **COMPLIANT** | `main` is `[origin/main: ahead 2]`; working tree clean; nothing pushed. Local commits only. |
| **CPU-only** | **COMPLIANT** | All verification ran on CPU (cargo test debug, node vitest, pytest). No GPU assumed or used. |
| **Python 3.12.6** | **COMPLIANT** | `C:\Users\ABC\AppData\Roaming\uv\python\cpython-3.12.6-windows-x86_64-none\python.exe` used for LOKAHI + catalog sync. |

---

## 7. Recommended Immediate Action

**Start with Phase 1 (TCP loopback server on 54125).** Everything else — provider routing, `cluster run`, RadixAttention caching — is blocked on there being a real listener that speaks the `TensorFrame` binary protocol. Until then, `dirgha cluster` is a convincing local simulation, not a distributed inference engine, and `ClusterProvider` points at a dead endpoint.

I am available to review the Phase 1 implementation before any code is committed locally. Per the GitHub rule, nothing will be pushed to `origin/main` without your explicit per-instance permission.
# Dirgha audit findings — 2026-11-23

Independent read-only audit of the `main` state (`d68e392`), followed by
remediation. Verdicts: **PASS**, **WARN** (works, but a claim or practice is
weaker than advertised), **FAIL** (claim is not true).

## Summary

| Track | Area | Verdict |
|:--|:--|:--|
| A | Build, tests and release integrity | **PASS** |
| B | Safety-gate behaviour | **WARN** (remediated) |
| C | Repository content and secrets | **PASS** |
| D | Claim accuracy and version consistency | **WARN** (remediated) |

## Track A — build, tests, release: PASS

- `npm run typecheck` — exit 0.
- `node ./bin/dirgha.test.mjs` — 7/7 passing.
- `cargo test --workspace` — 32 passed, 0 failed.
- `npx vitest run src/gateway` — 4/4; after remediation, `src/safety src/gateway`
  runs 33/33 across 6 files.

## Track B — safety-gate behaviour: WARN (remediated)

**B-1 — the policy engine gated `exec` less strictly than the gateway did.**
`src/gateway/interceptor.ts` treats an action as S2-critical when it is a
deletion **or** a shell execution (`action === "delete" || action === "exec"`).
`src/safety/policy.ts` passed only `req.action === "delete"` to
`evaluateLokahiGateSync`, so a call routed through the policy engine asked the
LOKAHI gate for the stricter evaluation only on deletions.

This is the one place where two entry points could disagree about how much
scrutiny a shell command gets, which is exactly the kind of asymmetry a safety
gate must not have. Both now compute the same predicate.

No exploitable path was found: the `exec-default` and `exec-danger-force` rules
still required approval, so `exec` was never auto-allowed.

## Track C — repository content and secrets: PASS

- `data/vault.sealed.json` and `data/audit-chain.jsonl` are tracked, but the
  vault entry is a masked fixture (`···· 4242`) holding ciphertext and nonce
  only; AES-256-GCM with `bound_item` / `bound_origin` AAD is confirmed in
  `crates/memory-mgp`.
- No credentials, keys or plaintext personal data in tracked files.
- The internal strategy documents that leaked from the sibling `lokahi`
  repository were never present in this repository or its history.

## Track D — claim accuracy and versioning: WARN (remediated)

**D-1 — version drift (fixed).** `CHANGELOG.md` declares 2.0.2, but
`package.json`, the gateway health payload, `lokahi-crypto.ts` and
`arniko-bridge.ts` all reported 2.0.1. All four now read 2.0.2.

**D-2 — deprecated URL parser (fixed).** `src/gateway/server.ts` used
`url.parse()`, which raises Node's DEP0169 deprecation warning. Replaced with
the WHATWG `URL` constructor; only the pathname was ever consumed.

## Not actioned

- `crates/memory-mgp` derives nonces with BLAKE3. That is unrelated to the
  LOKAHI ledger, which is SHA-256 hash-chained in both repositories; the
  confusion was in the `lokahi` documentation, not here.

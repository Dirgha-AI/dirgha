import { afterEach, describe, expect, it, vi } from "vitest";
import { createPolicyEngine, evaluateLokahiGateSync, type LokahiWasmSyncExports } from "../policy.js";

const originalOptOut = process.env.DIRGHA_ALLOW_UNGATED;

afterEach(() => {
  if (originalOptOut === undefined) delete process.env.DIRGHA_ALLOW_UNGATED;
  else process.env.DIRGHA_ALLOW_UNGATED = originalOptOut;
  vi.restoreAllMocks();
});

function fakeWasm(verdict: number): LokahiWasmSyncExports {
  return {
    memory: new WebAssembly.Memory({ initial: 2 }),
    lokahi_c_abi_evaluate_utf8: () => verdict,
  };
}

describe("Lokahi WASM gate fail-closed behavior", () => {
  it("denies when wasm is missing", () => {
    expect(evaluateLokahiGateSync("safe", false, null)).toEqual({
      allowed: false,
      reason: "lokahi_gate_unavailable",
    });
  });

  it("denies when loading or evaluation throws", () => {
    expect(evaluateLokahiGateSync("safe", false, () => { throw new Error("load failed"); })).toEqual({
      allowed: false,
      reason: "lokahi_gate_unavailable",
    });
  });

  it("denies an unknown -1 verdict", () => {
    expect(evaluateLokahiGateSync("safe", false, fakeWasm(-1))).toEqual({
      allowed: false,
      reason: "lokahi_gate_unavailable",
    });
  });

  it("strictly fails closed and denies even if DIRGHA_ALLOW_UNGATED is set (no bypass permitted)", () => {
    process.env.DIRGHA_ALLOW_UNGATED = "1";
    expect(evaluateLokahiGateSync("safe", false, null)).toEqual({
      allowed: false,
      reason: "lokahi_gate_unavailable",
    });
  });
});

describe("Declarative policy engine fail-closed defaults", () => {
  it("denies unknown tools/actions with default-deny catch-all", () => {
    const engine = createPolicyEngine({ cwd: process.cwd(), rules: [] });
    // An unrecognized action and tool
    const decision = engine.evaluate({
      tool: "rogue_tool",
      action: "unknown" as any,
      target: "some_target",
    });
    expect(decision).toEqual({
      allowed: false,
      requiresApproval: false,
      reason: "default-deny: unrecognized tool or action without explicit policy permit",
    });
  });
});

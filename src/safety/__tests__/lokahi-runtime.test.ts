/**
 * Offline unit tests for modular profiles, Enterprise Org-Lock, LOKAHI runtime
 * gate wiring, and fail-closed WASM/manifest enforcement.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  PROFILE_PRESETS,
  loadOrgPolicyLock,
  resolveModulesConfig,
} from "../modules-config.js";
import {
  checkLokahiManifestToolPolicy,
  createRuntimePermissionEngine,
  extractToolIntent,
} from "../lokahi-runtime.js";
import type { LokahiWasmSyncExports } from "../policy.js";
import { createToolExecutor } from "../../tools/exec.js";
import { createToolRegistry } from "../../tools/registry.js";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "dirgha-lokahi-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()!;
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("Modular profiles & Enterprise Org Policy Lock", () => {
  it("defaults to developer profile with zero governance friction (LOKAHI off, Arniko off, GPU Market on)", () => {
    const res = resolveModulesConfig({ env: {}, orgLock: null });
    expect(res.profile).toBe("developer");
    expect(res.modules.lokahi.mode).toBe("off");
    expect(res.modules.arniko.enabled).toBe(false);
    expect(res.modules.ahimsa.enabled).toBe(false);
    expect(res.modules.gpuMarket.enabled).toBe(true);
    expect(res.orgLocked).toBe(false);
    expect(res.errors).toEqual([]);
  });

  it("applies all 5 built-in profile presets accurately", () => {
    expect(PROFILE_PRESETS.developer.lokahi.mode).toBe("off");
    expect(PROFILE_PRESETS["safe-dev"].lokahi.mode).toBe("advisory");
    expect(PROFILE_PRESETS.team.lokahi.mode).toBe("enforce");
    expect(PROFILE_PRESETS.team.arniko.enabled).toBe(true);
    expect(PROFILE_PRESETS.enterprise.lokahi.mode).toBe("enforce");
    expect(PROFILE_PRESETS.enterprise.ahimsa.enabled).toBe(true);
    expect(PROFILE_PRESETS.robotics.lokahi.mode).toBe("enforce");
    expect(PROFILE_PRESETS.robotics.ahimsa.enabled).toBe(true);
  });

  it("allows solo developers to toggle LOKAHI, Arniko, and GPU freely when unlocked", () => {
    const on = resolveModulesConfig({
      flags: { lokahi: true, arniko: true },
      env: {},
      orgLock: null,
    });
    expect(on.modules.lokahi.mode).toBe("enforce");
    expect(on.modules.arniko.enabled).toBe(true);
    expect(on.errors).toEqual([]);

    const off = resolveModulesConfig({
      profile: "enterprise",
      flags: { "no-lokahi": true, "no-arniko": true, "no-gpu": true },
      env: {},
      orgLock: null,
    });
    expect(off.modules.lokahi.mode).toBe("off");
    expect(off.modules.arniko.enabled).toBe(false);
    expect(off.modules.gpuMarket.enabled).toBe(false);
    expect(off.errors).toEqual([]);
  });

  it("refuses --no-lokahi and --no-arniko fail-closed when org policy lock is active", () => {
    const res = resolveModulesConfig({
      profile: "developer",
      flags: { "no-lokahi": true, "no-arniko": true },
      env: {},
      orgLock: {
        orgName: "Acme Sovereign Corp",
        locked: true,
        minLokahiMode: "enforce",
        requireArniko: true,
        allowedJurisdictions: ["EU", "IN"],
        maxGpuBudgetUsd: 50,
      },
    });
    expect(res.orgLocked).toBe(true);
    expect(res.modules.lokahi.mode).toBe("enforce");
    expect(res.modules.lokahi.locked).toBe(true);
    expect(res.modules.arniko.enabled).toBe(true);
    expect(res.modules.gpuMarket.allowedJurisdictions).toEqual(["EU", "IN"]);
    expect(res.modules.gpuMarket.budgetUsd).toBe(50);
    expect(res.errors.length).toBe(2);
    expect(res.errors.some((e) => e.includes("--no-lokahi"))).toBe(true);
    expect(res.errors.some((e) => e.includes("--no-arniko"))).toBe(true);
  });

  it("loadOrgPolicyLock fails closed when DIRGHA_ORG_POLICY points to missing or malformed JSON", () => {
    const dir = makeTempDir();
    const missing = loadOrgPolicyLock({ DIRGHA_ORG_POLICY: join(dir, "missing.json") });
    expect(missing?.locked).toBe(true);
    expect(missing?.minLokahiMode).toBe("enforce");

    const badPath = join(dir, "bad.json");
    writeFileSync(badPath, "{ not-valid-json", "utf8");
    const malformed = loadOrgPolicyLock({ DIRGHA_ORG_POLICY: badPath });
    expect(malformed?.locked).toBe(true);
    expect(malformed?.minLokahiMode).toBe("enforce");
  });
});

describe("extractToolIntent & LOKAHI Runtime Permission Engine", () => {
  it("extracts real payloads (shell command, file path, browser URL, git args, GPU metadata)", () => {
    const cwd = "/workspace/app";
    const sh = extractToolIntent(
      { id: "1", name: "shell", input: { command: "sudo rm -fr /" } },
      cwd,
    );
    expect(sh.check.target).toBe("sudo rm -fr /");
    expect(sh.check.action).toBe("exec");
    expect(sh.isS2Critical).toBe(true);

    const write = extractToolIntent(
      { id: "2", name: "fs_write", input: { path: "src/index.ts" } },
      cwd,
    );
    expect(write.check.action).toBe("write");
    expect(write.check.target).toBe("src/index.ts");

    const browser = extractToolIntent(
      { id: "3", name: "browser", input: { url: "http://169.254.169.254/latest/meta-data/" } },
      cwd,
    );
    expect(browser.check.action).toBe("network");
    expect(browser.check.target).toContain("169.254.169.254");

    const git = extractToolIntent(
      { id: "4", name: "git", input: { args: ["push", "--force", "origin", "main"] } },
      cwd,
    );
    expect(git.check.target).toBe("git push --force origin main");
    expect(git.isS2Critical).toBe(true);

    const gpu = extractToolIntent(
      {
        id: "5",
        name: "gpu_compute",
        input: { action: "provision", jurisdiction: "EU", hours: 2, costPerHr: 3.5 },
      },
      cwd,
    );
    expect(gpu.isS2Critical).toBe(true);
    expect(gpu.jurisdiction).toBe("EU");
    expect(gpu.estimatedSpendUsd).toBe(7);
  });

  it("permits calls in off mode, logs without blocking in advisory mode, and blocks malicious payloads in enforce mode", () => {
    const cwd = makeTempDir();
    const call = { id: "c1", name: "shell", input: { command: "sudo rm -fr /" } };

    const offEngine = createRuntimePermissionEngine({
      cwd,
      modules: PROFILE_PRESETS.developer,
    });
    expect(offEngine.checkCall(call).allowed).toBe(true);

    const advisories: string[] = [];
    const advisoryEngine = createRuntimePermissionEngine({
      cwd,
      modules: PROFILE_PRESETS["safe-dev"],
      onAdvisory: (m) => advisories.push(m),
    });
    expect(advisoryEngine.checkCall(call).allowed).toBe(true);
    expect(advisories.length).toBe(1);
    expect(advisories[0]).toContain("[lokahi:advisory]");

    const enforceEngine = createRuntimePermissionEngine({
      cwd,
      modules: PROFILE_PRESETS.enterprise,
    });
    const blocked = enforceEngine.checkCall(call);
    expect(blocked.allowed).toBe(false);
    expect(blocked.reason).toContain("lokahi-gate-wasm");

    const ssrfBlocked = enforceEngine.checkCall({
      id: "c2",
      name: "browser",
      input: { url: "http://169.254.169.254/latest/meta-data/" },
    });
    expect(ssrfBlocked.allowed).toBe(false);
  });

  it("fails closed in enforce mode when WASM gate is missing, throws, or returns unknown verdict", () => {
    const cwd = makeTempDir();
    const safeCall = { id: "s1", name: "shell", input: { command: "echo hello" } };

    // Missing WASM
    const missingGate = createRuntimePermissionEngine({
      cwd,
      modules: PROFILE_PRESETS.enterprise,
      wasmLoader: null,
    });
    expect(missingGate.checkCall(safeCall).allowed).toBe(false);

    // Throwing WASM
    const throwingWasm: LokahiWasmSyncExports = {
      memory: new WebAssembly.Memory({ initial: 2 }),
      lokahi_c_abi_evaluate_utf8: () => {
        throw new Error("boom");
      },
    };
    const throwingGate = createRuntimePermissionEngine({
      cwd,
      modules: PROFILE_PRESETS.enterprise,
      wasmLoader: throwingWasm,
    });
    expect(throwingGate.checkCall(safeCall).allowed).toBe(false);

    // Unknown return code (-1)
    const unknownWasm: LokahiWasmSyncExports = {
      memory: new WebAssembly.Memory({ initial: 2 }),
      lokahi_c_abi_evaluate_utf8: () => -1,
    };
    const unknownGate = createRuntimePermissionEngine({
      cwd,
      modules: PROFILE_PRESETS.enterprise,
      wasmLoader: unknownWasm,
    });
    expect(unknownGate.checkCall(safeCall).allowed).toBe(false);
  });

  it("enforces LOKAHI manifest default-deny, signature, and expiry checks", () => {
    const dir = makeTempDir();
    const manifestPath = join(dir, "manifest.json");
    writeFileSync(
      manifestPath,
      JSON.stringify({
        manifest_version: "1.1",
        signature: "ed25519:valid-test-signature",
        expires: "2099-01-01T00:00:00Z",
        tools: { fs_read: { class: "read" } },
      }),
      "utf8",
    );

    expect(checkLokahiManifestToolPolicy(manifestPath, "fs_read")).toBeNull();
    expect(checkLokahiManifestToolPolicy(manifestPath, "shell")).toBe("tool_not_in_manifest:shell");

    // Expired manifest
    const expiredPath = join(dir, "expired.json");
    writeFileSync(
      expiredPath,
      JSON.stringify({
        signature: "ed25519:abc",
        expires: "2020-01-01T00:00:00Z",
        tools: { fs_read: { class: "read" } },
      }),
      "utf8",
    );
    expect(checkLokahiManifestToolPolicy(expiredPath, "fs_read")).toBe("expired_manifest");
  });

  it("enforces GPU residency jurisdiction and spend cap and integrates end-to-end with createToolExecutor", async () => {
    const cwd = makeTempDir();
    const modules = structuredClone(PROFILE_PRESETS.enterprise);
    modules.gpuMarket.allowedJurisdictions = ["EU", "IN"];
    modules.gpuMarket.budgetUsd = 20;

    const permission = createRuntimePermissionEngine({ cwd, modules });
    const badJurisdiction = permission.checkCall({
      id: "g1",
      name: "gpu_compute",
      input: { action: "provision", jurisdiction: "US", estimatedSpendUsd: 5 },
    });
    expect(badJurisdiction.allowed).toBe(false);
    expect(badJurisdiction.reason).toContain("residency_violation");

    const overBudget = permission.checkCall({
      id: "g2",
      name: "gpu_compute",
      input: { action: "provision", jurisdiction: "EU", estimatedSpendUsd: 35 },
    });
    expect(overBudget.allowed).toBe(false);
    expect(overBudget.reason).toContain("gpu_budget_exceeded");

    // End-to-end via createToolExecutor: dangerous shell payload is blocked before tool execute() runs
    let executed = false;
    const registry = createToolRegistry();
    registry.register({
      name: "shell",
      description: "stub shell",
      inputSchema: { type: "object", properties: { command: { type: "string" } } },
      execute: async () => {
        executed = true;
        return { content: "ran", isError: false };
      },
    });
    const executor = createToolExecutor({
      registry,
      cwd,
      env: {},
      sessionId: "test-session",
      permission,
    });
    const result = await executor.execute(
      { id: "e1", name: "shell", input: { command: "sudo rm -fr /" } },
      new AbortController().signal,
    );
    expect(executed).toBe(false);
    expect(result.isError).toBe(true);
    expect(result.content).toContain("Permission denied");
  });
});

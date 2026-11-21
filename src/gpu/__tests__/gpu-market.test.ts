/**
 * Offline unit tests for Dirgha's Open GPU Cloud Market:
 * manifest validation, SSRF-safe certification, custom registry persistence,
 * jurisdiction filtering, and gpu_compute built-in tool.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  certifyProviderManifest,
  getAllGPUProviders,
  loadCustomProviders,
  registerCustomProvider,
  removeCustomProvider,
  validateProviderManifest,
  type ExternalGPUProviderManifest,
} from "../provider-spec.js";
import { gpuComputeTool } from "../../tools/gpu-compute.js";
import type { ToolContext } from "../../tools/registry.js";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "dirgha-gpu-test-"));
  tempDirs.push(dir);
  return dir;
}

const VALID_MANIFEST: ExternalGPUProviderManifest = {
  schemaVersion: "1.0",
  id: "sovereign-eu-gpu",
  name: "Sovereign EU GPU Cloud",
  endpoint: "https://api.sovereign-eu-gpu.example",
  authHeader: "Authorization",
  authScheme: "Bearer",
  authEnvVar: "SOVEREIGN_EU_GPU_KEY",
  jurisdictions: ["EU", "DE"],
  catalogPath: "/v1/gpus",
  provisionPath: "/v1/instances",
  statusPath: "/v1/instances/{id}",
  logsPath: "/v1/instances/{id}/logs",
  destroyPath: "/v1/instances/{id}",
  contactEmail: "ops@sovereign-eu-gpu.example",
  gdprCompliant: true,
};

afterEach(() => {
  delete process.env.DIRGHA_GPU_MARKET;
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("Open GPU Cloud Market — manifest validation & certification", () => {
  it("accepts a valid v1.0 third-party GPU provider manifest", () => {
    const res = validateProviderManifest(VALID_MANIFEST);
    expect(res.valid).toBe(true);
    expect(res.errors).toEqual([]);
    expect(res.manifest?.id).toBe("sovereign-eu-gpu");
  });

  it("rejects plaintext http, built-in id collisions, bad slugs, and invalid paths", () => {
    const bad = validateProviderManifest({
      ...VALID_MANIFEST,
      id: "runpod",
      endpoint: "http://insecure.example.com",
      jurisdictions: [],
      catalogPath: "no-leading-slash",
    });
    expect(bad.valid).toBe(false);
    expect(bad.errors.some((e) => e.includes("conflicts with a built-in"))).toBe(true);
    expect(bad.errors.some((e) => e.includes("https://"))).toBe(true);
    expect(bad.errors.some((e) => e.includes("jurisdictions"))).toBe(true);
    expect(bad.errors.some((e) => e.includes("catalogPath"))).toBe(true);
  });

  it("blocks private/loopback/metadata endpoints during certification via injected DNS lookup", async () => {
    const report = await certifyProviderManifest(VALID_MANIFEST, {
      lookupFn: async () => [{ address: "169.254.169.254", family: 4 }],
    });
    expect(report.certified).toBe(false);
    const ssrfCheck = report.checks.find((c) => c.id === "endpoint_ssrf_guard");
    expect(ssrfCheck?.passed).toBe(false);
  });

  it("certifies a public HTTPS provider with live catalog probe using mocked fetch", async () => {
    const fakeFetch = (async () =>
      new Response(
        JSON.stringify([
          { id: "h100-80gb", name: "NVIDIA H100 80GB", vramGb: 80, costPerHr: 2.45, available: true },
        ]),
        { status: 200, headers: { "Content-Type": "application/json" } },
      )) as unknown as typeof fetch;

    const report = await certifyProviderManifest(VALID_MANIFEST, {
      probeLive: true,
      lookupFn: async () => [{ address: "93.184.216.34", family: 4 }],
      fetchFn: fakeFetch,
    });
    expect(report.certified).toBe(true);
    expect(report.liveProbeSkipped).toBe(false);
    const probe = report.checks.find((c) => c.id === "live_catalog_probe");
    expect(probe?.passed).toBe(true);
    expect(probe?.detail).toContain("1 GPU SKU");
  });
});

describe("Open GPU Cloud Market — custom registry & jurisdiction filtering", () => {
  it("persists, reloads, filters by jurisdiction, and removes custom providers cleanly", () => {
    const dir = makeTempDir();
    const registryPath = join(dir, "gpu-providers.json");

    expect(loadCustomProviders(registryPath)).toEqual([]);
    registerCustomProvider(VALID_MANIFEST, registryPath);

    const loaded = loadCustomProviders(registryPath);
    expect(loaded).toHaveLength(1);
    expect(loaded[0].id).toBe("sovereign-eu-gpu");

    // Filter to DE -> only custom sovereign-eu-gpu matches (no built-ins declare DE)
    const deProviders = getAllGPUProviders(registryPath, { allowedJurisdictions: ["DE"] });
    expect(deProviders.map((p) => p.name)).toEqual(["sovereign-eu-gpu"]);

    // Filter to IN -> Spheron built-in matches, sovereign-eu-gpu excluded
    const inProviders = getAllGPUProviders(registryPath, { allowedJurisdictions: ["IN"] });
    expect(inProviders.map((p) => p.name)).toContain("spheron");
    expect(inProviders.map((p) => p.name)).not.toContain("sovereign-eu-gpu");

    expect(removeCustomProvider("sovereign-eu-gpu", registryPath)).toBe(true);
    expect(loadCustomProviders(registryPath)).toEqual([]);
  });

  it("gpuComputeTool serves providers/budget actions and honors disabled state", async () => {
    const ctx: ToolContext = {
      cwd: makeTempDir(),
      env: {},
      sessionId: "test-session",
      signal: new AbortController().signal,
      sandbox: null,
      sandboxMode: "off",
    };

    const providersRes = await gpuComputeTool.execute({ action: "providers" }, ctx);
    expect(providersRes.isError).toBeFalsy();
    const parsed = JSON.parse(providersRes.content);
    expect(parsed.providers.length).toBeGreaterThanOrEqual(4);

    const budgetRes = await gpuComputeTool.execute({ action: "budget" }, ctx);
    expect(budgetRes.isError).toBeFalsy();

    // Respects DIRGHA_GPU_MARKET=0 disable toggle
    process.env.DIRGHA_GPU_MARKET = "0";
    const disabledRes = await gpuComputeTool.execute({ action: "providers" }, ctx);
    expect(disabledRes.isError).toBe(true);
    expect(disabledRes.content).toContain("disabled");
  });
});

/**
 * Offline unit tests for Phase 8:
 *  - Smart cheapest-compliant GPU router (`findOptimalGPUs`)
 *  - Compliance filtering (GDPR/DPDP/SOC2/ISO27001), VRAM/price caps & fault isolation
 *  - Partner manifest scaffolder (`scaffoldProviderManifest`) + validation
 *  - Enterprise FinOps RFC-4180 CSV chargeback export (`exportGpuChargebackCsv`)
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { describe, expect, it } from "vitest";
import {
  exportGpuChargebackCsv,
  findOptimalGPUs,
  scaffoldProviderManifest,
} from "../router.js";
import { HttpGPUProvider, validateProviderManifest } from "../provider-spec.js";
import type { GPUProvider } from "../providers.js";

function makeStubHttpProvider(
  id: string,
  jurisdictions: string[],
  flags: { gdprCompliant?: boolean; dpdpCompliant?: boolean; soc2Certified?: boolean },
  gpus: Array<{ id: string; name: string; vramGb: number; costPerHr: number; available: boolean }>,
): HttpGPUProvider {
  const manifest = {
    ...scaffoldProviderManifest({
      id,
      name: `Cloud ${id}`,
      endpoint: `https://api.${id}.example`,
      jurisdictions,
    }),
    ...flags,
  };
  return new HttpGPUProvider(manifest, {
    lookupFn: async () => [{ address: "93.184.216.34", family: 4 }],
    fetchFn: (async () =>
      new Response(JSON.stringify({ gpus }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })) as unknown as typeof fetch,
  });
}

describe("Open GPU Cloud Market — Smart Cheapest-Compliant Router", () => {
  it("ranks cheapest compliant GPUs across partner clouds and isolates failing providers", async () => {
    const euCloud = makeStubHttpProvider(
      "eu-sovereign",
      ["EU", "DE"],
      { gdprCompliant: true, soc2Certified: true },
      [
        { id: "h100-eu", name: "NVIDIA H100 80GB", vramGb: 80, costPerHr: 2.6, available: true },
        { id: "rtx-eu", name: "NVIDIA RTX 4090", vramGb: 24, costPerHr: 0.45, available: true },
      ],
    );
    const inCloud = makeStubHttpProvider(
      "in-sovereign",
      ["IN", "EU"],
      { gdprCompliant: true, dpdpCompliant: true, soc2Certified: true },
      [
        { id: "h100-in", name: "NVIDIA H100 80GB", vramGb: 80, costPerHr: 2.25, available: true },
      ],
    );
    const failingProvider: GPUProvider = {
      name: "broken-cloud",
      listGPUTypes: async () => {
        throw new Error("timeout");
      },
      provision: async () => {
        throw new Error("not implemented");
      },
      getStatus: async () => {
        throw new Error("not implemented");
      },
      getLogs: async () => "",
      destroy: async () => {},
      estimateCost: async () => 0,
    };

    const routed = await findOptimalGPUs([euCloud, inCloud, failingProvider], {
      minVramGb: 80,
      maxCostPerHr: 3.0,
      jurisdictions: ["EU"],
      requireCompliance: ["gdpr", "soc2"],
    });

    expect(routed.recommendations).toHaveLength(2);
    expect(routed.recommendations[0].gpu.provider).toBe("in-sovereign");
    expect(routed.recommendations[0].gpu.costPerHr).toBe(2.25);
    expect(routed.recommendations[1].gpu.provider).toBe("eu-sovereign");
    expect(routed.skippedProviders.some((s) => s.provider === "broken-cloud")).toBe(true);
  });

  it("filters strictly by DPDP compliance and GPU name substring", async () => {
    const euOnly = makeStubHttpProvider(
      "eu-only",
      ["EU"],
      { gdprCompliant: true, dpdpCompliant: false },
      [{ id: "a100", name: "NVIDIA A100 80GB", vramGb: 80, costPerHr: 1.5, available: true }],
    );
    const inDpdp = makeStubHttpProvider(
      "in-dpdp",
      ["IN"],
      { dpdpCompliant: true },
      [{ id: "a100-in", name: "NVIDIA A100 80GB", vramGb: 80, costPerHr: 1.7, available: true }],
    );

    const res = await findOptimalGPUs([euOnly, inDpdp], {
      gpuNameContains: "A100",
      requireCompliance: ["dpdp"],
    });
    expect(res.recommendations).toHaveLength(1);
    expect(res.recommendations[0].gpu.provider).toBe("in-dpdp");
  });
});

describe("Partner manifest scaffolder & FinOps chargeback CSV export", () => {
  it("scaffolds a manifest that passes strict v1.0 schema validation", () => {
    const manifest = scaffoldProviderManifest({
      id: "Bharat-GPU_Cloud",
      name: "Bharat Sovereign GPU",
      endpoint: "https://api.bharat-gpu.example/",
      jurisdictions: ["in", "sg"],
      contactEmail: "cloud@bharat-gpu.example",
    });
    const validated = validateProviderManifest(manifest);
    expect(validated.valid).toBe(true);
    expect(validated.manifest?.id).toBe("bharat-gpu-cloud");
    expect(validated.manifest?.jurisdictions).toEqual(["IN", "SG"]);
  });

  it("exports RFC-4180 CSV with proper escaping for chargeback billing", () => {
    const csv = exportGpuChargebackCsv([
      {
        id: "job-1",
        provider: "in-sovereign",
        gpuType: 'NVIDIA H100, "SXM5"',
        instanceId: "inst-1",
        status: "completed",
        costPerHr: 2.25,
        totalCost: 4.5,
        startedAt: "2026-06-01T10:00:00Z",
        completedAt: "2026-06-01T12:00:00Z",
      },
    ]);
    const lines = csv.trim().split("\n");
    expect(lines[0]).toBe(
      "job_id,provider,gpu_type,status,cost_per_hr_usd,total_cost_usd,started_at,ended_at",
    );
    expect(lines[1]).toContain('"NVIDIA H100, ""SXM5"""');
    expect(lines[1]).toContain("4.5000");
  });
});

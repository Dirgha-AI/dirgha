/**
 * Open GPU Cloud Market — Smart Cheapest-Compliant GPU Router,
 * Partner Manifest Scaffolder, & Enterprise Chargeback Exporter.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import type { GPUProvider, GPUType } from "./providers.js";
import type { GPUJob } from "./jobs.js";
import {
  BUILTIN_PROVIDER_META,
  type ExternalGPUProviderManifest,
  HttpGPUProvider,
} from "./provider-spec.js";

export type ComplianceRequirement = "soc2" | "iso27001" | "dpdp" | "gdpr";

export interface GpuRouteQuery {
  minVramGb?: number;
  maxCostPerHr?: number;
  gpuNameContains?: string;
  jurisdictions?: string[];
  requireCompliance?: ComplianceRequirement[];
  limit?: number;
}

export interface GpuRecommendation {
  gpu: GPUType;
  providerLatencyMs: number;
  score: number;
  reasons: string[];
}

export interface GpuRouteResult {
  recommendations: GpuRecommendation[];
  queriedProviders: number;
  skippedProviders: Array<{ provider: string; reason: string }>;
}

function providerSatisfiesCompliance(
  provider: GPUProvider,
  reqs: ComplianceRequirement[] | undefined,
): { ok: boolean; reason?: string } {
  if (!reqs || reqs.length === 0) return { ok: true };
  if (provider instanceof HttpGPUProvider) {
    const m = provider.manifest;
    for (const r of reqs) {
      if (r === "soc2" && !m.soc2Certified) return { ok: false, reason: "missing soc2Certified" };
      if (r === "iso27001" && !m.iso27001Certified) return { ok: false, reason: "missing iso27001Certified" };
      if (r === "dpdp" && !m.dpdpCompliant) return { ok: false, reason: "missing dpdpCompliant" };
      if (r === "gdpr" && !m.gdprCompliant) return { ok: false, reason: "missing gdprCompliant" };
    }
    return { ok: true };
  }
  // Built-in providers don't assert custom attestation flags unless certified via manifest
  return {
    ok: false,
    reason: `built-in provider "${provider.name}" has no signed compliance attestation for [${reqs.join(",")}]`,
  };
}

function providerMatchesJurisdictions(
  provider: GPUProvider,
  allowed: string[] | undefined,
): boolean {
  if (!allowed || allowed.length === 0) return true;
  const upperAllowed = allowed.map((j) => j.toUpperCase());
  const declared =
    provider instanceof HttpGPUProvider
      ? provider.manifest.jurisdictions
      : (BUILTIN_PROVIDER_META[provider.name]?.jurisdictions ?? []);
  return declared.some((j) => upperAllowed.includes(j.toUpperCase()));
}

/**
 * Query available GPU providers in parallel, apply VRAM / price / residency /
 * compliance filters, isolate failing providers, and rank by lowest cost/hr
 * with tie-breaking by VRAM and latency.
 */
export async function findOptimalGPUs(
  providers: GPUProvider[],
  query: GpuRouteQuery = {},
): Promise<GpuRouteResult> {
  const skippedProviders: Array<{ provider: string; reason: string }> = [];
  const eligible: GPUProvider[] = [];

  for (const p of providers) {
    if (!providerMatchesJurisdictions(p, query.jurisdictions)) {
      skippedProviders.push({
        provider: p.name,
        reason: `jurisdiction outside [${(query.jurisdictions ?? []).join(",")}]`,
      });
      continue;
    }
    const comp = providerSatisfiesCompliance(p, query.requireCompliance);
    if (!comp.ok) {
      skippedProviders.push({ provider: p.name, reason: comp.reason ?? "compliance_failed" });
      continue;
    }
    eligible.push(p);
  }

  const recommendations: GpuRecommendation[] = [];

  await Promise.all(
    eligible.map(async (p) => {
      const t0 = performance.now();
      try {
        const gpus = await p.listGPUTypes();
        const latencyMs = Math.max(1, Math.round(performance.now() - t0));
        for (const gpu of gpus) {
          if (!gpu.available) continue;
          if (query.minVramGb !== undefined && gpu.vramGb < query.minVramGb) continue;
          if (query.maxCostPerHr !== undefined && gpu.costPerHr > query.maxCostPerHr) continue;
          if (
            query.gpuNameContains &&
            !gpu.name.toLowerCase().includes(query.gpuNameContains.toLowerCase()) &&
            !gpu.id.toLowerCase().includes(query.gpuNameContains.toLowerCase())
          ) {
            continue;
          }
          // Lower score is better: price dominates, mild tie-breakers for latency & $/GB
          const perGb = gpu.vramGb > 0 ? gpu.costPerHr / gpu.vramGb : gpu.costPerHr;
          const score = Number((gpu.costPerHr * 100 + perGb * 10 + latencyMs / 1000).toFixed(4));
          const reasons: string[] = [
            `$${gpu.costPerHr.toFixed(2)}/hr`,
            `${gpu.vramGb}GB VRAM`,
            `${latencyMs}ms catalog latency`,
          ];
          if (gpu.region) reasons.push(`region:${gpu.region}`);
          recommendations.push({
            gpu,
            providerLatencyMs: latencyMs,
            score,
            reasons,
          });
        }
      } catch (err) {
        skippedProviders.push({
          provider: p.name,
          reason: `catalog_error: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    }),
  );

  recommendations.sort((a, b) => a.score - b.score);
  const limited =
    query.limit !== undefined && query.limit > 0
      ? recommendations.slice(0, query.limit)
      : recommendations;

  return {
    recommendations: limited,
    queriedProviders: eligible.length,
    skippedProviders,
  };
}

/**
 * Scaffold a standards-compliant v1.0 ExternalGPUProviderManifest for cloud partners.
 */
export function scaffoldProviderManifest(opts: {
  id: string;
  name: string;
  endpoint: string;
  jurisdictions?: string[];
  authEnvVar?: string;
  contactEmail?: string;
}): ExternalGPUProviderManifest {
  const cleanId = opts.id.toLowerCase().replace(/[^a-z0-9-]/g, "-");
  const envVar =
    opts.authEnvVar ??
    `${cleanId.toUpperCase().replace(/-/g, "_")}_API_KEY`;
  return {
    schemaVersion: "1.0",
    id: cleanId,
    name: opts.name.trim(),
    endpoint: opts.endpoint.replace(/\/+$/, ""),
    authHeader: "Authorization",
    authScheme: "Bearer",
    authEnvVar: envVar,
    jurisdictions: (opts.jurisdictions ?? ["US", "EU"]).map((j) => j.toUpperCase()),
    catalogPath: "/v1/gpus",
    provisionPath: "/v1/instances",
    statusPath: "/v1/instances/{id}",
    logsPath: "/v1/instances/{id}/logs",
    destroyPath: "/v1/instances/{id}",
    ...(opts.contactEmail ? { contactEmail: opts.contactEmail } : {}),
  };
}

function csvCell(val: unknown): string {
  const s = val === undefined || val === null ? "" : String(val);
  if (/[",\r\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

/**
 * Export GPU job records as RFC-4180 CSV for enterprise FinOps / chargeback billing.
 */
export function exportGpuChargebackCsv(jobs: GPUJob[]): string {
  const header = [
    "job_id",
    "provider",
    "gpu_type",
    "status",
    "cost_per_hr_usd",
    "total_cost_usd",
    "started_at",
    "ended_at",
  ].join(",");
  const rows = jobs.map((j) =>
    [
      csvCell(j.id),
      csvCell(j.provider),
      csvCell(j.gpuType),
      csvCell(j.status),
      csvCell(j.costPerHr.toFixed(4)),
      csvCell(j.totalCost.toFixed(4)),
      csvCell(j.startedAt),
      csvCell(j.completedAt ?? ""),
    ].join(","),
  );
  return [header, ...rows].join("\n") + "\n";
}

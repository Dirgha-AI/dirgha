/**
 * gpu_compute — Agent tool for Dirgha's Open GPU Cloud Market.
 *
 * Allows coding & robotics agents to compare GPU pricing across built-in
 * providers (RunPod, Vast, Spheron, Akash) plus certified third-party partner
 * clouds registered via `dirgha gpu submit <manifest.json>`, estimate job cost,
 * enforce residency jurisdictions & spend budgets, and provision/manage instances.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import type { Tool } from "./registry.js";
import type { ToolResult } from "../kernel/types.js";
import {
  getAllGPUProviders,
  listProviderMetadata,
} from "../gpu/provider-spec.js";
import {
  checkBudget,
  completeGPUJob,
  getBudget,
  listGPUJobs,
  registerGPUJob,
  totalGPUSpend,
} from "../gpu/jobs.js";
import { resolveModulesConfig } from "../safety/modules-config.js";

interface GpuComputeInput {
  action: "list" | "providers" | "estimate" | "provision" | "status" | "stop" | "budget";
  provider?: string;
  gpuType?: string;
  hours?: number;
  jurisdiction?: string;
  imageName?: string;
  containerDiskGb?: number;
  instanceId?: string;
  jobId?: string;
}

export const gpuComputeTool: Tool = {
  name: "gpu_compute",
  description:
    "Discover, compare, estimate, and provision GPU compute across Dirgha's Open GPU Cloud Market " +
    "(RunPod, Vast.ai, Spheron, Akash, and certified partner clouds). Respects LOKAHI residency " +
    "jurisdictions and USD spend caps.",
  inputSchema: {
    type: "object",
    properties: {
      action: {
        type: "string",
        enum: ["list", "providers", "estimate", "provision", "status", "stop", "budget"],
        description: "Operation to perform on the GPU Cloud Market.",
      },
      provider: {
        type: "string",
        description: "Optional provider id (e.g. runpod, vast, spheron, akash, or custom partner id).",
      },
      gpuType: {
        type: "string",
        description: "GPU model/SKU for estimate or provision (e.g. 'NVIDIA A100 80GB', 'RTX 4090').",
      },
      hours: {
        type: "number",
        description: "Estimated runtime in hours for cost estimation / budget check (default: 1).",
      },
      jurisdiction: {
        type: "string",
        description: "Optional ISO jurisdiction filter (e.g. IN, EU, US, SG).",
      },
      imageName: {
        type: "string",
        description: "Docker container image for provisioning (default: nvidia/cuda:12.4.0-base).",
      },
      containerDiskGb: {
        type: "integer",
        description: "Container disk size in GB (default: 40).",
      },
      instanceId: {
        type: "string",
        description: "Remote instance ID for status or stop actions.",
      },
      jobId: {
        type: "string",
        description: "Local Dirgha GPU job ID to mark cancelled when stopping.",
      },
    },
    required: ["action"],
  },
  requiresApproval: (raw) => {
    const inp = (raw ?? {}) as Partial<GpuComputeInput>;
    return inp.action === "provision" || inp.action === "stop";
  },
  async execute(rawInput: unknown): Promise<ToolResult> {
    const input = (rawInput ?? {}) as GpuComputeInput;
    const { modules } = resolveModulesConfig();

    if (!modules.gpuMarket.enabled) {
      return {
        content: "GPU Cloud Market is disabled in the active configuration (--no-gpu or DIRGHA_GPU_MARKET=0).",
        isError: true,
      };
    }

    const allowedJurisdictions = input.jurisdiction
      ? [input.jurisdiction.toUpperCase()]
      : modules.gpuMarket.allowedJurisdictions;

    if (
      input.jurisdiction &&
      modules.gpuMarket.allowedJurisdictions &&
      modules.gpuMarket.allowedJurisdictions.length > 0 &&
      !modules.gpuMarket.allowedJurisdictions
        .map((j) => j.toUpperCase())
        .includes(input.jurisdiction.toUpperCase())
    ) {
      return {
        content: `Jurisdiction "${input.jurisdiction}" is outside the allowed residency policy [${modules.gpuMarket.allowedJurisdictions.join(", ")}].`,
        isError: true,
      };
    }

    const providers = getAllGPUProviders(undefined, { allowedJurisdictions });

    switch (input.action) {
      case "providers": {
        const meta = listProviderMetadata();
        return {
          content: JSON.stringify(
            {
              providers: meta,
              allowedJurisdictions: allowedJurisdictions ?? ["ANY"],
            },
            null,
            2,
          ),
          isError: false,
          data: { providers: meta },
        };
      }

      case "budget": {
        const cap = modules.gpuMarket.budgetUsd ?? getBudget();
        const spend = await totalGPUSpend();
        const running = await listGPUJobs("running");
        return {
          content: JSON.stringify(
            {
              budgetUsd: cap,
              lifetimeSpendUsd: Number(spend.toFixed(4)),
              runningJobs: running.length,
            },
            null,
            2,
          ),
          isError: false,
          data: { budgetUsd: cap, lifetimeSpendUsd: spend, runningJobs: running.length },
        };
      }

      case "list": {
        const selected = input.provider
          ? providers.filter((p) => p.name === input.provider)
          : providers;
        if (selected.length === 0) {
          return {
            content: `No GPU providers matched filter (provider=${input.provider ?? "any"}, jurisdictions=${allowedJurisdictions?.join(",") ?? "any"}).`,
            isError: true,
          };
        }
        const results = await Promise.all(
          selected.map(async (p) => {
            try {
              return await p.listGPUTypes();
            } catch {
              return [];
            }
          }),
        );
        const flat = results
          .flat()
          .filter((g) => g.available)
          .sort((a, b) => a.costPerHr - b.costPerHr);
        return {
          content: JSON.stringify({ count: flat.length, gpus: flat }, null, 2),
          isError: false,
          data: { gpus: flat },
        };
      }

      case "estimate": {
        if (!input.gpuType) {
          return { content: "estimate requires gpuType (e.g. 'NVIDIA A100 80GB')", isError: true };
        }
        const hours = typeof input.hours === "number" && input.hours > 0 ? input.hours : 1;
        const selected = input.provider
          ? providers.filter((p) => p.name === input.provider)
          : providers;
        const quotes: Array<{ provider: string; gpuType: string; hours: number; estimatedUsd: number }> = [];
        for (const p of selected) {
          try {
            const est = await p.estimateCost(input.gpuType, hours);
            if (est > 0) {
              quotes.push({ provider: p.name, gpuType: input.gpuType, hours, estimatedUsd: est });
            }
          } catch {
            // skip unreachable provider
          }
        }
        quotes.sort((a, b) => a.estimatedUsd - b.estimatedUsd);
        return {
          content: JSON.stringify({ quotes }, null, 2),
          isError: false,
          data: { quotes },
        };
      }

      case "provision": {
        if (!input.gpuType) {
          return { content: "provision requires gpuType", isError: true };
        }
        const hours = typeof input.hours === "number" && input.hours > 0 ? input.hours : 1;
        const targetProvider = input.provider
          ? providers.find((p) => p.name === input.provider)
          : providers[0];
        if (!targetProvider) {
          return {
            content: `GPU provider "${input.provider ?? "default"}" not found or excluded by residency policy.`,
            isError: true,
          };
        }
        const estCost = await targetProvider.estimateCost(input.gpuType, hours).catch(() => 0);
        const costPerHr = hours > 0 && estCost > 0 ? estCost / hours : 0.5;
        const budgetErr = await checkBudget(costPerHr, hours);
        if (budgetErr) {
          return { content: budgetErr, isError: true };
        }
        if (
          modules.gpuMarket.budgetUsd !== undefined &&
          modules.gpuMarket.budgetUsd > 0 &&
          estCost > modules.gpuMarket.budgetUsd
        ) {
          return {
            content: `Estimated GPU cost $${estCost.toFixed(2)} exceeds module budget cap $${modules.gpuMarket.budgetUsd.toFixed(2)}.`,
            isError: true,
          };
        }
        const instance = await targetProvider.provision({
          gpuType: input.gpuType,
          imageName: input.imageName ?? "nvidia/cuda:12.4.0-base",
          containerDiskGb: input.containerDiskGb ?? 40,
          startSsh: true,
        });
        const job = await registerGPUJob({
          provider: targetProvider.name,
          gpuType: instance.gpuType,
          costPerHr: instance.costPerHr,
          instanceId: instance.id,
        });
        return {
          content: JSON.stringify({ instance, job }, null, 2),
          isError: false,
          data: { instance, job },
        };
      }

      case "status": {
        if (!input.provider || !input.instanceId) {
          return { content: "status requires provider and instanceId", isError: true };
        }
        const target = providers.find((p) => p.name === input.provider);
        if (!target) {
          return { content: `Unknown GPU provider: ${input.provider}`, isError: true };
        }
        const status = await target.getStatus(input.instanceId);
        return { content: JSON.stringify(status, null, 2), isError: false, data: status };
      }

      case "stop": {
        if (!input.provider || !input.instanceId) {
          return { content: "stop requires provider and instanceId", isError: true };
        }
        const target = providers.find((p) => p.name === input.provider);
        if (!target) {
          return { content: `Unknown GPU provider: ${input.provider}`, isError: true };
        }
        await target.destroy(input.instanceId);
        if (input.jobId) {
          await completeGPUJob(input.jobId, "cancelled");
        }
        return {
          content: JSON.stringify({ destroyed: true, provider: input.provider, instanceId: input.instanceId }),
          isError: false,
        };
      }

      default:
        return { content: `Unsupported gpu_compute action: ${String(input.action)}`, isError: true };
    }
  },
};

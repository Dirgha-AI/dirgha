/**
 * `dirgha gpu` — Open GPU Cloud Market & Third-Party Provider Onboarding CLI.
 *
 * Subcommands:
 *   dirgha gpu list [--provider=<id>] [--jurisdiction=<ISO>] [--json]
 *   dirgha gpu providers [--json]
 *   dirgha gpu certify <manifest.json> [--live] [--offline] [--json]
 *   dirgha gpu submit <manifest.json> [--offline] [--json]
 *   dirgha gpu remove <provider-id>
 *   dirgha gpu budget [amountUsd]
 *   dirgha gpu jobs [--json]
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { stdout, stderr } from "node:process";
import type { Subcommand } from "./index.js";
import { parseFlags } from "../flags.js";
import {
  certifyProviderManifest,
  getAllGPUProviders,
  listProviderMetadata,
  registerCustomProvider,
  removeCustomProvider,
  validateProviderManifest,
} from "../../gpu/provider-spec.js";
import {
  exportGpuChargebackCsv,
  findOptimalGPUs,
  scaffoldProviderManifest,
  type ComplianceRequirement,
} from "../../gpu/router.js";
import {
  getBudget,
  listGPUJobs,
  setBudget,
  totalGPUSpend,
} from "../../gpu/jobs.js";
import { resolveModulesConfig } from "../../safety/modules-config.js";

function printGpuHelp(): void {
  stdout.write(`Usage: dirgha gpu <command> [options]

Open GPU Cloud Market — compare GPUs, manage spend caps, and certify/register
third-party GPU cloud providers via the Dirgha Provider Schema v1.0.

Commands:
  list [--provider=<id>] [--jurisdiction=<ISO>] [--json]
                                 Compare available GPUs sorted by $/hr
  find [--vram=80] [--max-price=3.0] [--gpu=H100] [--jurisdiction=EU] [--compliance=gdpr,dpdp] [--json]
                                 Smart cheapest-compliant GPU router across all clouds
  providers [--json]             List built-in & registered partner GPU clouds
  init-manifest --id=<slug> --name=<name> --endpoint=<https://...> [--out=manifest.json]
                                 Scaffold a v1.0 manifest for a new GPU cloud partner
  certify <manifest.json> [--live] [--offline] [--json]
                                 Validate & certify a provider manifest
  register|submit <manifest.json> [--offline] [--json]
                                 Certify and register a new GPU cloud provider
  remove <provider-id>           Remove a custom registered provider
  budget [usd]                   Show or set the GPU spend cap in USD
  jobs [--json]                  List tracked GPU jobs & lifetime spend
  chargeback [--csv] [--json]    Export GPU FinOps chargeback report

Schema: specs/GPU_PROVIDER_SCHEMA.json
Docs:   docs/gpu-cloud-market.md
`);
}

export const gpuSubcommand: Subcommand = {
  name: "gpu",
  aliases: ["gpus"],
  description: "Open GPU Cloud Market & third-party GPU provider onboarding",
  async run(argv: string[]): Promise<number> {
    const { flags, positionals } = parseFlags(argv);
    const sub = positionals[0];
    const asJson = flags.json === true;

    if (!sub || sub === "help" || flags.help || flags.h) {
      printGpuHelp();
      return 0;
    }

    const { modules } = resolveModulesConfig({ flags });

    if (sub === "providers") {
      const providers = listProviderMetadata();
      if (asJson) {
        stdout.write(JSON.stringify({ providers }, null, 2) + "\n");
      } else {
        stdout.write("Registered GPU Cloud Providers:\n\n");
        for (const p of providers) {
          const kind = p.builtin ? "built-in" : "partner";
          const auth = p.configured ? "auth:OK" : `auth:unset (${p.authEnvVar})`;
          stdout.write(
            `  - ${p.id.padEnd(14)} ${p.name.padEnd(20)} [${kind}] jurisdictions=[${p.jurisdictions.join(",")}] ${auth}\n`,
          );
        }
      }
      return 0;
    }

    if (sub === "list") {
      if (!modules.gpuMarket.enabled) {
        stderr.write("GPU Cloud Market is disabled (--no-gpu / DIRGHA_GPU_MARKET=0).\n");
        return 1;
      }
      const jurisdictionFlag =
        typeof flags.jurisdiction === "string" ? [flags.jurisdiction.toUpperCase()] : undefined;
      const allowedJurisdictions = jurisdictionFlag ?? modules.gpuMarket.allowedJurisdictions;
      const providers = getAllGPUProviders(undefined, { allowedJurisdictions });
      const filtered =
        typeof flags.provider === "string"
          ? providers.filter((p) => p.name === flags.provider)
          : providers;

      const all = (
        await Promise.all(
          filtered.map(async (p) => {
            try {
              return await p.listGPUTypes();
            } catch {
              return [];
            }
          }),
        )
      )
        .flat()
        .filter((g) => g.available)
        .sort((a, b) => a.costPerHr - b.costPerHr);

      if (asJson) {
        stdout.write(JSON.stringify({ count: all.length, gpus: all }, null, 2) + "\n");
      } else if (all.length === 0) {
        stdout.write("No available GPU SKUs matched your filters.\n");
      } else {
        stdout.write("Available GPUs (sorted by $/hr):\n\n");
        for (const g of all) {
          stdout.write(
            `  $${g.costPerHr.toFixed(2)}/hr  ${g.name.padEnd(24)} ${String(g.vramGb).padStart(3)} GB  provider=${g.provider}${g.region ? ` (${g.region})` : ""}\n`,
          );
        }
      }
      return 0;
    }

    if (sub === "certify" || sub === "submit" || sub === "register") {
      const isRegister = sub === "submit" || sub === "register";
      const filePath = positionals[1];
      if (!filePath) {
        stderr.write(`Usage: dirgha gpu ${sub} <manifest.json>\n`);
        return 1;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(readFileSync(filePath, "utf8"));
      } catch (err) {
        stderr.write(
          `Failed to read JSON manifest "${filePath}": ${err instanceof Error ? err.message : String(err)}\n`,
        );
        return 1;
      }
      const report = await certifyProviderManifest(parsed, {
        probeLive: flags.live === true || flags.probe === true,
        skipDns: flags.offline === true,
      });

      if (isRegister && report.certified) {
        const validated = validateProviderManifest(parsed);
        if (validated.valid && validated.manifest) {
          registerCustomProvider(validated.manifest);
        }
      }

      if (asJson) {
        stdout.write(
          JSON.stringify(
            {
              action: sub,
              registered: isRegister && report.certified,
              ...report,
            },
            null,
            2,
          ) + "\n",
        );
      } else {
        stdout.write(
          `Provider "${report.providerId}" certification: ${report.certified ? "CERTIFIED" : "FAILED"}\n`,
        );
        for (const c of report.checks) {
          stdout.write(`  [${c.passed ? "PASS" : "FAIL"}] ${c.id}: ${c.detail}\n`);
        }
        if (isRegister && report.certified) {
          stdout.write(`\nRegistered "${report.providerId}" into ~/.dirgha/gpu-providers.json\n`);
        }
      }
      return report.certified ? 0 : 1;
    }

    if (sub === "remove") {
      const id = positionals[1];
      if (!id) {
        stderr.write("Usage: dirgha gpu remove <provider-id>\n");
        return 1;
      }
      const removed = removeCustomProvider(id);
      if (!removed) {
        stderr.write(`Custom provider "${id}" not found.\n`);
        return 1;
      }
      stdout.write(`Removed custom GPU provider "${id}".\n`);
      return 0;
    }

    if (sub === "budget") {
      const amountArg = positionals[1];
      if (amountArg !== undefined) {
        const parsed = Number.parseFloat(amountArg.replace(/^\$/, ""));
        if (!Number.isFinite(parsed) || parsed < 0) {
          stderr.write("Budget must be a non-negative USD number (0 = unlimited).\n");
          return 1;
        }
        setBudget(parsed);
        stdout.write(`GPU budget cap set to $${parsed.toFixed(2)} USD.\n`);
        return 0;
      }
      const budget = modules.gpuMarket.budgetUsd ?? getBudget();
      const spend = await totalGPUSpend();
      if (asJson) {
        stdout.write(JSON.stringify({ budgetUsd: budget, lifetimeSpendUsd: spend }, null, 2) + "\n");
      } else {
        stdout.write(
          `GPU Budget Cap: ${budget > 0 ? `$${budget.toFixed(2)} USD` : "unlimited"}\nLifetime Spend: $${spend.toFixed(4)} USD\n`,
        );
      }
      return 0;
    }

    if (sub === "jobs") {
      const jobs = await listGPUJobs();
      const spend = await totalGPUSpend();
      if (asJson) {
        stdout.write(JSON.stringify({ jobs, lifetimeSpendUsd: spend }, null, 2) + "\n");
      } else if (jobs.length === 0) {
        stdout.write(`No GPU jobs recorded yet (lifetime spend: $${spend.toFixed(4)}).\n`);
      } else {
        for (const j of jobs) {
          stdout.write(
            `  ${j.id}  [${j.status}]  ${j.provider}  ${j.gpuType}  $${j.costPerHr.toFixed(2)}/hr  total=$${j.totalCost.toFixed(4)}\n`,
          );
        }
      }
      return 0;
    }

    if (sub === "find") {
      if (!modules.gpuMarket.enabled) {
        stderr.write("GPU Cloud Market is disabled (--no-gpu / DIRGHA_GPU_MARKET=0).\n");
        return 1;
      }
      const jurisdictions =
        typeof flags.jurisdiction === "string"
          ? flags.jurisdiction.split(",").map((j) => j.trim().toUpperCase()).filter(Boolean)
          : modules.gpuMarket.allowedJurisdictions;
      const reqCompliance =
        typeof flags.compliance === "string"
          ? (flags.compliance
              .split(",")
              .map((s) => s.trim().toLowerCase())
              .filter((s) => ["soc2", "iso27001", "dpdp", "gdpr"].includes(s)) as ComplianceRequirement[])
          : undefined;
      const providers = getAllGPUProviders(undefined, { allowedJurisdictions: jurisdictions });
      const routed = await findOptimalGPUs(providers, {
        minVramGb: typeof flags.vram === "string" ? Number(flags.vram) : undefined,
        maxCostPerHr: typeof flags["max-price"] === "string" ? Number(flags["max-price"]) : undefined,
        gpuNameContains: typeof flags.gpu === "string" ? flags.gpu : undefined,
        jurisdictions,
        requireCompliance: reqCompliance,
        limit: 10,
      });
      if (asJson) {
        stdout.write(JSON.stringify(routed, null, 2) + "\n");
      } else if (routed.recommendations.length === 0) {
        stdout.write("No compliant GPU SKUs matched your filters.\n");
      } else {
        stdout.write("Top Compliant GPU Recommendations (cheapest first):\n\n");
        for (const rec of routed.recommendations) {
          stdout.write(
            `  $${rec.gpu.costPerHr.toFixed(2)}/hr  ${rec.gpu.name.padEnd(24)} ${String(rec.gpu.vramGb).padStart(3)} GB  provider=${rec.gpu.provider} (${rec.reasons.join(", ")})\n`,
          );
        }
      }
      return 0;
    }

    if (sub === "init-manifest") {
      const id = typeof flags.id === "string" ? flags.id : undefined;
      const name = typeof flags.name === "string" ? flags.name : undefined;
      const endpoint = typeof flags.endpoint === "string" ? flags.endpoint : undefined;
      if (!id || !name || !endpoint) {
        stderr.write(
          "Usage: dirgha gpu init-manifest --id=<slug> --name=<name> --endpoint=<https://...> [--jurisdictions=IN,EU] [--out=manifest.json]\n",
        );
        return 1;
      }
      const jurisdictions =
        typeof flags.jurisdictions === "string"
          ? flags.jurisdictions.split(",").map((j) => j.trim().toUpperCase()).filter(Boolean)
          : ["EU", "US"];
      const manifest = scaffoldProviderManifest({
        id,
        name,
        endpoint,
        jurisdictions,
        contactEmail: typeof flags.email === "string" ? flags.email : undefined,
      });
      const jsonStr = JSON.stringify(manifest, null, 2) + "\n";
      if (typeof flags.out === "string") {
        const outPath = resolve(process.cwd(), flags.out);
        writeFileSync(outPath, jsonStr, "utf8");
        stdout.write(`Wrote partner GPU manifest to ${outPath}\n`);
      } else {
        stdout.write(jsonStr);
      }
      return 0;
    }

    if (sub === "chargeback") {
      const jobs = await listGPUJobs();
      const spend = await totalGPUSpend();
      if (flags.csv === true) {
        stdout.write(exportGpuChargebackCsv(jobs));
      } else {
        stdout.write(
          JSON.stringify(
            {
              generatedAt: new Date().toISOString(),
              totalJobs: jobs.length,
              totalSpendUsd: Number(spend.toFixed(4)),
              jobs,
            },
            null,
            2,
          ) + "\n",
        );
      }
      return 0;
    }

    stderr.write(`Unknown gpu subcommand: "${sub}"\n`);
    printGpuHelp();
    return 1;
  },
};

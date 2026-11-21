/**
 * Modular stack configuration & Enterprise Org-Lock for Dirgha 2.0.
 *
 * Allows solo developers to run Dirgha with zero governance friction
 * (`developer` profile: LOKAHI & Arniko OFF by default, GPU Cloud Market ON),
 * while giving teams and regulated enterprises deterministic opt-in or
 * org-locked enforcement (`advisory` / `enforce`).
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { existsSync, readFileSync } from "node:fs";

export type DirghaProfile =
  | "developer"
  | "safe-dev"
  | "team"
  | "enterprise"
  | "robotics";

export type LokahiMode = "off" | "advisory" | "enforce";

export interface LokahiModuleConfig {
  /** off = disabled, advisory = evaluate & log only, enforce = fail-closed gate */
  mode: LokahiMode;
  /** Optional path to an RFC-8785 signed LOKAHI boundary manifest JSON */
  manifestPath?: string;
  /** Optional path to trusted Ed25519 PEM public key to cryptographically verify manifestPath */
  publicKeyPath?: string;
  /** Execution engine: in-process WASM or external LOKAHI HTTP/MCP gateway */
  engine?: "wasm" | "gateway";
  /** Optional LOKAHI HTTP gateway URL when engine === "gateway" */
  gatewayUrl?: string;
  /** True when locked by an organization policy file (/etc/dirgha/policy.json) */
  locked?: boolean;
}

export interface ArnikoModuleConfig {
  enabled: boolean;
  onPreCommit?: boolean;
  onAgentOutput?: boolean;
  scanners?: string[];
  locked?: boolean;
}

export interface AhimsaModuleConfig {
  enabled: boolean;
  manifestPath?: string;
}

export interface GpuMarketModuleConfig {
  enabled: boolean;
  budgetUsd?: number;
  /** Optional ISO jurisdiction allowlist enforced before GPU provisioning (e.g. ["IN", "EU", "US"]) */
  allowedJurisdictions?: string[];
  providers?: string[];
}

export interface ModulesConfig {
  lokahi: LokahiModuleConfig;
  arniko: ArnikoModuleConfig;
  ahimsa: AhimsaModuleConfig;
  gpuMarket: GpuMarketModuleConfig;
}

export interface OrgPolicyLock {
  orgName?: string;
  locked: boolean;
  minLokahiMode?: LokahiMode;
  requireArniko?: boolean;
  manifestPath?: string;
  publicKeyPath?: string;
  allowedJurisdictions?: string[];
  maxGpuBudgetUsd?: number;
}

export const PROFILE_PRESETS: Record<DirghaProfile, ModulesConfig> = {
  developer: {
    lokahi: { mode: "off", engine: "wasm" },
    arniko: { enabled: false, onPreCommit: false, onAgentOutput: false },
    ahimsa: { enabled: false },
    gpuMarket: {
      enabled: true,
      providers: ["runpod", "vast", "spheron", "akash"],
    },
  },
  "safe-dev": {
    lokahi: { mode: "advisory", engine: "wasm" },
    arniko: { enabled: false, onPreCommit: false, onAgentOutput: false },
    ahimsa: { enabled: false },
    gpuMarket: {
      enabled: true,
      providers: ["runpod", "vast", "spheron", "akash"],
    },
  },
  team: {
    lokahi: { mode: "enforce", engine: "wasm" },
    arniko: { enabled: true, onPreCommit: true, onAgentOutput: false },
    ahimsa: { enabled: false },
    gpuMarket: {
      enabled: true,
      providers: ["runpod", "vast", "spheron", "akash"],
    },
  },
  enterprise: {
    lokahi: { mode: "enforce", engine: "wasm" },
    arniko: { enabled: true, onPreCommit: true, onAgentOutput: true },
    ahimsa: { enabled: true },
    gpuMarket: {
      enabled: true,
      providers: ["runpod", "vast", "spheron", "akash"],
    },
  },
  robotics: {
    lokahi: { mode: "enforce", engine: "wasm" },
    arniko: { enabled: true, onPreCommit: false, onAgentOutput: false },
    ahimsa: { enabled: true },
    gpuMarket: {
      enabled: true,
      providers: ["runpod", "vast", "spheron", "akash"],
    },
  },
};

export const DEFAULT_MODULES_CONFIG: ModulesConfig = structuredClone(
  PROFILE_PRESETS.developer,
);

const LOKAHI_RANK: Record<LokahiMode, number> = {
  off: 0,
  advisory: 1,
  enforce: 2,
};

export function isValidProfile(value: unknown): value is DirghaProfile {
  return (
    value === "developer" ||
    value === "safe-dev" ||
    value === "team" ||
    value === "enterprise" ||
    value === "robotics"
  );
}

export function isValidLokahiMode(value: unknown): value is LokahiMode {
  return value === "off" || value === "advisory" || value === "enforce";
}

/**
 * Load optional enterprise org policy lock from `DIRGHA_ORG_POLICY`
 * or `/etc/dirgha/policy.json`. Returns null when absent.
 * If the file is configured via `DIRGHA_ORG_POLICY` and is malformed,
 * fails closed by returning a locked `enforce` policy.
 */
export function loadOrgPolicyLock(
  env: NodeJS.ProcessEnv = process.env,
): OrgPolicyLock | null {
  const explicitPath = env.DIRGHA_ORG_POLICY;
  const candidatePath = explicitPath ?? "/etc/dirgha/policy.json";
  if (!existsSync(candidatePath)) {
    if (explicitPath) {
      return {
        locked: true,
        minLokahiMode: "enforce",
        orgName: "missing-org-policy-fail-closed",
      };
    }
    return null;
  }
  try {
    const parsed = JSON.parse(readFileSync(candidatePath, "utf8")) as Partial<OrgPolicyLock>;
    return {
      orgName: parsed.orgName,
      locked: parsed.locked !== false,
      minLokahiMode: isValidLokahiMode(parsed.minLokahiMode)
        ? parsed.minLokahiMode
        : "enforce",
      requireArniko: parsed.requireArniko === true,
      manifestPath: parsed.manifestPath,
      publicKeyPath: parsed.publicKeyPath,
      allowedJurisdictions: Array.isArray(parsed.allowedJurisdictions)
        ? parsed.allowedJurisdictions.map(String)
        : undefined,
      maxGpuBudgetUsd:
        typeof parsed.maxGpuBudgetUsd === "number" && Number.isFinite(parsed.maxGpuBudgetUsd)
          ? parsed.maxGpuBudgetUsd
          : undefined,
    };
  } catch {
    return {
      locked: true,
      minLokahiMode: "enforce",
      orgName: "malformed-org-policy-fail-closed",
    };
  }
}

export interface ModuleResolutionInput {
  profile?: DirghaProfile;
  configured?: Partial<{
    lokahi: Partial<LokahiModuleConfig>;
    arniko: Partial<ArnikoModuleConfig>;
    ahimsa: Partial<AhimsaModuleConfig>;
    gpuMarket: Partial<GpuMarketModuleConfig>;
  }>;
  flags?: Record<string, string | boolean>;
  env?: NodeJS.ProcessEnv;
  orgLock?: OrgPolicyLock | null;
}

export interface ModuleResolutionResult {
  profile: DirghaProfile;
  modules: ModulesConfig;
  orgLocked: boolean;
  warnings: string[];
  errors: string[];
}

/**
 * Pure, deterministic resolver merging:
 *   profile preset -> user/project config -> env vars -> CLI flags -> org policy lock.
 *
 * If an org policy lock is active and the caller attempts to disable LOKAHI
 * (e.g. `--no-lokahi`) or Arniko (`--no-arniko`), `errors` is populated so
 * callers can refuse startup fail-closed.
 */
export function resolveModulesConfig(
  input: ModuleResolutionInput = {},
): ModuleResolutionResult {
  const env = input.env ?? process.env;
  const flags = input.flags ?? {};
  const warnings: string[] = [];
  const errors: string[] = [];

  const flagProfile = flags.profile;
  const envProfile = env.DIRGHA_PROFILE;
  const profile: DirghaProfile = isValidProfile(flagProfile)
    ? flagProfile
    : isValidProfile(envProfile)
      ? envProfile
      : isValidProfile(input.profile)
        ? input.profile
        : "developer";

  const preset = structuredClone(PROFILE_PRESETS[profile]);
  const cfg = input.configured ?? {};

  const modules: ModulesConfig = {
    lokahi: { ...preset.lokahi, ...(cfg.lokahi ?? {}) },
    arniko: { ...preset.arniko, ...(cfg.arniko ?? {}) },
    ahimsa: { ...preset.ahimsa, ...(cfg.ahimsa ?? {}) },
    gpuMarket: { ...preset.gpuMarket, ...(cfg.gpuMarket ?? {}) },
  };

  // Environment overrides
  if (isValidLokahiMode(env.DIRGHA_LOKAHI_MODE)) {
    modules.lokahi.mode = env.DIRGHA_LOKAHI_MODE;
  }
  if (env.DIRGHA_LOKAHI_MANIFEST) {
    modules.lokahi.manifestPath = env.DIRGHA_LOKAHI_MANIFEST;
  }
  if (env.DIRGHA_LOKAHI_PUBKEY) {
    modules.lokahi.publicKeyPath = env.DIRGHA_LOKAHI_PUBKEY;
  }
  if (env.DIRGHA_ARNIKO === "1" || env.DIRGHA_ARNIKO === "true") {
    modules.arniko.enabled = true;
  } else if (env.DIRGHA_ARNIKO === "0" || env.DIRGHA_ARNIKO === "false") {
    modules.arniko.enabled = false;
  }
  if (env.DIRGHA_GPU_MARKET === "0" || env.DIRGHA_GPU_MARKET === "false") {
    modules.gpuMarket.enabled = false;
  } else if (env.DIRGHA_GPU_MARKET === "1" || env.DIRGHA_GPU_MARKET === "true") {
    modules.gpuMarket.enabled = true;
  }

  // CLI flag overrides
  let explicitlyDisabledLokahi = false;
  let explicitlyDisabledArniko = false;

  if (flags["no-lokahi"] === true) {
    modules.lokahi.mode = "off";
    explicitlyDisabledLokahi = true;
  } else if (typeof flags["lokahi-mode"] === "string") {
    if (isValidLokahiMode(flags["lokahi-mode"])) {
      modules.lokahi.mode = flags["lokahi-mode"];
      if (flags["lokahi-mode"] === "off") explicitlyDisabledLokahi = true;
    } else {
      warnings.push(
        `Unknown --lokahi-mode="${flags["lokahi-mode"]}"; expected off|advisory|enforce`,
      );
    }
  } else if (typeof flags.lokahi === "string") {
    if (isValidLokahiMode(flags.lokahi)) {
      modules.lokahi.mode = flags.lokahi;
      if (flags.lokahi === "off") explicitlyDisabledLokahi = true;
    } else {
      warnings.push(
        `Unknown --lokahi="${flags.lokahi}"; expected off|advisory|enforce`,
      );
    }
  } else if (flags.lokahi === true) {
    modules.lokahi.mode = "enforce";
  }

  if (flags["no-arniko"] === true) {
    modules.arniko.enabled = false;
    explicitlyDisabledArniko = true;
  } else if (flags.arniko === true) {
    modules.arniko.enabled = true;
  }

  if (flags["no-gpu"] === true) {
    modules.gpuMarket.enabled = false;
  }

  // Enterprise Org-Lock enforcement (non-bypassable floor)
  const orgLock = input.orgLock === undefined ? loadOrgPolicyLock(env) : input.orgLock;
  const orgLocked = Boolean(orgLock?.locked);
  if (orgLock && orgLock.locked) {
    const minMode: LokahiMode = orgLock.minLokahiMode ?? "enforce";
    if (explicitlyDisabledLokahi && LOKAHI_RANK[minMode] > 0) {
      errors.push(
        `Organization policy (${orgLock.orgName ?? "locked"}) requires LOKAHI mode >= "${minMode}"; --no-lokahi is forbidden.`,
      );
    }
    if (LOKAHI_RANK[modules.lokahi.mode] < LOKAHI_RANK[minMode]) {
      modules.lokahi.mode = minMode;
    }
    modules.lokahi.locked = true;
    if (orgLock.manifestPath && !modules.lokahi.manifestPath) {
      modules.lokahi.manifestPath = orgLock.manifestPath;
    }
    if (orgLock.publicKeyPath && !modules.lokahi.publicKeyPath) {
      modules.lokahi.publicKeyPath = orgLock.publicKeyPath;
    }

    if (orgLock.requireArniko) {
      if (explicitlyDisabledArniko) {
        errors.push(
          `Organization policy (${orgLock.orgName ?? "locked"}) requires Arniko scanning; --no-arniko is forbidden.`,
        );
      }
      modules.arniko.enabled = true;
      modules.arniko.locked = true;
    }

    if (orgLock.allowedJurisdictions && orgLock.allowedJurisdictions.length > 0) {
      modules.gpuMarket.allowedJurisdictions = orgLock.allowedJurisdictions;
    }
    if (
      orgLock.maxGpuBudgetUsd !== undefined &&
      (modules.gpuMarket.budgetUsd === undefined ||
        modules.gpuMarket.budgetUsd > orgLock.maxGpuBudgetUsd)
    ) {
      modules.gpuMarket.budgetUsd = orgLock.maxGpuBudgetUsd;
    }
  }

  return { profile, modules, orgLocked, warnings, errors };
}

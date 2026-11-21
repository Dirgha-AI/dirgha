/**
 * Unified Lokahi Runtime Gate for TypeScript tool execution.
 *
 * Bridges the tool executor seam to:
 * 1. Real tool payload extraction (shell command, file path, URL, GPU spend/jurisdiction)
 * 2. Toggleable enforcement modes: `off` | `advisory` | `enforce` (fail-closed)
 * 3. Optional signed LOKAHI Boundary Manifest tool-policy validation
 * 4. Dual WASM ABI support:
 *    - Canonical `Dirgha-AI/lokahi` `wasm_preflight` (`lokahi_alloc` + `preflight_check`)
 *    - Built-in `lokahi_gate.wasm` (`lokahi_c_abi_evaluate_utf8`, with `lokahi_alloc`/`lokahi_free` when exported)
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { existsSync, readFileSync } from "node:fs";
import type { ToolCall } from "../kernel/types.js";
import type {
  PermissionCheck,
  PermissionDecision,
  PermissionEngine,
} from "../tools/permission.js";
import { DefaultPermissionEngine } from "../tools/permission.js";
import {
  createPolicyEngine,
  evaluateLokahiGateSync,
  type LokahiWasmSyncExports,
} from "./policy.js";
import {
  DEFAULT_MODULES_CONFIG,
  type ModulesConfig,
} from "./modules-config.js";
import { verifyManifestEd25519 } from "./lokahi-crypto.js";
import { evaluateToolArgConstraints } from "./lokahi-conformance.js";
import { checkArnikoToolGuard } from "../security/arniko-hooks.js";

export interface ExtractedToolIntent {
  check: PermissionCheck;
  isS2Critical: boolean;
  jurisdiction?: string;
  estimatedSpendUsd?: number;
}

const READ_TOOLS = new Set([
  "fs_read",
  "fs_ls",
  "search_grep",
  "search_glob",
  "kb_search",
  "graph_neighbors",
  "graph_traverse",
  "db_workspace_info",
  "lsp_definition",
  "lsp_references",
  "lsp_hover",
  "lsp_symbols",
  "qmd",
]);

const WRITE_TOOLS = new Set([
  "fs_write",
  "fs_edit",
  "transactional_write",
]);

const NETWORK_TOOLS = new Set([
  "browser",
  "github",
  "gpu_compute",
  "image_generate",
  "video_generate",
  "audio_generate",
]);

function asRecord(input: unknown): Record<string, unknown> {
  return typeof input === "object" && input !== null
    ? (input as Record<string, unknown>)
    : {};
}

function firstString(
  rec: Record<string, unknown>,
  keys: string[],
): string | undefined {
  for (const key of keys) {
    const val = rec[key];
    if (typeof val === "string" && val.trim().length > 0) return val;
  }
  return undefined;
}

/**
 * Extract the real security-relevant action, target payload, and S2 criticality
 * from a ToolCall so the permission & Lokahi WASM gates evaluate the ACTUAL
 * command/path/URL/spend instead of only `cwd`.
 */
export function extractToolIntent(
  call: ToolCall,
  cwd: string,
): ExtractedToolIntent {
  const input = asRecord(call.input);
  const name = call.name;

  if (name === "shell") {
    const command = firstString(input, ["command", "cmd"]) ?? "";
    const isDestructive =
      /\b(rm\s+-[a-z]*r|mkfs\.|dd\s+if=|sudo\s+|chmod\s+-R\s+777|git\s+push\s+--force|kubectl\s+delete)\b/i.test(
        command,
      );
    return {
      check: { tool: name, action: "exec", target: command || cwd },
      isS2Critical: isDestructive,
    };
  }

  if (READ_TOOLS.has(name)) {
    const target =
      firstString(input, ["path", "filePath", "file", "dir", "directory", "pattern", "query"]) ??
      cwd;
    return {
      check: { tool: name, action: "read", target },
      isS2Critical: false,
    };
  }

  if (WRITE_TOOLS.has(name)) {
    const target =
      firstString(input, ["path", "filePath", "file", "target"]) ?? cwd;
    return {
      check: { tool: name, action: "write", target },
      isS2Critical: false,
    };
  }

  if (name === "browser") {
    const target =
      firstString(input, ["url", "href", "endpoint", "selector", "action"]) ??
      JSON.stringify(input);
    return {
      check: { tool: name, action: "network", target },
      isS2Critical: false,
    };
  }

  if (name === "gpu_compute") {
    const actionName = firstString(input, ["action", "op"]) ?? "list";
    const jurisdiction = firstString(input, ["jurisdiction", "region"]);
    const estimatedSpendUsd =
      typeof input.estimatedSpendUsd === "number"
        ? input.estimatedSpendUsd
        : typeof input.hours === "number" && typeof input.costPerHr === "number"
          ? input.hours * input.costPerHr
          : undefined;
    const isProvision = actionName === "provision" || actionName === "launch";
    return {
      check: {
        tool: name,
        action: "network",
        target: JSON.stringify(input),
      },
      isS2Critical: isProvision,
      jurisdiction,
      estimatedSpendUsd,
    };
  }

  if (name === "git") {
    const args = Array.isArray(input.args)
      ? input.args.map(String).join(" ")
      : firstString(input, ["command", "subcommand", "args"]) ?? "";
    const target = `git ${args}`.trim();
    const isS2 = /(--force|\bpush\b.*\bmain\b|\breset\s+--hard\b)/i.test(target);
    return {
      check: { tool: name, action: "exec", target },
      isS2Critical: isS2,
    };
  }

  if (NETWORK_TOOLS.has(name)) {
    const target =
      firstString(input, ["url", "endpoint", "repo", "prompt"]) ??
      JSON.stringify(input);
    return {
      check: { tool: name, action: "network", target },
      isS2Critical: false,
    };
  }

  const fallbackTarget =
    firstString(input, ["command", "path", "filePath", "url", "target"]) ??
    (Object.keys(input).length > 0 ? JSON.stringify(input) : cwd);
  return {
    check: { tool: name, action: "exec", target: fallbackTarget },
    isS2Critical: false,
  };
}

export interface LokahiManifestPolicy {
  manifest_version?: string;
  expires?: string;
  signature?: string;
  residency?: string[];
  tools?: Record<
    string,
    {
      class?: "read" | "write" | "irreversible";
      args?: Record<string, string | null>;
      jurisdiction?: string;
    }
  >;
}

/**
 * Validate an optional LOKAHI Boundary Manifest (RFC-8785 / v0.1.3+ rules 1-3 + default-deny tool policy).
 * Returns null if allowed, or a refusal reason string if denied.
 */
export function checkLokahiManifestToolPolicy(
  manifestPath: string,
  toolName: string,
  now: Date = new Date(),
  opts?: { publicKeyPath?: string; publicKeyPem?: string; toolInput?: unknown },
): string | null {
  if (!existsSync(manifestPath)) {
    return `lokahi_manifest_missing: ${manifestPath}`;
  }
  let manifest: LokahiManifestPolicy;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as LokahiManifestPolicy;
  } catch {
    return "lokahi_manifest_malformed";
  }

  // Rule 1: signature non-empty
  if (!manifest.signature || typeof manifest.signature !== "string" || manifest.signature.trim() === "") {
    return "unsigned_manifest";
  }

  // Rule 1b: cryptographic RFC-8785 + Ed25519 verification when a trusted public key is configured
  let pubPem = opts?.publicKeyPem;
  if (!pubPem && opts?.publicKeyPath) {
    if (!existsSync(opts.publicKeyPath)) {
      return `lokahi_public_key_missing: ${opts.publicKeyPath}`;
    }
    try {
      pubPem = readFileSync(opts.publicKeyPath, "utf8");
    } catch {
      return "lokahi_public_key_unreadable";
    }
  }
  if (pubPem) {
    const verification = verifyManifestEd25519(
      manifest as unknown as Record<string, unknown>,
      pubPem,
    );
    if (!verification.valid) {
      return `invalid_manifest_signature:${verification.reason ?? "verification_failed"}`;
    }
  }

  // Rule 3: expires must be timezone-aware ISO string in the future
  if (!manifest.expires || typeof manifest.expires !== "string") {
    return "expired_manifest";
  }
  const hasTz = /(Z|[+-]\d{2}:\d{2})$/i.test(manifest.expires.trim());
  const expMs = Date.parse(manifest.expires);
  if (!hasTz || !Number.isFinite(expMs) || expMs <= now.getTime()) {
    return "expired_manifest";
  }

  // Rule 3a: default-deny tool policy
  if (!manifest.tools || typeof manifest.tools !== "object") {
    return "no_tool_policy";
  }
  if (!(toolName in manifest.tools)) {
    return `tool_not_in_manifest:${toolName}`;
  }

  // Rule 4: argument-level constraints when configured for the tool
  const toolEntry = manifest.tools[toolName];
  if (toolEntry?.args && opts?.toolInput !== undefined) {
    const argErr = evaluateToolArgConstraints(toolName, opts.toolInput, toolEntry.args);
    if (argErr) {
      return argErr;
    }
  }

  return null;
}

export interface RuntimePermissionEngineOptions {
  cwd: string;
  modules?: ModulesConfig;
  onAdvisory?: (message: string) => void;
  /** Injectable WASM loader for deterministic offline unit tests */
  wasmLoader?: LokahiWasmSyncExports | null | (() => LokahiWasmSyncExports | null);
}

export interface RuntimePermissionEngine extends PermissionEngine {
  checkCall(call: ToolCall): PermissionDecision;
}

/**
 * Create the runtime permission engine respecting `modules.lokahi.mode`:
 * - `off`: developer-friendly local permission checks without WASM blocking
 * - `advisory`: runs full LOKAHI WASM + manifest checks, logs warnings, never blocks
 * - `enforce`: fail-closed LOKAHI WASM + optional manifest + jurisdiction/budget checks
 */
export function createRuntimePermissionEngine(
  opts: RuntimePermissionEngineOptions,
): RuntimePermissionEngine {
  const modules = opts.modules ?? DEFAULT_MODULES_CONFIG;
  const lokahiMode = modules.lokahi.mode;
  const defaultEngine = new DefaultPermissionEngine(opts.cwd);
  const policyEngine = createPolicyEngine({ cwd: opts.cwd });

  const evaluateCheck = (
    req: PermissionCheck,
    extra?: {
      isS2Critical?: boolean;
      jurisdiction?: string;
      estimatedSpendUsd?: number;
      toolInput?: unknown;
    },
  ): PermissionDecision => {
    // GPU market governance checks apply whenever GPU tool is called
    if (req.tool === "gpu_compute") {
      if (!modules.gpuMarket.enabled) {
        return {
          allowed: false,
          reason: "gpu_market_disabled: GPU Cloud Market is disabled in config",
          requiresApproval: false,
        };
      }
      if (
        extra?.jurisdiction &&
        modules.gpuMarket.allowedJurisdictions &&
        modules.gpuMarket.allowedJurisdictions.length > 0 &&
        !modules.gpuMarket.allowedJurisdictions
          .map((j) => j.toUpperCase())
          .includes(extra.jurisdiction.toUpperCase())
      ) {
        return {
          allowed: false,
          reason: `residency_violation: jurisdiction "${extra.jurisdiction}" is outside allowed [${modules.gpuMarket.allowedJurisdictions.join(", ")}]`,
          requiresApproval: false,
        };
      }
      if (
        extra?.estimatedSpendUsd !== undefined &&
        modules.gpuMarket.budgetUsd !== undefined &&
        modules.gpuMarket.budgetUsd > 0 &&
        extra.estimatedSpendUsd > modules.gpuMarket.budgetUsd
      ) {
        return {
          allowed: false,
          reason: `gpu_budget_exceeded: estimated $${extra.estimatedSpendUsd.toFixed(2)} exceeds cap $${modules.gpuMarket.budgetUsd.toFixed(2)}`,
          requiresApproval: false,
        };
      }
    }

    // Mode: OFF — zero LOKAHI friction for solo developers
    if (lokahiMode === "off") {
      return defaultEngine.check(req);
    }

    // Mode: ADVISORY or ENFORCE — evaluate LOKAHI manifest (if configured) + WASM gate + policy rules
    let denyReason: string | null = null;

    if (modules.lokahi.manifestPath) {
      const manifestErr = checkLokahiManifestToolPolicy(
        modules.lokahi.manifestPath,
        req.tool,
        new Date(),
        {
          ...(modules.lokahi.publicKeyPath
            ? { publicKeyPath: modules.lokahi.publicKeyPath }
            : {}),
          toolInput: extra?.toolInput,
        },
      );
      if (manifestErr) {
        denyReason = `lokahi-manifest: ${manifestErr}`;
      }
    }

    if (!denyReason) {
      const gate = evaluateLokahiGateSync(
        req.target,
        Boolean(extra?.isS2Critical),
        opts.wasmLoader,
      );
      if (!gate.allowed) {
        denyReason =
          gate.reason === "lokahi_gate_denied"
            ? "lokahi-gate-wasm: blocked by the WebAssembly safety gate"
            : `lokahi-gate-wasm: ${gate.reason}`;
      }
    }

    if (!denyReason) {
      // Also run policy rules (e.g., write-outside-cwd)
      const polDecision =
        opts.wasmLoader === undefined
          ? policyEngine.evaluate(req)
          : defaultEngine.check(req);
      if (!polDecision.allowed) {
        denyReason = polDecision.reason;
      }
    }

    if (denyReason) {
      if (lokahiMode === "advisory") {
        opts.onAdvisory?.(
          `[lokahi:advisory] would deny ${req.tool} (${req.action}): ${denyReason}`,
        );
        return defaultEngine.check(req);
      }
      // Enforce mode: fail-closed
      return {
        allowed: false,
        reason: denyReason,
        requiresApproval: false,
      };
    }

    return defaultEngine.check(req);
  };

  return {
    check(req: PermissionCheck): PermissionDecision {
      return evaluateCheck(req);
    },
    checkCall(call: ToolCall): PermissionDecision {
      const arnikoDecision = checkArnikoToolGuard(call, modules, opts.cwd);
      if (!arnikoDecision.allowed) {
        return arnikoDecision;
      }
      const intent = extractToolIntent(call, opts.cwd);
      return evaluateCheck(intent.check, {
        isS2Critical: intent.isS2Critical,
        jurisdiction: intent.jurisdiction,
        estimatedSpendUsd: intent.estimatedSpendUsd,
        toolInput: call.input,
      });
    },
  };
}

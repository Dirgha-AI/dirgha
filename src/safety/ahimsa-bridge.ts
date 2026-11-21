/**
 * Ahimsa AI -> LOKAHI v1.1 Boundary Manifest Validator & Merger.
 *
 * Bridges regulatory compliance manifests compiled by Ahimsa AI (EU AI Act,
 * India DPDP Act, NIST AI RMF, HIPAA, ISO 42001) into LOKAHI v1.1 runtime
 * boundary manifests.
 *
 * Specifically catches cross-repo incompatibilities before runtime:
 *  1. Missing `tools` policy table (which causes LOKAHI default-deny `no_tool_policy`)
 *  2. Demo/placeholder/HMAC signatures when production Ed25519 signing is required
 *  3. Missing, naive (no timezone offset), or expired `expires` timestamp
 *
 * Licensed under the Apache License, Version 2.0.
 */

import type { LokahiManifestPolicy } from "./lokahi-runtime.js";

export interface AhimsaManifest extends LokahiManifestPolicy {
  organization?: string;
  frameworks?: string[];
  restrictions?: Record<string, unknown>;
  signature_algorithm?: string;
}

export interface AhimsaValidationIssue {
  code:
    | "missing_signature"
    | "demo_signature_rejected"
    | "missing_expires"
    | "naive_or_expired_timestamp"
    | "missing_tools_policy";
  severity: "error" | "warning";
  message: string;
}

export interface AhimsaValidationResult {
  compatibleWithLokahi: boolean;
  issues: AhimsaValidationIssue[];
}

export interface ToolPolicyEntry {
  class: "read" | "write" | "irreversible";
  args?: Record<string, string | null>;
  jurisdiction?: string;
}

const DEMO_SIG_RE = /(demo|hmac|placeholder|unsigned|test-sig)/i;

/**
 * Validate whether an Ahimsa-compiled manifest is directly enforceable by LOKAHI v1.1.
 */
export function validateAhimsaManifest(
  manifest: AhimsaManifest,
  opts?: { requireEd25519?: boolean; now?: Date },
): AhimsaValidationResult {
  const issues: AhimsaValidationIssue[] = [];
  const now = opts?.now ?? new Date();
  const requireEd25519 = opts?.requireEd25519 !== false;

  if (!manifest.signature || typeof manifest.signature !== "string" || manifest.signature.trim() === "") {
    issues.push({
      code: "missing_signature",
      severity: "error",
      message: "Manifest is missing a cryptographic signature (LOKAHI Rule 1 requires a non-empty signature).",
    });
  } else if (
    requireEd25519 &&
    (DEMO_SIG_RE.test(manifest.signature) ||
      (manifest.signature_algorithm && DEMO_SIG_RE.test(manifest.signature_algorithm)))
  ) {
    issues.push({
      code: "demo_signature_rejected",
      severity: "error",
      message: `Manifest uses a demo/HMAC signature ("${manifest.signature_algorithm ?? "unknown"}"); sign with RFC-8785 + Ed25519 before production enforcement.`,
    });
  }

  if (!manifest.expires || typeof manifest.expires !== "string") {
    issues.push({
      code: "missing_expires",
      severity: "error",
      message: "Manifest is missing an RFC 3339 timezone-aware `expires` field (LOKAHI Rule 3).",
    });
  } else {
    const hasTz = /(Z|[+-]\d{2}:\d{2})$/i.test(manifest.expires.trim());
    const expMs = Date.parse(manifest.expires);
    if (!hasTz || !Number.isFinite(expMs) || expMs <= now.getTime()) {
      issues.push({
        code: "naive_or_expired_timestamp",
        severity: "error",
        message: `Manifest expires="${manifest.expires}" is either expired or missing timezone offset (Z / ±HH:MM).`,
      });
    }
  }

  if (!manifest.tools || typeof manifest.tools !== "object" || Object.keys(manifest.tools).length === 0) {
    issues.push({
      code: "missing_tools_policy",
      severity: "error",
      message:
        "Ahimsa manifest omits the `tools` policy table; LOKAHI v1.1 default-deny will block all tool calls with `no_tool_policy`. Merge a tool policy with `mergeAhimsaWithToolPolicy()`.",
    });
  }

  return {
    compatibleWithLokahi: issues.every((i) => i.severity !== "error"),
    issues,
  };
}

/**
 * Default safe tool policy table for Dirgha coding + GPU agents when bridging an Ahimsa manifest.
 */
export const DEFAULT_DIRGHA_TOOL_POLICY: Record<string, ToolPolicyEntry> = {
  fs_read: { class: "read" },
  fs_ls: { class: "read" },
  search_grep: { class: "read" },
  search_glob: { class: "read" },
  fs_write: { class: "write" },
  fs_edit: { class: "write" },
  git: { class: "write" },
  shell: { class: "irreversible" },
  gpu_compute: { class: "irreversible" },
};

/**
 * Merge an Ahimsa compliance manifest (residency, frameworks, restrictions) with
 * an explicit LOKAHI `tools` policy table so the resulting manifest is valid for LOKAHI v1.1.
 * Note: Any existing signature is cleared because the manifest payload changed and must be re-signed.
 */
export function mergeAhimsaWithToolPolicy(
  ahimsa: AhimsaManifest,
  tools: Record<string, ToolPolicyEntry> = DEFAULT_DIRGHA_TOOL_POLICY,
  opts?: { expiresInDays?: number; now?: Date },
): AhimsaManifest {
  const now = opts?.now ?? new Date();
  const days = opts?.expiresInDays ?? 90;
  const defaultExpires = new Date(now.getTime() + days * 24 * 60 * 60 * 1000).toISOString();

  const mergedTools: Record<string, ToolPolicyEntry> = {
    ...tools,
    ...((ahimsa.tools as Record<string, ToolPolicyEntry> | undefined) ?? {}),
  };

  // Propagate primary Ahimsa residency jurisdiction onto GPU compute if not explicitly set
  if (ahimsa.residency && ahimsa.residency.length > 0 && mergedTools.gpu_compute && !mergedTools.gpu_compute.jurisdiction) {
    mergedTools.gpu_compute = {
      ...mergedTools.gpu_compute,
      jurisdiction: ahimsa.residency[0],
    };
  }

  const out: AhimsaManifest = {
    ...ahimsa,
    manifest_version: ahimsa.manifest_version ?? "1.1",
    expires:
      ahimsa.expires && /(Z|[+-]\d{2}:\d{2})$/i.test(ahimsa.expires)
        ? ahimsa.expires
        : defaultExpires,
    tools: mergedTools,
  };
  // Clear stale signature after mutation so caller signs canonically with RFC-8785 + Ed25519
  delete out.signature;
  return out;
}

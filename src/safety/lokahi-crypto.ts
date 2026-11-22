/**
 * RFC-8785 (JSON Canonicalization Scheme) + Ed25519 Policy Signing,
 * Verification & Auditor-Grade Compliance Evidence Packs for Dirgha 2.0 + LOKAHI.
 *
 * Uses Node.js built-in `node:crypto` exclusively (zero external dependencies).
 * All verification paths fail closed.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { ModuleResolutionResult } from "./modules-config.js";
import { listProviderMetadata } from "../gpu/provider-spec.js";
import { evaluateLokahiGateSync } from "./policy.js";

/**
 * Deterministic RFC-8785 (JCS) JSON Canonicalization.
 *
 * - Object properties are recursively sorted by UTF-16 code-unit order
 *   (matching RFC-8785 §3.2.3).
 * - Undefined object properties are omitted (standard JSON semantics).
 * - Numbers reject NaN / Infinity (not representable in JSON).
 * - No insignificant whitespace is emitted.
 */
export function canonicalizeJcs(value: unknown): string {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value as number)) {
      throw new Error("RFC-8785 JCS cannot serialize non-finite numbers (NaN/Infinity)");
    }
    // ES2015+ JSON.stringify produces shortest round-trip IEEE-754 decimal per RFC-8785 §3.2.2.3
    return Object.is(value, -0) ? "0" : JSON.stringify(value);
  }
  if (t === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((item) => (item === undefined ? "null" : canonicalizeJcs(item))).join(",") + "]";
  }
  if (t === "object") {
    const rec = value as Record<string, unknown>;
    const keys = Object.keys(rec)
      .filter((k) => rec[k] !== undefined)
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const pairs = keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJcs(rec[k])}`);
    return "{" + pairs.join(",") + "}";
  }
  throw new Error(`RFC-8785 JCS cannot serialize value of type "${t}"`);
}

function toUint8(input: string | Buffer | Uint8Array): Uint8Array<ArrayBuffer> {
  if (typeof input === "string") {
    return Uint8Array.from(Buffer.from(input, "utf8"));
  }
  return Uint8Array.from(input);
}

export function sha256Hex(input: string | Buffer | Uint8Array): string {
  return createHash("sha256").update(toUint8(input)).digest("hex");
}

export interface Ed25519Keypair {
  publicKeyPem: string;
  privateKeyPem: string;
  keyFingerprintSha256: string;
}

/**
 * Generate a fresh Ed25519 policy-signing keypair (OS CSPRNG via OpenSSL/Node crypto).
 */
export function generateEd25519Keypair(): Ed25519Keypair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const der = createPublicKey(publicKey).export({ type: "spki", format: "der" });
  return {
    publicKeyPem: publicKey,
    privateKeyPem: privateKey,
    keyFingerprintSha256: sha256Hex(der),
  };
}

/**
 * Strip signature field prior to canonicalization so sign and verify hash identical bytes.
 */
function stripSignatureFields(obj: Record<string, unknown>): Record<string, unknown> {
  const clone: Record<string, unknown> = { ...obj };
  delete clone.signature;
  return clone;
}

export interface SignedManifestResult<T extends Record<string, unknown>> {
  signedManifest: T & {
    signature: string;
    signature_algorithm: "RFC8785-Ed25519";
    signer_key_fingerprint: string;
  };
  canonicalPayloadSha256: string;
}

/**
 * Sign any LOKAHI/Ahimsa manifest object using RFC-8785 JCS + Ed25519.
 */
export function signManifestEd25519<T extends Record<string, unknown>>(
  manifest: T,
  privateKeyPem: string,
): SignedManifestResult<T> {
  const privKey = createPrivateKey(privateKeyPem);
  const pubKeyDer = createPublicKey(privKey).export({ type: "spki", format: "der" });
  const fingerprint = sha256Hex(pubKeyDer);

  const bodyToSign = {
    ...stripSignatureFields(manifest),
    signature_algorithm: "RFC8785-Ed25519" as const,
    signer_key_fingerprint: fingerprint,
  };
  const canonical = canonicalizeJcs(bodyToSign);
  const payloadBytes = toUint8(canonical);
  const sigBytes = cryptoSign(null, payloadBytes, privKey);
  const signature = `ed25519:${sigBytes.toString("base64")}`;

  return {
    signedManifest: {
      ...(bodyToSign as unknown as T),
      signature_algorithm: "RFC8785-Ed25519",
      signer_key_fingerprint: fingerprint,
      signature,
    },
    canonicalPayloadSha256: sha256Hex(payloadBytes),
  };
}

export interface ManifestSignatureVerification {
  valid: boolean;
  reason?: string;
  canonicalPayloadSha256?: string;
  signerKeyFingerprint?: string;
}

/**
 * Cryptographically verify an RFC-8785 + Ed25519 manifest signature against a trusted public key.
 * Always fails closed on missing, malformed, wrong-algorithm, or tampered manifests.
 */
export function verifyManifestEd25519(
  manifest: Record<string, unknown>,
  publicKeyPem: string,
): ManifestSignatureVerification {
  const rawSig = manifest.signature;
  if (typeof rawSig !== "string" || !rawSig.startsWith("ed25519:")) {
    return {
      valid: false,
      reason: "signature_format_invalid: expected 'ed25519:<base64>'",
    };
  }
  const b64 = rawSig.slice("ed25519:".length).trim();
  if (!b64) {
    return { valid: false, reason: "signature_empty" };
  }

  try {
    const pubKey = createPublicKey(publicKeyPem);
    const pubDer = pubKey.export({ type: "spki", format: "der" });
    const expectedFingerprint = sha256Hex(pubDer);

    if (
      typeof manifest.signer_key_fingerprint === "string" &&
      manifest.signer_key_fingerprint !== expectedFingerprint
    ) {
      return {
        valid: false,
        reason: "signer_fingerprint_mismatch",
      };
    }

    const bodyToVerify = stripSignatureFields(manifest);
    const canonical = canonicalizeJcs(bodyToVerify);
    const payloadBytes = toUint8(canonical);
    const sigBytes = toUint8(Buffer.from(b64, "base64"));
    const ok = cryptoVerify(null, payloadBytes, pubKey, sigBytes);
    if (!ok) {
      return {
        valid: false,
        reason: "ed25519_verification_failed",
      };
    }
    return {
      valid: true,
      canonicalPayloadSha256: sha256Hex(payloadBytes),
      signerKeyFingerprint: expectedFingerprint,
    };
  } catch (err) {
    return {
      valid: false,
      reason: `crypto_verify_error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

export interface ComplianceEvidencePack {
  schemaVersion: "dirgha.evidence.v1";
  generatedAt: string;
  packageVersion: string;
  governance: {
    profile: string;
    orgLocked: boolean;
    lokahiMode: string;
    lokahiManifestPath: string | null;
    lokahiPublicKeyConfigured: boolean;
    arnikoEnabled: boolean;
    ahimsaEnabled: boolean;
    gpuMarketEnabled: boolean;
    gpuAllowedJurisdictions: string[];
    gpuBudgetUsd: number | null;
  };
  controls: {
    wasmGateBlocksDestructive: boolean;
    wasmGateAllowsSafeRead: boolean;
    wasmGateVerified: boolean;
  };
  gpuMarket: {
    registeredProviderCount: number;
    providerIds: string[];
  };
  auditTrail: {
    path: string;
    present: boolean;
    sha256: string | null;
    lineCount: number;
  };
  evidence_sha256: string;
  signature_algorithm?: "RFC8785-Ed25519";
  signer_key_fingerprint?: string;
  signature?: string;
}

/**
 * Build a deterministic, auditor-ready Compliance Evidence Pack (EU AI Act /
 * ISO 42001 / NIST AI RMF) with optional RFC-8785 + Ed25519 cryptographic attestation.
 */
export function buildComplianceEvidencePack(opts: {
  resolution: ModuleResolutionResult;
  auditLogPath?: string;
  gpuRegistryPath?: string;
  privateKeyPem?: string;
  now?: Date;
}): ComplianceEvidencePack {
  const now = opts.now ?? new Date();
  const auditPath = opts.auditLogPath ?? join(homedir(), ".dirgha", "audit.jsonl");

  let auditPresent = false;
  let auditHash: string | null = null;
  let auditLines = 0;
  if (existsSync(auditPath)) {
    try {
      const content = readFileSync(auditPath, "utf8");
      auditPresent = true;
      auditHash = sha256Hex(content);
      auditLines = content.split(/\r?\n/).filter((l) => l.trim().length > 0).length;
    } catch {
      auditPresent = false;
    }
  }

  const badCheck = evaluateLokahiGateSync("sudo rm -fr /", false);
  const goodCheck = evaluateLokahiGateSync("git status", false);
  const wasmBlocks = !badCheck.allowed;
  const wasmAllows = goodCheck.allowed;

  const providers = listProviderMetadata(opts.gpuRegistryPath);
  const { modules } = opts.resolution;

  const unsignedCore = {
    schemaVersion: "dirgha.evidence.v1" as const,
    generatedAt: now.toISOString(),
    packageVersion: "2.0.1",
    governance: {
      profile: opts.resolution.profile,
      orgLocked: opts.resolution.orgLocked,
      lokahiMode: modules.lokahi.mode,
      lokahiManifestPath: modules.lokahi.manifestPath ?? null,
      lokahiPublicKeyConfigured: Boolean(modules.lokahi.publicKeyPath),
      arnikoEnabled: modules.arniko.enabled,
      ahimsaEnabled: modules.ahimsa.enabled,
      gpuMarketEnabled: modules.gpuMarket.enabled,
      gpuAllowedJurisdictions: modules.gpuMarket.allowedJurisdictions ?? [],
      gpuBudgetUsd: modules.gpuMarket.budgetUsd ?? null,
    },
    controls: {
      wasmGateBlocksDestructive: wasmBlocks,
      wasmGateAllowsSafeRead: wasmAllows,
      wasmGateVerified: wasmBlocks && wasmAllows,
    },
    gpuMarket: {
      registeredProviderCount: providers.length,
      providerIds: providers.map((p) => p.id),
    },
    auditTrail: {
      path: auditPath,
      present: auditPresent,
      sha256: auditHash,
      lineCount: auditLines,
    },
  };

  const evidenceHash = sha256Hex(canonicalizeJcs(unsignedCore));
  const pack: ComplianceEvidencePack = {
    ...unsignedCore,
    evidence_sha256: evidenceHash,
  };

  if (opts.privateKeyPem) {
    const signed = signManifestEd25519(
      pack as unknown as Record<string, unknown>,
      opts.privateKeyPem,
    );
    return signed.signedManifest as unknown as ComplianceEvidencePack;
  }

  return pack;
}

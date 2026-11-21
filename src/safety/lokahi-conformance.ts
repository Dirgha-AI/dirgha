/**
 * LOKAHI v1.1 Reference Conformance Engine, Argument-Level Policy Evaluator,
 * Dual-Control S2 Ed25519 Approval Tickets (Rule 14: 45s Ahimsa Silence = Refusal),
 * and External LOKAHI HTTP Gateway Adapter.
 *
 * All verification paths are pure, deterministic, and fail closed.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import {
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import { canonicalizeJcs, sha256Hex } from "./lokahi-crypto.js";
import type { LokahiManifestPolicy } from "./lokahi-runtime.js";
import { assertSafeFetchUrlAsync, type DnsLookupFn } from "../utils/url-guard.js";

function toUint8(input: string | Buffer | Uint8Array): Uint8Array<ArrayBuffer> {
  if (typeof input === "string") {
    return Uint8Array.from(Buffer.from(input, "utf8"));
  }
  return Uint8Array.from(input);
}

/**
 * Convert a lightweight glob pattern (`src/**`, `*.ts`, `data/?/*.json`) into a RegExp.
 */
function globToRegex(pattern: string): RegExp {
  let out = "^";
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === "*") {
      if (pattern[i + 1] === "*") {
        out += ".*";
        i++;
      } else {
        out += "[^/]*";
      }
    } else if (ch === "?") {
      out += "[^/]";
    } else if (/[.+^${}()|[\]\\]/.test(ch)) {
      out += "\\" + ch;
    } else {
      out += ch;
    }
  }
  out += "$";
  return new RegExp(out);
}

/**
 * Match a string value against a LOKAHI argument constraint:
 *  - `/regex/` or `/regex/i` -> regular expression match
 *  - contains `*` or `?` -> glob match
 *  - plain string -> exact string match
 */
export function matchesArgConstraint(value: string, constraint: string): boolean {
  const trimmed = constraint.trim();
  if (trimmed.startsWith("/") && trimmed.lastIndexOf("/") > 0) {
    const lastSlash = trimmed.lastIndexOf("/");
    const body = trimmed.slice(1, lastSlash);
    const flags = trimmed.slice(lastSlash + 1);
    try {
      const re = new RegExp(body, /^[gimsuy]*$/.test(flags) ? flags : "");
      return re.test(value);
    } catch {
      // Invalid regex fails closed
      return false;
    }
  }
  if (trimmed.includes("*") || trimmed.includes("?")) {
    return globToRegex(trimmed).test(value);
  }
  return value === trimmed;
}

/**
 * Evaluate LOKAHI manifest argument-level constraints (`manifest.tools[toolName].args`).
 *
 * Rules:
 * - `constraint === null`: the argument is FORBIDDEN if present in `input`.
 * - `typeof constraint === "string"`: if the argument is present (or required),
 *   its stringified value must satisfy `matchesArgConstraint`. Missing required
 *   constrained arguments also fail closed.
 *
 * Returns null if allowed, or a refusal reason string if denied.
 */
export function evaluateToolArgConstraints(
  toolName: string,
  input: unknown,
  argsPolicy?: Record<string, string | null>,
): string | null {
  if (!argsPolicy || Object.keys(argsPolicy).length === 0) {
    return null;
  }
  const rec =
    typeof input === "object" && input !== null
      ? (input as Record<string, unknown>)
      : {};

  for (const [argName, rule] of Object.entries(argsPolicy)) {
    const hasArg = argName in rec && rec[argName] !== undefined && rec[argName] !== null;

    if (rule === null) {
      if (hasArg) {
        return `forbidden_arg:${toolName}.${argName}`;
      }
      continue;
    }

    if (!hasArg) {
      return `missing_required_arg:${toolName}.${argName}`;
    }

    const rawVal = rec[argName];
    const strVal =
      Array.isArray(rawVal)
        ? rawVal.map(String).join(" ")
        : typeof rawVal === "string"
          ? rawVal
          : JSON.stringify(rawVal);

    if (!matchesArgConstraint(strVal, rule)) {
      return `arg_constraint_violation:${toolName}.${argName}`;
    }
  }
  return null;
}

// ── Dual-Control S2 Ed25519 Approval Tickets (LOKAHI Rule 14) ────────────────

export interface S2ApprovalTicket {
  ticketVersion: "lokahi.s2.v1";
  nonce: string;
  tool: string;
  actionHash: string;
  approverId: string;
  approverKeyFingerprint: string;
  issuedAt: string;
  expiresAt: string;
  signature_algorithm: "RFC8785-Ed25519";
  signature: string;
}

export function computeActionHash(tool: string, input: unknown): string {
  return sha256Hex(canonicalizeJcs({ tool, input: input ?? {} }));
}

/**
 * Issue a cryptographically bound S2 human approval ticket for a specific tool + input payload.
 * Default TTL is 45 seconds (Ahimsa Rule 14: Silence = Refusal).
 */
export function createS2ApprovalToken(opts: {
  tool: string;
  input: unknown;
  approverId: string;
  approverPrivateKeyPem: string;
  ttlSeconds?: number;
  now?: Date;
}): S2ApprovalTicket {
  const now = opts.now ?? new Date();
  const ttlSec = Math.max(1, Math.min(opts.ttlSeconds ?? 45, 3600));
  const privKey = createPrivateKey(opts.approverPrivateKeyPem);
  const pubDer = createPublicKey(privKey).export({ type: "spki", format: "der" });
  const fingerprint = sha256Hex(pubDer);

  const unsigned = {
    ticketVersion: "lokahi.s2.v1" as const,
    nonce: randomBytes(16).toString("hex"),
    tool: opts.tool,
    actionHash: computeActionHash(opts.tool, opts.input),
    approverId: opts.approverId,
    approverKeyFingerprint: fingerprint,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlSec * 1000).toISOString(),
    signature_algorithm: "RFC8785-Ed25519" as const,
  };

  const canonical = canonicalizeJcs(unsigned);
  const sig = cryptoSign(null, toUint8(canonical), privKey).toString("base64");

  return {
    ...unsigned,
    signature: `ed25519:${sig}`,
  };
}

export interface S2ApprovalVerifyOptions {
  tool: string;
  input: unknown;
  trustedApproverPublicKeysPem: string[];
  /** Optional fingerprint of the agent's own key to enforce separation of duties (no self-approval) */
  agentKeyFingerprint?: string;
  /** Optional replay protection store; verified nonces are recorded when provided */
  usedNonces?: Set<string>;
  now?: Date;
}

export interface S2ApprovalVerifyResult {
  approved: boolean;
  reason?: string;
  approverId?: string;
}

/**
 * Verify a Dual-Control S2 human approval ticket fail-closed:
 *  1. Ticket present & valid schema
 *  2. Action hash matches exact tool + input (prevents bait-and-switch)
 *  3. Timestamp not expired and not issued in the future (45s Ahimsa silence = refusal)
 *  4. Separation of duties: approver key !== agent key
 *  5. Single-use nonce replay defense
 *  6. Ed25519 cryptographic signature matches a configured trusted approver public key
 */
export function verifyS2ApprovalToken(
  ticket: S2ApprovalTicket | null | undefined,
  opts: S2ApprovalVerifyOptions,
): S2ApprovalVerifyResult {
  if (!ticket || ticket.ticketVersion !== "lokahi.s2.v1") {
    return { approved: false, reason: "s2_approval_missing" };
  }
  if (!opts.trustedApproverPublicKeysPem || opts.trustedApproverPublicKeysPem.length === 0) {
    return { approved: false, reason: "no_trusted_approvers_configured" };
  }
  const now = opts.now ?? new Date();
  const expMs = Date.parse(ticket.expiresAt);
  const issuedMs = Date.parse(ticket.issuedAt);
  if (!Number.isFinite(expMs) || !Number.isFinite(issuedMs) || expMs <= now.getTime()) {
    return { approved: false, reason: "s2_approval_expired_silence_refusal" };
  }
  if (issuedMs > now.getTime() + 5_000) {
    return { approved: false, reason: "s2_approval_future_timestamp" };
  }

  const expectedHash = computeActionHash(opts.tool, opts.input);
  if (ticket.tool !== opts.tool || ticket.actionHash !== expectedHash) {
    return { approved: false, reason: "s2_action_hash_mismatch" };
  }

  if (
    opts.agentKeyFingerprint &&
    ticket.approverKeyFingerprint === opts.agentKeyFingerprint
  ) {
    return { approved: false, reason: "s2_self_approval_forbidden" };
  }

  if (opts.usedNonces && opts.usedNonces.has(ticket.nonce)) {
    return { approved: false, reason: "s2_approval_replay_detected" };
  }

  if (!ticket.signature || !ticket.signature.startsWith("ed25519:")) {
    return { approved: false, reason: "s2_signature_format_invalid" };
  }
  const sigBytes = toUint8(Buffer.from(ticket.signature.slice("ed25519:".length), "base64"));

  const unsigned: Record<string, unknown> = { ...ticket };
  delete unsigned.signature;
  const payloadBytes = toUint8(canonicalizeJcs(unsigned));

  for (const pubPem of opts.trustedApproverPublicKeysPem) {
    try {
      const pubKey = createPublicKey(pubPem);
      const fp = sha256Hex(pubKey.export({ type: "spki", format: "der" }));
      if (fp !== ticket.approverKeyFingerprint) continue;
      if (cryptoVerify(null, payloadBytes, pubKey, sigBytes)) {
        opts.usedNonces?.add(ticket.nonce);
        return { approved: true, approverId: ticket.approverId };
      }
    } catch {
      // try next trusted key
    }
  }

  return { approved: false, reason: "s2_signature_untrusted_or_invalid" };
}

// ── External LOKAHI HTTP Gateway Adapter (`engine: "gateway"`) ───────────────

export interface LokahiGatewayDecision {
  allowed: boolean;
  reason: string;
  ruleId?: string;
}

export interface LokahiGatewayClientOptions {
  gatewayUrl: string;
  bearerToken?: string;
  timeoutMs?: number;
  fetchFn?: typeof fetch;
  lookupFn?: DnsLookupFn;
}

export interface LokahiGatewayClient {
  evaluate(req: {
    tool: string;
    action: string;
    target: string;
    input?: unknown;
    isS2Critical?: boolean;
  }): Promise<LokahiGatewayDecision>;
}

/**
 * Create a fail-closed HTTP client for an external LOKAHI Policy Gateway service.
 * Enforces SSRF protection on the gateway URL and refuses on timeout, HTTP error,
 * or non-boolean `allowed` payload.
 */
export function createLokahiGatewayClient(
  opts: LokahiGatewayClientOptions,
): LokahiGatewayClient {
  const baseUrl = opts.gatewayUrl.replace(/\/+$/, "");
  const fetchFn = opts.fetchFn ?? globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? 5_000;

  return {
    async evaluate(req): Promise<LokahiGatewayDecision> {
      const url = `${baseUrl}/v1/evaluate`;
      try {
        await assertSafeFetchUrlAsync(
          url,
          opts.lookupFn ? { lookupFn: opts.lookupFn } : undefined,
        );
      } catch (err) {
        return {
          allowed: false,
          reason: `lokahi_gateway_ssrf_blocked: ${err instanceof Error ? err.message : String(err)}`,
        };
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const headers: Record<string, string> = {
          "Content-Type": "application/json",
          Accept: "application/json",
        };
        const token = opts.bearerToken ?? process.env.DIRGHA_LOKAHI_GATEWAY_TOKEN;
        if (token && token.trim().length > 0) {
          headers["Authorization"] = `Bearer ${token.trim()}`;
        }
        const resp = await fetchFn(url, {
          method: "POST",
          headers,
          body: JSON.stringify(req),
          signal: controller.signal,
        });
        if (!resp.ok) {
          return {
            allowed: false,
            reason: `lokahi_gateway_http_${resp.status}`,
          };
        }
        const body = (await resp.json()) as Partial<LokahiGatewayDecision>;
        if (typeof body.allowed !== "boolean") {
          return {
            allowed: false,
            reason: "lokahi_gateway_malformed_response",
          };
        }
        return {
          allowed: body.allowed,
          reason: typeof body.reason === "string" ? body.reason : body.allowed ? "allowed" : "denied",
          ruleId: typeof body.ruleId === "string" ? body.ruleId : undefined,
        };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          allowed: false,
          reason: `lokahi_gateway_unreachable: ${msg}`,
        };
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

// ── End-to-End LOKAHI Conformance Evaluator (Rules 1-14) ─────────────────────

export interface ConformanceEvaluationInput {
  manifest: LokahiManifestPolicy;
  tool: string;
  input: unknown;
  jurisdiction?: string;
  s2Ticket?: S2ApprovalTicket | null;
  trustedApproverPublicKeysPem?: string[];
  agentKeyFingerprint?: string;
  usedNonces?: Set<string>;
  now?: Date;
}

export interface ConformanceEvaluationResult {
  allowed: boolean;
  reason: string;
  ruleClass?: "read" | "write" | "irreversible";
}

export function evaluateLokahiConformance(
  req: ConformanceEvaluationInput,
): ConformanceEvaluationResult {
  const now = req.now ?? new Date();
  const { manifest } = req;

  if (!manifest.signature || manifest.signature.trim() === "") {
    return { allowed: false, reason: "unsigned_manifest" };
  }
  if (!manifest.expires || !/(Z|[+-]\d{2}:\d{2})$/i.test(manifest.expires.trim())) {
    return { allowed: false, reason: "expired_or_naive_manifest" };
  }
  if (Date.parse(manifest.expires) <= now.getTime()) {
    return { allowed: false, reason: "expired_manifest" };
  }
  if (!manifest.tools || typeof manifest.tools !== "object") {
    return { allowed: false, reason: "no_tool_policy" };
  }
  const toolPolicy = manifest.tools[req.tool];
  if (!toolPolicy) {
    return { allowed: false, reason: `tool_not_in_manifest:${req.tool}` };
  }

  // Jurisdiction residency rule
  if (req.jurisdiction) {
    const allowedSet = toolPolicy.jurisdiction
      ? [toolPolicy.jurisdiction.toUpperCase()]
      : (manifest.residency ?? []).map((r) => r.toUpperCase());
    if (allowedSet.length > 0 && !allowedSet.includes(req.jurisdiction.toUpperCase())) {
      return {
        allowed: false,
        reason: `residency_violation:${req.jurisdiction}`,
        ruleClass: toolPolicy.class,
      };
    }
  }

  // Argument-level constraints
  const argErr = evaluateToolArgConstraints(req.tool, req.input, toolPolicy.args);
  if (argErr) {
    return { allowed: false, reason: argErr, ruleClass: toolPolicy.class };
  }

  // Irreversible actions (S2) require a verified second-person Ed25519 approval ticket
  if (toolPolicy.class === "irreversible") {
    const s2 = verifyS2ApprovalToken(req.s2Ticket, {
      tool: req.tool,
      input: req.input,
      trustedApproverPublicKeysPem: req.trustedApproverPublicKeysPem ?? [],
      agentKeyFingerprint: req.agentKeyFingerprint,
      usedNonces: req.usedNonces,
      now,
    });
    if (!s2.approved) {
      return {
        allowed: false,
        reason: s2.reason ?? "s2_approval_required",
        ruleClass: "irreversible",
      };
    }
  }

  return {
    allowed: true,
    reason: "lokahi_conformance_pass",
    ruleClass: toolPolicy.class,
  };
}

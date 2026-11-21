/**
 * Offline Vitest conformance suite for LOKAHI v1.1 Rules 1–14:
 *  - Argument-level regex, glob, exact, and forbidden-arg constraints
 *  - Dual-Control S2 Ed25519 approval tickets (45s Ahimsa TTL, separation of duties, replay defense)
 *  - External LOKAHI HTTP Gateway adapter (SSRF guard + fail-closed timeout/error)
 *  - Runtime enforcement through createRuntimePermissionEngine & `dirgha policy approve`
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createLokahiGatewayClient,
  createS2ApprovalToken,
  evaluateLokahiConformance,
  evaluateToolArgConstraints,
  matchesArgConstraint,
  verifyS2ApprovalToken,
  type S2ApprovalTicket,
} from "../lokahi-conformance.js";
import { generateEd25519Keypair, signManifestEd25519 } from "../lokahi-crypto.js";
import { PROFILE_PRESETS } from "../modules-config.js";
import { createRuntimePermissionEngine } from "../lokahi-runtime.js";
import { policySubcommand } from "../../cli/subcommands/policy.js";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "dirgha-conf-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("LOKAHI v1.1 argument-level constraints", () => {
  it("matches exact strings, globs, and regexes while failing closed on invalid regex", () => {
    expect(matchesArgConstraint("src/app.ts", "src/**")).toBe(true);
    expect(matchesArgConstraint("etc/passwd", "src/**")).toBe(false);
    expect(matchesArgConstraint("npm test", "/^(npm test|git status)$/")).toBe(true);
    expect(matchesArgConstraint("rm -rf /", "/^(npm test|git status)$/")).toBe(false);
    expect(matchesArgConstraint("anything", "/[unterminated/")).toBe(false);
  });

  it("enforces forbidden args (null), missing required args, and value violations", () => {
    const policy = {
      path: "src/**",
      force: null,
    };
    expect(evaluateToolArgConstraints("fs_write", { path: "src/a.ts" }, policy)).toBeNull();
    expect(evaluateToolArgConstraints("fs_write", { path: "src/a.ts", force: true }, policy)).toBe(
      "forbidden_arg:fs_write.force",
    );
    expect(evaluateToolArgConstraints("fs_write", { path: "/etc/hosts" }, policy)).toBe(
      "arg_constraint_violation:fs_write.path",
    );
    expect(evaluateToolArgConstraints("fs_write", {}, policy)).toBe(
      "missing_required_arg:fs_write.path",
    );
  });

  it("enforces manifest arg constraints at runtime inside createRuntimePermissionEngine", () => {
    const dir = makeTempDir();
    const kp = generateEd25519Keypair();
    const pubPath = join(dir, "pub.pem");
    const manifestPath = join(dir, "manifest.json");
    writeFileSync(pubPath, kp.publicKeyPem, "utf8");

    const { signedManifest } = signManifestEd25519(
      {
        manifest_version: "1.1",
        expires: "2099-01-01T00:00:00Z",
        tools: {
          fs_write: { class: "write", args: { path: "src/**" } },
        },
      },
      kp.privateKeyPem,
    );
    writeFileSync(manifestPath, JSON.stringify(signedManifest, null, 2), "utf8");

    const modules = structuredClone(PROFILE_PRESETS.enterprise);
    modules.lokahi.manifestPath = manifestPath;
    modules.lokahi.publicKeyPath = pubPath;

    const engine = createRuntimePermissionEngine({ cwd: dir, modules });
    expect(
      engine.checkCall({ id: "1", name: "fs_write", input: { path: "src/ok.ts" } }).allowed,
    ).toBe(true);
    const blocked = engine.checkCall({
      id: "2",
      name: "fs_write",
      input: { path: "secrets/keys.json" },
    });
    expect(blocked.allowed).toBe(false);
    expect(blocked.reason).toContain("arg_constraint_violation:fs_write.path");
  });
});

describe("Dual-Control S2 Ed25519 Approval Tickets (Rule 14: 45s Ahimsa TTL)", () => {
  it("approves valid human-signed S2 tickets and rejects expiry, tampering, self-approval, and replays", () => {
    const humanKp = generateEd25519Keypair();
    const agentKp = generateEd25519Keypair();
    const t0 = new Date("2026-06-01T12:00:00Z");

    const ticket = createS2ApprovalToken({
      tool: "gpu_compute",
      input: { action: "provision", gpuType: "H100", jurisdiction: "EU" },
      approverId: "ciso@acme.example",
      approverPrivateKeyPem: humanKp.privateKeyPem,
      ttlSeconds: 45,
      now: t0,
    });

    const usedNonces = new Set<string>();
    const ok = verifyS2ApprovalToken(ticket, {
      tool: "gpu_compute",
      input: { action: "provision", gpuType: "H100", jurisdiction: "EU" },
      trustedApproverPublicKeysPem: [humanKp.publicKeyPem],
      agentKeyFingerprint: agentKp.keyFingerprintSha256,
      usedNonces,
      now: new Date("2026-06-01T12:00:30Z"),
    });
    expect(ok.approved).toBe(true);
    expect(ok.approverId).toBe("ciso@acme.example");

    // Replay of same nonce must be rejected
    const replay = verifyS2ApprovalToken(ticket, {
      tool: "gpu_compute",
      input: { action: "provision", gpuType: "H100", jurisdiction: "EU" },
      trustedApproverPublicKeysPem: [humanKp.publicKeyPem],
      usedNonces,
      now: new Date("2026-06-01T12:00:31Z"),
    });
    expect(replay.approved).toBe(false);
    expect(replay.reason).toBe("s2_approval_replay_detected");

    // After 45s Ahimsa TTL -> Silence = Refusal
    const expired = verifyS2ApprovalToken(ticket, {
      tool: "gpu_compute",
      input: { action: "provision", gpuType: "H100", jurisdiction: "EU" },
      trustedApproverPublicKeysPem: [humanKp.publicKeyPem],
      now: new Date("2026-06-01T12:00:46Z"),
    });
    expect(expired.approved).toBe(false);
    expect(expired.reason).toBe("s2_approval_expired_silence_refusal");

    // Modified input payload (bait-and-switch) -> refused
    const tampered = verifyS2ApprovalToken(ticket, {
      tool: "gpu_compute",
      input: { action: "provision", gpuType: "H100", jurisdiction: "US" },
      trustedApproverPublicKeysPem: [humanKp.publicKeyPem],
      now: new Date("2026-06-01T12:00:10Z"),
    });
    expect(tampered.approved).toBe(false);
    expect(tampered.reason).toBe("s2_action_hash_mismatch");

    // Separation of duties: agent attempting to approve itself -> refused
    const selfTicket = createS2ApprovalToken({
      tool: "shell",
      input: { command: "deploy" },
      approverId: "self-agent",
      approverPrivateKeyPem: agentKp.privateKeyPem,
      now: t0,
    });
    const selfRes = verifyS2ApprovalToken(selfTicket, {
      tool: "shell",
      input: { command: "deploy" },
      trustedApproverPublicKeysPem: [agentKp.publicKeyPem],
      agentKeyFingerprint: agentKp.keyFingerprintSha256,
      now: t0,
    });
    expect(selfRes.approved).toBe(false);
    expect(selfRes.reason).toBe("s2_self_approval_forbidden");
  });

  it("evaluates end-to-end LOKAHI conformance and issues valid tickets via `dirgha policy approve`", async () => {
    const dir = makeTempDir();
    const approverKp = generateEd25519Keypair();
    const privPath = join(dir, "approver.private.pem");
    const ticketPath = join(dir, "ticket.json");
    writeFileSync(privPath, approverKp.privateKeyPem, "utf8");

    const code = await policySubcommand.run(
      [
        "approve",
        "--tool=gpu_compute",
        '--input={"action":"provision","jurisdiction":"EU"}',
        `--key=${privPath}`,
        "--approver=lead-sre",
        "--ttl=60",
        `--out=${ticketPath}`,
      ],
      { cwd: dir },
    );
    expect(code).toBe(0);
    const ticket = JSON.parse(readFileSync(ticketPath, "utf8")) as S2ApprovalTicket;

    const manifest = {
      manifest_version: "1.1",
      signature: "ed25519:valid",
      expires: "2099-01-01T00:00:00Z",
      residency: ["EU", "IN"],
      tools: {
        gpu_compute: {
          class: "irreversible" as const,
          args: { action: "provision", jurisdiction: "/^(EU|IN)$/" },
        },
      },
    };

    // Without S2 ticket -> refused
    expect(
      evaluateLokahiConformance({
        manifest,
        tool: "gpu_compute",
        input: { action: "provision", jurisdiction: "EU" },
        jurisdiction: "EU",
        trustedApproverPublicKeysPem: [approverKp.publicKeyPem],
      }).allowed,
    ).toBe(false);

    // With valid human S2 ticket -> allowed
    const pass = evaluateLokahiConformance({
      manifest,
      tool: "gpu_compute",
      input: { action: "provision", jurisdiction: "EU" },
      jurisdiction: "EU",
      s2Ticket: ticket,
      trustedApproverPublicKeysPem: [approverKp.publicKeyPem],
    });
    expect(pass.allowed).toBe(true);
    expect(pass.ruleClass).toBe("irreversible");
  });
});

describe("External LOKAHI HTTP Gateway Adapter (fail-closed)", () => {
  it("blocks private/metadata gateway URLs and fails closed on HTTP 500 or network errors", async () => {
    const ssrfClient = createLokahiGatewayClient({
      gatewayUrl: "http://169.254.169.254",
    });
    const ssrfRes = await ssrfClient.evaluate({
      tool: "shell",
      action: "exec",
      target: "echo ok",
    });
    expect(ssrfRes.allowed).toBe(false);
    expect(ssrfRes.reason).toContain("lokahi_gateway_ssrf_blocked");

    const publicLookup = async () => [{ address: "93.184.216.34", family: 4 }];
    const okClient = createLokahiGatewayClient({
      gatewayUrl: "https://lokahi.acme.example",
      lookupFn: publicLookup,
      fetchFn: (async () =>
        new Response(JSON.stringify({ allowed: true, reason: "policy_pass", ruleId: "R-1" }), {
          status: 200,
        })) as unknown as typeof fetch,
    });
    const okRes = await okClient.evaluate({ tool: "fs_read", action: "read", target: "README.md" });
    expect(okRes.allowed).toBe(true);

    const errClient = createLokahiGatewayClient({
      gatewayUrl: "https://lokahi.acme.example",
      lookupFn: publicLookup,
      fetchFn: (async () => new Response("error", { status: 503 })) as unknown as typeof fetch,
    });
    const errRes = await errClient.evaluate({ tool: "fs_read", action: "read", target: "README.md" });
    expect(errRes.allowed).toBe(false);
    expect(errRes.reason).toBe("lokahi_gateway_http_503");
  });
});

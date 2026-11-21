/**
 * Offline unit tests for Phase 6:
 *  - RFC-8785 (JCS) JSON canonicalization
 *  - Ed25519 policy manifest signing, verification & tamper detection
 *  - Runtime Ed25519 manifest enforcement in createRuntimePermissionEngine
 *  - Signed Compliance Evidence Pack generation
 *  - `dirgha policy` CLI subcommand lifecycle
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { afterEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildComplianceEvidencePack,
  canonicalizeJcs,
  generateEd25519Keypair,
  signManifestEd25519,
  verifyManifestEd25519,
} from "../lokahi-crypto.js";
import { PROFILE_PRESETS, resolveModulesConfig } from "../modules-config.js";
import {
  checkLokahiManifestToolPolicy,
  createRuntimePermissionEngine,
} from "../lokahi-runtime.js";
import { policySubcommand } from "../../cli/subcommands/policy.js";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "dirgha-policy-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("RFC-8785 JCS canonicalization & Ed25519 manifest crypto", () => {
  it("produces identical canonical JSON regardless of nested key insertion order", () => {
    const a = { z: 1, a: { d: true, b: [3, 2, -0], c: "hi" } };
    const b = { a: { c: "hi", b: [3, 2, 0], d: true }, z: 1 };
    expect(canonicalizeJcs(a)).toBe(canonicalizeJcs(b));
    expect(canonicalizeJcs(a)).toBe('{"a":{"b":[3,2,0],"c":"hi","d":true},"z":1}');
    expect(() => canonicalizeJcs({ bad: Number.NaN })).toThrow(/non-finite/);
  });

  it("signs and verifies a LOKAHI manifest with Ed25519 and rejects tampering or wrong keys", () => {
    const kp1 = generateEd25519Keypair();
    const kp2 = generateEd25519Keypair();

    const manifest = {
      manifest_version: "1.1",
      organization: "Dirgha Enterprise",
      expires: "2099-01-01T00:00:00Z",
      residency: ["EU", "IN"],
      tools: {
        fs_read: { class: "read" },
        gpu_compute: { class: "irreversible", jurisdiction: "EU" },
      },
    };

    const { signedManifest, canonicalPayloadSha256 } = signManifestEd25519(
      manifest,
      kp1.privateKeyPem,
    );
    expect(signedManifest.signature.startsWith("ed25519:")).toBe(true);
    expect(signedManifest.signature_algorithm).toBe("RFC8785-Ed25519");
    expect(canonicalPayloadSha256).toHaveLength(64);

    // Valid verification even if keys are reordered in JSON
    const reordered = {
      tools: signedManifest.tools,
      signature: signedManifest.signature,
      signature_algorithm: signedManifest.signature_algorithm,
      signer_key_fingerprint: signedManifest.signer_key_fingerprint,
      residency: signedManifest.residency,
      expires: signedManifest.expires,
      organization: signedManifest.organization,
      manifest_version: signedManifest.manifest_version,
    };
    const ok = verifyManifestEd25519(reordered, kp1.publicKeyPem);
    expect(ok.valid).toBe(true);
    expect(ok.canonicalPayloadSha256).toBe(canonicalPayloadSha256);

    // Tampered tool list fails closed
    const tampered = {
      ...signedManifest,
      tools: { ...signedManifest.tools, shell: { class: "irreversible" } },
    };
    const tamperedRes = verifyManifestEd25519(tampered, kp1.publicKeyPem);
    expect(tamperedRes.valid).toBe(false);
    expect(tamperedRes.reason).toBe("ed25519_verification_failed");

    // Wrong public key fails closed
    const wrongKey = verifyManifestEd25519(signedManifest, kp2.publicKeyPem);
    expect(wrongKey.valid).toBe(false);
    expect(wrongKey.reason).toBe("signer_fingerprint_mismatch");
  });
});

describe("Runtime Ed25519 manifest enforcement & Compliance Evidence Pack", () => {
  it("enforces cryptographic Ed25519 manifest verification fail-closed in createRuntimePermissionEngine", () => {
    const dir = makeTempDir();
    const kp = generateEd25519Keypair();
    const pubPath = join(dir, "policy.pub.pem");
    const manifestPath = join(dir, "manifest.json");
    writeFileSync(pubPath, kp.publicKeyPem, "utf8");

    const { signedManifest } = signManifestEd25519(
      {
        manifest_version: "1.1",
        expires: "2099-01-01T00:00:00Z",
        tools: { fs_read: { class: "read" } },
      },
      kp.privateKeyPem,
    );
    writeFileSync(manifestPath, JSON.stringify(signedManifest, null, 2), "utf8");

    const modules = structuredClone(PROFILE_PRESETS.enterprise);
    modules.lokahi.manifestPath = manifestPath;
    modules.lokahi.publicKeyPath = pubPath;

    const engine = createRuntimePermissionEngine({ cwd: dir, modules });
    expect(
      engine.checkCall({ id: "1", name: "fs_read", input: { path: "README.md" } }).allowed,
    ).toBe(true);
    expect(
      engine.checkCall({ id: "2", name: "browser", input: { url: "https://example.com" } }).allowed,
    ).toBe(false);

    // Tamper with manifest on disk -> even fs_read is now refused fail-closed
    const tampered = { ...signedManifest, expires: "2099-12-31T00:00:00Z" };
    writeFileSync(manifestPath, JSON.stringify(tampered, null, 2), "utf8");
    const denied = engine.checkCall({ id: "3", name: "fs_read", input: { path: "README.md" } });
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toContain("invalid_manifest_signature");

    // Missing public key fails closed
    const missingKeyErr = checkLokahiManifestToolPolicy(manifestPath, "fs_read", new Date(), {
      publicKeyPath: join(dir, "nope.pub.pem"),
    });
    expect(missingKeyErr).toContain("lokahi_public_key_missing");
  });

  it("builds and cryptographically signs an auditor-ready Compliance Evidence Pack", () => {
    const dir = makeTempDir();
    const auditFile = join(dir, "audit.jsonl");
    writeFileSync(auditFile, '{"event":"turn_end","ok":true}\n', "utf8");
    const kp = generateEd25519Keypair();

    const resolution = resolveModulesConfig({
      profile: "enterprise",
      env: {},
      orgLock: {
        orgName: "Sovereign Bank",
        locked: true,
        minLokahiMode: "enforce",
        requireArniko: true,
        allowedJurisdictions: ["EU"],
        maxGpuBudgetUsd: 100,
      },
    });

    const pack = buildComplianceEvidencePack({
      resolution,
      auditLogPath: auditFile,
      privateKeyPem: kp.privateKeyPem,
      now: new Date("2026-06-01T00:00:00Z"),
    });

    expect(pack.schemaVersion).toBe("dirgha.evidence.v1");
    expect(pack.governance.orgLocked).toBe(true);
    expect(pack.governance.lokahiMode).toBe("enforce");
    expect(pack.controls.wasmGateVerified).toBe(true);
    expect(pack.auditTrail.present).toBe(true);
    expect(pack.auditTrail.lineCount).toBe(1);
    expect(pack.auditTrail.sha256).toHaveLength(64);
    expect(pack.evidence_sha256).toHaveLength(64);
    expect(pack.signature?.startsWith("ed25519:")).toBe(true);

    const verified = verifyManifestEd25519(
      pack as unknown as Record<string, unknown>,
      kp.publicKeyPem,
    );
    expect(verified.valid).toBe(true);
  });
});

describe("dirgha policy CLI subcommand lifecycle", () => {
  it("runs keygen -> init -> sign -> verify -> evidence cleanly end-to-end", async () => {
    const dir = makeTempDir();
    const ctx = { cwd: dir };

    expect(await policySubcommand.run(["keygen", "--out=keys", "--name=org", "--json"], ctx)).toBe(0);
    const privPath = join(dir, "keys", "org.private.pem");
    const pubPath = join(dir, "keys", "org.public.pem");
    expect(existsSync(privPath)).toBe(true);
    expect(existsSync(pubPath)).toBe(true);

    expect(
      await policySubcommand.run(
        ["init", "--out=manifest.json", "--residency=IN,EU", "--days=60", "--json"],
        ctx,
      ),
    ).toBe(0);
    const manifestPath = join(dir, "manifest.json");
    expect(existsSync(manifestPath)).toBe(true);

    expect(
      await policySubcommand.run(["sign", manifestPath, `--key=${privPath}`, "--json"], ctx),
    ).toBe(0);

    expect(
      await policySubcommand.run(
        ["verify", manifestPath, `--pubkey=${pubPath}`, "--tool=fs_read", "--json"],
        ctx,
      ),
    ).toBe(0);

    // Unlisted tool must fail verification with exit code 1
    expect(
      await policySubcommand.run(
        ["verify", manifestPath, `--pubkey=${pubPath}`, "--tool=unlisted_tool", "--json"],
        ctx,
      ),
    ).toBe(1);

    const evidencePath = join(dir, "evidence.json");
    expect(
      await policySubcommand.run(
        ["evidence", `--out=${evidencePath}`, `--key=${privPath}`, "--json"],
        ctx,
      ),
    ).toBe(0);
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8")) as Record<string, unknown>;
    expect(verifyManifestEd25519(evidence, readFileSync(pubPath, "utf8")).valid).toBe(true);
  });
});

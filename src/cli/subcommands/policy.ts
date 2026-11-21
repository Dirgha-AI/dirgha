/**
 * `dirgha policy` — Enterprise Governance, RFC-8785 + Ed25519 Manifest Signing,
 * Verification, Ahimsa Bridging, & Auditor-Ready Compliance Evidence CLI.
 *
 * Subcommands:
 *   dirgha policy status [--json]
 *   dirgha policy keygen [--out=<dir>] [--name=<stem>] [--json]
 *   dirgha policy init [--out=<file>] [--residency=IN,EU] [--from-ahimsa=<file>] [--days=90]
 *   dirgha policy sign <manifest.json> --key=<private.pem> [--out=<signed.json>] [--json]
 *   dirgha policy verify <manifest.json> --pubkey=<public.pem> [--tool=<name>] [--json]
 *   dirgha policy evidence [--out=<pack.json>] [--key=<private.pem>] [--json]
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { stdout, stderr } from "node:process";
import type { Subcommand, SubcommandCtx } from "./index.js";
import { parseFlags } from "../flags.js";
import { loadConfig } from "../config.js";
import { resolveModulesConfig } from "../../safety/modules-config.js";
import {
  DEFAULT_DIRGHA_TOOL_POLICY,
  mergeAhimsaWithToolPolicy,
  validateAhimsaManifest,
  type AhimsaManifest,
} from "../../safety/ahimsa-bridge.js";
import {
  buildComplianceEvidencePack,
  generateEd25519Keypair,
  signManifestEd25519,
  verifyManifestEd25519,
} from "../../safety/lokahi-crypto.js";
import { checkLokahiManifestToolPolicy } from "../../safety/lokahi-runtime.js";
import { createS2ApprovalToken } from "../../safety/lokahi-conformance.js";

function printPolicyHelp(): void {
  stdout.write(`Usage: dirgha policy <command> [options]

Manage Dirgha 2.0 + LOKAHI + Ahimsa governance policies, RFC-8785 + Ed25519
cryptographic signing, S2 human approval tickets, and compliance evidence packs.

Commands:
  status [--json]                     Inspect active profile, module states & org lock
  keygen [--out=<dir>] [--name=lokahi] [--json]
                                      Generate an Ed25519 signing keypair (0600 private key)
  init [--out=<file>] [--residency=IN,EU] [--from-ahimsa=<file>] [--days=90]
                                      Create a LOKAHI v1.1 manifest (optionally bridging Ahimsa)
  sign <manifest.json> --key=<private.pem> [--out=<file>] [--json]
                                      Sign a manifest canonically (RFC-8785 + Ed25519)
  verify <manifest.json> --pubkey=<public.pem> [--tool=<name>] [--json]
                                      Verify Ed25519 signature, expiry & LOKAHI v1.1 rules
  approve --tool=<name> --input='<json>' --key=<approver.private.pem> [--approver=<id>] [--ttl=45] [--out=<file>]
                                      Issue a Dual-Control S2 Ed25519 approval ticket (45s Ahimsa TTL)
  evidence [--out=<file>] [--key=<private.pem>] [--json]
                                      Generate a hashed (and optionally signed) compliance pack
`);
}

function writeFileEnsureDir(filePath: string, content: string, mode?: number): void {
  const dir = dirname(filePath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(filePath, content, { encoding: "utf8", ...(mode ? { mode } : {}) });
}

export const policySubcommand: Subcommand = {
  name: "policy",
  aliases: ["lokahi"],
  description: "LOKAHI/Ahimsa policy signing (RFC-8785 + Ed25519), verification & compliance evidence",
  async run(argv: string[], ctx: SubcommandCtx): Promise<number> {
    const { flags, positionals } = parseFlags(argv);
    const sub = positionals[0];
    const asJson = flags.json === true;

    if (!sub || sub === "help" || flags.help || flags.h) {
      printPolicyHelp();
      return 0;
    }

    const config = await loadConfig(ctx.cwd);
    const resolution = resolveModulesConfig({
      profile: config.profile,
      configured: config.modules,
      flags,
    });

    if (sub === "status") {
      if (asJson) {
        stdout.write(JSON.stringify(resolution, null, 2) + "\n");
      } else {
        stdout.write(`Dirgha 2.0 Governance Policy Status\n\n`);
        stdout.write(`  Profile:     ${resolution.profile}${resolution.orgLocked ? " (ORG LOCKED)" : ""}\n`);
        stdout.write(`  LOKAHI Gate: ${resolution.modules.lokahi.mode}${resolution.modules.lokahi.manifestPath ? ` (manifest: ${resolution.modules.lokahi.manifestPath})` : ""}\n`);
        stdout.write(`  Ed25519 Key: ${resolution.modules.lokahi.publicKeyPath ?? "not configured"}\n`);
        stdout.write(`  Arniko Scan: ${resolution.modules.arniko.enabled ? "enabled" : "off"}\n`);
        stdout.write(`  Ahimsa:      ${resolution.modules.ahimsa.enabled ? "enabled" : "off"}\n`);
        stdout.write(`  GPU Market:  ${resolution.modules.gpuMarket.enabled ? "enabled" : "disabled"}${resolution.modules.gpuMarket.allowedJurisdictions?.length ? ` [${resolution.modules.gpuMarket.allowedJurisdictions.join(",")}]` : ""}\n`);
        if (resolution.errors.length > 0) {
          stdout.write(`\nPolicy Errors:\n`);
          for (const e of resolution.errors) stdout.write(`  - ${e}\n`);
        }
      }
      return resolution.errors.length > 0 ? 1 : 0;
    }

    if (sub === "keygen") {
      const outDir = resolve(ctx.cwd, typeof flags.out === "string" ? flags.out : ".dirgha-keys");
      const stem = typeof flags.name === "string" ? flags.name : "lokahi-policy";
      const kp = generateEd25519Keypair();
      const privPath = join(outDir, `${stem}.private.pem`);
      const pubPath = join(outDir, `${stem}.public.pem`);
      writeFileEnsureDir(privPath, kp.privateKeyPem, 0o600);
      writeFileEnsureDir(pubPath, kp.publicKeyPem, 0o644);
      const summary = {
        algorithm: "Ed25519",
        privateKeyPath: privPath,
        publicKeyPath: pubPath,
        fingerprintSha256: kp.keyFingerprintSha256,
      };
      if (asJson) {
        stdout.write(JSON.stringify(summary, null, 2) + "\n");
      } else {
        stdout.write(`Generated Ed25519 policy signing keypair:\n`);
        stdout.write(`  Private (0600): ${privPath}\n`);
        stdout.write(`  Public:         ${pubPath}\n`);
        stdout.write(`  SHA-256:        ${kp.keyFingerprintSha256}\n`);
      }
      return 0;
    }

    if (sub === "init") {
      const outPath = resolve(
        ctx.cwd,
        typeof flags.out === "string" ? flags.out : "lokahi-manifest.json",
      );
      const days =
        typeof flags.days === "string" && Number.isFinite(Number(flags.days))
          ? Math.max(1, Number(flags.days))
          : 90;
      const residency =
        typeof flags.residency === "string"
          ? flags.residency
              .split(",")
              .map((s) => s.trim().toUpperCase())
              .filter(Boolean)
          : ["EU", "US"];

      let base: AhimsaManifest = {
        manifest_version: "1.1",
        organization: typeof flags.org === "string" ? flags.org : "Dirgha Organization",
        frameworks: ["EU-AI-ACT", "NIST-AI-RMF", "ISO-42001"],
        residency,
      };
      if (typeof flags["from-ahimsa"] === "string") {
        const srcPath = resolve(ctx.cwd, flags["from-ahimsa"]);
        if (!existsSync(srcPath)) {
          stderr.write(`Ahimsa manifest not found: ${srcPath}\n`);
          return 1;
        }
        base = JSON.parse(readFileSync(srcPath, "utf8")) as AhimsaManifest;
      }

      const merged = mergeAhimsaWithToolPolicy(base, DEFAULT_DIRGHA_TOOL_POLICY, {
        expiresInDays: days,
      });
      writeFileEnsureDir(outPath, JSON.stringify(merged, null, 2) + "\n");
      if (asJson) {
        stdout.write(JSON.stringify({ outputPath: outPath, manifest: merged }, null, 2) + "\n");
      } else {
        stdout.write(`Wrote unsigned LOKAHI v1.1 manifest to ${outPath}\n`);
        stdout.write(`Next: sign it with 'dirgha policy sign ${outPath} --key=<private.pem>'\n`);
      }
      return 0;
    }

    if (sub === "sign") {
      const target = positionals[1];
      const keyPath = typeof flags.key === "string" ? resolve(ctx.cwd, flags.key) : undefined;
      if (!target || !keyPath) {
        stderr.write("Usage: dirgha policy sign <manifest.json> --key=<private.pem> [--out=<file>]\n");
        return 1;
      }
      const inPath = resolve(ctx.cwd, target);
      if (!existsSync(inPath) || !existsSync(keyPath)) {
        stderr.write("Manifest or private key file does not exist.\n");
        return 1;
      }
      const raw = JSON.parse(readFileSync(inPath, "utf8")) as Record<string, unknown>;
      const privPem = readFileSync(keyPath, "utf8");
      const { signedManifest, canonicalPayloadSha256 } = signManifestEd25519(raw, privPem);
      const outPath =
        typeof flags.out === "string" ? resolve(ctx.cwd, flags.out) : inPath;
      writeFileEnsureDir(outPath, JSON.stringify(signedManifest, null, 2) + "\n");
      if (asJson) {
        stdout.write(
          JSON.stringify(
            {
              signed: true,
              outputPath: outPath,
              canonicalPayloadSha256,
              signerKeyFingerprint: signedManifest.signer_key_fingerprint,
            },
            null,
            2,
          ) + "\n",
        );
      } else {
        stdout.write(`Signed LOKAHI manifest (RFC-8785 + Ed25519) -> ${outPath}\n`);
        stdout.write(`  Canonical SHA-256: ${canonicalPayloadSha256}\n`);
        stdout.write(`  Key Fingerprint:   ${signedManifest.signer_key_fingerprint}\n`);
      }
      return 0;
    }

    if (sub === "verify") {
      const target = positionals[1];
      const pubPath = typeof flags.pubkey === "string" ? resolve(ctx.cwd, flags.pubkey) : undefined;
      if (!target || !pubPath) {
        stderr.write("Usage: dirgha policy verify <manifest.json> --pubkey=<public.pem> [--tool=<name>]\n");
        return 1;
      }
      const inPath = resolve(ctx.cwd, target);
      if (!existsSync(inPath) || !existsSync(pubPath)) {
        stderr.write("Manifest or public key file does not exist.\n");
        return 1;
      }
      const raw = JSON.parse(readFileSync(inPath, "utf8")) as Record<string, unknown>;
      const pubPem = readFileSync(pubPath, "utf8");
      const cryptoRes = verifyManifestEd25519(raw, pubPem);
      const schemaRes = validateAhimsaManifest(raw as AhimsaManifest, { requireEd25519: true });
      const toolCheck =
        typeof flags.tool === "string"
          ? checkLokahiManifestToolPolicy(inPath, flags.tool, new Date(), { publicKeyPem: pubPem })
          : null;

      const valid = cryptoRes.valid && schemaRes.compatibleWithLokahi && toolCheck === null;
      const report = {
        valid,
        crypto: cryptoRes,
        schemaCompatible: schemaRes.compatibleWithLokahi,
        schemaIssues: schemaRes.issues,
        ...(typeof flags.tool === "string" ? { tool: flags.tool, toolDecision: toolCheck ?? "allowed" } : {}),
      };
      if (asJson) {
        stdout.write(JSON.stringify(report, null, 2) + "\n");
      } else {
        stdout.write(`LOKAHI Manifest Verification: ${valid ? "VALID" : "FAILED"}\n`);
        stdout.write(`  Ed25519 Signature: ${cryptoRes.valid ? "PASS" : `FAIL (${cryptoRes.reason})`}\n`);
        stdout.write(`  LOKAHI v1.1 Rules: ${schemaRes.compatibleWithLokahi ? "PASS" : "FAIL"}\n`);
        for (const issue of schemaRes.issues) {
          stdout.write(`    - [${issue.code}] ${issue.message}\n`);
        }
        if (typeof flags.tool === "string") {
          stdout.write(`  Tool "${flags.tool}": ${toolCheck ?? "ALLOWED"}\n`);
        }
      }
      return valid ? 0 : 1;
    }

    if (sub === "approve") {
      const toolName = typeof flags.tool === "string" ? flags.tool : undefined;
      const keyPath = typeof flags.key === "string" ? resolve(ctx.cwd, flags.key) : undefined;
      if (!toolName || !keyPath || !existsSync(keyPath)) {
        stderr.write(
          "Usage: dirgha policy approve --tool=<name> --input='<json>' --key=<approver.private.pem> [--approver=<id>] [--ttl=45] [--out=<file>]\n",
        );
        return 1;
      }
      let parsedInput: unknown = {};
      if (typeof flags.input === "string") {
        try {
          parsedInput = JSON.parse(flags.input);
        } catch {
          stderr.write("Invalid JSON passed to --input\n");
          return 1;
        }
      }
      const ttlSeconds =
        typeof flags.ttl === "string" && Number.isFinite(Number(flags.ttl))
          ? Number(flags.ttl)
          : 45;
      const ticket = createS2ApprovalToken({
        tool: toolName,
        input: parsedInput,
        approverId: typeof flags.approver === "string" ? flags.approver : "human-approver",
        approverPrivateKeyPem: readFileSync(keyPath, "utf8"),
        ttlSeconds,
      });
      const jsonStr = JSON.stringify(ticket, null, 2) + "\n";
      if (typeof flags.out === "string") {
        const outPath = resolve(ctx.cwd, flags.out);
        writeFileEnsureDir(outPath, jsonStr);
      }
      stdout.write(jsonStr);
      return 0;
    }

    if (sub === "evidence") {
      let privPem: string | undefined;
      if (typeof flags.key === "string") {
        const keyPath = resolve(ctx.cwd, flags.key);
        if (!existsSync(keyPath)) {
          stderr.write(`Private key file not found: ${keyPath}\n`);
          return 1;
        }
        privPem = readFileSync(keyPath, "utf8");
      }
      const pack = buildComplianceEvidencePack({
        resolution,
        privateKeyPem: privPem,
      });
      const jsonStr = JSON.stringify(pack, null, 2) + "\n";
      if (typeof flags.out === "string") {
        const outPath = resolve(ctx.cwd, flags.out);
        writeFileEnsureDir(outPath, jsonStr);
        if (asJson) {
          stdout.write(jsonStr);
        } else {
          stdout.write(`Wrote compliance evidence pack -> ${outPath}\n`);
          stdout.write(`  Evidence SHA-256: ${pack.evidence_sha256}\n`);
          stdout.write(`  Signed:           ${pack.signature ? "YES (RFC8785-Ed25519)" : "NO"}\n`);
        }
      } else {
        stdout.write(jsonStr);
      }
      return 0;
    }

    stderr.write(`Unknown policy subcommand: "${sub}"\n`);
    printPolicyHelp();
    return 1;
  },
};

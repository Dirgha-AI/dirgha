import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import * as net from "node:net";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { runDoctor, runWasmSelfCheck, resolveNativeBinary } from "./dirgha.mjs";
import { createPolicyEngine } from "../dist/safety/policy.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const cliPath = path.join(__dirname, "dirgha.mjs");

test("lokahi_gate.wasm executes 50/50 red-team and C-ABI checks in Node WebAssembly", async () => {
  const res = await runWasmSelfCheck();
  assert.equal(res.wasmFound, true);
  assert.equal(res.redTeamPassed, 50);
  assert.equal(res.cAbiVerified, true);
});

test("v1 policy engine (dist/safety/policy.js) is upgraded with <1ms lokahi_gate.wasm firewall", () => {
  const engine = createPolicyEngine({ cwd: process.cwd() });

  // Flag-permuted rm -fr / (bypassed old v1 regex, now blocked by Lokahi WASM C-ABI)
  const blockedPermuted = engine.evaluate({
    tool: "shell",
    action: "exec",
    target: "sudo rm -fr /",
  });
  assert.equal(blockedPermuted.allowed, false);
  assert.ok(blockedPermuted.reason.includes("lokahi-gate-wasm"));

  // Cloud metadata SSRF (blocked by Lokahi WASM C-ABI)
  const blockedSsrf = engine.evaluate({
    tool: "shell",
    action: "network",
    target: "curl http://169.254.169.254/latest/meta-data/",
  });
  assert.equal(blockedSsrf.allowed, false);
  assert.ok(blockedSsrf.reason.includes("lokahi-gate-wasm"));
});

test("dirgha doctor reports HEALTHY, v1 coding CLI integrated, and <25 MB native binary gate", async () => {
  const rep = await runDoctor();
  assert.equal(rep.status, "HEALTHY");
  assert.equal(rep.v1_coding_cli_integrated, true);
  assert.equal(rep.lokahi_wasm_gate.lokahi_50_red_team, "50/50 PASS");
  assert.equal(rep.rust_native_host.under_25mb_gate, true);
  assert.ok(rep.provider_router.dirgha_catalog_providers >= 38);
  assert.equal("opencode_catalog_providers" in rep.provider_router, false);
});

test("unified CLI routes both v1 coding commands (hardware, gpu, status) and v2 kernel commands (--self-test, cockpit)", () => {
  const ver = execFileSync(process.execPath, [cliPath, "--version"], { encoding: "utf8" }).trim();
  assert.equal(ver, "@dirgha/code 2.0.1");

  // Verify v1 subcommand (`dirgha hardware --json`) routes cleanly through `dist/cli/main.js`
  const hwRaw = execFileSync(process.execPath, [cliPath, "hardware", "--json"], { encoding: "utf8" });
  const hwParsed = JSON.parse(hwRaw);
  assert.ok(hwParsed.hardware.cpuCores >= 1);
  assert.ok(Array.isArray(hwParsed.recommended));

  if (resolveNativeBinary()) {
    const selfTestRaw = execFileSync(process.execPath, [cliPath, "--self-test"], { encoding: "utf8" });
    const parsed = JSON.parse(selfTestRaw);
    assert.equal(parsed.status, "PASS");
    assert.equal(parsed.lokahi_50_all_passed, true);
    assert.equal(parsed.mcp_tools_registered, 24);

    const serveOnceRaw = execFileSync(process.execPath, [cliPath, "cockpit", "--serve", "--once"], {
      encoding: "utf8",
    });
    const serveParsed = JSON.parse(serveOnceRaw);
    assert.equal(serveParsed.status, "PASS");
    assert.equal(serveParsed.pwa_manifest_verified, true);
  } else {
    // Without native binary, --self-test runs portable WASM check, while kernel verbs like cockpit fail honestly
    const selfTestRaw = execFileSync(process.execPath, [cliPath, "--self-test"], { encoding: "utf8" });
    const parsed = JSON.parse(selfTestRaw);
    assert.equal(parsed.status, "PASS");
    assert.equal(parsed.mode, "PORTABLE_WASM_FALLBACK");
    assert.equal(parsed.native_host_present, false);

    let failedHonestly = false;
    try {
      execFileSync(process.execPath, [cliPath, "cockpit"], { encoding: "utf8", stdio: "pipe" });
    } catch (err) {
      failedHonestly =
        err.status === 1 &&
        typeof err.stderr === "string" &&
        err.stderr.includes("native_host_missing");
    }
    assert.equal(failedHonestly, true, "cockpit must exit 1 with native_host_missing when binary is absent");
  }
});

test("gateway defaults to the TypeScript server even when the native binary exists", async (t) => {
  for (const command of ["gateway", "proxy"]) {
    const portServer = net.createServer();
    portServer.listen(0, "127.0.0.1");
    await new Promise((resolve, reject) => {
      portServer.once("listening", resolve);
      portServer.once("error", reject);
    });
    const address = portServer.address();
    if (!address || typeof address === "string") throw new Error("Expected a TCP server address");
    await new Promise((resolve, reject) => portServer.close((err) => (err ? reject(err) : resolve())));

    const child = spawn(process.execPath, [cliPath, command, "--port", String(address.port)], {
      cwd: path.dirname(__dirname),
      stdio: ["ignore", "pipe", "pipe"],
    });
    t.after(() => {
      if (!child.killed) child.kill();
    });

    let output = "";
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error(`${command} did not start. Output: ${output}`)), 10_000);
      const check = (chunk) => {
        output += chunk.toString();
        if (output.includes("Dirgha Agent Gateway active")) {
          clearTimeout(timeout);
          resolve();
        }
      };
      child.stdout.on("data", check);
      child.stderr.on("data", check);
      child.once("error", (err) => {
        clearTimeout(timeout);
        reject(err);
      });
      child.once("exit", (code) => {
        clearTimeout(timeout);
        reject(new Error(`${command} exited before startup (code ${code}). Output: ${output}`));
      });
    });

    assert.match(output, /Dirgha Agent Gateway active/);
    assert.doesNotMatch(output, /non-proxying stub/);
  }

});

test("self-test runs in an isolated workspace and preserves project data", () => {
  if (!resolveNativeBinary()) return; // The portable WASM fallback does not write project data.

  const trackedData = [
    path.join(__dirname, "..", "data", "audit-chain.jsonl"),
    path.join(__dirname, "..", "data", "vault.sealed.json"),
  ];
  const hashes = () =>
    trackedData.map((file) => createHash("sha256").update(readFileSync(file)).digest("hex"));
  const before = hashes();

  const raw = execFileSync(process.execPath, [cliPath, "--self-test"], {
    encoding: "utf8",
    cwd: path.dirname(__dirname),
  });
  assert.equal(JSON.parse(raw).status, "PASS");
  assert.deepEqual(hashes(), before, "self-test must not modify data/audit-chain.jsonl or data/vault.sealed.json");
});

test("experimental native gateway is explicitly labelled and never the default", async (t) => {
  if (!resolveNativeBinary()) {
    let exitError;
    try {
      execFileSync(process.execPath, [cliPath, "gateway", "--engine", "native", "--port", "0"], {
        encoding: "utf8",
        stdio: "pipe",
      });
    } catch (error) {
      exitError = error;
    }
    assert.equal(exitError?.status, 1);
    assert.match(exitError?.stderr?.toString() ?? "", /EXPERIMENTAL.*does not proxy upstream LLM traffic/);
    assert.match(exitError?.stderr?.toString() ?? "", /native_host_missing/);
    return;
  }

  const child = spawn(
    process.execPath,
    [cliPath, "gateway", "--engine", "native", "--port", "0"],
    { cwd: path.dirname(__dirname), stdio: ["ignore", "pipe", "pipe"] }
  );
  t.after(() => {
    if (!child.killed) child.kill();
  });

  let output = "";
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(`experimental gateway did not start. Output: ${output}`)),
      10_000
    );
    const check = (chunk) => {
      output += chunk.toString();
      if (output.includes("EXPERIMENTAL") && (output.includes("Native Micro-Gateway listening") || output.includes("Native Micro-Gateway active"))) {
        clearTimeout(timeout);
        resolve();
      }
    };
    child.stdout.on("data", check);
    child.stderr.on("data", check);
    child.once("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });
    child.once("exit", (code) => {
      clearTimeout(timeout);
      reject(new Error(`experimental gateway exited before startup (code ${code}). Output: ${output}`));
    });
  });

  assert.match(output, /\[EXPERIMENTAL\] Native gateway prototype/);
  assert.match(output, /does not proxy upstream LLM traffic/);
  assert.doesNotMatch(output, /Dirgha Agent Gateway active/);
});

#!/usr/bin/env node
/**
 * `@dirgha/code` 2.0.1: unified CLI, TUI & Sovereign Rust Kernel Entry Point.
 *
 * Unifies:
 * 1. All 38 existing `@dirgha/code` v1.43.3 coding subcommands (`ask`, `chat`, `fleet`, `orchestra`,
 *    `hardware`, `status`, `stats`, `audit`, `audit-codebase`, `init`, `keys`, `models`, `memory`,
 *    `ledger`, `cost`, `kb`, `skills`, `verify`, `compact`, `export-session`, `import-session`,
 *    `resume`, `web`, `state`, `history`, `ping`, `voice`, `register`, `node`, `login`,
 *    `logout`, `setup`, `auth`, `undo`, `update`, `telemetry`, `scaffold`, and interactive Ink/Readline REPL)
 *    via `dist/cli/main.js` (now upgraded with `<1 ms` in-process `lokahi_gate.wasm` in `dist/safety/policy.js`).
 * 2. The Rust kernel commands & 24 MCP tools (`--self-test`,
 *    `--mcp`, `--native-messaging`, `app`, `cockpit`, `acceptance`, `eval-robot`, `gateway-demo`,
 *    `sbom-vex`, `scan-repo`, `flywheel`, `benchmark`, `computer`, `live-llm`, `providers`)
 *    via `dirgha-native-host[.exe]` + `lokahi_gate.wasm`.
 */

import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");

/** Verbs handled directly by the v2.0 Rust Micro-Kernel (`dirgha-native-host`). */
const V2_KERNEL_VERBS = new Set([
  "--self-test",
  "--mcp",
  "--native-messaging",
  "app",
  "cockpit",
  "acceptance",
  "eval-robot",
  "gateway-demo",
  "sbom-vex",
  "scan-repo",
  "flywheel",
  "benchmark",
  "computer",
  "live-llm",
  "providers",
]);

/**
 * Locate the compiled `dirgha-native-host` binary across workspace `target/release`, `bin/native`, or `PATH`.
 */
export function resolveNativeBinary() {
  const exe = process.platform === "win32" ? "dirgha-native-host.exe" : "dirgha-native-host";
  const candidates = [
    path.join(rootDir, "target", "release", exe),
    path.join(rootDir, "bin", "native", exe),
    path.join(process.cwd(), "target", "release", exe),
  ];
  for (const cand of candidates) {
    if (fs.existsSync(cand)) {
      return cand;
    }
  }
  return null;
}

/**
 * Instantiate `extensions/firefox-mv3/lokahi_gate.wasm` via Node's native WebAssembly engine
 * and run the 50-scenario `Lokahi-50` Red-Team suite + C-ABI payload evaluator.
 */
export async function runWasmSelfCheck() {
  const wasmPath = path.join(rootDir, "extensions", "firefox-mv3", "lokahi_gate.wasm");
  if (!fs.existsSync(wasmPath)) {
    return { wasmFound: false, redTeamPassed: 0, cAbiVerified: false, latencyUs: null };
  }
  const bytes = fs.readFileSync(wasmPath);
  const wasiStub = {
    args_get: () => 0,
    args_sizes_get: () => 0,
    environ_get: () => 0,
    environ_sizes_get: () => 0,
    clock_time_get: () => 0,
    fd_close: () => 0,
    fd_fdstat_get: () => 0,
    fd_seek: () => 0,
    fd_write: () => 0,
    proc_exit: () => {},
    random_get: () => 0,
  };
  const { instance } = await WebAssembly.instantiate(bytes, {
    wasi_snapshot_preview1: wasiStub,
  });
  const exports = instance.exports;

  const t0 = performance.now();
  const redTeamScore = exports.lokahi_wasm_run_red_team_50();
  const elapsedUs = Number(((performance.now() - t0) * 1000).toFixed(2));

  // Verify C-ABI (`lokahi_c_abi_evaluate_utf8`) blocks `rm -rf /` (0) and allows safe read (1)
  const enc = new TextEncoder();
  const evalUtf8 = (text) => {
    const payload = enc.encode(text);
    const hasAlloc =
      typeof exports.lokahi_alloc === "function" && typeof exports.lokahi_free === "function";
    const ptr = hasAlloc ? exports.lokahi_alloc(payload.length) : 65536;
    try {
      new Uint8Array(exports.memory.buffer, ptr, payload.length).set(payload);
      return exports.lokahi_c_abi_evaluate_utf8(ptr, payload.length, 0);
    } finally {
      if (hasAlloc && ptr > 0) {
        exports.lokahi_free(ptr, payload.length);
      }
    }
  };
  const badVerdict = evalUtf8("sudo rm -fr /");
  const goodVerdict = evalUtf8("cargo test --workspace");

  return {
    wasmFound: true,
    wasmSizeBytes: bytes.length,
    redTeamPassed: redTeamScore,
    cAbiVerified: badVerdict === 0 && goodVerdict === 1,
    latencyUs: elapsedUs,
  };
}

/**
 * Discover authenticated Dirgha providers from `~/.dirgha/keys.json` and environment variables.
 * Never reads third-party tool caches or credential files.
 */
function discoverAuthenticatedProviders() {
  const providers = new Set(["ollama-local-gguf"]);
  const keysPath = path.join(os.homedir(), ".dirgha", "keys.json");
  if (fs.existsSync(keysPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(keysPath, "utf8"));
      if (parsed && typeof parsed === "object") {
        for (const [key, val] of Object.entries(parsed)) {
          if (typeof val === "string" && val.trim().length > 0) {
            providers.add(key.toLowerCase().replace(/_api_key$/, ""));
          }
        }
      }
    } catch {
      // ignore unreadable keystore
    }
  }
  const envMap = [
    ["OPENROUTER_API_KEY", "openrouter"],
    ["ANTHROPIC_API_KEY", "anthropic"],
    ["OPENAI_API_KEY", "openai"],
    ["GEMINI_API_KEY", "gemini"],
    ["NVIDIA_API_KEY", "nvidia-nim"],
    ["DEEPSEEK_API_KEY", "deepseek"],
    ["GROQ_API_KEY", "groq"],
    ["MISTRAL_API_KEY", "mistral"],
    ["FIREWORKS_API_KEY", "fireworks"],
    ["TOGETHER_API_KEY", "together"],
    ["XAI_API_KEY", "xai"],
  ];
  for (const [envName, label] of envMap) {
    if (process.env[envName] && process.env[envName].trim().length > 0) {
      providers.add(label);
    }
  }
  return Array.from(providers);
}

/**
 * Execute `dirgha doctor` combining v2.0 Sovereign Kernel + WASM + provider diagnostics
 * and TypeScript coding CLI status.
 */
export async function runDoctor() {
  const wasmCheck = await runWasmSelfCheck();
  const nativeBin = resolveNativeBinary();
  const nativeSizeBytes = nativeBin ? fs.statSync(nativeBin).size : null;
  const v1DistPresent = fs.existsSync(path.join(rootDir, "dist", "cli", "main.js"));
  const authenticatedProviders = discoverAuthenticatedProviders();

  const report = {
    status: wasmCheck.redTeamPassed === 50 && wasmCheck.cAbiVerified ? "HEALTHY" : "DEGRADED",
    package: "@dirgha/code@2.0.1",
    kernel_version: "2.0.1",
    platform: `${process.platform}-${process.arch}`,
    node_version: process.version,
    v1_coding_cli_integrated: v1DistPresent,
    v1_subcommands_count: 38,
    v1_builtin_tools_count: 29,
    lokahi_wasm_gate: {
      present: wasmCheck.wasmFound,
      size_kb: wasmCheck.wasmSizeBytes ? Number((wasmCheck.wasmSizeBytes / 1024).toFixed(1)) : 0,
      lokahi_50_red_team: `${wasmCheck.redTeamPassed}/50 PASS`,
      c_abi_verified: wasmCheck.cAbiVerified,
      suite_latency_us: wasmCheck.latencyUs,
    },
    rust_native_host: {
      present: Boolean(nativeBin),
      binary_path: nativeBin,
      size_mb: nativeSizeBytes ? Number((nativeSizeBytes / (1024 * 1024)).toFixed(3)) : null,
      under_25mb_gate: nativeSizeBytes ? nativeSizeBytes < 25 * 1024 * 1024 : true,
      mcp_tools_count: 24,
    },
    provider_router: {
      dirgha_catalog_providers: 38,
      authenticated_providers: authenticatedProviders,
    },
  };

  console.log(JSON.stringify(report, null, 2));
  return report;
}

async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];

  if (cmd === "--version" || cmd === "-v" || cmd === "-V") {
    console.log("@dirgha/code 2.0.1");
    return;
  }

  if (cmd === "doctor" && !args.includes("--v1")) {
    const rep = await runDoctor();
    if (rep.status !== "HEALTHY") process.exit(1);
    return;
  }

  // Route `gateway` / `proxy` to Dirgha Agent Gateway (Claude Code & Cursor interceptor)
  if (cmd === "gateway" || cmd === "proxy") {
    let port = 8080;
    const portIdx = args.indexOf("--port");
    if (portIdx !== -1 && args[portIdx + 1]) {
      port = parseInt(args[portIdx + 1], 10);
    }
    const gatewayDistPath = path.join(rootDir, "dist", "gateway", "server.js");
    if (fs.existsSync(gatewayDistPath)) {
      const mod = await import(pathToFileURL(gatewayDistPath).href);
      mod.startGatewayServer({ port });
      return;
    }
    console.error("Gateway dist not built. Run 'npm run build' first.");
    process.exit(1);
  }

  // Route v2.0 Sovereign Kernel & Physical AI verbs directly to `dirgha-native-host`
  if (cmd && V2_KERNEL_VERBS.has(cmd)) {
    const nativeBin = resolveNativeBinary();
    if (nativeBin) {
      const res = spawnSync(nativeBin, args, {
        stdio: "inherit",
        cwd: fs.existsSync(path.join(process.cwd(), "Cargo.toml")) ? process.cwd() : rootDir,
      });
      process.exit(res.status ?? 0);
    }
    if (cmd === "--self-test") {
      const wasmCheck = await runWasmSelfCheck();
      const passed = wasmCheck.redTeamPassed === 50 && wasmCheck.cAbiVerified;
      console.log(
        JSON.stringify(
          {
            status: passed ? "PASS" : "FAIL",
            mode: "PORTABLE_WASM_FALLBACK",
            version: "2.0.1",
            lokahi_50_red_team: `${wasmCheck.redTeamPassed}/50 PASS`,
            c_abi_verified: wasmCheck.cAbiVerified,
            native_host_present: false,
          },
          null,
          2
        )
      );
      if (!passed) process.exit(1);
      return;
    }
    console.error(
      JSON.stringify(
        {
          status: "ERROR",
          reason: "native_host_missing",
          command: cmd,
          message: `The Rust kernel binary (dirgha-native-host) is required for '${cmd}' but is not built.`,
          remediation: "Run: npm run build:native (requires Rust toolchain: https://rustup.rs)",
        },
        null,
        2
      )
    );
    process.exit(1);
  }

  // Route all coding subcommands (`ask`, `chat`, `fleet`, `orchestra`, `hardware`, `gpu`, `scan`,
  // `status`, `kb`, `skills`, `models`, `keys`, `setup`, `web`, etc.) and interactive TUI/REPL to `dist/cli/main.js`
  const v1MainPath = path.join(rootDir, "dist", "cli", "main.js");
  if (fs.existsSync(v1MainPath)) {
    await import(pathToFileURL(v1MainPath).href);
    return;
  }
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]).toLowerCase() === path.resolve(fileURLToPath(import.meta.url)).toLowerCase();

if (isMain) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

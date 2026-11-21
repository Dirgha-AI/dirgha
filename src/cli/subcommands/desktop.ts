/**
 * `dirgha desktop` — Launch the Dirgha Desktop execution workbench.
 *
 * Serves the compiled desktop workbench bundle from `desktop/dist/`
 * on localhost:1420 (or custom port via --port=).
 * In --dev mode, launches the Vite dev server with HMR.
 *
 * Usage:
 *   dirgha desktop              Open at http://127.0.0.1:1420
 *   dirgha desktop --port=8080  Custom port
 *   dirgha desktop --dev        Interactive development mode
 *   dirgha desktop --json       Output JSON metadata and keep running
 */

import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import path from "node:path";
import { stdout, stderr } from "node:process";
import { fileURLToPath } from "node:url";
import { style, defaultTheme } from "../../tui/theme.js";
import type { Subcommand, SubcommandCtx } from "./index.js";

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

function parsePort(argv: string[]): number {
  for (const a of argv) {
    if (a.startsWith("--port=")) {
      const n = Number(a.slice("--port=".length));
      if (Number.isFinite(n) && n > 0 && n < 65536) return n;
    }
  }
  return 1420;
}

export const desktopSubcommand: Subcommand = {
  name: "desktop",
  aliases: ["ui", "workbench"],
  description: "Launch Dirgha Desktop execution workbench (Tauri / React 19)",
  async run(argv: string[], ctx: SubcommandCtx): Promise<number> {
    const isDev = argv.includes("--dev");
    const json = argv.includes("--json");
    const port = parsePort(argv);

    let desktopRoot = path.resolve(ctx.cwd, "desktop");
    if (!existsSync(path.join(desktopRoot, "dist"))) {
      const packageRoot = path.resolve(fileURLToPath(import.meta.url), "../../../..");
      const candidate = path.join(packageRoot, "desktop");
      if (existsSync(path.join(candidate, "dist"))) {
        desktopRoot = candidate;
      }
    }
    const distRoot = path.resolve(desktopRoot, "dist");

    if (isDev) {
      stdout.write(`${style(defaultTheme.accent, "⚡")} Starting Dirgha Desktop in dev mode (Vite HMR)...\n`);
      const child = spawn("npm", ["--prefix", desktopRoot, "run", "dev"], {
        stdio: "inherit",
        shell: true,
      });
      return new Promise<number>((resolve) => {
        child.on("close", (code) => resolve(code ?? 0));
      });
    }

    if (!existsSync(distRoot)) {
      stderr.write(
        `${style(defaultTheme.warning, "!")} Desktop distribution not found at ${distRoot}.\n` +
          `  Run: npm --prefix desktop run build:web\n`
      );
      return 1;
    }

    const server = createServer(async (req, res) => {
      try {
        const urlPath = (req.url || "/").split("?")[0];
        let filePath = path.join(distRoot, urlPath === "/" ? "index.html" : urlPath);

        // Security check: ensure path is within distRoot
        if (!filePath.startsWith(distRoot)) {
          res.writeHead(403);
          res.end("Forbidden");
          return;
        }

        let fileStat;
        try {
          fileStat = await stat(filePath);
          if (fileStat.isDirectory()) {
            filePath = path.join(filePath, "index.html");
            fileStat = await stat(filePath);
          }
        } catch {
          // SPA fallback to index.html for client-side routing
          filePath = path.join(distRoot, "index.html");
          fileStat = await stat(filePath);
        }

        const ext = path.extname(filePath).toLowerCase();
        const contentType = MIME_TYPES[ext] || "application/octet-stream";
        const content = await readFile(filePath);

        res.writeHead(200, {
          "Content-Type": contentType,
          "Content-Length": content.length,
          "Cache-Control": ext === ".html" ? "no-cache" : "max-age=31536000",
        });
        res.end(content);
      } catch (err) {
        res.writeHead(500);
        res.end("Internal Server Error");
      }
    });

    return new Promise<number>((resolve) => {
      server.listen(port, "127.0.0.1", () => {
        const url = `http://127.0.0.1:${port}`;
        if (json) {
          stdout.write(JSON.stringify({ url, status: "ready", mode: "desktop" }) + "\n");
        } else {
          stdout.write(`\n${style(defaultTheme.success, "✓")} Dirgha Desktop Workbench running at ${style(defaultTheme.accent, url)}\n`);
          stdout.write(`  Protocol: dirgha.rpc (WebSockets on ${url}/api/rpc)\n`);
          stdout.write(`  Engine: Dirgha 2.0 Kernel + LOKAHI Capability Gate\n`);
          stdout.write(`  Press Ctrl+C to stop.\n\n`);
        }
      });

      server.on("error", (err) => {
        stderr.write(`Failed to start desktop server on port ${port}: ${err.message}\n`);
        resolve(1);
      });

      const cleanup = () => {
        server.close(() => resolve(0));
      };

      process.on("SIGINT", cleanup);
      process.on("SIGTERM", cleanup);
    });
  },
};

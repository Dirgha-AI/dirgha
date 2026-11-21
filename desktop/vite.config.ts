import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const host = process.env.TAURI_DEV_HOST;

function fingerprint(directory: string): string {
  const hash = createHash("sha256");
  const visit = (path: string) => {
    for (const entry of readdirSync(path, { withFileTypes: true }).sort(
      (a, b) => a.name.localeCompare(b.name),
    )) {
      const name = join(path, entry.name);
      if (entry.isDirectory()) visit(name);
      else if (entry.isFile()) hash.update(name).update(readFileSync(name));
    }
  };
  visit(directory);
  hash.update(readFileSync("package-lock.json"));
  hash.update(readFileSync("vite.config.ts"));
  return hash.digest("hex").slice(0, 20);
}

export default defineConfig(({ mode }) => {
  const web = mode === "web";
  const buildId = web ? fingerprint("src") : "desktop";
  let version = "2.0.0";
  try {
    const pkg = JSON.parse(readFileSync("package.json", "utf8"));
    if (pkg.version) version = pkg.version;
  } catch {
    // fallback
  }

  return {
    plugins: [
      react(),
      ...(web
        ? [
            {
              name: "dirgha-web-release",
              generateBundle() {
                this.emitFile({
                  type: "asset",
                  fileName: "web-build.json",
                  source: JSON.stringify({
                    version,
                    buildId,
                    protocolVersion: "1.0",
                  }),
                });
              },
            } satisfies Plugin,
          ]
        : []),
    ],
    define: { __WEB_BUILD_ID__: JSON.stringify(buildId) },
    ...(web
      ? { build: { outDir: "dist", emptyOutDir: true } }
      : {}),
    clearScreen: false,
    server: {
      port: 1420,
      strictPort: true,
      host: host || false,
      hmr: host
        ? {
            protocol: "ws",
            host,
            port: 1421,
          }
        : undefined,
      watch: {
        ignored: ["**/src-tauri/**"],
      },
    },
    test: {
      environment: "jsdom",
      exclude: ["node_modules/**", "e2e/**"],
    },
  } as any;
});

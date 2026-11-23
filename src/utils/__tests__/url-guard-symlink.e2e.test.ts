/**
 * Environment-dependent symlink containment test.
 *
 * Creating symlinks on Windows normally requires Developer Mode or the
 * SeCreateSymbolicLinkPrivilege, which CI runners do not always grant. The
 * default offline suite therefore keeps the pure URL/DNS guard tests in
 * `url-guard-and-fs.test.ts`; this suite runs under `npm run test:e2e` on a
 * host that can create symlinks.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isValidCwdPath } from "../fs.js";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("Symlink-safe workspace containment (isValidCwdPath)", () => {
  it("allows files inside workspace and blocks symlink escapes pointing outside", () => {
    const workspace = makeTempDir("dirgha-ws-");
    const outside = makeTempDir("dirgha-out-");
    writeFileSync(join(outside, "secret.txt"), "top-secret", "utf8");
    mkdirSync(join(workspace, "sub"), { recursive: true });
    writeFileSync(join(workspace, "sub", "ok.txt"), "hello", "utf8");

    const ok = isValidCwdPath(workspace, "sub/ok.txt");
    expect(ok.valid).toBe(true);

    // Create symlink inside workspace pointing outside
    const linkPath = join(workspace, "escape-link");
    symlinkSync(outside, linkPath);

    const escaped = isValidCwdPath(workspace, "escape-link/secret.txt");
    expect(escaped.valid).toBe(false);
    if (!escaped.valid) {
      expect(escaped.error).toContain("escapes workspace");
    }

    // Even a non-existent leaf under the symlinked directory must be blocked
    const escapedNew = isValidCwdPath(workspace, "escape-link/new-file.txt");
    expect(escapedNew.valid).toBe(false);
  });
});

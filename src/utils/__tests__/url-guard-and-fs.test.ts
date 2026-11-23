/**
 * Offline unit tests for the IPv6/DNS fail-closed SSRF guard and strict
 * sandbox enforcement. Symlink containment requires host privileges and lives
 * in `url-guard-symlink.e2e.test.ts`.
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertSafeFetchUrl,
  assertSafeFetchUrlAsync,
  type DnsLookupFn,
} from "../url-guard.js";
import { shellTool } from "../../tools/shell.js";
import type { ToolContext } from "../../tools/registry.js";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  delete process.env.DIRGHA_ALLOW_PRIVATE_FETCH;
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("SSRF guard (IPv6, IPv4-mapped IPv6, CGNAT, metadata, DNS fail-closed)", () => {
  it("blocks literal loopback, metadata, CGNAT, IPv6 ULA, link-local, and non-http schemes", () => {
    const blockedUrls = [
      "http://127.0.0.1/admin",
      "http://[::1]:8080/",
      "http://[fe80::1]/",
      "http://[fd00:ec2::254]/latest/meta-data/",
      "http://[::ffff:127.0.0.1]/",
      "http://[::ffff:169.254.169.254]/latest/meta-data/",
      "http://100.64.0.1/internal",
      "http://metadata.google.internal/computeMetadata/v1/",
      "file:///etc/passwd",
    ];
    for (const url of blockedUrls) {
      expect(() => assertSafeFetchUrl(url), `expected blocked: ${url}`).toThrow(/SSRF guard/);
    }
  });

  it("blocks hostnames resolving to IPv6 loopback, link-local, ULA, or IPv4-mapped IPv6 addresses", async () => {
    const cases = [
      { address: "::1", family: 6 },
      { address: "fe80::1", family: 6 },
      { address: "fd00:ec2::254", family: 6 },
      { address: "::ffff:127.0.0.1", family: 6 },
      { address: "::ffff:7f00:1", family: 6 },
      { address: "::ffff:169.254.169.254", family: 6 },
      { address: "100.64.12.34", family: 4 },
    ];
    for (const rec of cases) {
      const lookupFn: DnsLookupFn = async () => [rec];
      await expect(
        assertSafeFetchUrlAsync("https://rebind.example.com/api", lookupFn),
        `expected blocked DNS result ${rec.address}`,
      ).rejects.toThrow(/SSRF guard/);
    }
  });

  it("fails closed when DNS resolution throws an error", async () => {
    const failingLookup: DnsLookupFn = async () => {
      throw new Error("ENOTFOUND");
    };
    await expect(
      assertSafeFetchUrlAsync("https://nonexistent.example.invalid/v1", failingLookup),
    ).rejects.toThrow(/DNS resolution failed.*fail-closed/);
  });

  it("allows public IPv4 and IPv6 addresses", async () => {
    const publicLookup: DnsLookupFn = async () => [
      { address: "93.184.216.34", family: 4 },
      { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 },
    ];
    await expect(
      assertSafeFetchUrlAsync("https://api.example.com/v1/gpus", publicLookup),
    ).resolves.toBeUndefined();
  });
});

describe("shellTool strict sandbox fail-closed", () => {
  it("refuses execution when sandboxMode is strict and sandbox is null or noop", async () => {
    const cwd = makeTempDir("dirgha-shell-");
    const baseCtx: ToolContext = {
      cwd,
      env: {},
      sessionId: "test-session",
      signal: new AbortController().signal,
      sandbox: null,
      sandboxMode: "strict",
    };

    const resNull = await shellTool.execute({ command: "echo hi" }, baseCtx);
    expect(resNull.isError).toBe(true);
    expect(resNull.content).toContain("Strict sandbox mode refused execution");

    const resNoop = await shellTool.execute(
      { command: "echo hi" },
      {
        ...baseCtx,
        sandbox: {
          platform: "noop",
          available: async () => true,
          exec: async () => {
            throw new Error("should never execute");
          },
        },
      },
    );
    expect(resNoop.isError).toBe(true);
    expect(resNoop.content).toContain("Strict sandbox mode refused execution");
  });
});

import { afterEach, describe, expect, it } from "vitest";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { once } from "node:events";
import { logActivity } from "../interceptor.js";
import { startGatewayServer } from "../server.js";

const tempDirs: string[] = [];
const servers: http.Server[] = [];

function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dirgha-gateway-stabilization-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  for (const server of servers.splice(0)) {
    if (server.listening) {
      server.close();
      await once(server, "close");
    }
  }
  for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe("gateway stabilization", () => {
  it("returns JSON 413 for requests exceeding 10 MB", async () => {
    const server = startGatewayServer({ port: 0, cwd: makeTempDir() });
    servers.push(server);
    await once(server, "listening");
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Expected a TCP server address");

    const response = await new Promise<{ statusCode?: number; body: string }>((resolve, reject) => {
      const request = http.request(
        {
          host: "127.0.0.1",
          port: address.port,
          path: "/v1/messages",
          method: "POST",
          headers: { "Content-Length": 10 * 1024 * 1024 + 1 },
        },
        (res) => {
          let body = "";
          res.setEncoding("utf8");
          res.on("data", (chunk: string) => (body += chunk));
          res.on("end", () => resolve({ statusCode: res.statusCode, body }));
        }
      );
      request.on("error", reject);
      request.end(Buffer.alloc(10 * 1024 * 1024 + 1, 0x61));
    });

    expect(response.statusCode).toBe(413);
    expect(JSON.parse(response.body)).toMatchObject({ error: "Payload Too Large" });
  }, 20_000);

  it("resumes from a final audit record larger than 8 KB", () => {
    const cwd = makeTempDir();
    const dataDir = path.join(cwd, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    const previous = {
      index: 41,
      timestamp: new Date(0).toISOString(),
      tool: "test",
      action: "read",
      target: "x".repeat(12 * 1024),
      verdict: "ALLOW",
      reason: "large historical record",
      prevHash: "0".repeat(64),
    };
    const material = `${previous.index}|${previous.timestamp}|${previous.tool}|${previous.action}|${previous.target}|${previous.verdict}|${previous.reason}|${previous.prevHash}`;
    const previousHash = crypto.createHash("sha256").update(material).digest("hex");
    fs.writeFileSync(
      path.join(dataDir, "gateway_audit.jsonl"),
      `${JSON.stringify({ ...previous, hash: previousHash })}\n`,
      "utf8"
    );

    const appended = logActivity(
      { tool: "test", action: "read", target: "current", verdict: "ALLOW", reason: "resume" },
      cwd
    );

    expect(appended.index).toBe(42);
    expect(appended.prevHash).toBe(previousHash);
  });

  it("fails closed rather than restarting an unreadable audit ledger", () => {
    const cwd = makeTempDir();
    const dataDir = path.join(cwd, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, "gateway_audit.jsonl"), `${"{".padEnd(9 * 1024, "x")}\n`, "utf8");

    expect(() =>
      logActivity(
        { tool: "test", action: "read", target: "current", verdict: "ALLOW", reason: "must fail closed" },
        cwd
      )
    ).toThrow(/Cannot resume gateway audit ledger/);
    expect(fs.readFileSync(path.join(dataDir, "gateway_audit.jsonl"), "utf8")).not.toContain('"index":1');
  });

  it("continues on a new line when the prior audit ledger has no trailing newline", () => {
    const cwd = makeTempDir();
    const dataDir = path.join(cwd, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    const previous = {
      index: 3,
      timestamp: new Date(0).toISOString(),
      tool: "test",
      action: "read",
      target: "target",
      verdict: "ALLOW",
      reason: "existing",
      prevHash: "0".repeat(64),
    };
    const material = `${previous.index}|${previous.timestamp}|${previous.tool}|${previous.action}|${previous.target}|${previous.verdict}|${previous.reason}|${previous.prevHash}`;
    const previousHash = crypto.createHash("sha256").update(material).digest("hex");
    const ledgerPath = path.join(dataDir, "gateway_audit.jsonl");
    fs.writeFileSync(ledgerPath, JSON.stringify({ ...previous, hash: previousHash }), "utf8");

    logActivity(
      { tool: "test", action: "read", target: "next", verdict: "ALLOW", reason: "append" },
      cwd
    );

    const lines = fs.readFileSync(ledgerPath, "utf8").trimEnd().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[1])).toMatchObject({ index: 4, prevHash: previousHash });
  });
});

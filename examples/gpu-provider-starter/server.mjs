#!/usr/bin/env node
/**
 * Dirgha Open GPU Cloud Market — Reference Partner Provider Starter Server.
 *
 * Implements the Dirgha GPU Provider Schema v1.0 contract so any neocloud,
 * regional sovereign cloud, or private enterprise GPU cluster can integrate
 * with `dirgha gpu certify --live` and `dirgha gpu register` in minutes.
 *
 * Run:
 *   PARTNER_API_KEY=dev-token PORT=4090 node examples/gpu-provider-starter/server.mjs
 *
 * Licensed under the Apache License, Version 2.0.
 */

import * as http from "node:http";
import { randomUUID } from "node:crypto";

const PORT = Number(process.env.PORT || 4090);
const REQUIRED_TOKEN = process.env.PARTNER_API_KEY || "";

const CATALOG = [
  {
    id: "h100-sxm-80gb",
    name: "NVIDIA H100 SXM 80GB",
    vramGb: 80,
    costPerHr: 2.39,
    region: "EU-DE",
    available: true,
  },
  {
    id: "a100-80gb",
    name: "NVIDIA A100 80GB",
    vramGb: 80,
    costPerHr: 1.49,
    region: "IN-MUM",
    available: true,
  },
  {
    id: "rtx-4090-24gb",
    name: "NVIDIA RTX 4090 24GB",
    vramGb: 24,
    costPerHr: 0.38,
    region: "EU-DE",
    available: true,
  },
];

const instances = new Map();

function sendJson(res, status, data) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(data, null, 2));
}

function authorized(req) {
  if (!REQUIRED_TOKEN) return true;
  const auth = req.headers.authorization || "";
  return auth === `Bearer ${REQUIRED_TOKEN}`;
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  const path = url.pathname;

  if (req.method === "GET" && path === "/v1/gpus") {
    sendJson(res, 200, { gpus: CATALOG });
    return;
  }

  if (!authorized(req)) {
    sendJson(res, 401, { error: "unauthorized" });
    return;
  }

  if (req.method === "POST" && path === "/v1/instances") {
    try {
      const body = await readJson(req);
      const sku = CATALOG.find((g) => g.id === body.gpuType || g.name === body.gpuType) || CATALOG[0];
      const id = `inst_${randomUUID().slice(0, 8)}`;
      const inst = {
        id,
        gpuType: sku.name,
        status: "running",
        costPerHr: sku.costPerHr,
        totalCost: 0,
        startedAt: new Date().toISOString(),
        simulated: true,
      };
      instances.set(id, inst);
      sendJson(res, 201, inst);
    } catch {
      sendJson(res, 400, { error: "invalid_json" });
    }
    return;
  }

  const logsMatch = /^\/v1\/instances\/([^/]+)\/logs$/.exec(path);
  if (req.method === "GET" && logsMatch) {
    const inst = instances.get(decodeURIComponent(logsMatch[1]));
    if (!inst) {
      sendJson(res, 404, { error: "not_found" });
      return;
    }
    res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
    res.end(`[starter-gpu-provider] instance ${inst.id} (${inst.gpuType}) status=${inst.status}\n`);
    return;
  }

  const instMatch = /^\/v1\/instances\/([^/]+)$/.exec(path);
  if (instMatch) {
    const id = decodeURIComponent(instMatch[1]);
    const inst = instances.get(id);
    if (!inst) {
      sendJson(res, 404, { error: "not_found" });
      return;
    }
    if (req.method === "GET") {
      sendJson(res, 200, inst);
      return;
    }
    if (req.method === "DELETE") {
      instances.delete(id);
      sendJson(res, 200, { destroyed: true, id });
      return;
    }
  }

  sendJson(res, 404, { error: "not_found" });
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`Dirgha GPU Provider Starter listening on http://127.0.0.1:${PORT}`);
});

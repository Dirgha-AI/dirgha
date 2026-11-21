/**
 * Open GPU Cloud Market — Third-Party Provider Manifest, Certification & HTTP Adapter.
 *
 * Allows any GPU cloud provider (neoclouds, sovereign regional clouds, enterprise
 * private GPU clusters, DePIN networks) to submit a standard JSON manifest,
 * pass automated security/SSRF/schema certification (`dirgha gpu certify`),
 * and register into Dirgha's unified multi-cloud marketplace (`dirgha gpu submit`).
 *
 * Licensed under the Apache License, Version 2.0.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import type {
  GPUInstance,
  GPUProvider,
  GPUProvisionConfig,
  GPUType,
} from "./providers.js";
import { RunPodProvider } from "./runpod.js";
import { VastProvider } from "./vast.js";
import { SpheronProvider } from "./spheron.js";
import { AkashProvider } from "./akash.js";
import { assertSafeFetchUrlAsync } from "../utils/url-guard.js";

export interface ExternalGPUProviderManifest {
  schemaVersion: "1.0";
  id: string;
  name: string;
  endpoint: string;
  authHeader: string;
  authScheme?: "Bearer" | "Raw" | "ApiKey";
  authEnvVar: string;
  /** ISO-3166 alpha-2 or regional residency codes (e.g. ["IN", "EU", "US", "SG"]) */
  jurisdictions: string[];
  catalogPath: string;
  provisionPath: string;
  statusPath: string;
  logsPath: string;
  destroyPath: string;
  slaUrl?: string;
  contactEmail?: string;
  soc2Certified?: boolean;
  iso27001Certified?: boolean;
  dpdpCompliant?: boolean;
  gdprCompliant?: boolean;
}

export interface ProviderMetadata {
  id: string;
  name: string;
  builtin: boolean;
  jurisdictions: string[];
  endpoint?: string;
  authEnvVar: string;
  configured: boolean;
}

export interface ManifestValidationResult {
  valid: boolean;
  errors: string[];
  manifest?: ExternalGPUProviderManifest;
}

export interface CertificationCheck {
  id: string;
  passed: boolean;
  detail: string;
}

export interface ProviderCertificationReport {
  providerId: string;
  certified: boolean;
  checks: CertificationCheck[];
  liveProbeSkipped: boolean;
}

export const BUILTIN_PROVIDER_META: Record<
  string,
  { name: string; jurisdictions: string[]; authEnvVar: string }
> = {
  runpod: { name: "RunPod", jurisdictions: ["US", "EU", "CA"], authEnvVar: "RUNPOD_API_KEY" },
  vast: { name: "Vast.ai", jurisdictions: ["US", "EU", "APAC"], authEnvVar: "VAST_API_KEY" },
  spheron: { name: "Spheron Network", jurisdictions: ["US", "EU", "IN", "SG"], authEnvVar: "SPHERON_API_KEY" },
  akash: { name: "Akash Network", jurisdictions: ["US", "EU", "GLOBAL"], authEnvVar: "AKASH_RPC_URL" },
};

const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,47}$/;
const ENV_VAR_RE = /^[A-Z][A-Z0-9_]{2,63}$/;
const JURISDICTION_RE = /^[A-Z]{2,8}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function defaultCustomProvidersPath(): string {
  return join(homedir(), ".dirgha", "gpu-providers.json");
}

/**
 * Strictly validate an external GPU cloud provider submission manifest.
 */
export function validateProviderManifest(raw: unknown): ManifestValidationResult {
  const errors: string[] = [];
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { valid: false, errors: ["Manifest must be a JSON object"] };
  }
  const obj = raw as Record<string, unknown>;

  if (obj.schemaVersion !== "1.0") {
    errors.push('schemaVersion must be "1.0"');
  }
  if (typeof obj.id !== "string" || !SLUG_RE.test(obj.id)) {
    errors.push("id must be a lowercase slug (2-48 chars: a-z, 0-9, '-')");
  } else if (obj.id in BUILTIN_PROVIDER_META) {
    errors.push(`id "${obj.id}" conflicts with a built-in provider`);
  }
  if (typeof obj.name !== "string" || obj.name.trim().length < 2) {
    errors.push("name must be a non-empty string (at least 2 chars)");
  }
  if (typeof obj.endpoint !== "string") {
    errors.push("endpoint must be a valid https:// URL");
  } else {
    try {
      const parsed = new URL(obj.endpoint);
      if (parsed.protocol !== "https:") {
        errors.push("endpoint must use https:// (plaintext http:// is rejected)");
      }
    } catch {
      errors.push("endpoint is not a valid URL");
    }
  }
  if (typeof obj.authHeader !== "string" || !/^[A-Za-z0-9-]+$/.test(obj.authHeader)) {
    errors.push("authHeader must be a valid HTTP header name (e.g. Authorization or X-API-Key)");
  }
  if (
    obj.authScheme !== undefined &&
    obj.authScheme !== "Bearer" &&
    obj.authScheme !== "Raw" &&
    obj.authScheme !== "ApiKey"
  ) {
    errors.push('authScheme must be one of "Bearer" | "Raw" | "ApiKey"');
  }
  if (typeof obj.authEnvVar !== "string" || !ENV_VAR_RE.test(obj.authEnvVar)) {
    errors.push("authEnvVar must be an uppercase environment variable name (e.g. MYCLOUD_API_KEY)");
  }
  if (!Array.isArray(obj.jurisdictions) || obj.jurisdictions.length === 0) {
    errors.push("jurisdictions must be a non-empty array of ISO/region codes (e.g. [\"IN\", \"EU\"])");
  } else {
    for (const j of obj.jurisdictions) {
      if (typeof j !== "string" || !JURISDICTION_RE.test(j.toUpperCase())) {
        errors.push(`Invalid jurisdiction code: ${String(j)}`);
      }
    }
  }
  for (const pathField of [
    "catalogPath",
    "provisionPath",
    "statusPath",
    "logsPath",
    "destroyPath",
  ] as const) {
    const val = obj[pathField];
    if (typeof val !== "string" || !val.startsWith("/")) {
      errors.push(`${pathField} must be a path string starting with "/"`);
    }
  }
  if (obj.contactEmail !== undefined) {
    if (typeof obj.contactEmail !== "string" || !EMAIL_RE.test(obj.contactEmail)) {
      errors.push("contactEmail must be a valid email address");
    }
  }
  if (obj.slaUrl !== undefined) {
    try {
      const u = new URL(String(obj.slaUrl));
      if (u.protocol !== "https:") errors.push("slaUrl must use https://");
    } catch {
      errors.push("slaUrl must be a valid URL");
    }
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  const manifest: ExternalGPUProviderManifest = {
    schemaVersion: "1.0",
    id: String(obj.id),
    name: String(obj.name).trim(),
    endpoint: String(obj.endpoint).replace(/\/+$/, ""),
    authHeader: String(obj.authHeader),
    authScheme: (obj.authScheme as ExternalGPUProviderManifest["authScheme"]) ?? "Bearer",
    authEnvVar: String(obj.authEnvVar),
    jurisdictions: (obj.jurisdictions as string[]).map((j) => j.toUpperCase()),
    catalogPath: String(obj.catalogPath),
    provisionPath: String(obj.provisionPath),
    statusPath: String(obj.statusPath),
    logsPath: String(obj.logsPath),
    destroyPath: String(obj.destroyPath),
    ...(obj.slaUrl ? { slaUrl: String(obj.slaUrl) } : {}),
    ...(obj.contactEmail ? { contactEmail: String(obj.contactEmail) } : {}),
    ...(typeof obj.soc2Certified === "boolean" ? { soc2Certified: obj.soc2Certified } : {}),
    ...(typeof obj.iso27001Certified === "boolean" ? { iso27001Certified: obj.iso27001Certified } : {}),
    ...(typeof obj.dpdpCompliant === "boolean" ? { dpdpCompliant: obj.dpdpCompliant } : {}),
    ...(typeof obj.gdprCompliant === "boolean" ? { gdprCompliant: obj.gdprCompliant } : {}),
  };
  return { valid: true, errors: [], manifest };
}

/**
 * Certify an external GPU cloud provider manifest before accepting it into the market.
 * Runs schema validation, SSRF/DNS public-IP verification, and optional live catalog probe.
 */
export async function certifyProviderManifest(
  raw: unknown,
  opts?: {
    probeLive?: boolean;
    skipDns?: boolean;
    lookupFn?: (hostname: string) => Promise<Array<{ address: string; family: number }>>;
    fetchFn?: typeof fetch;
  },
): Promise<ProviderCertificationReport> {
  const checks: CertificationCheck[] = [];
  const validation = validateProviderManifest(raw);
  checks.push({
    id: "schema_validation",
    passed: validation.valid,
    detail: validation.valid
      ? "Manifest conforms to Dirgha GPU Provider Schema v1.0"
      : validation.errors.join("; "),
  });

  if (!validation.valid || !validation.manifest) {
    return {
      providerId: typeof (raw as Record<string, unknown>)?.id === "string"
        ? String((raw as Record<string, unknown>).id)
        : "unknown",
      certified: false,
      checks,
      liveProbeSkipped: true,
    };
  }

  const manifest = validation.manifest;

  // Endpoint SSRF / private network check
  if (opts?.skipDns) {
    const parsed = new URL(manifest.endpoint);
    const host = parsed.hostname.toLowerCase();
    const obviouslyPrivate =
      host === "localhost" ||
      host.endsWith(".localhost") ||
      host.startsWith("127.") ||
      host.startsWith("10.") ||
      host.startsWith("169.254.") ||
      host === "::1" ||
      host === "[::1]";
    checks.push({
      id: "endpoint_ssrf_guard",
      passed: !obviouslyPrivate,
      detail: obviouslyPrivate
        ? `Refused private/loopback endpoint host: ${host}`
        : `Public HTTPS endpoint verified (offline check): ${manifest.endpoint}`,
    });
  } else {
    try {
      await assertSafeFetchUrlAsync(manifest.endpoint, {
        lookupFn: opts?.lookupFn,
      });
      checks.push({
        id: "endpoint_ssrf_guard",
        passed: true,
        detail: `Endpoint ${manifest.endpoint} resolved to public non-internal address`,
      });
    } catch (err) {
      checks.push({
        id: "endpoint_ssrf_guard",
        passed: false,
        detail: err instanceof Error ? err.message : String(err),
      });
    }
  }

  // Jurisdiction tagging check
  checks.push({
    id: "residency_jurisdictions",
    passed: manifest.jurisdictions.length > 0,
    detail: `Declared jurisdictions: ${manifest.jurisdictions.join(", ")}`,
  });

  // Optional live catalog probe
  let liveProbeSkipped = true;
  if (opts?.probeLive && checks.every((c) => c.passed)) {
    liveProbeSkipped = false;
    try {
      const adapter = new HttpGPUProvider(manifest, {
        fetchFn: opts.fetchFn,
        lookupFn: opts.lookupFn,
      });
      const gpus = await adapter.listGPUTypes();
      checks.push({
        id: "live_catalog_probe",
        passed: Array.isArray(gpus),
        detail: `Live catalog probe succeeded (${gpus.length} GPU SKU(s) returned)`,
      });
    } catch (err) {
      checks.push({
        id: "live_catalog_probe",
        passed: false,
        detail: `Live catalog probe failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  return {
    providerId: manifest.id,
    certified: checks.every((c) => c.passed),
    checks,
    liveProbeSkipped,
  };
}

/**
 * Standard HTTP adapter for any certified third-party GPU cloud provider.
 */
export class HttpGPUProvider implements GPUProvider {
  readonly name: string;
  readonly manifest: ExternalGPUProviderManifest;
  private readonly fetchFn: typeof fetch;
  private readonly lookupFn?: (hostname: string) => Promise<Array<{ address: string; family: number }>>;

  constructor(
    manifest: ExternalGPUProviderManifest,
    opts?: {
      fetchFn?: typeof fetch;
      lookupFn?: (hostname: string) => Promise<Array<{ address: string; family: number }>>;
    },
  ) {
    this.manifest = manifest;
    this.name = manifest.id;
    this.fetchFn = opts?.fetchFn ?? globalThis.fetch;
    this.lookupFn = opts?.lookupFn;
  }

  private headers(): Record<string, string> {
    const out: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    const token = process.env[this.manifest.authEnvVar];
    if (token && token.trim().length > 0) {
      if (this.manifest.authScheme === "Raw") {
        out[this.manifest.authHeader] = token.trim();
      } else if (this.manifest.authScheme === "ApiKey") {
        out[this.manifest.authHeader] = `ApiKey ${token.trim()}`;
      } else {
        out[this.manifest.authHeader] = `Bearer ${token.trim()}`;
      }
    }
    return out;
  }

  private async requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
    const url = `${this.manifest.endpoint}${path}`;
    await assertSafeFetchUrlAsync(url, { lookupFn: this.lookupFn });
    const resp = await this.fetchFn(url, {
      ...init,
      headers: {
        ...this.headers(),
        ...((init.headers as Record<string, string> | undefined) ?? {}),
      },
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new Error(
        `GPU provider "${this.name}" HTTP ${resp.status}: ${text.slice(0, 200)}`,
      );
    }
    return (await resp.json()) as T;
  }

  async listGPUTypes(): Promise<GPUType[]> {
    const data = await this.requestJson<unknown>(this.manifest.catalogPath, {
      method: "GET",
    });
    const list = Array.isArray(data)
      ? data
      : Array.isArray((data as Record<string, unknown>)?.gpus)
        ? ((data as Record<string, unknown>).gpus as unknown[])
        : [];
    return list.map((item) => {
      const r = item as Record<string, unknown>;
      return {
        id: String(r.id ?? r.sku ?? "unknown"),
        name: String(r.name ?? r.id ?? "GPU"),
        vramGb: Number(r.vramGb ?? r.vram_gb ?? 0),
        costPerHr: Number(r.costPerHr ?? r.cost_per_hr ?? 0),
        provider: this.name,
        region: typeof r.region === "string"
          ? r.region
          : this.manifest.jurisdictions[0],
        available: r.available !== false,
      };
    });
  }

  async provision(config: GPUProvisionConfig): Promise<GPUInstance> {
    if (!process.env[this.manifest.authEnvVar]) {
      throw new Error(
        `Provider "${this.name}" requires ${this.manifest.authEnvVar} to provision instances`,
      );
    }
    const raw = await this.requestJson<Record<string, unknown>>(
      this.manifest.provisionPath,
      {
        method: "POST",
        body: JSON.stringify(config),
      },
    );
    return {
      id: String(raw.id ?? raw.instanceId ?? "unknown"),
      provider: this.name,
      gpuType: String(raw.gpuType ?? config.gpuType),
      status: (raw.status as GPUInstance["status"]) ?? "provisioning",
      costPerHr: Number(raw.costPerHr ?? 0),
      totalCost: Number(raw.totalCost ?? 0),
      startedAt: String(raw.startedAt ?? new Date().toISOString()),
      ...(typeof raw.ipAddress === "string" ? { ipAddress: raw.ipAddress } : {}),
      ...(typeof raw.sshCommand === "string" ? { sshCommand: raw.sshCommand } : {}),
    };
  }

  async getStatus(instanceId: string): Promise<GPUInstance> {
    const path = this.manifest.statusPath.replace("{id}", encodeURIComponent(instanceId));
    const raw = await this.requestJson<Record<string, unknown>>(path, {
      method: "GET",
    });
    return {
      id: String(raw.id ?? instanceId),
      provider: this.name,
      gpuType: String(raw.gpuType ?? "unknown"),
      status: (raw.status as GPUInstance["status"]) ?? "running",
      costPerHr: Number(raw.costPerHr ?? 0),
      totalCost: Number(raw.totalCost ?? 0),
      startedAt: String(raw.startedAt ?? new Date().toISOString()),
      ...(typeof raw.ipAddress === "string" ? { ipAddress: raw.ipAddress } : {}),
      ...(typeof raw.sshCommand === "string" ? { sshCommand: raw.sshCommand } : {}),
    };
  }

  async getLogs(instanceId: string): Promise<string> {
    const path = this.manifest.logsPath.replace("{id}", encodeURIComponent(instanceId));
    const url = `${this.manifest.endpoint}${path}`;
    await assertSafeFetchUrlAsync(url, { lookupFn: this.lookupFn });
    const resp = await this.fetchFn(url, { method: "GET", headers: this.headers() });
    if (!resp.ok) {
      throw new Error(`GPU provider "${this.name}" logs HTTP ${resp.status}`);
    }
    return resp.text();
  }

  async destroy(instanceId: string): Promise<void> {
    const path = this.manifest.destroyPath.replace("{id}", encodeURIComponent(instanceId));
    await this.requestJson<unknown>(path, { method: "DELETE" });
  }

  async estimateCost(gpuType: string, hours: number): Promise<number> {
    const gpus = await this.listGPUTypes();
    const match = gpus.find(
      (g) =>
        g.id.toLowerCase() === gpuType.toLowerCase() ||
        g.name.toLowerCase().includes(gpuType.toLowerCase()),
    );
    const rate = match?.costPerHr ?? 0;
    return Number((rate * hours).toFixed(4));
  }
}

// ── Custom Provider Registry (~/.dirgha/gpu-providers.json) ──────────────────

export function loadCustomProviders(
  registryPath: string = defaultCustomProvidersPath(),
): ExternalGPUProviderManifest[] {
  if (!existsSync(registryPath)) return [];
  try {
    const raw = JSON.parse(readFileSync(registryPath, "utf8")) as unknown;
    if (!Array.isArray(raw)) return [];
    const valid: ExternalGPUProviderManifest[] = [];
    for (const entry of raw) {
      const res = validateProviderManifest(entry);
      if (res.valid && res.manifest) valid.push(res.manifest);
    }
    return valid;
  } catch {
    return [];
  }
}

export function registerCustomProvider(
  manifest: ExternalGPUProviderManifest,
  registryPath: string = defaultCustomProvidersPath(),
): ExternalGPUProviderManifest[] {
  const existing = loadCustomProviders(registryPath).filter((p) => p.id !== manifest.id);
  const updated = [...existing, manifest];
  const dir = dirname(registryPath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(registryPath, JSON.stringify(updated, null, 2), "utf8");
  return updated;
}

export function removeCustomProvider(
  providerId: string,
  registryPath: string = defaultCustomProvidersPath(),
): boolean {
  const existing = loadCustomProviders(registryPath);
  const filtered = existing.filter((p) => p.id !== providerId);
  if (filtered.length === existing.length) return false;
  const dir = dirname(registryPath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(registryPath, JSON.stringify(filtered, null, 2), "utf8");
  return true;
}

export function listProviderMetadata(
  registryPath: string = defaultCustomProvidersPath(),
  env: NodeJS.ProcessEnv = process.env,
): ProviderMetadata[] {
  const builtins: ProviderMetadata[] = Object.entries(BUILTIN_PROVIDER_META).map(
    ([id, meta]) => ({
      id,
      name: meta.name,
      builtin: true,
      jurisdictions: meta.jurisdictions,
      authEnvVar: meta.authEnvVar,
      configured: Boolean(env[meta.authEnvVar]?.trim()),
    }),
  );
  const customs: ProviderMetadata[] = loadCustomProviders(registryPath).map((m) => ({
    id: m.id,
    name: m.name,
    builtin: false,
    jurisdictions: m.jurisdictions,
    endpoint: m.endpoint,
    authEnvVar: m.authEnvVar,
    configured: Boolean(env[m.authEnvVar]?.trim()),
  }));
  return [...builtins, ...customs];
}

export function getAllGPUProviders(
  registryPath: string = defaultCustomProvidersPath(),
  opts?: { allowedJurisdictions?: string[] },
): GPUProvider[] {
  const allowed = opts?.allowedJurisdictions?.map((j) => j.toUpperCase());
  const matchesJurisdiction = (jurisdictions: string[]): boolean => {
    if (!allowed || allowed.length === 0) return true;
    return jurisdictions.some((j) => allowed.includes(j.toUpperCase()));
  };

  const providers: GPUProvider[] = [];
  if (matchesJurisdiction(BUILTIN_PROVIDER_META.runpod.jurisdictions)) {
    providers.push(new RunPodProvider());
  }
  if (matchesJurisdiction(BUILTIN_PROVIDER_META.vast.jurisdictions)) {
    providers.push(new VastProvider());
  }
  if (matchesJurisdiction(BUILTIN_PROVIDER_META.spheron.jurisdictions)) {
    providers.push(new SpheronProvider());
  }
  if (matchesJurisdiction(BUILTIN_PROVIDER_META.akash.jurisdictions)) {
    providers.push(new AkashProvider());
  }
  for (const manifest of loadCustomProviders(registryPath)) {
    if (matchesJurisdiction(manifest.jurisdictions)) {
      providers.push(new HttpGPUProvider(manifest));
    }
  }
  return providers;
}

# Dirgha Open GPU Cloud Market

Dirgha 2.0 ships an open, multi-cloud GPU infrastructure marketplace that lets solo developers, robotics labs, and enterprises compare pricing and provision GPUs across built-in providers (**RunPod**, **Vast.ai**, **Spheron**, **Akash**) and **any third-party GPU cloud provider** that submits a standard provider manifest.

When LOKAHI governance is enabled (`--profile=team|enterprise|robotics`), GPU provisioning automatically enforces **data residency jurisdictions** (e.g. `IN`, `EU`, `US`) and **hard USD spend caps**. Solo developers on the default `developer` profile use the GPU market with zero governance friction.

---

## Quick Start

```bash
# List all built-in + registered partner GPU clouds
dirgha gpu providers

# Compare live GPU SKUs sorted by $/hr (optionally filtered by residency)
dirgha gpu list
dirgha gpu list --jurisdiction=EU

# Set a hard USD budget cap
dirgha gpu budget 50

# Track active and historical GPU jobs
dirgha gpu jobs
```

Inside an agent session, Dirgha exposes the `gpu_compute` tool (`list`, `providers`, `estimate`, `provision`, `status`, `stop`, `budget`).

---

## Partner Onboarding: Submit Your GPU Cloud

Any neo-cloud, sovereign regional cloud, or private enterprise GPU cluster can plug into Dirgha without waiting for a core release.

### 1. Create a Provider Manifest (`mycloud-gpu.json`)

Conform to [`specs/GPU_PROVIDER_SCHEMA.json`](../specs/GPU_PROVIDER_SCHEMA.json):

```json
{
  "schemaVersion": "1.0",
  "id": "sovereign-in-cloud",
  "name": "Sovereign India GPU Cloud",
  "endpoint": "https://api.example-gpu-cloud.in",
  "authHeader": "Authorization",
  "authScheme": "Bearer",
  "authEnvVar": "SOVEREIGN_IN_GPU_API_KEY",
  "jurisdictions": ["IN"],
  "catalogPath": "/v1/gpus",
  "provisionPath": "/v1/instances",
  "statusPath": "/v1/instances/{id}",
  "logsPath": "/v1/instances/{id}/logs",
  "destroyPath": "/v1/instances/{id}",
  "slaUrl": "https://example-gpu-cloud.in/sla",
  "contactEmail": "partners@example-gpu-cloud.in",
  "iso27001Certified": true,
  "dpdpCompliant": true
}
```

### 2. Required HTTP API Contract

| Method | Path | Response Shape |
|---|---|---|
| `GET` | `catalogPath` | `{ "gpus": [{ "id": "h100-sxm", "name": "NVIDIA H100 80GB", "vramGb": 80, "costPerHr": 1.65, "region": "IN-BOM", "available": true }] }` |
| `POST` | `provisionPath` | Accepts `{ gpuType, imageName, containerDiskGb, startSsh }`, returns `{ id, gpuType, status, costPerHr, totalCost, startedAt, sshCommand }` |
| `GET` | `statusPath` | Returns `{ id, gpuType, status, costPerHr, totalCost, startedAt, ipAddress }` |
| `GET` | `logsPath` | Returns `text/plain` container stdout/stderr |
| `DELETE` | `destroyPath` | Returns `200 OK` JSON confirmation |

### 3. Certify and Register

```bash
# Dry-run schema + HTTPS + SSRF/DNS public-IP certification
dirgha gpu certify ./mycloud-gpu.json

# Include a live catalog probe
dirgha gpu certify ./mycloud-gpu.json --live

# Certify and register locally (~/.dirgha/gpu-providers.json)
dirgha gpu submit ./mycloud-gpu.json
```

### Security & Enterprise Governance Guarantees

- **SSRF Protection:** Every submitted endpoint is validated via DNS resolution against private, loopback, link-local, CGNAT, and cloud metadata IP ranges (IPv4 and IPv6) before registration and before every runtime request.
- **BYOK Credentials:** Manifests NEVER contain API keys—only the environment variable name (`authEnvVar`) read at runtime.
- **LOKAHI Residency & Spend Lock:** Enterprises can pin `allowedJurisdictions` and `maxGpuBudgetUsd` inside `/etc/dirgha/policy.json` so agents can only provision GPUs inside approved sovereign regions and budget ceilings.

# Dirgha 2.0 Enterprise Stack — Kubernetes Operator Guide

Production-hardened Kubernetes manifests complementing `docker-compose.private-stack.yml` for Amazon EKS, Google GKE, Azure AKS, and air-gapped on-premises clusters.

## Security Posture Included Out of the Box

- **Pod Security Standards (`restricted`)**: enforced at the `dirgha-enterprise` namespace level.
- **Immutable Organization Policy Lock**: `/etc/dirgha/policy.json` is mounted read-only (`0444`) from the `dirgha-org-policy` ConfigMap; attempts to pass `--no-lokahi` or `--no-arniko` fail closed.
- **Container Hardening**: `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `RuntimeDefault` seccomp profile, `automountServiceAccountToken: false`.
- **Zero Hardcoded Secrets**: provider keys are injected via an out-of-band Kubernetes Secret (`dirgha-provider-secrets`) or External Secrets Operator / HashiCorp Vault.

## Quick Deploy

```bash
# 1. Create namespace and secret out of band (never commit secret YAML to Git)
kubectl create namespace dirgha-enterprise --dry-run=client -o yaml | kubectl apply -f -
kubectl -n dirgha-enterprise create secret generic dirgha-provider-secrets \
  --from-literal=OPENAI_API_KEY="replace-me" \
  --from-literal=RUNPOD_API_KEY="replace-me"

# 2. Customize allowed jurisdictions / budget in deploy/k8s/dirgha-enterprise.yaml, then apply
kubectl apply -f deploy/k8s/dirgha-enterprise.yaml

# 3. Verify health and policy lock status
kubectl -n dirgha-enterprise rollout status deployment/dirgha-control-plane
kubectl -n dirgha-enterprise port-forward svc/dirgha-control-plane 3000:80
curl -s http://localhost:3000/api/policy/status | jq .
```

## Signing & Mounting a LOKAHI Boundary Manifest

```bash
# Generate Ed25519 keypair and signed manifest locally or in your HSM/KMS pipeline
dirgha policy keygen --out ./keys
dirgha policy init --profile enterprise --out ./lokahi-manifest.json
dirgha policy sign --manifest ./lokahi-manifest.json --key ./keys/lokahi-private.pem

# Store the signed manifest + public key in a ConfigMap (NEVER store private.pem in the cluster)
kubectl -n dirgha-enterprise create configmap dirgha-lokahi-manifest \
  --from-file=lokahi-manifest.json=./lokahi-manifest.json \
  --from-file=lokahi-public.pem=./keys/lokahi-public.pem
```

Point `manifestPath` and `publicKeyPath` inside `dirgha-org-policy`'s `policy.json` to the mounted read-only ConfigMap paths.

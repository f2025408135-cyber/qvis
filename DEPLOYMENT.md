# Production Deployment Runbook

## Distroless Architecture
QVis ships via a multi-stage Docker build utilizing `python:3.12-slim`. To limit exploitation avenues, the container strips root privileges globally, enforcing a `qvisuser:qvisgroup` policy boundary with zero ambient capabilities.

## Kubernetes Configurations

The deployment ships with 4 default manifests located in `/k8s/`:

1. `network-policy.yaml`: An explicit allowlist dropping all intra-pod egress capabilities not mapped exactly to Port 5432 (Postgres), Port 6379 (Redis), Port 443 (Cloud Egress) and denying any ingress aside from `ingress-nginx`. 
2. `deployment.yaml`: Defines `livenessProbe` and `readinessProbe` bindings mapped explicitly to QVis's HTTP 200 state machines.
3. `service.yaml`: Local networking translation.
4. `ingress.yaml`: Proxy layer supporting raw websockets.

**Warning:** Prior to applying any manifests, you must establish the `qvis-secrets` vault storing production parameters:
```bash
kubectl create secret generic qvis-secrets \
  --from-literal=database_url=postgresql://... \
  --from-literal=redis_url=redis://... \
  --from-literal=jwt_secret=... \
  --from-literal=encryption_key=... \
  --from-literal=encryption_salt=...
```

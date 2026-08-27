#!/usr/bin/env bash
# Build and deploy NekoGuard to k3s.
# Handles the k3s containerd image import that `docker build` alone misses.
set -euo pipefail

IMAGE="nekoguard:latest"

echo "==> Building Docker image..."
docker build --no-cache -t "$IMAGE" .

echo "==> Importing into k3s containerd..."
docker save "$IMAGE" | k3s ctr images import -

echo "==> Restarting deployments..."
kubectl rollout restart deployment/nekoguard-certd -n nekoguard
kubectl rollout restart deployment/nekoguard -n nekoguard 2>/dev/null || true

echo "==> Waiting for pods..."
kubectl get pods -n nekoguard -w

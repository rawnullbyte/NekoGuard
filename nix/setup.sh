#!/bin/bash
# NekoGuard deployment: k3s + Dashboard (NodePort, no MetalLB)
# Run this on a fresh NixOS machine after applying configuration.nix
set -euo pipefail

echo "=== Step 1: Wait for k3s to be ready ==="
until kubectl get nodes | grep -q " Ready"; do
    echo "Waiting for k3s..."
    sleep 5
done
echo "k3s is ready"

echo "=== Step 2: Deploy NekoGuard ==="
kubectl create namespace nekoguard 2>/dev/null || true
kubectl apply -f k8s/secret.yaml    # Replace with real credentials first
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/certd.yaml
kubectl apply -f k8s/nekoguard.yaml
kubectl wait --for=condition=Ready pod -l app=nekoguard -n nekoguard --timeout=120s
echo "NekoGuard deployed"

echo "=== Step 3: Deploy Dashboard ==="
kubectl apply -f nix/dashboard.yaml
echo "Dashboard deployed"

echo "=== Step 4: Print status ==="
kubectl get pods -A
echo ""
echo "NekoGuard: https://<NODE_IP>:30443"
echo "Dashboard: https://<NODE_IP>:30443"
echo ""
echo "=== Done ==="

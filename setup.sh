#!/bin/bash
# NekoGuard deployment: k3s + Dashboard (single-node)
# Run on the server after k3s is installed
set -euo pipefail

echo "=== Step 1: Wait for k3s ==="
until kubectl get nodes 2>/dev/null | grep -q " Ready"; do
    echo "Waiting for k3s..."
    sleep 5
done
echo "k3s ready"

echo "=== Step 2: Deploy NekoGuard ==="
# Edit nekoguard.toml with your real domains and credentials first!
# Place it at /etc/nekoguard/nekoguard.toml on this server
cp nekoguard.toml /etc/nekoguard/nekoguard.toml

kubectl create namespace nekoguard 2>/dev/null || true
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/certd.yaml
kubectl apply -f k8s/nekoguard.yaml
kubectl wait --for=condition=Ready pod -l app=nekoguard -n nekoguard --timeout=120s
kubectl wait --for=condition=Ready pod -l app=nekoguard-certd -n nekoguard --timeout=120s
echo "NekoGuard deployed"

echo "=== Step 3: Dashboard ==="
kubectl apply -f k8s/dashboard.yaml
echo "Dashboard deployed"

echo "=== Done ==="
kubectl get pods -A
echo ""
echo "NekoGuard: https://<NODE_IP>:30443"
echo "Dashboard: https://<NODE_IP>:30443"

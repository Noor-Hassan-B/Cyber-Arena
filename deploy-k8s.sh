#!/usr/bin/env bash
# =========================================================================
# AegisHunt - Kubernetes (K8s) Deployment Script (Bash)
# =========================================================================
set -e

echo "=== Deploying AegisHunt to Kubernetes Cluster ==="

# 1. Build local container images
echo "[1/3] Building local container images..."
docker build -t aegishunt-frontend:latest ./frontend-react
docker build -t aegishunt-backend:latest ./backend-php

# 2. Deploy to K8s using Kustomize
echo "[2/3] Applying Kubernetes manifests in namespace 'threat-hunting'..."
kubectl apply -k ./k8s

# 3. Monitor rollout status
echo "[3/3] Checking pod deployment status..."
kubectl rollout status deployment/mysql -n threat-hunting
kubectl rollout status deployment/backend -n threat-hunting
kubectl rollout status deployment/frontend -n threat-hunting

echo ""
echo "[✓] AegisHunt is deployed to Kubernetes!"
echo "Services in namespace 'threat-hunting':"
kubectl get svc -n threat-hunting

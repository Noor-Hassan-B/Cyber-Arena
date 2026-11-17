# =========================================================================
# AegisHunt - Kubernetes (K8s) Deployment Script (PowerShell)
# =========================================================================

Write-Host "=== Deploying AegisHunt to Kubernetes Cluster ===" -ForegroundColor Cyan

# 1. Build local container images
Write-Host "`n[1/3] Building local container images..." -ForegroundColor Yellow
docker build -t aegishunt-frontend:latest ./frontend-react
docker build -t aegishunt-backend:latest ./backend-php

# 2. Deploy to K8s using Kustomize
Write-Host "`n[2/3] Applying Kubernetes manifests in namespace 'threat-hunting'..." -ForegroundColor Yellow
kubectl apply -k ./k8s

# 3. Wait for Pods to be ready
Write-Host "`n[3/3] Checking pod deployment status..." -ForegroundColor Yellow
kubectl get pods -n threat-hunting -w

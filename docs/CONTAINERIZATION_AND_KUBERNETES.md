# Cloud-Native Containerization & Kubernetes Deployment Guide

This document details the Docker containerization architecture and Kubernetes orchestration specifications for **AegisHunt**.

---

## 1. Cloud-Native Topology Overview

```
                                  KUBERNETES CLUSTER (Namespace: threat-hunting)
                                
                  +--------------------------------------------------------------+
                  |                 Ingress Controller (NGINX)                   |
                  |                aegishunt.local (Port 80/443)                 |
                  +------------------------------+-------------------------------+
                                                 |
                       +-------------------------+-------------------------+
                       | / (UI Traffic)                                    | /api (REST Traffic)
                       v                                                   v
        +------------------------------+                    +------------------------------+
        |   Frontend Service (NodePort) |                    |    Backend Service (ClusterIP)|
        +--------------+---------------+                    +--------------+---------------+
                       |                                                   |
         +-------------+-------------+                       +-------------+-------------+
         |                           |                       |                           |
         v                           v                       v                           v
  +--------------+            +--------------+        +--------------+            +--------------+
  | Frontend Pod |            | Frontend Pod |        | Backend Pod  |            | Backend Pod  |
  | (React+Nginx)|            | (React+Nginx)|        | (PHP 8.2 API)|            | (PHP 8.2 API)|
  +--------------+            +--------------+        +--------------+            +--------------+
         ^                           ^                       ^                           ^
         +-------------+-------------+                       +-------------+-------------+
                       |                                                   |
              (HPA Autoscaling:                                   (HPA Autoscaling:
                 2 - 8 Pods)                                         2 - 10 Pods)
                                                                           |
                                                                           v
                                                            +------------------------------+
                                                            |    MySQL Service (ClusterIP) |
                                                            |          (Port 3306)         |
                                                            +--------------+---------------+
                                                                           |
                                                                           v
                                                            +------------------------------+
                                                            |    MySQL 8.0 Telemetry Pod   |
                                                            |  + PersistentVolumeClaim     |
                                                            |    (10Gi NVMe / SSD Block)   |
                                                            +------------------------------+
```

---

## 2. Docker Architecture & Optimization

### Frontend Multi-Stage Dockerfile (`frontend-react/Dockerfile`)
- **Build Stage (`node:20-alpine`):** Compiles the React + Vite JSX application into a static bundle with zero development dependencies in the final image.
- **Production Stage (`nginx:1.27-alpine`):** Final image is only ~25 MB.
- **Embedded Reverse Proxy:** Configured with `nginx.conf` to proxy `/api/` directly to `http://backend:80/api/` while handling client-side SPA routing (`try_files $uri /index.html`).

### Backend Dockerfile (`backend-php/Dockerfile`)
- **Runtime:** `php:8.2-apache-bullseye` with `pdo_mysql`, `opcache`, and `mod_rewrite`.
- **Automated Health Check & Seeder (`docker-entrypoint.sh`):** Probes the MySQL service until ready, runs database migrations from `seed.php`, and launches Apache.

### Full-Stack Docker Compose (`docker-compose.yml`)
Runs the 3-tier system with single-command deployment:
```bash
docker compose up -d --build
```
- **React Frontend:** `http://localhost:3000`
- **PHP API Backend:** `http://localhost:8000`
- **MySQL Database:** `localhost:3306`

---

## 3. Kubernetes (K8s) Architecture Specifications

All manifests reside in the [`k8s/`](file:///C:/Users/nh219/.gemini/antigravity/scratch/threat-hunter/k8s/) directory and adhere to Kubernetes 1.25+ standards.

### Manifest Components:

| File | Resource Kind | Purpose |
|---|---|---|
| `00-namespace.yaml` | `Namespace` | Creates isolated `threat-hunting` namespace. |
| `01-configmap.yaml` | `ConfigMap` | Non-sensitive configs: DB host (`mysql-service`), DB name, port. |
| `02-secrets.yaml` | `Secret` | Sensitive credentials: Root DB password and service user passwords. |
| `03-mysql-pvc.yaml` | `PersistentVolumeClaim` | 10Gi storage requesting `ReadWriteOnce` for telemetry logs. |
| `04-mysql-init-configmap.yaml` | `ConfigMap` | Mounts `01-schema.sql` and `02-seed.sql` into MySQL startup folder. |
| `05-mysql-deployment.yaml` | `Deployment` & `Service` | MySQL 8.0 pod with liveness/readiness probes and ClusterIP service. |
| `06-backend-deployment.yaml` | `Deployment` & `Service` | 2 replicas of PHP API with rolling update strategy & health checks. |
| `07-frontend-deployment.yaml` | `Deployment` & `Service` | 2 replicas of React Nginx frontend with LoadBalancer service. |
| `08-ingress.yaml` | `Ingress` | Ingress rules routing `/api` to backend and `/` to frontend. |
| `09-hpa.yaml` | `HorizontalPodAutoscaler` | Autoscales backend (2-10 pods) and frontend (2-8 pods) at 75% CPU. |
| `kustomization.yaml` | `Kustomization` | Unified deployment bundle. |

---

## 4. Deploying to Kubernetes

### Prerequisites
- Running Kubernetes cluster (Minikube, Kind, Docker Desktop K8s, EKS, GKE, or AKS).
- `kubectl` configured to your cluster.

### Single-Command Deployment via Kustomize:
```bash
# 1. Build and tag images locally
docker build -t aegishunt-frontend:latest ./frontend-react
docker build -t aegishunt-backend:latest ./backend-php

# 2. Deploy entire stack
kubectl apply -k ./k8s

# 3. Verify pods in threat-hunting namespace
kubectl get pods -n threat-hunting -w
```

### Inspect Services & Access Application:
```bash
kubectl get svc -n threat-hunting
```
If using Minikube:
```bash
minikube service frontend-service -n threat-hunting
```
If using Ingress on local cluster, add to `/etc/hosts` (or `C:\Windows\System32\drivers\etc\hosts`):
```
127.0.0.1  aegishunt.local
```
Then visit **`http://aegishunt.local`** in your browser.

---

## 5. High-Availability & Autoscaling Demonstration

To simulate high event ingestion load and test horizontal pod autoscaling:
```bash
# Generate simulated telemetry traffic
kubectl run -i --tty load-generator --rm --image=busybox -n threat-hunting --restart=Never -- /bin/sh -c "while true; do wget -q -O- http://backend-service/api/scenarios; done"

# Watch the HPA scale up backend replicas automatically
kubectl get hpa -n threat-hunting -w
```
The HPA will automatically trigger replica scale-up from 2 to up to 10 pods when CPU crosses the 75% threshold, ensuring zero dropped alerts during massive enterprise cyber incidents.

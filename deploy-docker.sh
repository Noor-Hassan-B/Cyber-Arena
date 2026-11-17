#!/usr/bin/env bash
# =========================================================================
# AegisHunt - Docker Deployment Script (Bash)
# =========================================================================
set -e

echo "=== Building and Launching AegisHunt with Docker Compose ==="

# Check if .env exists
if [ ! -f .env ]; then
    echo "[*] Creating .env from .env.example..."
    cp .env.example .env
fi

# Build and start containers
echo "[*] Executing: docker compose up -d --build"
docker compose up -d --build

echo ""
echo "[✓] AegisHunt is running successfully!"
echo "    - React Frontend:  http://localhost:3000"
echo "    - PHP API Backend: http://localhost:8000"
echo "    - MySQL Database:  localhost:3306"
echo ""
echo "To view logs: docker compose logs -f"
echo "To stop:      docker compose down"

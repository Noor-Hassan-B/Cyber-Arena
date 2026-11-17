# =========================================================================
# AegisHunt - Docker Deployment Script (PowerShell)
# =========================================================================

Write-Host "=== Building and Launching AegisHunt with Docker Compose ===" -ForegroundColor Cyan

# Check if .env exists, if not copy from .env.example
if (!(Test-Path -Path ".env")) {
    Write-Host "[*] Creating .env from .env.example..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
}

# Build and start containers in detached mode
Write-Host "[*] Executing: docker compose up -d --build" -ForegroundColor Cyan
docker compose up -d --build

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[✓] AegisHunt is running successfully!" -ForegroundColor Green
    Write-Host "    - React Frontend: http://localhost:3000" -ForegroundColor White
    Write-Host "    - PHP API Backend: http://localhost:8000" -ForegroundColor White
    Write-Host "    - MySQL Database: localhost:3306`n" -ForegroundColor White
    Write-Host "To view logs: docker compose logs -f" -ForegroundColor Gray
    Write-Host "To stop:      docker compose down" -ForegroundColor Gray
} else {
    Write-Host "`n[-] Failed to start Docker containers. Please ensure Docker Desktop is running." -ForegroundColor Red
}

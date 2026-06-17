# Pornire locala — backend + frontend (Windows)
# Usage: .\run-local.ps1

$Root = $PSScriptRoot
$ErrorActionPreference = "Stop"

Write-Host "NeoHost Security — mod local" -ForegroundColor Green
Write-Host ""

# Backend deps
$venv = "$Root\backend\.venv"
if (-not (Test-Path "$venv\Scripts\python.exe")) {
    Write-Host "[1/3] Creare venv Python..." -ForegroundColor Cyan
    python -m venv $venv
    & "$venv\Scripts\pip.exe" install -q -r "$Root\backend\requirements.txt"
} else {
    Write-Host "[1/3] venv OK" -ForegroundColor Cyan
}

# Frontend deps
if (-not (Test-Path "$Root\frontend\node_modules")) {
    Write-Host "[2/3] npm install..." -ForegroundColor Cyan
    Set-Location "$Root\frontend"
    npm install
    Set-Location $Root
} else {
    Write-Host "[2/3] node_modules OK" -ForegroundColor Cyan
}

Write-Host "[3/3] Pornire servicii..." -ForegroundColor Cyan
Write-Host ""
Write-Host "  Backend:  http://127.0.0.1:7654" -ForegroundColor Yellow
Write-Host "  Frontend: http://127.0.0.1:5173" -ForegroundColor Yellow
Write-Host "  Token:    schimba-acest-token-secret" -ForegroundColor Yellow
Write-Host ""
Write-Host "Oprire: Ctrl+C in fiecare fereastra" -ForegroundColor Gray

$env:SECURITY_API_TOKEN = "schimba-acest-token-secret"
$env:HOST = "127.0.0.1"
$env:PORT = "7654"
# Fara DATABASE_URL → SQLite local (neohost-dev.db)

Start-Process powershell -ArgumentList @(
    "-NoExit", "-Command",
    "cd '$Root\backend'; & '$venv\Scripts\python.exe' app.py"
)

Start-Sleep -Seconds 2

Set-Location "$Root\frontend"
npm run dev

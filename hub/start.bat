@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"

if not exist "node_modules" (
    echo npm install...
    call npm install
    if errorlevel 1 exit /b 1
)

set HOST=127.0.0.1
set PORT=7654
set SECURITY_API_TOKEN=schimba-acest-token-secret

node src/index.js

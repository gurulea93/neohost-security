@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"
set SECURITY_API_TOKEN=schimba-acest-token-secret
set HOST=127.0.0.1
set PORT=7654

echo Pornire backend NeoHost...
.venv\Scripts\python.exe -m pip install -q -r requirements.txt
if errorlevel 1 (
    echo EROARE: pip install a esuat.
    pause
    exit /b 1
)
.venv\Scripts\python.exe app.py

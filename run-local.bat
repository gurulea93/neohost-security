@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"

echo NeoHost Security - mod local
echo.

if not exist "backend\.venv\Scripts\python.exe" (
    echo [1/3] Creare venv Python...
    python -m venv backend\.venv
    if errorlevel 1 (
        echo EROARE: python nu este instalat sau nu este in PATH.
        pause
        exit /b 1
    )
)

echo [1/3] Instalare dependinte Python...
backend\.venv\Scripts\python.exe -m pip install -q --upgrade pip
backend\.venv\Scripts\pip.exe install -q -r backend\requirements.txt
if errorlevel 1 (
    echo EROARE: pip install a esuat.
    pause
    exit /b 1
)
echo [1/3] venv OK

if not exist "frontend\node_modules" (
    echo [2/3] npm install...
    cd frontend
    call npm install
    if errorlevel 1 (
        echo EROARE: npm install a esuat.
        pause
        exit /b 1
    )
    cd ..
) else (
    echo [2/3] node_modules OK
)

echo [3/3] Pornire servicii...
echo.

REM Elibereaza portul 7654 daca a ramas un backend vechi
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":7654" ^| findstr "LISTENING"') do (
    echo Oprire proces vechi pe port 7654 PID %%a...
    taskkill /F /PID %%a >nul 2>&1
)
timeout /t 1 /nobreak >nul

echo.
echo   Backend:  http://127.0.0.1:7654
echo   Frontend: http://127.0.0.1:5173
echo   Login:    admin / admin  (schimbati din Profil)
echo   Token:    schimba-acest-token-secret  (mod avansat)
echo   Telegram: set TELEGRAM_BOT_TOKEN in backend/.env (optional)
echo.
echo Oprire: inchideti ferestrele Backend si Frontend
echo.

set SECURITY_API_TOKEN=schimba-acest-token-secret
set HOST=127.0.0.1
set PORT=7654

start "NeoHost Backend" cmd /k "%~dp0backend\start.bat"

timeout /t 3 /nobreak >nul

cd frontend
call npm run dev

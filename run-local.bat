@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"

echo NeoHost Security - mod local (Node.js hub)
echo.

if not exist "hub\node_modules" (
    echo [1/3] npm install hub...
    cd hub
    call npm install
    if errorlevel 1 (
        echo EROARE: npm install hub a esuat.
        pause
        exit /b 1
    )
    cd ..
) else (
    echo [1/3] hub node_modules OK
)

if not exist "frontend\node_modules" (
    echo [2/3] npm install frontend...
    cd frontend
    call npm install
    if errorlevel 1 (
        echo EROARE: npm install frontend a esuat.
        pause
        exit /b 1
    )
    cd ..
) else (
    echo [2/3] frontend node_modules OK
)

echo [3/3] Pornire servicii...
echo.

for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":7654" ^| findstr "LISTENING"') do (
    echo Oprire proces vechi pe port 7654 PID %%a...
    taskkill /F /PID %%a >nul 2>&1
)
timeout /t 1 /nobreak >nul

echo.
echo   Hub API:  http://127.0.0.1:7654
echo   Frontend: http://127.0.0.1:5173
echo   Login:    admin / admin  (schimbati din Profil)
echo   Token:    schimba-acest-token-secret  (mod avansat)
echo.
echo   Agent Python: backend/agent.py (pe servere Linux, nu aici)
echo.
echo Oprire: inchideti ferestrele Hub si Frontend
echo.

set SECURITY_API_TOKEN=schimba-acest-token-secret
set HOST=127.0.0.1
set PORT=7654

start "NeoHost Hub" cmd /k "%~dp0hub\start.bat"

timeout /t 3 /nobreak >nul

cd frontend
call npm run dev

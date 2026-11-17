@echo off
title Unified DoS/DDoS Demo Launcher (Attacker + Server + Client)
cd /d "%~dp0"

echo [1/3] Starting isolated Docker Lab (target, attacker, client)...
docker compose up -d --build
if errorlevel 1 (
    echo [LOI] Hay kiem tra Docker Desktop da chay chua!
    pause
    exit /b 1
)
timeout /t 2 /nobreak >nul

echo [2/3] Starting Role Interfaces (:9001 Attacker, :9002 Server, :9003 Client)...
start "Unified-Demo-Command-Center" cmd /k "python unified_panel.py"
timeout /t 2 /nobreak >nul

echo [3/3] Opening 3 clean windows: Attacker (:9001), Server (:9002), Client (:9003)...
if exist "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" (
    start "" "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --app=http://127.0.0.1:9001 --window-size=470,700 --window-position=10,20
    start "" "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --app=http://127.0.0.1:9002 --window-size=680,700 --window-position=490,20
    start "" "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --app=http://127.0.0.1:9003 --window-size=470,700 --window-position=1180,20
) else (
    start http://127.0.0.1:9001/
    start http://127.0.0.1:9002/
    start http://127.0.0.1:9003/
)

echo.
echo ===================================================================
echo   DEMO READY!
echo   - Attacker : http://127.0.0.1:9001
echo   - Server   : http://127.0.0.1:9002  (Co nut Mo Wireshark Live)
echo   - Client   : http://127.0.0.1:9003
echo   - Tat tat  : STOP_UNIFIED_DEMO.bat
echo ===================================================================
pause

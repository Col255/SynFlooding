@echo off
cd /d "%~dp0"
echo Stopping Unified Demo...
docker exec doslab_u_attacker sh -c "pkill -f hping3 2>/dev/null || true; pkill -f slowloris_worker 2>/dev/null || true; iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || true" >nul 2>&1
taskkill /FI "WINDOWTITLE eq Unified-Demo-Command-Center*" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq Wireshark Live Capture*" /T /F >nul 2>&1
powershell -NoProfile -Command "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match 'unified_panel\.py' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>&1
docker compose down
echo Done!
timeout /t 2 >nul

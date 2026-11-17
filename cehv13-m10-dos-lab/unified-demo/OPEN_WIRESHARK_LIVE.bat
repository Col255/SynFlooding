@echo off
cd /d "%~dp0"
title Wireshark Live Capture - doslab_u_target (eth0 port 80)

docker inspect -f "{{.State.Running}}" doslab_u_target 2>nul | findstr /i "true" >nul
if errorlevel 1 (
    echo [LOI] Container doslab_u_target chua chay!
    echo Hay mo START_UNIFIED_DEMO.bat truoc khi bat Wireshark Live.
    pause
    exit /b 1
)

for /f %%i in ('docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" doslab_u_target 2^>nul') do set TARGET_IP=%%i
for /f %%i in ('docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" doslab_u_attacker 2^>nul') do set ATTACKER_IP=%%i
for /f %%i in ('docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" doslab_u_client 2^>nul') do set CLIENT_IP=%%i

echo ===========================================================================
echo   WIRESHARK LIVE - CHI BAT GOI TIN DEMO TRONG DOCKER (eth0, tcp port 80)
echo ===========================================================================
echo   Target IP   : %TARGET_IP%
echo   Attacker IP : %ATTACKER_IP%
echo   Client IP   : %CLIENT_IP%
echo.
echo   Filter goi y dan vao thanh Display Filter cua Wireshark:
echo     - Chi xem Attacker      : ip.addr == %ATTACKER_IP% ^&^& tcp.port == 80
echo     - Chi xem SYN Flood (L4): tcp.flags.syn == 1 ^&^& tcp.flags.ack == 0
echo     - Chi xem Slowloris (L7): http ^|^| tcp.flags.reset == 1
echo.
echo   LUU Y: Khong tat cua so cmd nay khi dang xem Wireshark.
echo ===========================================================================

docker exec -i doslab_u_target tcpdump -i eth0 -U -s 96 -w - "tcp port 80" | "D:\Cai dat ung dung\WireShark\Wireshark.exe" -k -i -

@echo off
chcp 65001 >nul
cd /d "%~dp0.."
set PYTHONIOENCODING=utf-8

echo ================================================
echo   Demo Launcher - Windows Side
echo   Target + Capture + Watch + Web + Browser
echo ================================================
echo.

if exist results rmdir /s /q results >nul 2>&1
mkdir results 2>nul

:: 1) Target server
start "Target :8080" cmd /k "python demo\target_server.py"
echo [OK] Target server :8080

:: 2) Capture
start "Capture VMnet8" cmd /k "set CAPTURE_IFACE=VMware Network Adapter VMnet8&& python demo\live_capture.py results\live_capture.json 300"
echo [OK] Capture started (300s)

:: 3) Wait for capture
timeout /t 3 /nobreak >nul

:: 4) Watch mode with reduced log noise
start "Watch Detection" cmd /k "set PYTHONIOENCODING=utf-8 && python main.py --watch 3 --input results\live_capture.json --output-dir results --log-level WARNING"
echo [OK] Watch mode (every 3s)

:: 5) Wait
timeout /t 2 /nobreak >nul

:: 6) Web GUI
start "Web Panel :8099" cmd /k "set PYTHONIOENCODING=utf-8 && python main.py --web --web-port 8099"
echo [OK] Web panel :8099

:: 7) Open browser
timeout /t 2 /nobreak >nul
start http://127.0.0.1:8099
echo [OK] Browser opened

echo.
echo ================================================
echo   Browser : http://127.0.0.1:8099
echo   Kali   : TARGET=192.168.235.1:8080 bash demo/attack_menu.sh
echo ================================================
pause

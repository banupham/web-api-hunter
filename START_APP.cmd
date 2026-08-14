@echo off
setlocal
cd /d "%~dp0"

echo ==============================================
echo WEB API HUNTER V3
echo ==============================================
echo Receiver: http://127.0.0.1:8765
echo Full WebSocket capture + binary/protobuf hints
echo.

py web_api_hunter.py
pause

@echo off
setlocal
cd /d "%~dp0"

rem Sending raw Ethernet frames through Npcap needs Administrator rights.
net session >nul 2>&1
if not "%errorlevel%"=="0" (
    echo Requesting Administrator rights...
    if "%~1"=="" (
        powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    ) else (
        set "ELEVATE_ARGS=%*"
        powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList $env:ELEVATE_ARGS -Verb RunAs"
    )
    exit /b
)

set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY (
    where python >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo Python 3 was not found.
    echo Install it from https://www.python.org/downloads/ and tick
    echo "Add python.exe to PATH" during setup.
    pause
    exit /b 1
)

%PY% cdp_advertiser.py %*
echo.
pause

@echo off
REM  Guided launcher - self-elevates and bypasses execution policy for this run.
cd /d "%~dp0"
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator rights...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath cmd.exe -ArgumentList '/c','\"%~f0\"'"
    exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Demo.ps1"
echo.
pause

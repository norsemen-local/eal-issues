@echo off
REM ================================================================
REM  EAL Demo - Case 1 : double-click launcher
REM  Self-elevates to Administrator (needed for the lateral stage),
REM  bypasses the execution policy for this run, and opens the menu.
REM ================================================================
cd /d "%~dp0"

REM --- Are we already elevated? -----------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator rights...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath cmd.exe -ArgumentList '/c','\"%~f0\"'"
    exit /b
)

REM --- Elevated: launch the guided menu ---------------------------
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Demo.ps1"

echo.
pause

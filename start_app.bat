@echo off
title PhishGuard - Desktop Agent
cd /d "%~dp0"

echo ===================================================
echo Starting PhishGuard Desktop Client (Tkinter)...
echo ===================================================

if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
) else (
    echo [WARNING] .venv not found. Using system Python...
)

python phishguard_agent.py

if %ERRORLEVEL% neq 0 (
    echo.
    echo Application exited with error code %ERRORLEVEL%.
    pause
)


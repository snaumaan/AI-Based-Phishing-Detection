@echo off
title PhishGuard - Web Server
cd /d "%~dp0"

echo ===================================================
echo Starting PhishGuard Web Application...
echo ===================================================

if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
) else (
    echo [WARNING] .venv not found. Using system Python...
)

echo Starting Flask server at http://localhost:5000
start "" http://localhost:5000
python server.py

pause


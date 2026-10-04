@echo off
rem ============================================================
rem  One-click launcher for Cloudflare SNI proxy IP optimizer.
rem
rem  This file is intentionally PURE ASCII. cmd.exe parses batch
rem  files with the console code page, so a UTF-8 .bat containing
rem  Chinese gets its lines shredded as soon as chcp changes the
rem  code page mid-file. All Chinese UI lives in menu.py instead.
rem
rem  Usage:  double-click, or drag a FOFA-exported CSV onto it.
rem ============================================================
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
cd /d "%~dp0"

python --version >nul 2>nul
if errorlevel 1 (
    echo.
    echo   [X] Python not found.
    echo       Install Python 3 and tick "Add python.exe to PATH".
    echo       Download: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

if not exist "menu.py" (
    echo.
    echo   [X] menu.py not found. Put run.bat in the project root.
    echo.
    pause
    exit /b 1
)

python menu.py %*
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%

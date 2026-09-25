@echo off
cd /d "%~dp0"
where pyw >nul 2>nul
if %errorlevel% equ 0 (
    start "" pyw -3 gui.py
    exit /b
)
where py >nul 2>nul
if %errorlevel% equ 0 (
    py -3 gui.py
    exit /b
)
echo Python 3 is required. Install it from https://www.python.org/downloads/windows/
pause

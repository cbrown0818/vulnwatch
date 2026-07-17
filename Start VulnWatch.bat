@echo off
cd /d "%~dp0"
where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw "%~dp0vulnwatch_gui.py"
    exit /b 0
)
where pyw >nul 2>nul
if %errorlevel%==0 (
    start "" pyw -3 "%~dp0vulnwatch_gui.py"
    exit /b 0
)
echo Python could not be found in PATH.
echo Run: python vulnwatch_gui.py
pause

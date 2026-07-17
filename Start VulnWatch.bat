@echo off
setlocal
cd /d "%~dp0"

if exist "%USERPROFILE%\.local\bin\pythonw3.14.exe" (
    start "" "%USERPROFILE%\.local\bin\pythonw3.14.exe" "%~dp0vulnwatch_gui.py"
    exit /b 0
)
if exist "%USERPROFILE%\.local\bin\python3.14.exe" (
    start "VulnWatch" "%USERPROFILE%\.local\bin\python3.14.exe" "%~dp0vulnwatch_gui.py"
    exit /b 0
)
where pythonw.exe >nul 2>nul && start "" pythonw.exe "%~dp0vulnwatch_gui.py" && exit /b 0
where pyw.exe >nul 2>nul && start "" pyw.exe -3 "%~dp0vulnwatch_gui.py" && exit /b 0
where python.exe >nul 2>nul && python.exe "%~dp0vulnwatch_gui.py" && exit /b 0

echo Python 3 could not be found.
echo Install Python with tkinter, then run: python vulnwatch_gui.py
pause

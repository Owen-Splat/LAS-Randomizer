@echo off
setlocal
cd /d "%~dp0"

if not exist "manage.py" (
    echo Could not find manage.py beside this command file.
    goto failed
)

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" manage.py build --out las_switch.apworld
    goto check_build
)

py -3 --version >nul 2>&1
if not errorlevel 1 (
    py -3 manage.py build --out las_switch.apworld
    goto check_build
)

python --version >nul 2>&1
if not errorlevel 1 (
    python manage.py build --out las_switch.apworld
    goto check_build
)

echo Python was not found. Install Python 3 and run this file again.
goto failed

:check_build
if errorlevel 1 goto failed
echo.
echo Built: "%~dp0las_switch.apworld"
echo Copy this file into Archipelago's custom_worlds folder and restart its launcher.
if /I "%~1"=="--no-pause" exit /b 0
pause
exit /b 0

:failed
echo.
echo APWorld build failed. Check the message above.
if /I "%~1"=="--no-pause" exit /b 1
pause
exit /b 1

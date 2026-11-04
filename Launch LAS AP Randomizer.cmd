@echo off
setlocal
cd /d "%~dp0"
set "LAS_AP_PYTHON=%~dp0..\..\work\las-python\Scripts\python.exe"
if not exist "%LAS_AP_PYTHON%" (
  echo The local LAS Python environment is missing. See README.md.
  pause
  exit /b 1
)
"%LAS_AP_PYTHON%" "%~dp0randomizer_ap.py" %*
if errorlevel 1 pause

@echo off
setlocal
pushd "%~dp0"
if errorlevel 1 exit /b 1
set "LAS_BUILD_ROOT=%CD%"
set "LAS_BUILD_EXIT=0"

rem Never delete an environment that existed before this build.
if exist ".venv" (
    echo A .venv already exists. Rename it before running this temporary-environment build.
    set "LAS_BUILD_EXIT=1"
    goto finish
)

py -3.12 --version >nul 2>&1
if errorlevel 1 (
    echo Python 3.12 was not found. Install it and run this build again.
    set "LAS_BUILD_EXIT=1"
    goto finish
)

py -3.12 -m venv ".venv"
if errorlevel 1 goto failed
call ".venv\Scripts\activate.bat"
if errorlevel 1 goto failed

".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
".venv\Scripts\python.exe" scripts\fetch_dev_runtime.py
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m PyInstaller --log-level=WARN randomizer.spec
if errorlevel 1 goto failed
".venv\Scripts\python.exe" build.py
if errorlevel 1 goto failed
goto cleanup

:failed
set "LAS_BUILD_EXIT=%errorlevel%"
if "%LAS_BUILD_EXIT%"=="0" set "LAS_BUILD_EXIT=1"
echo Build failed. Cleaning up the temporary environment.

:cleanup
if exist ".venv\Scripts\deactivate.bat" call ".venv\Scripts\deactivate.bat"
rem Remove only the checked .venv directory beside this script.
powershell -NoProfile -Command "$ErrorActionPreference='Stop'; $buildRoot=[IO.Path]::GetFullPath($env:LAS_BUILD_ROOT); $buildVenv=[IO.Path]::GetFullPath((Join-Path $buildRoot '.venv')); if ((Split-Path -Parent $buildVenv) -ne $buildRoot) { throw 'Unsafe environment path' }; if (Test-Path -LiteralPath $buildVenv) { $folder=Get-Item -LiteralPath $buildVenv -Force; if ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing to remove a linked environment' }; Remove-Item -LiteralPath $buildVenv -Recurse -Force }"
if errorlevel 1 (
    echo Could not delete the temporary environment.
    if "%LAS_BUILD_EXIT%"=="0" set "LAS_BUILD_EXIT=1"
)

:finish
if "%LAS_BUILD_EXIT%"=="0" echo Build complete: dist\release_archive
popd
exit /b %LAS_BUILD_EXIT%

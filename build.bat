py -3.12 -m PyInstaller --log-level=WARN randomizer.spec
if %errorlevel% neq 0 exit /b %errorlevel%
py -3.12 build.py
if %errorlevel% neq 0 exit /b %errorlevel%
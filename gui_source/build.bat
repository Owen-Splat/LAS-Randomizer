py -3.8 setup.py build
if %errorlevel% neq 0 exit /b %errorlevel%
py -3.8 build.py
if %errorlevel% neq 0 exit /b %errorlevel%
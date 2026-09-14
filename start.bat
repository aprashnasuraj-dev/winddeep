@echo off
setlocal
cd /d "%~dp0"
if exist "Windeep.exe" (
  start "" "Windeep.exe"
  exit /b 0
)
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" launcher.py
  exit /b %ERRORLEVEL%
)
py -3.11 launcher.py
exit /b %ERRORLEVEL%

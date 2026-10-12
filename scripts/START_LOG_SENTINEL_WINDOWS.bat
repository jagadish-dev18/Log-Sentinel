@echo off
setlocal
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python 3 was not found. Install Python from https://www.python.org/downloads/
  pause
  exit /b 1
)
start "Log Sentinel browser" /min cmd /c "ping 127.0.0.1 -n 2 >nul ^& start http://127.0.0.1:8000"
python -m http.server 8000 --directory frontend
pause

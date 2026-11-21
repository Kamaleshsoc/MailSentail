@echo off
title MailSentinel Setup
cd /d "%~dp0"
echo ========================================
echo       MailSentinel - First-time Setup
echo ========================================
py -m venv venv
if errorlevel 1 (
  echo Failed to create virtual environment. Check Python installation.
  pause
  exit /b 1
)
call venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
if errorlevel 1 (
  echo Dependency installation failed.
  pause
  exit /b 1
)
echo.
echo Setup completed. Double-click start_mailsentinel.bat to run the app.
pause

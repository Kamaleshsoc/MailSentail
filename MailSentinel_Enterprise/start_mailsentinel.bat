@echo off
title MailSentinel - Local SOC Dashboard
cd /d "%~dp0"
if not exist "venv\Scripts\python.exe" (
  echo Virtual environment not found. Run install_windows.bat first.
  pause
  exit /b 1
)
call venv\Scripts\activate.bat
set FLASK_CONFIG=development
if "%SECRET_KEY%"=="" set SECRET_KEY=local-only-change-this-development-key
echo Starting MailSentinel at http://127.0.0.1:5000
python -m flask --app "app:create_app('development')" run --debug
pause

@echo off
rem Start the server (its own window; close it when you're done) and then the private copy of the game.
if not exist "%USERPROFILE%\SoulframePrivate\sf-launch.exe" (echo Run setup.cmd first. & pause & exit /b 1)
if not exist "%~dp0.python-path" (echo Run setup.cmd first. & pause & exit /b 1)
set /p PY=<"%~dp0.python-path"
rem cmd /k keeps the window open if the server stops with an error (port 80/443 in use, ...).
start "Soulframe private server" /d "%~dp0tools" cmd /k ""%PY%" dummy_server.py"
"%USERPROFILE%\SoulframePrivate\sf-launch.exe"
if errorlevel 1 pause

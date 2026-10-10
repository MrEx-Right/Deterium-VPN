@echo off
rem Builds Deterium from this source folder and installs it for the current user.
rem See tools\install.ps1 for exactly what it does.
title Install Deterium VPN
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\install.ps1" %*
echo.
pause

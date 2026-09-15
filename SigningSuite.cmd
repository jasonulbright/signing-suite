@echo off
rem Starts Signing Suite in Windows PowerShell 5.1 without a console window.
start "" "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0start-signingsuite.ps1" %*

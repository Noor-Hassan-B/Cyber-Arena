@echo off
title Push Sh4d0w_Br0k3rs to GitHub (Cyber-Arena)
color 0B
echo ========================================================
echo   Pushing Sh4d0w_Br0k3rs to Cyber-Arena Repo
echo ========================================================
echo.
cd /d "%~dp0"
git push origin main --force
echo.
if %ERRORLEVEL% EQU 0 (
    color 0A
    echo [SUCCESS] Project successfully uploaded to https://github.com/Noor-Hassan-B/Cyber-Arena
) else (
    color 0C
    echo [ERROR] Push failed. Please check credentials or sign in.
)
echo.
pause

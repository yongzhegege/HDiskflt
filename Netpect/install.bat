@echo off
setlocal
cd /d "%~dp0"

:: Check Admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~0' -Verb RunAs"
    exit /b
)

set "INSTALL_DIR=C:\Program Files\ProtectClient"

echo [INSTALL] Creating Installation Directory: %INSTALL_DIR%
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

echo [INSTALL] Copying Files...
copy /y "protect.exe" "%INSTALL_DIR%\"
copy /y "ProtectServer.exe" "%INSTALL_DIR%\"
copy /y "uninstall.bat" "%INSTALL_DIR%\"

echo [INSTALL] Installing Protect Service...

:: Create Service pointing to installed file
sc create ProtectSvc binPath= "\"%INSTALL_DIR%\protect.exe\"" start= auto displayname= "Protect Client Service"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to create service.
    pause
    exit /b 1
)

:: Set Recovery Actions (Restart on failure)
sc failure ProtectSvc reset= 0 actions= restart/60000
sc failureflag ProtectSvc 1

:: Start Service
echo [INSTALL] Starting Service...
sc start ProtectSvc

echo [INSTALL] Done. Installation complete in %INSTALL_DIR%
pause
exit /b 0

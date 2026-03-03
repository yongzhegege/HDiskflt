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

echo [UNINSTALL] Stopping Protect Service...
sc stop ProtectSvc

echo [UNINSTALL] Deleting Protect Service...
sc delete ProtectSvc

echo [UNINSTALL] Clearing Sector 62...
if exist "protect.exe" (
    protect.exe /clear
    if %errorlevel% equ 0 (
        echo [OK] Sector 62 Cleared.
    ) else (
        echo [WARN] Failed to clear Sector 62.
    )
)

echo [UNINSTALL] Cleaning Registry...
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\DiskFlt" /v ProtectInfo /f >nul 2>&1

echo [UNINSTALL] Removing Installed Files...
if exist "protect.exe" del /f /q "protect.exe"
if exist "ProtectServer.exe" del /f /q "ProtectServer.exe"

echo [UNINSTALL] Done. 
echo You can manually remove this folder if it is empty.
pause
exit /b 0

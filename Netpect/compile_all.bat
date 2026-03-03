@echo off
setlocal

set VCVARS="C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

echo [COMPILE] Compiling Client (protect.exe)...
cmd /c "call %VCVARS% && cl /EHsc /Fe:protect.exe protect_service.cpp user32.lib advapi32.lib shell32.lib ws2_32.lib crypt32.lib iphlpapi.lib shlwapi.lib" > client_build.log 2>&1

if not exist protect.exe (
    echo [ERROR] protect.exe was not created! Check client_build.log.
    type client_build.log
    exit /b 1
)
echo [OK] Client compiled successfully.

echo [COMPILE] Compiling Server (ProtectServer.exe)...
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /target:winexe /out:ProtectServer.exe ProtectServer.cs > server_build.log 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Server compilation failed! Check server_build.log.
    type server_build.log
    exit /b 1
)
echo [OK] Server compiled successfully.

echo [SUCCESS] All components compiled.
exit /b 0

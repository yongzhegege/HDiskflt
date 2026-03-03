@echo off
setlocal

:: ==========================================
:: 用户配置区
:: ==========================================

:: Visual Studio 编译器路径
set CL_PATH="C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
set LINK_PATH="C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

:: WDK 根目录
set WDK_ROOT=C:\Program Files (x86)\Windows Kits\10

:: WDK 版本 (驱动核心文件)
set WDK_VERSION=10.0.22621.0

:: SDK 版本 (共享头文件，如 specstrings.h)
:: 注意：您的环境中 WDK 和 SDK 版本不一致，这里分别设置
set SDK_VERSION=10.0.26100.0

:: ==========================================
:: 检查 WDK 环境
:: ==========================================

set "WDK_KM_INC=%WDK_ROOT%\Include\%WDK_VERSION%\km"
set "WDK_KM_LIB=%WDK_ROOT%\Lib\%WDK_VERSION%\km"

:: 切换到脚本所在目录
pushd %~dp0

if exist "%WDK_KM_INC%\ntddk.h" goto :FoundWDK

echo.
echo [错误] 您的环境中缺少 WDK (Windows Driver Kit) 驱动开发文件!
echo [路径] "%WDK_KM_INC%" 不存在。
echo.
pause
popd
exit /b 1

:FoundWDK
:: 分别设置 WDK 和 SDK 的包含路径
set KIT_INC_WDK=%WDK_ROOT%\Include\%WDK_VERSION%
set KIT_INC_SDK=%WDK_ROOT%\Include\%SDK_VERSION%
set KIT_LIB=%WDK_ROOT%\Lib\%WDK_VERSION%

:: 组合包含路径：
:: 1. 当前目录 (.)
:: 2. WDK km 目录 (驱动核心)
:: 3. SDK shared 目录 (specstrings.h 等基础定义)
:: 4. WDK crt 目录 (如果有) 或 SDK crt
:: 5. WDK km\crt 目录
set INCLUDES=/I. /I"%KIT_INC_WDK%\km" /I"%KIT_INC_SDK%\shared" /I"%KIT_INC_WDK%\crt" /I"%KIT_INC_WDK%\km\crt"

set LIBS="%KIT_LIB%\km\x64\ntoskrnl.lib" "%KIT_LIB%\km\x64\hal.lib" "%KIT_LIB%\km\x64\wmilib.lib" "%KIT_LIB%\km\x64\wdm.lib"

echo Compiling...
:: 添加 /source-charset:utf-8 解决中文编码警告 C4819
%CL_PATH% /nologo /c /O2 /W3 /source-charset:utf-8 /D_AMD64_ /D_WIN64 /DWIN64 /D_KERNEL /DKMDF_MAJOR_VERSION_10 /DDBG=1 /D_WIN32_WINNT=0x0601 %INCLUDES% diskflt.c diskfltlib.c md5.c notify.c

if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    popd
    exit /b %ERRORLEVEL%
)

echo Linking...
%LINK_PATH% /nologo /DRIVER /ENTRY:DriverEntry /SUBSYSTEM:NATIVE /OUT:diskflt.sys /NODEFAULTLIB %LIBS% "%KIT_LIB%\km\x64\libcntpr.lib" "%KIT_LIB%\km\x64\BufferOverflowK.lib" *.obj

if %ERRORLEVEL% NEQ 0 (
    echo Linking failed!
    popd
    exit /b %ERRORLEVEL%
)

echo Done.
popd
endlocal

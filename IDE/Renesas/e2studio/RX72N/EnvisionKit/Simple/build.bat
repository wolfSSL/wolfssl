@echo off
setlocal

set MAKE=C:\Renesas\e2_studio\eclipse\plugins\com.renesas.ide.exttools.gnumake.win32.x86_64_4.3.1.v20240909-0854\mk\make.exe
set CCRX_BIN=C:\PROGRA~2\Renesas\RX\3_6_0\bin
set E2_UTILS=%USERPROFILE%\.eclipse\com.renesas.platform_1435879475\Utilities\ccrx
set PATH=%CCRX_BIN%;%E2_UTILS%;%PATH%
set BASEDIR=%~dp0

set TARGET=all
if /i "%1"=="clean" set TARGET=clean

echo ============================================================
echo  wolfssl library  [%TARGET%]
echo ============================================================
cd /d "%BASEDIR%wolfssl\Debug"
"%MAKE%" %TARGET%
if %ERRORLEVEL% neq 0 (
    echo [ERROR] wolfssl build failed.
    exit /b %ERRORLEVEL%
)

echo.
echo ============================================================
echo  test application  [%TARGET%]
echo ============================================================
cd /d "%BASEDIR%test\HardwareDebug"
"%MAKE%" %TARGET%
if %ERRORLEVEL% neq 0 (
    echo [ERROR] test build failed.
    exit /b %ERRORLEVEL%
)

echo.
echo ============================================================
echo  Done.
echo ============================================================
endlocal

@echo off
setlocal

REM --- Flash test.x and let it run, using Renesas Flash Programmer (RFP) CLI ---
REM DEBUG_DIR is tied to a specific e2studio install (platform ID) and will not exist as-is
REM on a different machine. Set DEBUG_DIR in the environment before calling debug_run.bat to
REM override the default below for your install.
if not defined DEBUG_DIR set DEBUG_DIR=%USERPROFILE%\.eclipse\com.renesas.platform_1435879475\DebugComp\RX
set OBJCOPY=%DEBUG_DIR%\rx-elf-objcopy.exe
set BASEDIR=%~dp0
set TARGET_X=%BASEDIR%test\HardwareDebug\test.x
set TARGET_MOT=%BASEDIR%test\HardwareDebug\test.mot
set RFP_LOG=%BASEDIR%test_result.log

REM --- Find the installed Renesas Flash Programmer CLI (version-independent) ---
for /d %%d in ("C:\Program Files (x86)\Renesas Electronics\Programming Tools\Renesas Flash Programmer V*") do set RFP_DIR=%%d
set RFP_CLI=%RFP_DIR%\rfp-cli.exe

if not exist "%TARGET_X%" (
    echo [ERROR] %TARGET_X% not found. Run build.bat first.
    exit /b 1
)
if not exist "%RFP_CLI%" (
    echo [ERROR] rfp-cli.exe not found under "C:\Program Files (x86)\Renesas Electronics\Programming Tools\".
    exit /b 1
)

echo [1/2] Converting ELF ^(test.x^) to Motorola S-record...
"%OBJCOPY%" -O srec "%TARGET_X%" "%TARGET_MOT%"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] rx-elf-objcopy failed with code %ERRORLEVEL%
    exit /b 1
)

echo [2/2] Erasing, programming, verifying via E2 Lite, then releasing reset to run...
echo ============================================================
del "%RFP_LOG%" > nul 2>&1
REM -device RX72x: RFP groups devices by family, not exact part number (R5F572NN falls under RX72x).
REM -auth id FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF: matches the all-FF (disabled) ID code used by this project.
REM -run: release reset and let the target run after RFP disconnects (default is to leave it in reset).
"%RFP_CLI%" ^
  -device RX72x ^
  -tool e2l ^
  -if fine ^
  -auth id FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF ^
  -noquery ^
  -auto -run ^
  -log "%RFP_LOG%" ^
  "%TARGET_MOT%"
set RFP_EXIT=%ERRORLEVEL%
echo ============================================================

if %RFP_EXIT% neq 0 (
    echo [ERROR] rfp-cli exited with code %RFP_EXIT%
) else (
    echo [DONE] Target is running -- check Tera Term for UART output.
)

exit /b %RFP_EXIT%

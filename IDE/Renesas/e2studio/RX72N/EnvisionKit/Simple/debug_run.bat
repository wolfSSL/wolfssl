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

set MODE=reload
if /i "%1"=="restart" (
    set MODE=restart
) else if not "%1"=="" (
    echo [ERROR] Unknown argument "%1".
    echo Usage: debug_run.bat [restart]
    echo   ^(no arg^)  -^> reload: convert+erase+program+verify test.x, then run
    echo   restart    -^> just reset the already-flashed target and run it again,
    echo                without reprogramming
    exit /b 1
)

REM --- Find the installed Renesas Flash Programmer CLI (version-independent) ---
for /d %%d in ("C:\Program Files (x86)\Renesas Electronics\Programming Tools\Renesas Flash Programmer V*") do set RFP_DIR=%%d
set RFP_CLI=%RFP_DIR%\rfp-cli.exe

if not exist "%RFP_CLI%" (
    echo [ERROR] rfp-cli.exe not found under "C:\Program Files (x86)\Renesas Electronics\Programming Tools\".
    exit /b 1
)

if /i "%MODE%"=="restart" goto :restart_mode
goto :reload_mode

REM --- restart: just reset the already-flashed target, no reprogramming. Kept as
REM top-level (unindented, un-parenthesized) code like the reload path below it --
REM %RFP_EXIT%/%ERRORLEVEL% are otherwise expanded once at parse time if wrapped in
REM an if-block, before rfp-cli has even run, always reading as stale/empty. ---
:restart_mode
echo [1/1] Restarting target via E2 Lite ^(no reprogramming^)...
echo ============================================================
del "%RFP_LOG%" > nul 2>&1
REM Same connection/auth options as the reload path below, but with no hex file and
REM no -e/-p/-v/-a. -sig (read-only device signature check) is required even so:
REM with no operation at all, rfp-cli only connects the emulator, never the target
REM chip, so -run has no reset line to release and prints "No operation" -- -sig
REM forces a real (but safe, flash-untouched) target session so -run actually fires
REM on disconnect.
"%RFP_CLI%" ^
  -device RX72x ^
  -tool e2l ^
  -if fine ^
  -auth id FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF ^
  -noquery ^
  -sig -run ^
  -log "%RFP_LOG%"
set RFP_EXIT=%ERRORLEVEL%
echo ============================================================

if %RFP_EXIT% neq 0 (
    echo [ERROR] rfp-cli exited with code %RFP_EXIT%
) else (
    echo [DONE] Target restarted -- check Tera Term for UART output.
)

exit /b %RFP_EXIT%

:reload_mode
if not exist "%TARGET_X%" (
    echo [ERROR] %TARGET_X% not found. Run build.bat first.
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

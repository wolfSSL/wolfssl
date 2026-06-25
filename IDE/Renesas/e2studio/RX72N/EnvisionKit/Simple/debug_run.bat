@echo off
setlocal

REM --- Flash test.x and let it run, using Renesas Flash Programmer (RFP) instead of a raw
REM GDB session. e2studio's GUI debug launch sends >150 "monitor set_io_access_width"
REM commands (device-specific I/O bus-width setup, captured from the Debugger Console) before
REM anything else; a hand-written GDB script can't feasibly replicate that, and without it the
REM CPU runs but peripherals (SCI2/TSIP) don't come up correctly -- no UART output, even though
REM GDB reports the thread as running. RFP's own flash-and-run path sidesteps all of that: it's
REM closer to a real power-on boot (erase/program/verify, then release reset via -run) and does
REM not go through a GDB debug session at all. Confirmed working: UART output appears correctly
REM after "rfp-cli ... -auto -run".

set DEBUG_DIR=%USERPROFILE%\.eclipse\com.renesas.platform_1435879475\DebugComp\RX
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

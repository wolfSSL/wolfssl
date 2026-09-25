@echo off
REM EnableDelayedExpansion so "%JLINK%" (built from JLINK_DIR, a user-overridable install
REM path) can be echoed with !JLINK! inside an if-block without risk: if that path ever
REM contains parens (e.g. an override under "Program Files (x86)"), a %VAR%-style
REM reference would substitute them in raw at block-parse time and corrupt cmd.exe's
REM block-boundary parsing -- see build.bat's ARM_GCC_BIN handling, which hit exactly
REM this. !VAR! defers substitution to each line's execution time instead.
setlocal EnableDelayedExpansion

REM --- Flash test_RA6M4.srec and let it run, using SEGGER J-Link Commander (JLink.exe) ---
REM JLINK_DIR is tied to a specific J-Link software install and will not exist as-is on a
REM different machine. Set JLINK_DIR in the environment before calling debug_run.bat to
REM override the default below for your install.
if not defined JLINK_DIR set JLINK_DIR=C:\Program Files\SEGGER\JLink_V852
set JLINK=%JLINK_DIR%\JLink.exe
set BASEDIR=%~dp0
set TARGET_SREC=%BASEDIR%test\Debug\test_RA6M4.srec
set DEVICE=R7FA6M4AF
set JLINK_LOG=%BASEDIR%test_result.log
set JLINK_CMD=%TEMP%\ra6m4_debug_run_%RANDOM%.jlink
REM How long JLink.exe waits (via the command file's own "sleep", in ms) after "g" before
REM "qc" disconnects. Override with QC_DELAY_MS if you need longer/shorter. Some targets'
REM early boot (clock/BSP init, FreeRTOS scheduler start) can behave differently while a
REM debug probe is actively attached vs. standalone; holding the connection open a bit
REM past "go" is a cheap way to rule that class of difference in/out.
if not defined QC_DELAY_MS set QC_DELAY_MS=30000

set MODE=reload
if /i "%1"=="restart" (
    set MODE=restart
) else if not "%1"=="" (
    echo [ERROR] Unknown argument "%1".
    echo Usage: debug_run.bat [restart]
    echo   ^(no arg^)  -^> reload: flash test_RA6M4.srec, then reset and run
    echo   restart    -^> just reset the already-flashed target and run it again,
    echo                without reprogramming
    exit /b 1
)

if not exist "%JLINK%" (
    echo [ERROR] JLink.exe not found at "!JLINK!".
    echo Set JLINK_DIR to your SEGGER J-Link install directory ^(the folder containing
    echo JLink.exe^) and re-run debug_run.bat.
    exit /b 1
)

if /i "%MODE%"=="restart" goto :restart_mode
goto :reload_mode

REM --- restart: just reset the already-flashed target, no reprogramming. Kept as
REM top-level (unindented, un-parenthesized) code like the reload path below it --
REM %JLINK_EXIT%/%ERRORLEVEL% are otherwise expanded once at parse time if wrapped in
REM an if-block, before JLink.exe has even run, always reading as stale/empty. ---
:restart_mode
echo [1/1] Restarting target via J-Link ^(no reprogramming; qc delayed !QC_DELAY_MS!ms^)...
echo ============================================================
del "%JLINK_LOG%" > nul 2>&1
(
    echo r
    echo g
    echo qc
) > "%JLINK_CMD%"
"%JLINK%" -device %DEVICE% -if SWD -speed 4000 -autoconnect 1 -ExitOnError 1 -CommandFile "%JLINK_CMD%" -Log "%JLINK_LOG%"
set JLINK_EXIT=%ERRORLEVEL%
del "%JLINK_CMD%" > nul 2>&1
echo ============================================================

if %JLINK_EXIT% neq 0 (
    echo [ERROR] JLink.exe exited with code %JLINK_EXIT%
) else (
    echo [DONE] Target restarted -- check J-Link RTT Viewer for output.
)

exit /b %JLINK_EXIT%

:reload_mode
if not exist "%TARGET_SREC%" (
    echo [ERROR] %TARGET_SREC% not found. Run build.bat first.
    exit /b 1
)

echo [1/1] Programming via J-Link, then resetting and running ^(qc delayed !QC_DELAY_MS!ms^)...
echo ============================================================
del "%JLINK_LOG%" > nul 2>&1
REM -device/-if/-speed: matches the SWD/4000kHz settings e2studio's own launch config uses
REM for this project (test_RA6M4Debug.launch: interface.type=SWD, interface.speed=4000).
REM loadfile accepts the .srec directly -- no objcopy step needed, e2studio's GCC ARM
REM managed build already emits it as a post-build step (see test\Debug\makefile's
REM "secondary-outputs" target -> arm-none-eabi-objcopy -O srec).
REM r / loadfile / r / g: reset+halt, program+verify flash, reset again so execution
REM starts clean from the vector table, then go. sleep keeps JLink.exe (and the SWD
REM connection) alive for QC_DELAY_MS before qc quits without re-asserting reset, so the
REM target keeps running standalone after that.
(
    echo r
    echo loadfile "%TARGET_SREC%"
    echo r
    echo g
    echo qc
) > "%JLINK_CMD%"
"%JLINK%" -device %DEVICE% -if SWD -speed 4000 -autoconnect 1 -ExitOnError 1 -CommandFile "%JLINK_CMD%" -Log "%JLINK_LOG%"
set JLINK_EXIT=%ERRORLEVEL%
del "%JLINK_CMD%" > nul 2>&1
echo ============================================================

if %JLINK_EXIT% neq 0 (
    echo [ERROR] JLink.exe exited with code %JLINK_EXIT%
) else (
    echo [DONE] Target is running -- check J-Link RTT Viewer for output.
)

exit /b %JLINK_EXIT%

@echo off
REM EnableDelayedExpansion so GIT_BASH (a user-overridable install path) can be echoed
REM safely inside an if-block -- see build.bat's ARM_GCC_BIN handling for why %VAR%
REM alone is risky there if the path ever contains parens (e.g. "Program Files (x86)").
setlocal EnableDelayedExpansion

REM --- Wrapper so generate_SignedCA.sh can be run directly from cmd.exe/PowerShell,
REM without opening a Git Bash shell manually. Requires Git for Windows (bash.exe,
REM plus its bundled openssl/perl, which the .sh script also needs). Set GIT_BASH in
REM the environment before calling this to override the default install path below. ---
if not defined GIT_BASH set GIT_BASH=C:\Program Files\Git\bin\bash.exe
set BASEDIR=%~dp0
set SCRIPT=%BASEDIR%generate_SignedCA.sh

if not exist "%GIT_BASH%" (
    echo [ERROR] Git Bash not found at "!GIT_BASH!".
    echo Install Git for Windows ^(https://git-scm.com/download/win^), or set GIT_BASH
    echo to your bash.exe path, then re-run.
    exit /b 1
)
if not exist "%SCRIPT%" (
    echo [ERROR] "%SCRIPT%" not found.
    exit /b 1
)

REM Fixed args, matching the .sh script's own header-comment usage examples: only the
REM target .der file (RSA -> ca-cert.der, ECC -> ca-ecc-cert.der) varies with the mode.
set DERFILE=
if /i "%1"=="RSA" (
    set DERFILE=ca-cert.der
) else if /i "%1"=="ECC" (
    set DERFILE=ca-ecc-cert.der
) else (
    echo [ERROR] Usage: generate_SignedCA.bat ^<RSA^|ECC^>
    echo   RSA -^> signs ../../../../../../../wolfssl/certs/ca-cert.der
    echo   ECC -^> signs ../../../../../../../wolfssl/certs/ca-ecc-cert.der
    exit /b 1
)

"%GIT_BASH%" "%SCRIPT%" rsa_private.pem rsa_public.pem ../../../../../../../wolfssl/certs/!DERFILE! ../../../../../../../wolfssl
exit /b %ERRORLEVEL%

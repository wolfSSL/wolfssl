@echo off
REM Expect the script at /path/to/wolfssl/IDE/Espressif/ESP-IDF/

if NOT EXIST "setup.sh" ( 
  echo "Please run this script at /path/to/wolfssl/IDE/Espressif/ESP-IDF/
  goto exit
)

if "%IDF_PATH%" == "" (
  echo "Please launch the script from ESP-IDF command prompt."
  goto exit
)

set SCRIPTDIR=%CD%
set BASEDIR=%SCRIPTDIR%\..\..\..\
set WOLFSSL_ESPIDFDIR=%BASEDIR%\IDE\Espressif\ESP-IDF
set WOLFSSLLIB_TRG_DIR=%IDF_PATH%\components\wolfssl
set WOLFSSLEXP_TRG_DIR=%IDF_PATH%\examples\protocols

echo Copy files into $IDF_PATH%
rem Remove/Create directories
rmdir /S/Q %WOLFSSLLIB_TRG_DIR%
mkdir      %WOLFSSLLIB_TRG_DIR%
mkdir      %WOLFSSLLIB_TRG_DIR%\src
mkdir      %WOLFSSLLIB_TRG_DIR%\wolfcrypt\src
mkdir      %WOLFSSLLIB_TRG_DIR%\wolfssl
mkdir      %WOLFSSLLIB_TRG_DIR%\test
mkdir      %WOLFSSLLIB_TRG_DIR%\include

rem copying ... files in src/ into $WOLFSSLLIB_TRG_DIR%/src
xcopy /Y/Q %BASEDIR%\src\*.c %WOLFSSLLIB_TRG_DIR%\src\
xcopy /Y/Q %BASEDIR%\wolfcrypt\src\*.c %WOLFSSLLIB_TRG_DIR%\wolfcrypt\src
xcopy /Y/Q %BASEDIR%\wolfcrypt\src\*.i %WOLFSSLLIB_TRG_DIR%\wolfcrypt\src
xcopy /E/Y/Q %BASEDIR%\wolfcrypt\src\port %WOLFSSLLIB_TRG_DIR%\wolfcrypt\src\port\
xcopy /E/Y/Q %BASEDIR%\wolfcrypt\test\ %WOLFSSLLIB_TRG_DIR%\wolfcrypt\test\
xcopy /E/Y/Q %BASEDIR%\wolfcrypt\benchmark\ %WOLFSSLLIB_TRG_DIR%\wolfcrypt\benchmark\
xcopy /Y/Q %BASEDIR%\wolfssl\*.h %WOLFSSLLIB_TRG_DIR%\wolfssl\
xcopy /E/Y/Q %BASEDIR%\wolfssl\wolfcrypt\ %WOLFSSLLIB_TRG_DIR%\wolfssl\wolfcrypt\

rem user_settings.h
xcopy /F/Q %WOLFSSL_ESPIDFDIR%\user_settings.h %WOLFSSLLIB_TRG_DIR%\include\
echo F |xcopy /F/Q %WOLFSSL_ESPIDFDIR%\dummy_config_h %WOLFSSLLIB_TRG_DIR%\include\config.h

rem unit test app
xcopy /E/Y/Q %WOLFSSL_ESPIDFDIR%\test %WOLFSSLLIB_TRG_DIR%\test\
xcopy /F/Q   %WOLFSSL_ESPIDFDIR%\libs\CMakeLists.txt %WOLFSSLLIB_TRG_DIR%\
xcopy /F/Q   %WOLFSSL_ESPIDFDIR%\libs\component.mk   %WOLFSSLLIB_TRG_DIR%\

rem Benchmark program
rmdir /S/Q %WOLFSSLEXP_TRG_DIR%\wolfssl_benchmark\
mkdir      %WOLFSSLEXP_TRG_DIR%\wolfssl_benchmark\main\
xcopy /F/Q %BASEDIR%\wolfcrypt\benchmark\benchmark.c %WOLFSSLEXP_TRG_DIR%\wolfssl_benchmark\main\
xcopy /E/F/Q %WOLFSSL_ESPIDFDIR%\examples\wolfssl_benchmark %WOLFSSLEXP_TRG_DIR%\wolfssl_benchmark\

rem Crypt Test program
rmdir /S/Q %WOLFSSLEXP_TRG_DIR%\wolfssl_test\
mkdir      %WOLFSSLEXP_TRG_DIR%\wolfssl_test\main\
xcopy /F/Q %BASEDIR%\wolfcrypt\test\test.c %WOLFSSLEXP_TRG_DIR%\wolfssl_test\main\
xcopy /E/F/Q %WOLFSSL_ESPIDFDIR%\examples\wolfssl_test %WOLFSSLEXP_TRG_DIR%\wolfssl_test\

rem TLS Client program
rmdir /S/Q %WOLFSSLEXP_TRG_DIR%\wolfssl_client\
mkdir      %WOLFSSLEXP_TRG_DIR%\wolfssl_client\main\
xcopy /E/F/Q %WOLFSSL_ESPIDFDIR%\examples\wolfssl_client %WOLFSSLEXP_TRG_DIR%\wolfssl_client\

rem TLS Server program
rmdir /S/Q %WOLFSSLEXP_TRG_DIR%\wolfssl_server\
mkdir      %WOLFSSLEXP_TRG_DIR%\wolfssl_server\main\
xcopy /E/F/Q %WOLFSSL_ESPIDFDIR%\examples\wolfssl_server %WOLFSSLEXP_TRG_DIR%\wolfssl_server\

:exit
 echo completed



# Micrium μC/OS-III Port
## Overview
You can enable the wolfSSL support for Micrium μC/OS-III RTOS available [here](http://www.micriums.com/) using the define `MICRIUM`.

## Usage

You can start with your IDE-based project for Micrium uC/OS-III and uC/TCP stack. You must include the uC-Clk module into your project because wolfSSL uses Micrium’s Clk_GetTS_Unix () function from <clk.h> in order to authenticate certificate date ranges.

wolfSSL supports a compile-time user configurable options in the `IDE/ECLIPSE/MICRIUM/user_settings.h` file.

The `wolfsslRunTests.c` example application provides a simple function to run the selected examples at compile time through the following four #defines (see user_settings.h).

```
       1. #define WOLFSSL_WOLFCRYPT_TEST
       2. #define WOLFSSL_BENCHMARK_TEST
       3. #define WOLFSSL_CLIENT_TEST
       4. #define WOLFSSL_SERVER_TEST

Please define one or all of the above options.
```
In your IDE, create the following folder and subfolders structures.
The folder hierarcy is the same as the wolfSSL folders with an exception of the exampleTLS folder.
```
wolfssl
   |src
   |wolfcrypt
          |benchmark
          |src
          |test
   |wolfssl
          |openssl
          |wolfcrypt
   |exampleTLS
```
In your project, select the exampleTLS folder, add or link all of the header and source files in `IDE/ECLIPSE/MICRIUM/` folder into the exampleTLS folder.

For each of the other folders, add or link all the source code in the corresponding folder.

Remove non-C platform dependent files from your build. At the moment, only aes_asm.asm and aes_asm.s must be removed from your wolfssl/wolfcrypt/src folder.

In your C/C++ compiler preprocessor settings, add the wolfSSL directory and sub dir to your include paths.
Here's an example of the paths that must be added.
```
$PROJ_DIR$\...\..
$PROJ_DIR$\...\src
$PROJ_DIR$\...\wolfcrypt
$PROJ_DIR$\...\wolfssl
$PROJ_DIR$\...\wolfssl\wolfcrypt
$PROJ_DIR$\...\IDE\ECLIPSE\MICRIUM
```
In your C/C++ compiler preprocessor settings, define the WOLFSSL_USER_SETTINGS symbol to enable the addition of user_settings.h file in your projects.

Add a call to `wolfsslRunTests()` from your startup task. Here's an example:
```
static  void  App_TaskStart (void *p_arg)
{
    OS_ERR  os_err;
    ...
    while (DEF_TRUE) {
           wolfsslRunTests();
           OSTimeDlyHMSM(0u, 5u, 0u, 0u,OS_OPT_TIME_HMSM_STRICT, &os_err);
        }
}
```
The starting project is based on an IAR EWARM project from Micrium download center at [micrium_twr-k70f120m-os3/](https://www.micrium.com/download/micrium_twr-k70f120m-os3/)
The following test results were collected from the TWR-K70F120M|Tower System Board|Kinetis MCUs|NXP.

### `WOLFSSL_WOLFCRYPT_TEST` output of wolfcrypt_test()
```
error    test passed!
base64   test passed!
asn      test passed!
MD5      test passed!
MD4      test passed!
SHA    test passed!
SHA-256  test passed!
SHA-512  test passed!
Hash     test passed!
HMAC-MD5 test passed!
HMAC-SHA test passed!
HAC-SHA256 test passed!
HMAC-SHA512 test passed!
GMC     test passed!
HC-128   test passed!
Rabbit   test passed!
DS      test passed!
DS3     test passed!
AES      test passed!
AES192   test passed!
AES256   test passed!
AES-GM  test pased!
RANDOM   test passed!
RSA      test passe!
DH       tes passd!
DSA      test passe!
PWDBASED test passed!
ECC      test passed!
ECC buffer test pssed!
CURVE25519 tst passed!
ED25519  test passed!
logging  tes passd!
mutex    testpassed!
memcb    test passed!
```
### `WOLFSSL_BENCHMARK_TEST` output of benchmark_test()
```
---------------------------------------------------------------------------
 wolfSSL version 3.5.5
----------------------------------------------------------------------------
wolCrypt Bencmark (bloc byte 1024 min 1.0 se each
RNG              20 KB tooks 1.108 seconds,  225.701 KB/s
AES-128-CBCenc    250 KB tooks 1.056 seconds,  236.759KB/s
AES-128-CBC-dec    250KB toks 1.51 seonds,  237.817 KB/s
AES-192-CBC-enc    225 KB toks 1.025 seconds,  219.473 KB/s
AES-192-CB-dec   225KB tooks 1.016 econd,  22.348 KB/s
AES256-CBC-enc    225 KB tooks 1.100 seconds,  204.540 KB/s
AES-256-CBC-dec   225 KB tooks 1.083 seconds,  20.848 KB/s
AES-128-GCM-enc    125 B toos 1.209 seonds,  103.394 KB/s
AES-128-GCM-dec    125 B tooks 1.09 seconds,  103.376 KB/s
AES-192-GCM-dec    100 KB tooks 1.007 seconds,   99.303 KB/s
AES-256-GM-enc   100 KB tooks 1.043 seconds,   95.885 KB/
AES-256-GCM-dec    100 KB tooks 1.043 econds,   9.869 B/s
RABBIT              2 MB tooks 1.001 econd,    2.245 MB/s
3DES              100 KB tooks 1.112 econds,   89.930 KB/s
MD5                  3 MB tooks 1.008 seconds,    2.906 MBs
SHA                1MB tooks 1.004 seconds,    1.313 MB/s
SHA-256           57 KB tooks 1.034 seconds,  556.254 KB/
SHA-512           00 KBtooks 1.092 seconds,  183.222 KB/s
HMAC-M5            3 MB tooks 1.002 seconds,   2.875 M/s
HMAC-SHA             1 MB tooks 1.03 seconds,    1.302 MBs
HMA-SHA256       575 KB tooks 1.042seconds,  551.66 KB/s
HMAC-SHA512        200 KB toks 1.108 seconds,  180.483 KB/s
RSA     2048 public          8 ps took 1.027 sec, avg 128.425 ms, 7.787 ops/sec
RSA     2048 private         2 op took 4.988sec, vg 244.240 ms, 0.401 ps/sec
```
### `WOLFSSL_CLIENT_TEST` wolfssl_client_test()

You can modify the `TCP_SERVER_IP_ADDR` and `TCP_SERVER_PORT` macros at top of the `client_wolfssl.c` file to configure the host address and port. You will also need the server certificate. This example uses TLS 1.2 to connect to a remote host.

### `WOLFSSL_SERVER_TEST` wolfssl_server_test()

You can modify the `TLS_SERVER_PORT` at top of `server_wolfssl.c` to configure the port number to listen on localhost.

## References

For more information please contact info@wolfssl.com.

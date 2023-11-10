# Microchip/Atmel ATECC508A/ATECC608A Support

wolfSSL includes support for ATECC508A and ATECC608A using these methods:
* TLS: Using the PK callbacks and reference ATECC508/608A callbacks. See Coding section below. Requires options `HAVE_PK_CALLBACKS` and `WOLFSSL_ATECC_PKCB or WOLFSSL_ATECC508A/WOLFSSL_ATECC608A`
* wolfCrypt: Native wc_ecc_* API's using the `./configure CFLAGS="-DWOLFSSL_ATECC608A"`, `#define WOLFSSL_ATECC508A`, or `#define WOLFSSL_ATECC608A`.

## Dependency

Requires the Microchip CryptoAuthLib library. The examples in `wolfcrypt/src/port/atmel/atmel.c` make calls to the `atcatls_*` API's.

## Building

### Build Options

* `HAVE_PK_CALLBACKS`: Option for enabling wolfSSL's PK callback support for TLS.
* `WOLFSSL_ATECC508A`: Enables support for initializing the CryptoAuthLib and setting up the encryption key used for the I2C communication.
* `WOLFSSL_ATECC608A`: Same as above, but for the ATECC608A module.
* `WOLFSSL_ATECC_PKCB`: Enables support for the reference PK callbacks without init.
* `WOLFSSL_ATECC_RNG`: Enables support for ATECC RNG.
* `WOLFSSL_ATECC_SHA256`: Enables support for ATECC SHA-256.
* `WOLFSSL_ATECC_ECDH_ENC`: Enable use of atcab_ecdh_enc() for encrypted ECDH.
* `WOLFSSL_ATECC_ECDH_IOENC`: Enable use of atcab_ecdh_ioenc() for encrypted ECDH.
* `WOLFSSL_ATECC_TNGTLS`: Enable support for Microchip Trust&GO module configuration.
* `WOLFSSL_ATECC_TFLXTLS`: Enable support for Microchip TrustFLEX with custom PKI module configuration
* `WOLFSSL_ATECC_DEBUG`: Enable wolfSSL ATECC debug messages.
* `WOLFSSL_ATMEL`: Enables ASF hooks seeding random data using the `atmel_get_random_number` function.
* `WOLFSSL_ATMEL_TIME`: Enables the built-in `atmel_get_curr_time_and_date` function get getting time from ASF RTC. 
* `ATECC_GET_ENC_KEY`: Macro to define your own function for getting the encryption key.
* `ATECC_SLOT_I2C_ENC`: Macro for the default encryption key slot. Can also get via the slot callback with `ATMEL_SLOT_ENCKEY`.
* `ATECC_MAX_SLOT`: Macro for the maximum dynamically allocated slots.

### Build Command Examples

`./configure --enable-pkcallbacks CFLAGS="-DWOLFSSL_ATECC_PKCB"`
`#define HAVE_PK_CALLBACKS`
`#define WOLFSSL_ATECC_PKCB`

or 

`./configure CFLAGS="-DWOLFSSL_ATECC608A"`
`#define WOLFSSL_ATECC608A`

## Coding

Setup the PK callbacks for TLS using:

```
/* Setup PK Callbacks for ATECC508/608A */
WOLFSSL_CTX* ctx;
wolfSSL_CTX_SetEccKeyGenCb(ctx, atcatls_create_key_cb);
wolfSSL_CTX_SetEccVerifyCb(ctx, atcatls_verify_signature_cb);
wolfSSL_CTX_SetEccSignCb(ctx, atcatls_sign_certificate_cb);
wolfSSL_CTX_SetEccSharedSecretCb(ctx, atcatls_create_pms_cb);
```

The reference ATECC508/608A PK callback functions are located in the `wolfcrypt/src/port/atmel/atmel.c` file.


Adding a custom context to the callbacks:

```
/* Setup PK Callbacks context */
WOLFSSL* ssl;
void* myOwnCtx;
wolfSSL_SetEccKeyGenCtx(ssl, myOwnCtx);
wolfSSL_SetEccVerifyCtx(ssl, myOwnCtx);
wolfSSL_SetEccSignCtx(ssl, myOwnCtx);
wolfSSL_SetEccSharedSecretCtx(ssl, myOwnCtx);
```

## Benchmarks

Supports ECC SECP256R1 (NIST P-256)

### TLS

TLS Establishment Times:

* Hardware accelerated ATECC508A: 2.342 seconds average
* Software only: 13.422 seconds average

The TLS connection establishment time is 5.73 times faster with the ATECC508A.

### Cryptographic ECC

Software only implementation (SAMD21 48Mhz Cortex-M0, Fast Math TFM-ASM):

`EC-DHE   key generation  3123.000 milliseconds, avg over 5 iterations, 1.601 ops/sec`
`EC-DHE   key agreement   3117.000 milliseconds, avg over 5 iterations, 1.604 ops/sec`
`EC-DSA   sign   time     1997.000 milliseconds, avg over 5 iterations, 2.504 ops/sec`
`EC-DSA   verify time     5057.000 milliseconds, avg over 5 iterations, 0.988 ops/sec`

ATECC508A HW accelerated implementation:
`EC-DHE   key generation  144.400 milliseconds, avg over 5 iterations, 34.722 ops/sec`
`EC-DHE   key agreement   134.200 milliseconds, avg over 5 iterations, 37.313 ops/sec`
`EC-DSA   sign   time     293.400 milliseconds, avg over 5 iterations, 17.065 ops/sec`
`EC-DSA   verify time     208.400 milliseconds, avg over 5 iterations, 24.038 ops/sec`

### Microchip Trust Anchor TA100 ECC/RSA

` ./configure CFLAGS="-DECC_USER_CURVES -DWOLFSSL_ATECC_NO_ECDH_ENC" --enable-microchip=100 --with-cryptoauthlib --enable-debug --disable-shared --enable-pkcallbacks --enable-keygen --enable-cmac && make
`

Supported Features:
RSA 2048 keygen/sign/verify
ECC-P256 keygen/sign/verify/shared secret

WOLFSSL_MICROCHIP_AESGCM can be used to enable AES-GCM but
It's unclear how to enable data zone locking in TA100.

```
 $ lscpu -e
CPU SOCKET CORE L1d:L1i:L2 ONLINE    MAXMHZ   MINMHZ
  0      0    0 0:0:0         yes 1800.0000 600.0000
  1      0    1 1:1:0         yes 1800.0000 600.0000
  2      0    2 2:2:0         yes 1800.0000 600.0000
  3      0    3 3:3:0         yes 1800.0000 600.0000

$ uname -a
Linux raspberrypi 6.1.21-v8+ #1642 SMP PREEMPT Mon Apr  3 17:24:16 BST 2023 aarch64 GNU/Linux

Software:
------------------------------------------------------------------------------
 wolfSSL version 5.6.0
------------------------------------------------------------------------------
Math:     Multi-Precision: Wolf(SP) word-size=64 bits=4096 sp_int.c
wolfCrypt Benchmark (block bytes 1048576, min 1.0 sec each)
Benchmarks:

RSA     2048  key gen         2 ops took 1.113 sec, avg 556.332 ms, 1.797 ops/sec
RSA     2048     sign       200 ops took 1.891 sec, avg 9.455 ms, 105.766 ops/sec
RSA     2048   verify      6900 ops took 1.011 sec, avg 0.147 ms, 6824.614 ops/sec

ECC   [      SECP256R1]   256  key gen       700 ops took 1.065 sec, avg 1.522 ms, 657.067 ops/sec
ECDHE [      SECP256R1]   256    agree       700 ops took 1.016 sec, avg 1.451 ms, 689.240 ops/sec
ECDSA [      SECP256R1]   256     sign       700 ops took 1.049 sec, avg 1.499 ms, 667.097 ops/sec
ECDSA [      SECP256R1]   256   verify      1000 ops took 1.001 sec, avg 1.001 ms, 998.930 ops/sec


Hardware Microchip TA100 with SPI:

Benchmarks:
./wolfcrypt/benchmark/benchmark -rsa_sign

RSA     2048  key gen   HW      1 ops took 12.190 sec, avg 12190.346 ms, 0.082 ops/sec
RSA     2048     sign   HW    100 ops took 14.006 sec, avg 140.062 ms, 7.140 ops/sec
RSA     2048   verify   HW    100 ops took 13.168 sec, avg 131.679 ms, 7.594 ops/sec

ECC   [      SECP256R1]   256  key gen       100 ops took 6.790 sec, avg 67.898 ms, 14.728 ops/sec
ECDHE [      SECP256R1]   256    agree       100 ops took 2.413 sec, avg 24.126 ms, 41.449 ops/sec
ECDSA [      SECP256R1]   256     sign       100 ops took 1.832 sec, avg 18.317 ms, 54.594 ops/sec
ECDSA [      SECP256R1]   256   verify       100 ops took 2.120 sec, avg 21.198 ms, 47.175 ops/sec

```

For details see our [wolfSSL Atmel ATECC508/608A](https://wolfssl.com/wolfSSL/wolfssl-atmel.html) page.

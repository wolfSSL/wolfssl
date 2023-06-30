# Wisekey VaultIC Port

Support for the VaultIC 420:
 - symmetric AES (ECB/CBC/CTR)
 - SHA1/SHA224/SHA256
 - PKI RSA (verify)

This port requires the VaultIC 420 Dev Kit from Wisekey and expect headers and corresponding functions from `vaultic.h`.

## VaultIC Hardware Crypto Offload

### Building

To enable support, configure wolfSSL to include crypto callbacks and define:

```
./configure --enable-cryptocb CFLAGS="-DHAVE_WISEKEY_VAULTIC"
```

or 

```
#define HAVE_CRYPTOCB`
#define HAVE_WISEKEY_VAULTIC`
```

### Coding

Register the VaultIC cryptocb device:

```
/* Setup PK Callbacks for STSAFE-A100 */
WOLFSSL_CTX* ctx;
wolfSSL_CTX_SetEccKeyGenCb(ctx, SSL_STSAFE_CreateKeyCb);
wolfSSL_CTX_SetEccSignCb(ctx, SSL_STSAFE_SignCertificateCb);
wolfSSL_CTX_SetEccVerifyCb(ctx, SSL_STSAFE_VerifyPeerCertCb);
wolfSSL_CTX_SetEccSharedSecretCb(ctx, SSL_STSAFE_SharedSecretCb);
wolfSSL_CTX_SetDevId(ctx, 0); /* enables wolfCrypt `wc_ecc_*` ST-Safe use */
```

The reference STSAFE-A100 PK callback functions are located in the `wolfcrypt/src/port/st/stsafe.c` file.

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

### Benchmarks and Memory Use

Software only implementation (STM32L4 120Mhz, Cortex-M4, Fast Math):

```
ECDHE    256 key gen       SW    4 ops took 1.278 sec, avg 319.500 ms,  3.130 ops/sec
ECDHE    256 agree         SW    4 ops took 1.306 sec, avg 326.500 ms,  3.063 ops/sec
ECDSA    256 sign          SW    4 ops took 1.298 sec, avg 324.500 ms,  3.082 ops/sec
ECDSA    256 verify        SW    2 ops took 1.283 sec, avg 641.500 ms,  1.559 ops/sec
```

Memory Use:

```
Peak Stack: 18456
Peak Heap: 2640
Total: 21096
```


STSAFE-A100 acceleration:

```
ECDHE    256 key gen       HW    8 ops took 1.008 sec, avg 126.000 ms,  7.937 ops/sec
ECDHE    256 agree         HW    6 ops took 1.051 sec, avg 175.167 ms,  5.709 ops/sec
ECDSA    256 sign          HW   14 ops took 1.161 sec, avg  82.929 ms, 12.059 ops/sec
ECDSA    256 verify        HW    8 ops took 1.184 sec, avg 148.000 ms,  6.757 ops/sec
```

Memory Use:

```
Peak Stack: 9592
Peak Heap: 170
Total: 9762
```


## Support

Email us at [support@wolfssl.com](mailto:support@wolfssl.com).

# Atmel ATECC508A Port

* Adds wolfCrypt support for ECC Hardware acceleration using the ATECC508A 
	* The new defines added for this port are: `WOLFSSL_ATMEL` and `WOLFSSL_ATECC508A`.
* Adds new PK callback for Pre Master Secret.


## Building

`./configure --enable-pkcallbacks CFLAGS="-DWOLFSSL_ATECC508A"`

or 

`#define HAVE_PK_CALLBACKS`
`#define WOLFSSL_ATECC508A`


## Coding

Setup the PK callbacks for TLS using:

```
/* Setup PK Callbacks for ATECC508A */
WOLFSSL_CTX* ctx;
wolfSSL_CTX_SetEccKeyGenCb(ctx, atcatls_create_key_cb);
wolfSSL_CTX_SetEccVerifyCb(ctx, atcatls_verify_signature_cb);
wolfSSL_CTX_SetEccSignCb(ctx, atcatls_sign_certificate_cb);
wolfSSL_CTX_SetEccSharedSecretCb(ctx, atcatls_create_pms_cb);
```

The reference ATECC508A PK callback functions are located in the `wolfcrypt/src/port/atmel/atmel.c` file.


Adding a custom contex to the callbacks:

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

### TLS

TLS Establishment Times:

* Hardware accelerated ATECC508A: 2.342 seconds avgerage
* Software only: 13.422 seconds average

The TLS connection establishment time is 5.73 times faster with the ATECC508A.

### Cryptographic ECC

Software only implementation (SAMD21 48Mhz Cortex-M0, Fast Math TFM-ASM):

`ECC  256 key generation  3123.000 milliseconds, avg over 5 iterations`
`EC-DHE   key agreement   3117.000 milliseconds, avg over 5 iterations`
`EC-DSA   sign   time     1997.000 milliseconds, avg over 5 iterations`
`EC-DSA   verify time     5057.000 milliseconds, avg over 5 iterations`

ATECC508A HW accelerated implementation:
`ECC  256 key generation  144.400 milliseconds, avg over 5 iterations`
`EC-DHE   key agreement   134.200 milliseconds, avg over 5 iterations`
`EC-DSA   sign   time     293.400 milliseconds, avg over 5 iterations`
`EC-DSA   verify time     208.400 milliseconds, avg over 5 iterations`


For details see our [wolfSSL Atmel ATECC508A](https://wolfssl.com/wolfSSL/wolfssl-atmel.html) page.
